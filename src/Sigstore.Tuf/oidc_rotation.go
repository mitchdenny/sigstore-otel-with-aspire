package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	tuf "github.com/theupdateframework/go-tuf"
)

const (
	oidcRotationRequestFile    = "rotate-oidc-signing-key.request"
	oidcRotationCompletionFile = "rotate-oidc-signing-key.completed"
	oidcRotationCompletionSchema = 1
)

// oidcRotationRequest is the schema-versioned request signal file content.
type oidcRotationRequest struct {
	SchemaVersion int    `json:"schemaVersion"`
	OperationID   string `json:"operationId"`
	TrustDomainID string `json:"trustDomainId"`
}

// oidcRotationCompletion records that OIDC rotation completed successfully.
type oidcRotationCompletion struct {
	SchemaVersion      int       `json:"schemaVersion"`
	OperationID        string    `json:"operationId"`
	TrustDomainID      string    `json:"trustDomainId"`
	CompletedAt        time.Time `json:"completedAtUtc"`
	PriorGeneration    int       `json:"priorGeneration"`
	PriorGenerationID  string    `json:"priorGenerationId"`
	PriorOidcKeyID     string    `json:"priorOidcKeyId"`
	NewGeneration      int       `json:"newGeneration"`
	NewGenerationID    string    `json:"newGenerationId"`
	NewOidcKeyID       string    `json:"newOidcKeyId"`
	ManifestSHA256     string    `json:"manifestSha256"`
	JwksKeyIDs         []string  `json:"jwksKeyIds"`
}

// jwk represents a single RSA public key in JWK format.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwks represents a JSON Web Key Set.
type jwks struct {
	Keys []jwk `json:"keys"`
}

// dispatchOidcRotation handles the full lifecycle of an OIDC signing key
// rotation request: validation, replay detection, generation advance, TUF
// republication, and completion. Holds the shared state lock across the
// entire operation for exactly-once semantics.
func dispatchOidcRotation(statePath string) (repositoryAction, error) {
	return dispatchOidcRotationWithHooks(statePath, publicationHooks{})
}

func dispatchOidcRotationWithHooks(statePath string, hooks publicationHooks) (repositoryAction, error) {
	requestPath := filepath.Join(statePath, oidcRotationRequestFile)

	// Read and validate the request strictly before acquiring the lock.
	requestData, err := os.ReadFile(requestPath)
	if err != nil {
		return "", fmt.Errorf("read OIDC rotation request: %w", err)
	}
	var req oidcRotationRequest
	if err := json.Unmarshal(requestData, &req); err != nil {
		return "", fmt.Errorf("parse OIDC rotation request: %w", err)
	}
	if req.SchemaVersion != 1 {
		return "", fmt.Errorf("OIDC rotation request schema %d unsupported (expected 1)", req.SchemaVersion)
	}
	if req.OperationID == "" {
		return "", fmt.Errorf("OIDC rotation request missing operationId")
	}
	if req.TrustDomainID == "" {
		return "", fmt.Errorf("OIDC rotation request missing trustDomainId")
	}

	// Acquire the shared state lock for the entire dispatch lifecycle.
	stateLock, err := acquireStateLock(statePath, 30*time.Second, "oidc-rotation-dispatch")
	if err != nil {
		return "", err
	}
	defer stateLock.release()

	// Validate request trust domain against immutable state under lock.
	domain, err := loadTrustDomain(statePath)
	if err != nil {
		return "", fmt.Errorf("load trust domain for OIDC rotation: %w", err)
	}
	if domain.TrustDomainID != req.TrustDomainID {
		return "", fmt.Errorf(
			"OIDC rotation request trust domain %q does not match immutable domain %q",
			req.TrustDomainID, domain.TrustDomainID)
	}

	// Check for replay: if completion already exists with this operation ID.
	comp, err := loadOidcRotationCompletion(statePath)
	if err != nil {
		return "", fmt.Errorf("ambiguous OIDC rotation completion state: %w", err)
	}
	if comp != nil && comp.OperationID == req.OperationID {
		// Validate completion matches current live state.
		if err := validateOidcCompletionAgainstState(statePath, comp); err != nil {
			return "", fmt.Errorf("OIDC rotation completion replay validation failed: %w", err)
		}
		// Replay success — remove request file.
		if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("remove OIDC rotation request after replay: %w", err)
		}
		return repositoryActionPublished, nil
	}

	// Load current trust generation.
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return "", fmt.Errorf("load active generation for OIDC rotation: %w", err)
	}

	// Perform the OIDC key rotation: create generation N+1 with new keys.
	newBootstrap, err := rotateOidcGeneration(statePath, bootstrap)
	if err != nil {
		return "", fmt.Errorf("rotate OIDC generation: %w", err)
	}

	// Publish updated TUF trust_status through proper candidate→commit lifecycle.
	// This must happen BEFORE switching the active-generation symlink so that
	// the active publication's fingerprint remains valid during the switch.
	if err := publishOidcTrustStatusUpdate(statePath, bootstrap, newBootstrap, hooks); err != nil {
		return "", fmt.Errorf("publish OIDC trust status update: %w", err)
	}

	// Switch active-generation symlink now that TUF publication succeeded.
	if err := switchActiveGeneration(statePath, bootstrap, newBootstrap, newBootstrap.GenerationManifestSHA256); err != nil {
		return "", fmt.Errorf("switch active generation: %w", err)
	}

	// Read new JWKS for completion record.
	newGenPath := filepath.Join(statePath, "generations", newBootstrap.GenerationID)
	jwksData, err := os.ReadFile(filepath.Join(newGenPath, "public", "oidc", "jwks.json"))
	if err != nil {
		return "", fmt.Errorf("read new JWKS for completion: %w", err)
	}
	var newJwks jwks
	if err := json.Unmarshal(jwksData, &newJwks); err != nil {
		return "", fmt.Errorf("parse new JWKS for completion: %w", err)
	}
	var jwksKeyIDs []string
	for _, k := range newJwks.Keys {
		jwksKeyIDs = append(jwksKeyIDs, k.Kid)
	}

	// Write completion atomically.
	newComp := oidcRotationCompletion{
		SchemaVersion:     oidcRotationCompletionSchema,
		OperationID:       req.OperationID,
		TrustDomainID:     req.TrustDomainID,
		CompletedAt:       time.Now().UTC(),
		PriorGeneration:   bootstrap.Generation,
		PriorGenerationID: bootstrap.GenerationID,
		PriorOidcKeyID:    bootstrap.OIDCKeyID,
		NewGeneration:     newBootstrap.Generation,
		NewGenerationID:   newBootstrap.GenerationID,
		NewOidcKeyID:      newBootstrap.OIDCKeyID,
		ManifestSHA256:    newBootstrap.GenerationManifestSHA256,
		JwksKeyIDs:        jwksKeyIDs,
	}
	if err := writeOidcRotationCompletion(statePath, newComp); err != nil {
		return "", err
	}

	// Remove request file last.
	if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("remove OIDC rotation request file: %w", err)
	}

	fmt.Printf("OIDC signing key rotated: %s -> %s (generation %d -> %d)\n",
		bootstrap.OIDCKeyID, newBootstrap.OIDCKeyID,
		bootstrap.Generation, newBootstrap.Generation)

	return repositoryActionPublished, nil
}

// rotateOidcGeneration creates generation N+1 with a new OIDC signing key,
// overlapping JWKS containing all prior keys, and all non-OIDC material
// preserved unchanged from the current generation.
func rotateOidcGeneration(statePath string, current bootstrapManifest) (bootstrapManifest, error) {
	newGeneration := current.Generation + 1
	newGenerationID := fmt.Sprintf("generation-%08d", newGeneration)
	currentGenerationPath := filepath.Join(statePath, "generations", current.GenerationID)
	newGenerationPath := filepath.Join(statePath, "generations", newGenerationID)

	// If generation N+1 already exists (interrupted prior attempt), validate and reuse.
	if pathExists(newGenerationPath) {
		return validateAndReuseOidcGeneration(statePath, current, newGenerationPath, newGenerationID, newGeneration)
	}

	// Generate new RSA 2048 key pair.
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("generate new OIDC signing key: %w", err)
	}

	// Compute new key ID: base64url(SHA-256(SPKI DER))
	newSPKI, err := x509.MarshalPKIXPublicKey(&newKey.PublicKey)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("marshal new OIDC public key: %w", err)
	}
	newKidHash := sha256.Sum256(newSPKI)
	newKid := base64.RawURLEncoding.EncodeToString(newKidHash[:])

	// Copy all files from current generation to new generation.
	if err := os.MkdirAll(newGenerationPath, 0o755); err != nil {
		return bootstrapManifest{}, fmt.Errorf("create new generation directory: %w", err)
	}
	if err := copyDirectory(currentGenerationPath, newGenerationPath); err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("copy prior generation material: %w", err)
	}

	// Remove prior manifest (will write new one).
	_ = os.Remove(filepath.Join(newGenerationPath, "manifest.json"))

	// Write new active private key.
	newPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustMarshalPKCS8(newKey),
	})
	signerKeyPath := filepath.Join(newGenerationPath, "private", "oidc", "signer.key")
	if err := os.WriteFile(signerKeyPath, newPrivateKeyPEM, 0o600); err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("write new OIDC signer key: %w", err)
	}

	// Retain old private key with a stable kid-based path.
	oldPrivateKeyPEM, err := os.ReadFile(filepath.Join(currentGenerationPath, "private", "oidc", "signer.key"))
	if err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("read old OIDC signer key: %w", err)
	}
	retainedDir := filepath.Join(newGenerationPath, "private", "oidc", "retained")
	if err := os.MkdirAll(retainedDir, 0o700); err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("create retained key directory: %w", err)
	}
	// Also preserve any existing retained keys from the current generation.
	currentRetainedDir := filepath.Join(currentGenerationPath, "private", "oidc", "retained")
	if pathExists(currentRetainedDir) {
		// Already copied by copyDirectory, so they exist in newGenerationPath
	}
	// Write old active key to retained (may overwrite copy if same name).
	oldRetainedPath := filepath.Join(retainedDir, fmt.Sprintf("signer-%s.key", current.OIDCKeyID))
	if err := os.WriteFile(oldRetainedPath, oldPrivateKeyPEM, 0o600); err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("write retained OIDC key: %w", err)
	}

	// Write new public key.
	newPublicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: newSPKI,
	})
	pubKeyPath := filepath.Join(newGenerationPath, "public", "oidc", "signer.pub")
	if err := os.WriteFile(pubKeyPath, newPublicKeyPEM, 0o644); err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("write new OIDC public key: %w", err)
	}

	// Build overlapping JWKS containing new key + all prior keys.
	existingJwksData, err := os.ReadFile(filepath.Join(currentGenerationPath, "public", "oidc", "jwks.json"))
	if err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("read existing JWKS: %w", err)
	}
	var existingJwks jwks
	if err := json.Unmarshal(existingJwksData, &existingJwks); err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("parse existing JWKS: %w", err)
	}

	// Create new JWK entry for the new key.
	newJWK := rsaPublicKeyToJWK(&newKey.PublicKey, newKid)

	// Overlapping JWKS: new key first, then all existing keys.
	overlappingJwks := jwks{
		Keys: append([]jwk{newJWK}, existingJwks.Keys...),
	}
	overlappingJwksData, err := json.MarshalIndent(overlappingJwks, "", "  ")
	if err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("marshal overlapping JWKS: %w", err)
	}
	overlappingJwksData = append(overlappingJwksData, '\n')
	jwksPath := filepath.Join(newGenerationPath, "public", "oidc", "jwks.json")
	if err := os.WriteFile(jwksPath, overlappingJwksData, 0o644); err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("write overlapping JWKS: %w", err)
	}

	// Compute file hashes for new generation.
	newFiles, err := collectGenerationFileHashes(newGenerationPath)
	if err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, err
	}

	// Write new generation manifest.
	now := time.Now().UTC()
	genManifest := generationManifest{
		SchemaVersion:        trustStateSchemaVersion,
		Generation:           newGeneration,
		GenerationID:         newGenerationID,
		TrustDomainID:        current.TrustDomainID,
		CreatedAtUTC:         now,
		SourceSchemaVersion:  trustStateSchemaVersion,
		SourceManifestSHA256: nil,
		FulcioRootSHA256:     current.FulcioRootSHA256,
		CtLogPublicKeySHA256: current.CtLogPublicKeySHA256,
		RekorPublicKeySHA256: current.RekorPublicKeySHA256,
		TsaRootSHA256:        current.TsaRootSHA256,
		TsaLeafSHA256:        current.TsaLeafSHA256,
		OIDCKeyID:            newKid,
		Files:                newFiles,
	}

	manifestBytes, err := json.MarshalIndent(genManifest, "", "  ")
	if err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("marshal OIDC rotation generation manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	manifestPath := filepath.Join(newGenerationPath, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o644); err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("write OIDC rotation generation manifest: %w", err)
	}
	manifestHash := hashBytes(manifestBytes)

	return bootstrapManifest{
		SchemaVersion:            4,
		CreatedAtUTC:             now,
		FulcioRootSHA256:         current.FulcioRootSHA256,
		CtLogPublicKeySHA256:     current.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:     current.RekorPublicKeySHA256,
		TsaRootSHA256:            current.TsaRootSHA256,
		TsaLeafSHA256:            current.TsaLeafSHA256,
		OIDCKeyID:                newKid,
		TrustDomainID:            current.TrustDomainID,
		Generation:               newGeneration,
		GenerationID:             newGenerationID,
		GenerationManifestSHA256: manifestHash,
	}, nil
}

// validateAndReuseOidcGeneration validates a pre-existing generation N+1
// directory from an interrupted prior OIDC rotation attempt.
func validateAndReuseOidcGeneration(
	statePath string,
	current bootstrapManifest,
	newGenPath string,
	newGenID string,
	newGen int,
) (bootstrapManifest, error) {
	manifestPath := filepath.Join(newGenPath, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("read pre-existing next-gen manifest: %w", err)
	}
	var genManifest generationManifest
	if err := json.Unmarshal(manifestBytes, &genManifest); err != nil {
		return bootstrapManifest{}, fmt.Errorf("parse pre-existing next-gen manifest: %w", err)
	}
	if genManifest.Generation != newGen {
		return bootstrapManifest{}, fmt.Errorf(
			"pre-existing generation has number %d, expected %d", genManifest.Generation, newGen)
	}
	if genManifest.GenerationID != newGenID {
		return bootstrapManifest{}, fmt.Errorf(
			"pre-existing generation has ID %q, expected %q", genManifest.GenerationID, newGenID)
	}
	if genManifest.TrustDomainID != current.TrustDomainID {
		return bootstrapManifest{}, fmt.Errorf(
			"pre-existing generation trust domain %q does not match current %q",
			genManifest.TrustDomainID, current.TrustDomainID)
	}
	// Verify files match manifest.
	actualFiles, err := collectGenerationFileHashes(newGenPath)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("hash pre-existing next-gen files: %w", err)
	}
	if len(actualFiles) != len(genManifest.Files) {
		return bootstrapManifest{}, errors.New("pre-existing generation file count mismatch")
	}
	for k, v := range genManifest.Files {
		if actualFiles[k] != v {
			return bootstrapManifest{}, fmt.Errorf("pre-existing generation file %q hash mismatch", k)
		}
	}

	manifestHash := hashBytes(manifestBytes)
	return bootstrapManifest{
		SchemaVersion:            4,
		CreatedAtUTC:             genManifest.CreatedAtUTC,
		FulcioRootSHA256:         genManifest.FulcioRootSHA256,
		CtLogPublicKeySHA256:     genManifest.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:     genManifest.RekorPublicKeySHA256,
		TsaRootSHA256:            genManifest.TsaRootSHA256,
		TsaLeafSHA256:            genManifest.TsaLeafSHA256,
		OIDCKeyID:                genManifest.OIDCKeyID,
		TrustDomainID:            genManifest.TrustDomainID,
		Generation:               genManifest.Generation,
		GenerationID:             genManifest.GenerationID,
		GenerationManifestSHA256: manifestHash,
	}, nil
}

// publishOidcTrustStatusUpdate updates TUF with the new generation's
// trust_status.v1.json using the proper candidate→commit publication lifecycle.
// TrustedRoot, SigningConfig, and all other targets remain byte-identical.
func publishOidcTrustStatusUpdate(
	statePath string,
	oldBootstrap bootstrapManifest,
	newBootstrap bootstrapManifest,
	hooks publicationHooks,
) error {
	oldFingerprint, err := fingerprintSource(oldBootstrap)
	if err != nil {
		return fmt.Errorf("compute old source fingerprint: %w", err)
	}
	newFingerprint, err := fingerprintSource(newBootstrap)
	if err != nil {
		return fmt.Errorf("compute new source fingerprint: %w", err)
	}

	layout := newTUFLayout(statePath)
	if err := ensureTUFLayout(layout); err != nil {
		return err
	}
	state, err := loadPublicationState(layout)
	if err != nil {
		return fmt.Errorf("load TUF publication state: %w", err)
	}
	if state.Status != publicationStatusCommitted {
		return fmt.Errorf("OIDC rotation requires committed publication, found %q", state.Status)
	}
	if state.Active == nil {
		return fmt.Errorf("no active TUF publication for OIDC rotation")
	}
	if err := cleanupPublicationTemps(layout); err != nil {
		return err
	}
	if err := cleanupUnjournaledCandidate(layout); err != nil {
		return err
	}

	activePath := committedPath(layout, state.Active.ID)
	if _, _, err := validateExistingRepository(activePath, oldFingerprint); err != nil {
		return fmt.Errorf("validate active publication before OIDC rotation: %w", err)
	}

	// Copy active publication to candidate.
	if err := os.Mkdir(layout.candidate, 0o755); err != nil {
		return fmt.Errorf("create OIDC rotation candidate directory: %w", err)
	}
	if err := copyDirectory(activePath, layout.candidate); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return err
	}

	// Read and update trust_status in candidate.
	statusPath := filepath.Join(layout.candidate, "targets", trustStatusTargetName)
	statusData, err := os.ReadFile(statusPath)
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("read trust status from candidate: %w", err)
	}
	var status trustStatusTarget
	if err := json.Unmarshal(statusData, &status); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("parse trust status: %w", err)
	}

	status.Generation = newBootstrap.Generation
	status.GenerationID = newBootstrap.GenerationID
	status.GenerationManifestSHA256 = newBootstrap.GenerationManifestSHA256

	updatedStatus, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("marshal updated trust status: %w", err)
	}
	updatedStatusBytes := append(updatedStatus, '\n')

	// Write updated target to candidate staged + public.
	if err := os.WriteFile(statusPath, updatedStatusBytes, 0o644); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("write candidate trust status target: %w", err)
	}
	stagedPath := filepath.Join(layout.candidate, "staged", "targets", trustStatusTargetName)
	if err := os.MkdirAll(filepath.Dir(stagedPath), 0o755); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("create candidate staged targets dir: %w", err)
	}
	if err := os.WriteFile(stagedPath, updatedStatusBytes, 0o644); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("write candidate staged trust status: %w", err)
	}

	// Re-sign TUF metadata in candidate with updated target.
	store := tuf.FileSystemStore(layout.candidate, nil)
	repository, err := tuf.NewRepoIndent(store, "", "  ")
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("open candidate TUF repository: %w", err)
	}
	rootVersion, err := repository.RootVersion()
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("read candidate root version: %w", err)
	}
	targetsVersion, err := repository.TargetsVersion()
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("read candidate targets version: %w", err)
	}
	newTargetsVersion := int(targetsVersion) + 1

	// Patch trust_status with correct TUF versions.
	status.TUFRootVersion = int(rootVersion)
	status.TUFTargetsVersion = newTargetsVersion
	updatedStatus, err = json.MarshalIndent(status, "", "  ")
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("re-marshal trust status with versions: %w", err)
	}
	updatedStatusBytes = append(updatedStatus, '\n')
	if err := os.WriteFile(statusPath, updatedStatusBytes, 0o644); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("rewrite candidate trust status with versions: %w", err)
	}
	if err := os.WriteFile(stagedPath, updatedStatusBytes, 0o644); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("rewrite staged trust status with versions: %w", err)
	}

	rootAndTargetsExpires := time.Now().UTC().AddDate(1, 0, 0)
	if err := repository.AddTargetWithExpires(trustStatusTargetName, nil, rootAndTargetsExpires); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("add updated trust status target: %w", err)
	}
	if err := repository.SnapshotWithExpires(time.Now().UTC().Add(30 * 24 * time.Hour)); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("OIDC rotation TUF snapshot: %w", err)
	}
	if err := repository.TimestampWithExpires(time.Now().UTC().Add(24 * time.Hour)); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("OIDC rotation TUF timestamp: %w", err)
	}
	if err := repository.Commit(); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("commit OIDC rotation TUF: %w", err)
	}

	// Write repository manifest with new source fingerprint.
	manifest := tufManifest{
		SchemaVersion:     tufSchemaVersion,
		CreatedAtUTC:      time.Now().UTC(),
		UpdatedAtUTC:      time.Now().UTC(),
		SourceFingerprint: newFingerprint,
	}
	if err := writeRepositoryManifest(layout.candidate, manifest); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("write OIDC rotation manifest: %w", err)
	}

	// Compute candidate reference and validate uniqueness.
	candidate, err := repositoryReference(layout.candidate, newFingerprint)
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("compute OIDC rotation candidate reference: %w", err)
	}
	if candidate.ID == state.Active.ID {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("OIDC rotation candidate is identical to active publication")
	}
	if pathExists(committedPath(layout, candidate.ID)) {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("OIDC rotation candidate %s already committed", candidate.ID)
	}

	// Begin transactional publication lifecycle.
	preparing := state
	preparing.Status = publicationStatusPreparing
	preparing.UpdatedAtUTC = time.Now().UTC()
	preparing.Candidate = &candidate
	if err := writePublicationState(layout, preparing); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return err
	}
	if err := runCheckpoint(hooks, checkpointCandidatePrepared); err != nil {
		return rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}

	if state.Previous != nil {
		if err := os.Rename(layout.previous, layout.retiredPrevious); err != nil {
			return rollbackPreparingPublication(layout, preparing, oldFingerprint,
				fmt.Errorf("park previous publication: %w", err))
		}
	}
	if err := runCheckpoint(hooks, checkpointHistoryParked); err != nil {
		return rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}

	candidatePath := committedPath(layout, candidate.ID)
	if err := os.Rename(layout.candidate, candidatePath); err != nil {
		return rollbackPreparingPublication(layout, preparing, oldFingerprint,
			fmt.Errorf("commit OIDC rotation candidate: %w", err))
	}
	if err := runCheckpoint(hooks, checkpointCandidateCommitted); err != nil {
		return rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}
	if err := switchActivePublication(layout, candidate.ID, hooks); err != nil {
		return rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}
	if err := runCheckpoint(hooks, checkpointActiveSwitched); err != nil {
		return err
	}

	return finalizePublishPublication(layout, preparing, oldFingerprint, newFingerprint, hooks)
}

// loadOidcRotationCompletion reads the OIDC rotation completion file.
// Returns (nil, nil) if the file does not exist.
func loadOidcRotationCompletion(statePath string) (*oidcRotationCompletion, error) {
	completionPath := filepath.Join(statePath, oidcRotationCompletionFile)
	data, err := os.ReadFile(completionPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read OIDC rotation completion: %w", err)
	}
	var comp oidcRotationCompletion
	if err := json.Unmarshal(data, &comp); err != nil {
		return nil, fmt.Errorf("malformed OIDC rotation completion: %w", err)
	}
	if comp.SchemaVersion != oidcRotationCompletionSchema {
		return nil, fmt.Errorf("OIDC rotation completion schema %d unsupported", comp.SchemaVersion)
	}
	if comp.OperationID == "" || comp.TrustDomainID == "" {
		return nil, fmt.Errorf("OIDC rotation completion missing required fields")
	}
	return &comp, nil
}

// writeOidcRotationCompletion atomically writes the completion record.
func writeOidcRotationCompletion(statePath string, comp oidcRotationCompletion) error {
	data, err := json.MarshalIndent(comp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal OIDC rotation completion: %w", err)
	}
	data = append(data, '\n')
	return writeAtomicJSON(filepath.Join(statePath, oidcRotationCompletionFile), data)
}

// validateOidcCompletionAgainstState ensures completion matches live state.
func validateOidcCompletionAgainstState(statePath string, comp *oidcRotationCompletion) error {
	domain, err := loadTrustDomain(statePath)
	if err != nil {
		return fmt.Errorf("load trust domain: %w", err)
	}
	if comp.TrustDomainID != domain.TrustDomainID {
		return fmt.Errorf("completion trust domain %q does not match active %q",
			comp.TrustDomainID, domain.TrustDomainID)
	}
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return fmt.Errorf("load active generation: %w", err)
	}
	if comp.NewGeneration != bootstrap.Generation {
		return fmt.Errorf("completion generation %d does not match active %d",
			comp.NewGeneration, bootstrap.Generation)
	}
	if comp.NewGenerationID != bootstrap.GenerationID {
		return fmt.Errorf("completion generationId %q does not match active %q",
			comp.NewGenerationID, bootstrap.GenerationID)
	}
	if comp.ManifestSHA256 != bootstrap.GenerationManifestSHA256 {
		return fmt.Errorf("completion manifestSha256 does not match active generation")
	}
	if comp.NewOidcKeyID != bootstrap.OIDCKeyID {
		return fmt.Errorf("completion OIDC key ID %q does not match active %q",
			comp.NewOidcKeyID, bootstrap.OIDCKeyID)
	}
	return nil
}

// rsaPublicKeyToJWK converts an RSA public key to JWK format.
func rsaPublicKeyToJWK(pub *rsa.PublicKey, kid string) jwk {
	return jwk{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// mustMarshalPKCS8 marshals an RSA private key to PKCS#8 DER.
func mustMarshalPKCS8(key *rsa.PrivateKey) []byte {
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(fmt.Sprintf("marshal PKCS#8: %v", err))
	}
	return data
}
