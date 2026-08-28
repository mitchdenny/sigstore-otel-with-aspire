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

	// Update TUF trust_status target with new generation info.
	if err := updateTrustStatusForOidcRotation(statePath, newBootstrap); err != nil {
		return "", fmt.Errorf("update TUF trust status: %w", err)
	}

	// Switch active-generation symlink.
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
	if err := os.MkdirAll(filepath.Dir(newGenerationPath), 0o755); err != nil {
		return bootstrapManifest{}, fmt.Errorf("create generations directory: %w", err)
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

// updateTrustStatusForOidcRotation updates the trust_status.v1.json target
// in TUF with the new generation information. TrustedRoot and SigningConfig
// bytes remain unchanged (OIDC keys are not in TrustedRoot).
func updateTrustStatusForOidcRotation(statePath string, newBootstrap bootstrapManifest) error {
	tufPath := filepath.Join(statePath, "tuf")
	layout := newTUFLayout(statePath)
	state, err := loadPublicationState(layout)
	if err != nil {
		return fmt.Errorf("load TUF publication state: %w", err)
	}
	if state.Active == nil {
		return fmt.Errorf("no active TUF publication for OIDC rotation trust status update")
	}

	activePath := committedPath(layout, state.Active.ID)
	statusPath := filepath.Join(activePath, "targets", trustStatusTargetName)
	statusData, err := os.ReadFile(statusPath)
	if err != nil {
		return fmt.Errorf("read existing trust status target: %w", err)
	}
	var status trustStatusTarget
	if err := json.Unmarshal(statusData, &status); err != nil {
		return fmt.Errorf("parse existing trust status target: %w", err)
	}

	// Update generation info (TrustedRoot/SigningConfig unchanged).
	status.Generation = newBootstrap.Generation
	status.GenerationID = newBootstrap.GenerationID
	status.GenerationManifestSHA256 = newBootstrap.GenerationManifestSHA256
	status.TUFTargetsVersion = status.TUFTargetsVersion + 1

	updatedStatus, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal updated trust status: %w", err)
	}
	updatedStatusBytes := append(updatedStatus, '\n')

	// Write to both TUF repository targets and public targets.
	store := tuf.FileSystemStore(tufPath, nil)
	repository, err := tuf.NewRepoIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("open TUF repository for OIDC rotation: %w", err)
	}

	stagedStatusPath := filepath.Join(tufPath, "staged", "targets", trustStatusTargetName)
	if err := os.MkdirAll(filepath.Dir(stagedStatusPath), 0o755); err != nil {
		return fmt.Errorf("create staged targets directory: %w", err)
	}
	if err := os.WriteFile(stagedStatusPath, updatedStatusBytes, 0o644); err != nil {
		return fmt.Errorf("write staged trust status: %w", err)
	}
	// Update in active publication targets too.
	if err := os.WriteFile(statusPath, updatedStatusBytes, 0o644); err != nil {
		return fmt.Errorf("write active trust status: %w", err)
	}

	rootExpires := time.Now().UTC().AddDate(1, 0, 0)
	if err := repository.AddTargetWithExpires(trustStatusTargetName, nil, rootExpires); err != nil {
		return fmt.Errorf("re-add trust status target: %w", err)
	}
	if err := repository.SnapshotWithExpires(time.Now().UTC().Add(30 * 24 * time.Hour)); err != nil {
		return fmt.Errorf("create OIDC rotation TUF snapshot: %w", err)
	}
	if err := repository.TimestampWithExpires(time.Now().UTC().Add(24 * time.Hour)); err != nil {
		return fmt.Errorf("create OIDC rotation TUF timestamp: %w", err)
	}
	if err := repository.Commit(); err != nil {
		return fmt.Errorf("commit OIDC rotation TUF update: %w", err)
	}
	return nil
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
