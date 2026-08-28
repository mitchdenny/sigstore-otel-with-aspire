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
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	tuf "github.com/theupdateframework/go-tuf"
)

const (
	oidcRotationRequestFile      = "rotate-oidc-signing-key.request"
	oidcRotationCompletionFile   = "rotate-oidc-signing-key.completed"
	oidcRotationCompletionSchema = 2
	oidcRotationSchema           = 2
	oidcRotationDirectory        = "oidc-rotation"
)

// oidcRotationRequest is the schema-versioned request signal file content.
type oidcRotationRequest struct {
	SchemaVersion        int    `json:"schemaVersion"`
	OperationID          string `json:"operationId"`
	TrustDomainID        string `json:"trustDomainId"`
	StartingGeneration   int    `json:"startingGeneration"`
	StartingGenerationID string `json:"startingGenerationId"`
	StartingOIDCKeyID    string `json:"startingOidcKeyId"`
}

// oidcRotationCompletion records that OIDC rotation completed successfully.
type oidcRotationCompletion struct {
	SchemaVersion        int       `json:"schemaVersion"`
	OperationID          string    `json:"operationId"`
	TrustDomainID        string    `json:"trustDomainId"`
	CompletedAt          time.Time `json:"completedAtUtc"`
	PriorGeneration      int       `json:"priorGeneration"`
	PriorGenerationID    string    `json:"priorGenerationId"`
	PriorOidcKeyID       string    `json:"priorOidcKeyId"`
	NewGeneration        int       `json:"newGeneration"`
	NewGenerationID      string    `json:"newGenerationId"`
	NewOidcKeyID         string    `json:"newOidcKeyId"`
	ManifestSHA256       string    `json:"manifestSha256"`
	JwksKeyIDs           []string  `json:"jwksKeyIds"`
	JwksSHA256           string    `json:"jwksSha256"`
	RetainedKeyPaths     []string  `json:"retainedKeyPaths"`
	TokenLifetimeSeconds int       `json:"tokenLifetimeSeconds"`
	OverlapExpiresAt     time.Time `json:"overlapExpiresAtUtc"`
	PublicationID        string    `json:"publicationId"`
}

const (
	// oidcTokenLifetimeSeconds is the configured OIDC token lifetime (30 min).
	oidcTokenLifetimeSeconds = 1800
	// oidcClockSkewSeconds is allowed clock drift for token validation.
	oidcClockSkewSeconds = 30
)

var (
	oidcOperationIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	oidcKeyIDPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

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
	requestData, err := os.ReadFile(requestPath)
	if err != nil {
		return "", fmt.Errorf("read OIDC rotation request: %w", err)
	}
	var req oidcRotationRequest
	if err := json.Unmarshal(requestData, &req); err != nil {
		return "", fmt.Errorf("parse OIDC rotation request: %w", err)
	}
	if err := validateOIDCRotationRequest(req); err != nil {
		return "", err
	}

	stateLock, err := acquireStateLock(statePath, 30*time.Second, "oidc-rotation-dispatch")
	if err != nil {
		return "", err
	}
	defer stateLock.release()

	domain, err := loadTrustDomain(statePath)
	if err != nil {
		return "", fmt.Errorf("load trust domain for OIDC rotation: %w", err)
	}
	if domain.TrustDomainID != req.TrustDomainID {
		return "", fmt.Errorf(
			"OIDC rotation request trust domain %q does not match immutable domain %q",
			req.TrustDomainID, domain.TrustDomainID)
	}

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

	if err := recoverCommittedOIDCRotation(statePath, req); err != nil {
		return "", fmt.Errorf("recover committed OIDC rotation: %w", err)
	}
	if _, err := recoverTUFStateLocked(statePath, hooks); err != nil {
		return "", fmt.Errorf("recover TUF publication for OIDC rotation: %w", err)
	}
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return "", fmt.Errorf("load active generation for OIDC rotation: %w", err)
	}
	if bootstrap.Generation == req.StartingGeneration+1 {
		generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
		if err != nil {
			return "", err
		}
		if generation.OIDCRotationOperationID != req.OperationID {
			return "", fmt.Errorf(
				"active generation %s belongs to OIDC rotation %q, not %q",
				bootstrap.GenerationID,
				generation.OIDCRotationOperationID,
				req.OperationID,
			)
		}
		if err := validateOIDCRequestStartingState(req, generation); err != nil {
			return "", err
		}
		if err := finalizeOIDCRotationCompletion(statePath, req, bootstrap); err != nil {
			return "", err
		}
		if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("remove recovered OIDC rotation request: %w", err)
		}
		return repositoryActionRecovered, nil
	}
	if bootstrap.Generation != req.StartingGeneration ||
		bootstrap.GenerationID != req.StartingGenerationID ||
		bootstrap.OIDCKeyID != req.StartingOIDCKeyID {
		return "", errors.New("OIDC rotation request does not match the active starting generation")
	}

	newBootstrap, err := rotateOidcGeneration(statePath, bootstrap, req)
	if err != nil {
		return "", fmt.Errorf("rotate OIDC generation: %w", err)
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("oidc-generation-committed")); err != nil {
		return "", err
	}

	if err := publishOidcTrustStatusUpdate(statePath, bootstrap, newBootstrap, hooks); err != nil {
		return "", fmt.Errorf("publish OIDC trust status update: %w", err)
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("oidc-tuf-committed")); err != nil {
		return "", err
	}

	if err := switchActiveGeneration(statePath, bootstrap, newBootstrap, newBootstrap.GenerationManifestSHA256); err != nil {
		return "", fmt.Errorf("switch active generation: %w", err)
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("oidc-generation-switched")); err != nil {
		return "", err
	}

	if err := finalizeOIDCRotationCompletion(statePath, req, newBootstrap); err != nil {
		return "", err
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("oidc-completion-written")); err != nil {
		return "", err
	}

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
func rotateOidcGeneration(
	statePath string,
	current bootstrapManifest,
	request oidcRotationRequest,
) (bootstrapManifest, error) {
	newGeneration := current.Generation + 1
	newGenerationID := fmt.Sprintf("generation-%08d", newGeneration)
	currentGenerationPath := filepath.Join(statePath, "generations", current.GenerationID)
	newGenerationPath := filepath.Join(statePath, "generations", newGenerationID)

	if pathExists(newGenerationPath) {
		return validateAndReuseOidcGeneration(
			statePath,
			current,
			newGenerationPath,
			newGenerationID,
			newGeneration,
			request,
		)
	}
	stagingGenerationPath := filepath.Join(
		statePath,
		oidcRotationDirectory,
		request.OperationID,
		newGenerationID+".staging",
	)
	if err := os.RemoveAll(stagingGenerationPath); err != nil {
		return bootstrapManifest{}, fmt.Errorf("clean OIDC generation staging directory: %w", err)
	}
	currentManifest, err := readOIDCGenerationManifest(
		statePath,
		current.GenerationID,
	)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("read current OIDC generation manifest: %w", err)
	}
	if err := validateOIDCGenerationMaterial(
		currentGenerationPath,
		currentManifest,
	); err != nil {
		return bootstrapManifest{}, fmt.Errorf("validate current OIDC generation: %w", err)
	}
	newKey, err := ensureOIDCOperationCandidate(statePath, request.OperationID)
	if err != nil {
		return bootstrapManifest{}, err
	}

	// Compute new key ID: base64url(SHA-256(SPKI DER))
	newSPKI, err := x509.MarshalPKIXPublicKey(&newKey.PublicKey)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("marshal new OIDC public key: %w", err)
	}
	newKidHash := sha256.Sum256(newSPKI)
	newKid := base64.RawURLEncoding.EncodeToString(newKidHash[:])

	// Copy all files from current generation to new generation.
	if err := os.MkdirAll(stagingGenerationPath, 0o755); err != nil {
		return bootstrapManifest{}, fmt.Errorf("create new generation directory: %w", err)
	}
	if err := copyDirectory(currentGenerationPath, stagingGenerationPath); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("copy prior generation material: %w", err)
	}

	// Remove prior manifest (will write new one).
	_ = os.Remove(filepath.Join(stagingGenerationPath, "manifest.json"))

	// Write new active private key.
	newPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustMarshalPKCS8(newKey),
	})
	signerKeyPath := filepath.Join(stagingGenerationPath, "private", "oidc", "signer.key")
	if err := os.WriteFile(signerKeyPath, newPrivateKeyPEM, 0o600); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("write new OIDC signer key: %w", err)
	}

	// Retain old private key with a stable kid-based path.
	oldPrivateKeyPEM, err := os.ReadFile(filepath.Join(currentGenerationPath, "private", "oidc", "signer.key"))
	if err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("read old OIDC signer key: %w", err)
	}
	retainedDir := filepath.Join(stagingGenerationPath, "private", "oidc", "retained")
	if err := os.MkdirAll(retainedDir, 0o700); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
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
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("write retained OIDC key: %w", err)
	}

	// Write new public key.
	newPublicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: newSPKI,
	})
	pubKeyPath := filepath.Join(stagingGenerationPath, "public", "oidc", "signer.pub")
	if err := os.WriteFile(pubKeyPath, newPublicKeyPEM, 0o644); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("write new OIDC public key: %w", err)
	}

	// Build overlapping JWKS containing new key + retained prior keys.
	existingJwksData, err := os.ReadFile(filepath.Join(currentGenerationPath, "public", "oidc", "jwks.json"))
	if err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("read existing JWKS: %w", err)
	}
	var existingJwks jwks
	if err := json.Unmarshal(existingJwksData, &existingJwks); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("parse existing JWKS: %w", err)
	}

	// Create new JWK entry for the new key.
	newJWK := rsaPublicKeyToJWK(&newKey.PublicKey, newKid)

	retainedKeys := append([]jwk(nil), existingJwks.Keys...)

	// Overlapping JWKS: new active key first, then retained historical keys.
	overlappingJwks := jwks{
		Keys: append([]jwk{newJWK}, retainedKeys...),
	}

	overlappingJwksData, err := json.MarshalIndent(overlappingJwks, "", "  ")
	if err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("marshal overlapping JWKS: %w", err)
	}
	overlappingJwksData = append(overlappingJwksData, '\n')
	jwksPath := filepath.Join(stagingGenerationPath, "public", "oidc", "jwks.json")
	if err := os.WriteFile(jwksPath, overlappingJwksData, 0o644); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("write overlapping JWKS: %w", err)
	}

	// Compute file hashes for new generation.
	newFiles, err := collectGenerationFileHashes(stagingGenerationPath)
	if err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, err
	}

	// Write new generation manifest.
	now := time.Now().UTC()
	overlapExpires := now.Add(
		time.Duration(oidcTokenLifetimeSeconds+oidcClockSkewSeconds) * time.Second,
	)
	retainedPaths := make([]string, 0, len(retainedKeys))
	for _, key := range retainedKeys {
		retainedPaths = append(
			retainedPaths,
			filepath.ToSlash(filepath.Join(
				"private",
				"oidc",
				"retained",
				fmt.Sprintf("signer-%s.key", key.Kid),
			)),
		)
	}
	sort.Strings(retainedPaths)
	genManifest := generationManifest{
		SchemaVersion:               trustStateSchemaVersion,
		Generation:                  newGeneration,
		GenerationID:                newGenerationID,
		TrustDomainID:               current.TrustDomainID,
		CreatedAtUTC:                now,
		SourceSchemaVersion:         trustStateSchemaVersion,
		SourceManifestSHA256:        nil,
		FulcioRootSHA256:            current.FulcioRootSHA256,
		CtLogPublicKeySHA256:        current.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:        current.RekorPublicKeySHA256,
		TsaRootSHA256:               current.TsaRootSHA256,
		TsaLeafSHA256:               current.TsaLeafSHA256,
		OIDCKeyID:                   newKid,
		OIDCRotationOperationID:     request.OperationID,
		OIDCPriorGeneration:         current.Generation,
		OIDCPriorGenerationID:       current.GenerationID,
		OIDCPriorKeyID:              current.OIDCKeyID,
		OIDCOverlapExpiresAtUTC:     &overlapExpires,
		OIDCRetainedPrivateKeyPaths: retainedPaths,
		TSARotationOperationID:      currentManifest.TSARotationOperationID,
		TSAPriorGeneration:          currentManifest.TSAPriorGeneration,
		TSAPriorGenerationID:        currentManifest.TSAPriorGenerationID,
		TSAPriorRootSHA256:          currentManifest.TSAPriorRootSHA256,
		TSAPriorLeafSHA256:          currentManifest.TSAPriorLeafSHA256,
		FulcioRotationOperationID:   currentManifest.FulcioRotationOperationID,
		FulcioPriorGeneration:       currentManifest.FulcioPriorGeneration,
		FulcioPriorGenerationID:     currentManifest.FulcioPriorGenerationID,
		FulcioPriorRootSHA256:       currentManifest.FulcioPriorRootSHA256,
		Files:                       newFiles,
	}

	manifestBytes, err := json.MarshalIndent(genManifest, "", "  ")
	if err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("marshal OIDC rotation generation manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	manifestPath := filepath.Join(stagingGenerationPath, "manifest.json")
	if err := writeGenerationManifest(manifestPath, manifestBytes); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("write OIDC rotation generation manifest: %w", err)
	}
	manifestHash := hashBytes(manifestBytes)
	if err := validateOIDCGenerationMaterial(stagingGenerationPath, genManifest); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("validate rotated OIDC generation: %w", err)
	}
	if err := validateUnchangedNonOIDCMaterial(
		currentGenerationPath,
		stagingGenerationPath,
	); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, err
	}
	if err := os.Rename(stagingGenerationPath, newGenerationPath); err != nil {
		return bootstrapManifest{}, fmt.Errorf("commit OIDC generation: %w", err)
	}
	if err := syncDirectory(filepath.Dir(newGenerationPath)); err != nil {
		return bootstrapManifest{}, fmt.Errorf("sync committed OIDC generation: %w", err)
	}

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
	request oidcRotationRequest,
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
	if genManifest.OIDCRotationOperationID != request.OperationID ||
		genManifest.OIDCPriorGeneration != request.StartingGeneration ||
		genManifest.OIDCPriorGenerationID != request.StartingGenerationID ||
		genManifest.OIDCPriorKeyID != request.StartingOIDCKeyID {
		return bootstrapManifest{}, errors.New(
			"pre-existing generation is not bound to this OIDC rotation request",
		)
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
	if err := validateOIDCGenerationMaterial(newGenPath, genManifest); err != nil {
		return bootstrapManifest{}, err
	}
	if err := validateUnchangedNonOIDCMaterial(
		filepath.Join(statePath, "generations", current.GenerationID),
		newGenPath,
	); err != nil {
		return bootstrapManifest{}, err
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
	if !oidcOperationIDPattern.MatchString(comp.OperationID) ||
		comp.NewGeneration != comp.PriorGeneration+1 ||
		comp.PriorGenerationID != fmt.Sprintf(
			"generation-%08d",
			comp.PriorGeneration,
		) ||
		comp.NewGenerationID != fmt.Sprintf(
			"generation-%08d",
			comp.NewGeneration,
		) ||
		!oidcKeyIDPattern.MatchString(comp.PriorOidcKeyID) ||
		!oidcKeyIDPattern.MatchString(comp.NewOidcKeyID) ||
		validateSHA256(comp.ManifestSHA256) != nil ||
		validateSHA256(comp.JwksSHA256) != nil ||
		comp.TokenLifetimeSeconds != oidcTokenLifetimeSeconds ||
		comp.OverlapExpiresAt.IsZero() ||
		comp.PublicationID == "" {
		return nil, errors.New("OIDC rotation completion has invalid durable state")
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
	generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return err
	}
	if generation.OIDCRotationOperationID != comp.OperationID ||
		generation.OIDCPriorGeneration != comp.PriorGeneration ||
		generation.OIDCPriorGenerationID != comp.PriorGenerationID ||
		generation.OIDCPriorKeyID != comp.PriorOidcKeyID ||
		generation.OIDCOverlapExpiresAtUTC == nil ||
		!generation.OIDCOverlapExpiresAtUTC.Equal(comp.OverlapExpiresAt) ||
		!reflect.DeepEqual(
			generation.OIDCRetainedPrivateKeyPaths,
			comp.RetainedKeyPaths,
		) {
		return errors.New("completion does not match OIDC generation metadata")
	}
	generationPath := filepath.Join(statePath, "generations", bootstrap.GenerationID)
	keyIDs, jwksHash, err := readValidatedOIDCJWKS(generationPath)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(keyIDs, comp.JwksKeyIDs) ||
		jwksHash != comp.JwksSHA256 {
		return errors.New("completion does not match the active OIDC JWKS")
	}
	publication, err := loadPublicationState(newTUFLayout(statePath))
	if err != nil {
		return err
	}
	if publication.Status != publicationStatusCommitted ||
		publication.Active == nil ||
		publication.Active.ID != comp.PublicationID {
		return errors.New("completion does not match the active TUF publication")
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

func validateOIDCRotationRequest(request oidcRotationRequest) error {
	if request.SchemaVersion != oidcRotationSchema {
		return fmt.Errorf(
			"OIDC rotation request schema %d unsupported (expected %d)",
			request.SchemaVersion,
			oidcRotationSchema,
		)
	}
	if !oidcOperationIDPattern.MatchString(request.OperationID) {
		return errors.New("OIDC rotation operationId must be 32 lowercase hexadecimal characters")
	}
	if request.TrustDomainID == "" ||
		request.StartingGeneration < initialGeneration ||
		request.StartingGenerationID != fmt.Sprintf(
			"generation-%08d",
			request.StartingGeneration,
		) ||
		!oidcKeyIDPattern.MatchString(request.StartingOIDCKeyID) {
		return errors.New("OIDC rotation request has invalid starting trust state")
	}
	return nil
}

func validateOIDCRequestStartingState(
	request oidcRotationRequest,
	generation generationManifest,
) error {
	if generation.OIDCPriorGeneration != request.StartingGeneration ||
		generation.OIDCPriorGenerationID != request.StartingGenerationID ||
		generation.OIDCPriorKeyID != request.StartingOIDCKeyID ||
		generation.TrustDomainID != request.TrustDomainID {
		return errors.New("OIDC rotation generation does not match its request starting state")
	}
	return nil
}

func ensureOIDCOperationCandidate(
	statePath string,
	operationID string,
) (*rsa.PrivateKey, error) {
	operationPath := filepath.Join(statePath, oidcRotationDirectory, operationID)
	if err := os.MkdirAll(operationPath, 0o700); err != nil {
		return nil, fmt.Errorf("create OIDC operation state: %w", err)
	}
	path := filepath.Join(operationPath, "candidate.key")
	if data, err := os.ReadFile(path); err == nil {
		return parseOIDCPrivateKey(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read OIDC operation candidate: %w", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate OIDC operation candidate: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustMarshalPKCS8(key),
	})
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create OIDC operation candidate: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write OIDC operation candidate: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("fsync OIDC operation candidate: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close OIDC operation candidate: %w", err)
	}
	if err := syncDirectory(operationPath); err != nil {
		return nil, err
	}
	return key, nil
}

func parseOIDCPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil ||
		block.Type != "PRIVATE KEY" ||
		len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("OIDC private key is not one PKCS#8 PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok || rsaKey.N.BitLen() < 2048 {
		return nil, errors.New("OIDC private key must be RSA with at least 2048 bits")
	}
	if err := rsaKey.Validate(); err != nil {
		return nil, err
	}
	return rsaKey, nil
}

func readOIDCGenerationManifest(
	statePath string,
	generationID string,
) (generationManifest, error) {
	data, err := os.ReadFile(filepath.Join(
		statePath,
		"generations",
		generationID,
		"manifest.json",
	))
	if err != nil {
		return generationManifest{}, err
	}
	var manifest generationManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return generationManifest{}, err
	}
	return manifest, nil
}

func finalizeOIDCRotationCompletion(
	statePath string,
	request oidcRotationRequest,
	bootstrap bootstrapManifest,
) error {
	generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return fmt.Errorf("read rotated generation for completion: %w", err)
	}
	if generation.OIDCRotationOperationID != request.OperationID {
		return errors.New("rotated generation operation ID does not match completion request")
	}
	generationPath := filepath.Join(statePath, "generations", bootstrap.GenerationID)
	keyIDs, jwksHash, err := readValidatedOIDCJWKS(generationPath)
	if err != nil {
		return err
	}
	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return fmt.Errorf("load final OIDC TUF publication: %w", err)
	}
	if publication.Status != publicationStatusCommitted || publication.Active == nil {
		return errors.New("OIDC rotation has no committed active TUF publication")
	}
	now := time.Now().UTC()
	overlapExpires := generation.OIDCOverlapExpiresAtUTC
	if overlapExpires == nil {
		return errors.New("rotated generation omits overlap expiry")
	}
	completion := oidcRotationCompletion{
		SchemaVersion:        oidcRotationCompletionSchema,
		OperationID:          request.OperationID,
		TrustDomainID:        request.TrustDomainID,
		CompletedAt:          now,
		PriorGeneration:      request.StartingGeneration,
		PriorGenerationID:    request.StartingGenerationID,
		PriorOidcKeyID:       request.StartingOIDCKeyID,
		NewGeneration:        bootstrap.Generation,
		NewGenerationID:      bootstrap.GenerationID,
		NewOidcKeyID:         bootstrap.OIDCKeyID,
		ManifestSHA256:       bootstrap.GenerationManifestSHA256,
		JwksKeyIDs:           keyIDs,
		JwksSHA256:           jwksHash,
		RetainedKeyPaths:     generation.OIDCRetainedPrivateKeyPaths,
		TokenLifetimeSeconds: oidcTokenLifetimeSeconds,
		OverlapExpiresAt:     *overlapExpires,
		PublicationID:        publication.Active.ID,
	}
	if err := writeOidcRotationCompletion(statePath, completion); err != nil {
		return err
	}
	candidatePath := filepath.Join(
		statePath,
		oidcRotationDirectory,
		request.OperationID,
		"candidate.key",
	)
	if err := os.Remove(candidatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove completed OIDC operation candidate: %w", err)
	}
	return nil
}

func recoverCommittedOIDCRotation(
	statePath string,
	request oidcRotationRequest,
) error {
	journalPath := filepath.Join(statePath, "transition", "state.json")
	journalData, err := os.ReadFile(journalPath)
	if err != nil {
		return err
	}
	var journal trustTransitionJournal
	if err := json.Unmarshal(journalData, &journal); err != nil {
		return err
	}
	if journal.Operation != "oidc-rotation" ||
		journal.TransitionID != request.OperationID ||
		journal.Status != "staged" {
		return nil
	}
	if journal.Candidate.Generation != request.StartingGeneration+1 ||
		journal.Candidate.GenerationID != fmt.Sprintf(
			"generation-%08d",
			request.StartingGeneration+1,
		) ||
		journal.PriorGeneration == nil ||
		journal.PriorGeneration.Generation != request.StartingGeneration ||
		journal.PriorGeneration.GenerationID != request.StartingGenerationID ||
		journal.CandidateManifest.OIDCRotationOperationID != request.OperationID {
		return errors.New("staged OIDC transition does not match its request")
	}
	generationPath := filepath.Join(
		statePath,
		"generations",
		journal.Candidate.GenerationID,
	)
	manifestData, err := os.ReadFile(filepath.Join(generationPath, "manifest.json"))
	if err != nil {
		return err
	}
	if hashBytes(manifestData) != journal.Candidate.ManifestSHA256 {
		return errors.New("staged OIDC transition manifest hash does not match")
	}
	if err := validateOIDCGenerationMaterial(
		generationPath,
		journal.CandidateManifest,
	); err != nil {
		return err
	}
	nextBootstrap := bootstrapManifest{
		SchemaVersion:            4,
		CreatedAtUTC:             journal.CandidateManifest.CreatedAtUTC,
		FulcioRootSHA256:         journal.CandidateManifest.FulcioRootSHA256,
		CtLogPublicKeySHA256:     journal.CandidateManifest.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:     journal.CandidateManifest.RekorPublicKeySHA256,
		TsaRootSHA256:            journal.CandidateManifest.TsaRootSHA256,
		TsaLeafSHA256:            journal.CandidateManifest.TsaLeafSHA256,
		OIDCKeyID:                journal.CandidateManifest.OIDCKeyID,
		TrustDomainID:            journal.CandidateManifest.TrustDomainID,
		Generation:               journal.Candidate.Generation,
		GenerationID:             journal.Candidate.GenerationID,
		GenerationManifestSHA256: journal.Candidate.ManifestSHA256,
	}
	fingerprint, err := fingerprintSource(nextBootstrap)
	if err != nil {
		return err
	}
	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return err
	}
	if publication.Status != publicationStatusCommitted ||
		publication.Active == nil {
		return errors.New("staged OIDC transition lacks a committed TUF publication")
	}
	if err := validateReference(
		committedPath(layout, publication.Active.ID),
		*publication.Active,
		fingerprint,
	); err != nil {
		return fmt.Errorf("validate staged OIDC TUF publication: %w", err)
	}
	activeID, err := readActiveGeneration(filepath.Join(statePath, "active-generation"))
	if err != nil {
		return err
	}
	switch activeID {
	case request.StartingGenerationID:
		activeLink := filepath.Join(statePath, "active-generation")
		nextLink := filepath.Join(statePath, "active-generation.next")
		if pathExists(nextLink) {
			if err := os.Remove(nextLink); err != nil {
				return err
			}
		}
		target := filepath.Join("generations", journal.Candidate.GenerationID)
		if err := os.Symlink(target, nextLink); err != nil {
			return err
		}
		if err := os.Rename(nextLink, activeLink); err != nil {
			return err
		}
	case journal.Candidate.GenerationID:
	default:
		return fmt.Errorf("staged OIDC transition has unexpected active generation %q", activeID)
	}
	journal.Status = "recovered"
	journal.LastCheckpoint = "transition-finalized"
	journal.UpdatedAtUTC = time.Now().UTC()
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicJSON(journalPath, append(data, '\n'))
}

func readValidatedOIDCJWKS(
	generationPath string,
) ([]string, string, error) {
	data, err := os.ReadFile(filepath.Join(
		generationPath,
		"public",
		"oidc",
		"jwks.json",
	))
	if err != nil {
		return nil, "", err
	}
	var set jwks
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, "", err
	}
	if len(set.Keys) == 0 {
		return nil, "", errors.New("OIDC JWKS is empty")
	}
	ids := make([]string, 0, len(set.Keys))
	seen := map[string]bool{}
	for _, key := range set.Keys {
		if !oidcKeyIDPattern.MatchString(key.Kid) ||
			key.Kty != "RSA" ||
			key.Use != "sig" ||
			key.Alg != "RS256" {
			return nil, "", fmt.Errorf("OIDC JWK %q has invalid metadata", key.Kid)
		}
		if seen[key.Kid] {
			return nil, "", fmt.Errorf("OIDC JWKS contains duplicate kid %q", key.Kid)
		}
		seen[key.Kid] = true
		publicKey, err := oidcJWKPublicKey(key)
		if err != nil {
			return nil, "", err
		}
		spki, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, "", err
		}
		if oidcKeyID(spki) != key.Kid {
			return nil, "", fmt.Errorf("OIDC JWK %q kid does not match its key", key.Kid)
		}
		ids = append(ids, key.Kid)
	}
	return ids, hashBytes(data), nil
}

func oidcJWKPublicKey(key jwk) (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil || len(modulus) < 256 {
		return nil, fmt.Errorf("OIDC JWK %q has invalid RSA modulus", key.Kid)
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return nil, fmt.Errorf("OIDC JWK %q has invalid RSA exponent", key.Kid)
	}
	exponent := 0
	for _, value := range exponentBytes {
		exponent = exponent<<8 | int(value)
	}
	if exponent < 3 || exponent%2 == 0 {
		return nil, fmt.Errorf("OIDC JWK %q has invalid RSA exponent", key.Kid)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}, nil
}

func validateOIDCGenerationMaterial(
	generationPath string,
	manifest generationManifest,
) error {
	actual, err := collectGenerationFileHashes(generationPath)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, manifest.Files) {
		return errors.New("OIDC generation files do not exactly match the manifest")
	}
	keyIDs, _, err := readValidatedOIDCJWKS(generationPath)
	if err != nil {
		return err
	}
	jwksData, err := os.ReadFile(filepath.Join(
		generationPath,
		"public",
		"oidc",
		"jwks.json",
	))
	if err != nil {
		return err
	}
	var set jwks
	if err := json.Unmarshal(jwksData, &set); err != nil {
		return err
	}
	jwkByID := make(map[string]jwk, len(set.Keys))
	for _, key := range set.Keys {
		jwkByID[key.Kid] = key
	}
	signerData, err := os.ReadFile(filepath.Join(
		generationPath,
		"private",
		"oidc",
		"signer.key",
	))
	if err != nil {
		return err
	}
	signer, err := parseOIDCPrivateKey(signerData)
	if err != nil {
		return err
	}
	if err := validateOIDCKeyMatchesJWK(signer, manifest.OIDCKeyID, jwkByID); err != nil {
		return fmt.Errorf("active OIDC signer: %w", err)
	}
	signerSPKI, err := x509.MarshalPKIXPublicKey(&signer.PublicKey)
	if err != nil {
		return err
	}
	publicData, err := os.ReadFile(filepath.Join(
		generationPath,
		"public",
		"oidc",
		"signer.pub",
	))
	if err != nil {
		return err
	}
	publicBlock, rest := pem.Decode(publicData)
	if publicBlock == nil ||
		publicBlock.Type != "PUBLIC KEY" ||
		len(strings.TrimSpace(string(rest))) != 0 ||
		!reflect.DeepEqual(publicBlock.Bytes, signerSPKI) {
		return errors.New("active OIDC public key does not match signer")
	}
	expectedPaths := make([]string, 0, len(keyIDs)-1)
	for _, kid := range keyIDs {
		if kid == manifest.OIDCKeyID {
			continue
		}
		path := filepath.ToSlash(filepath.Join(
			"private",
			"oidc",
			"retained",
			fmt.Sprintf("signer-%s.key", kid),
		))
		expectedPaths = append(expectedPaths, path)
		data, err := os.ReadFile(filepath.Join(
			generationPath,
			filepath.FromSlash(path),
		))
		if err != nil {
			return fmt.Errorf("read retained OIDC key %q: %w", kid, err)
		}
		key, err := parseOIDCPrivateKey(data)
		if err != nil {
			return fmt.Errorf("parse retained OIDC key %q: %w", kid, err)
		}
		if err := validateOIDCKeyMatchesJWK(key, kid, jwkByID); err != nil {
			return fmt.Errorf("retained OIDC key %q: %w", kid, err)
		}
	}
	sort.Strings(expectedPaths)
	actualPaths := append([]string(nil), manifest.OIDCRetainedPrivateKeyPaths...)
	sort.Strings(actualPaths)
	if len(actualPaths) != len(expectedPaths) {
		return errors.New("OIDC retained private-key paths do not match historical JWKS keys")
	}
	for index := range expectedPaths {
		if actualPaths[index] != expectedPaths[index] {
			return errors.New("OIDC retained private-key paths do not match historical JWKS keys")
		}
	}
	for path := range manifest.Files {
		if strings.HasPrefix(path, "private/oidc/retained/") {
			found := false
			for _, expected := range expectedPaths {
				if path == expected {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("unexpected retained OIDC private key %q", path)
			}
		}
	}
	if manifest.OIDCRotationOperationID == "" {
		if manifest.OIDCRotationOperationID != "" ||
			manifest.OIDCPriorGeneration != 0 ||
			manifest.OIDCPriorGenerationID != "" ||
			manifest.OIDCPriorKeyID != "" ||
			manifest.OIDCOverlapExpiresAtUTC != nil {
			return errors.New("generation contains partial OIDC rotation metadata")
		}
	} else {
		if !oidcOperationIDPattern.MatchString(manifest.OIDCRotationOperationID) ||
			manifest.OIDCPriorGeneration != manifest.Generation-1 ||
			manifest.OIDCPriorGenerationID != fmt.Sprintf(
				"generation-%08d",
				manifest.Generation-1,
			) ||
			!oidcKeyIDPattern.MatchString(manifest.OIDCPriorKeyID) ||
			manifest.OIDCOverlapExpiresAtUTC == nil {
			return errors.New("rotated generation has invalid OIDC operation metadata")
		}
	}
	return nil
}

func validateOIDCKeyMatchesJWK(
	privateKey *rsa.PrivateKey,
	kid string,
	keys map[string]jwk,
) error {
	spki, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	if oidcKeyID(spki) != kid {
		return errors.New("kid does not match private key")
	}
	key, ok := keys[kid]
	if !ok {
		return errors.New("matching JWK is missing")
	}
	publicKey, err := oidcJWKPublicKey(key)
	if err != nil {
		return err
	}
	if privateKey.PublicKey.E != publicKey.E ||
		privateKey.PublicKey.N.Cmp(publicKey.N) != 0 {
		return errors.New("JWK does not match private key")
	}
	return nil
}

func validateUnchangedNonOIDCMaterial(currentPath, nextPath string) error {
	current, err := collectGenerationFileHashes(currentPath)
	if err != nil {
		return err
	}
	next, err := collectGenerationFileHashes(nextPath)
	if err != nil {
		return err
	}
	for path, hash := range current {
		if strings.HasPrefix(path, "private/oidc/") ||
			strings.HasPrefix(path, "public/oidc/") {
			continue
		}
		if next[path] != hash {
			return fmt.Errorf("non-OIDC generation material %q changed", path)
		}
	}
	for path := range next {
		if strings.HasPrefix(path, "private/oidc/") ||
			strings.HasPrefix(path, "public/oidc/") {
			continue
		}
		if _, ok := current[path]; !ok {
			return fmt.Errorf("unexpected non-OIDC generation material %q", path)
		}
	}
	return nil
}

func oidcKeyID(spki []byte) string {
	sum := sha256.Sum256(spki)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
