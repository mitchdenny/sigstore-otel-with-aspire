package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	commonv1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	trustrootv1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	tuf "github.com/theupdateframework/go-tuf"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	standbyRekorKeyFile     = "rekor-standby.pub"
	publishRequestFile      = "publish-trusted-root.request"
	publishCompletionFile   = "publish-trusted-root.completed"
	publishCompletionSchema = 2
)

// recoveryOutcome distinguishes no-op from actual state mutations.
type recoveryOutcome int

const (
	recoveryNoop             recoveryOutcome = iota // State was already coherent
	recoveryRolledBack                              // Rolled back to prior committed state
	recoveryForwardCompleted                        // Forward-completed interrupted publish
)

// publishRequest is the schema-versioned content of the request file.
type publishRequest struct {
	SchemaVersion int    `json:"schemaVersion"`
	OperationID   string `json:"operationId"`
	TrustDomainID string `json:"trustDomainId"`
}

// publishCompletion records that a specific operation ID was completed,
// bound to enough committed state to prove the operation outcome.
type publishCompletion struct {
	SchemaVersion  int       `json:"schemaVersion"`
	OperationID    string    `json:"operationId"`
	TrustDomainID  string    `json:"trustDomainId"`
	CompletedAt    time.Time `json:"completedAtUtc"`
	Generation     int       `json:"generation"`
	GenerationID   string    `json:"generationId"`
	PublicationID  string    `json:"publicationId"`
	ManifestSHA256 string    `json:"manifestSha256"`
}

// writeAtomicJSON writes data to path atomically via temp+fsync+rename.
func writeAtomicJSON(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".atomic-*")
	if err != nil {
		return fmt.Errorf("create temp for atomic write: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename atomic: %w", err)
	}
	return syncDirectory(dir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for fsync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("fsync directory: %w", err)
	}
	return nil
}

// loadAndValidateCompletion reads and strictly validates the completion file.
// Returns (nil, nil) if the file does not exist.
func loadAndValidateCompletion(statePath string) (*publishCompletion, error) {
	completionPath := filepath.Join(statePath, publishCompletionFile)
	data, err := os.ReadFile(completionPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read completion file: %w", err)
	}
	var comp publishCompletion
	if err := json.Unmarshal(data, &comp); err != nil {
		return nil, fmt.Errorf("malformed completion file: %w", err)
	}
	if comp.SchemaVersion != publishCompletionSchema {
		return nil, fmt.Errorf("completion schema %d unsupported (expected %d)", comp.SchemaVersion, publishCompletionSchema)
	}
	if comp.OperationID == "" || comp.TrustDomainID == "" || comp.GenerationID == "" || comp.PublicationID == "" {
		return nil, fmt.Errorf("completion file missing required fields")
	}
	return &comp, nil
}

// writeCompletion atomically writes a validated completion record.
func writeCompletion(statePath string, comp publishCompletion) error {
	comp.SchemaVersion = publishCompletionSchema
	data, err := json.MarshalIndent(comp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal completion: %w", err)
	}
	data = append(data, '\n')
	return writeAtomicJSON(filepath.Join(statePath, publishCompletionFile), data)
}

// validateCompletionAgainstState ensures a completion record matches the
// current live state (trust domain, generation, publication). A stale or
// tampered completion must not be accepted as replay success.
func validateCompletionAgainstState(statePath string, comp *publishCompletion) error {
	domain, err := loadTrustDomain(statePath)
	if err != nil {
		return fmt.Errorf("load trust domain: %w", err)
	}
	if comp.TrustDomainID != domain.TrustDomainID {
		return fmt.Errorf("completion trust domain %q does not match active %q", comp.TrustDomainID, domain.TrustDomainID)
	}
	if comp.Generation < 1 {
		return fmt.Errorf("completion generation %d invalid", comp.Generation)
	}
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return fmt.Errorf("load active generation: %w", err)
	}
	if comp.Generation != bootstrap.Generation {
		return fmt.Errorf("completion generation %d does not match active %d", comp.Generation, bootstrap.Generation)
	}
	if comp.GenerationID != bootstrap.GenerationID {
		return fmt.Errorf("completion generationId %q does not match active %q", comp.GenerationID, bootstrap.GenerationID)
	}
	layout := newTUFLayout(statePath)
	state, err := loadPublicationState(layout)
	if err != nil {
		return fmt.Errorf("load publication state: %w", err)
	}
	if state.Active == nil {
		return fmt.Errorf("no active publication for completion validation")
	}
	if comp.PublicationID != state.Active.ID {
		return fmt.Errorf("completion publicationId %q does not match active %q", comp.PublicationID, state.Active.ID)
	}
	if comp.ManifestSHA256 != state.Active.ManifestSHA256 {
		return fmt.Errorf("completion manifestSha256 %q does not match active %q", comp.ManifestSHA256, state.Active.ManifestSHA256)
	}
	return nil
}

// dispatchPublishRequest handles the full lifecycle of a publish-trusted-root
// request including recovery, replay detection, and deterministic consumption.
// This is the production entry point called from main. Holds the shared state
// lock across recovery, decision, publication, completion, and request removal.
func dispatchPublishRequest(statePath string) (repositoryAction, error) {
	return dispatchPublishRequestWithHooks(statePath, publicationHooks{})
}

func dispatchPublishRequestWithHooks(statePath string, hooks publicationHooks) (repositoryAction, error) {
	requestPath := filepath.Join(statePath, publishRequestFile)

	// Read and validate the request strictly before acquiring the lock.
	requestData, err := os.ReadFile(requestPath)
	if err != nil {
		return "", fmt.Errorf("read publish request: %w", err)
	}
	var req publishRequest
	if err := json.Unmarshal(requestData, &req); err != nil {
		return "", fmt.Errorf("parse publish request (must be valid JSON with operationId): %w", err)
	}
	if req.SchemaVersion != 1 {
		return "", fmt.Errorf("publish request schema %d unsupported (expected 1)", req.SchemaVersion)
	}
	if req.OperationID == "" {
		return "", fmt.Errorf("publish request missing operationId")
	}
	if req.TrustDomainID == "" {
		return "", fmt.Errorf("publish request missing trustDomainId")
	}

	// Acquire the shared state lock for the entire dispatch lifecycle.
	stateLock, err := acquireStateLock(statePath, 30*time.Second, "tuf-publish-dispatch")
	if err != nil {
		return "", err
	}
	defer stateLock.release()

	// (B) Validate request trust domain against immutable state under lock.
	domain, err := loadTrustDomain(statePath)
	if err != nil {
		return "", fmt.Errorf("load trust domain for request validation: %w", err)
	}
	if domain.TrustDomainID != req.TrustDomainID {
		return "", fmt.Errorf("request trust domain %q does not match immutable domain %q", req.TrustDomainID, domain.TrustDomainID)
	}

	// Check if this operation was already completed (crash after completion
	// write but before request file removal).
	comp, err := loadAndValidateCompletion(statePath)
	if err != nil {
		// Malformed/corrupted completion file is ambiguous — fail loudly.
		return "", fmt.Errorf("ambiguous completion state: %w", err)
	}
	if comp != nil && comp.OperationID == req.OperationID {
		// (A) Validate completion matches live state before accepting replay.
		if err := validateCompletionAgainstState(statePath, comp); err != nil {
			return "", fmt.Errorf("completion replay validation failed: %w", err)
		}
		if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("remove request after replay: %w", err)
		}
		return repositoryActionPublished, nil
	}

	// Recover any interrupted TUF/generation state (lock-free internal).
	outcome, err := recoverTUFStateLocked(statePath, hooks)
	if err != nil {
		return "", fmt.Errorf("recover TUF state: %w", err)
	}

	// After recovery, determine if publication already completed.
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return "", fmt.Errorf("load generation after recovery: %w", err)
	}

	if bootstrap.Generation > 1 {
		switch outcome {
		case recoveryForwardCompleted:
			// Recovery forward-completed an interrupted publish. This must be
			// the same operation (since no other code path exists). Verify
			// trust domain matches and write completion.
			if req.TrustDomainID != "" {
				domain, loadErr := loadTrustDomain(statePath)
				if loadErr == nil && domain.TrustDomainID != req.TrustDomainID {
					return "", fmt.Errorf("request trust domain %q does not match active %q", req.TrustDomainID, domain.TrustDomainID)
				}
			}
			layout := newTUFLayout(statePath)
			state, stateErr := loadPublicationState(layout)
			if stateErr != nil {
				return "", fmt.Errorf("load publication state for completion: %w", stateErr)
			}
			newComp := publishCompletion{
				OperationID:    req.OperationID,
				TrustDomainID:  req.TrustDomainID,
				CompletedAt:    time.Now().UTC(),
				Generation:     bootstrap.Generation,
				GenerationID:   bootstrap.GenerationID,
				PublicationID:  state.Active.ID,
				ManifestSHA256: state.Active.ManifestSHA256,
			}
			if err := writeCompletion(statePath, newComp); err != nil {
				return "", err
			}
			if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("remove request after forward-recovery: %w", err)
			}
			return repositoryActionPublished, nil

		case recoveryNoop, recoveryRolledBack:
			// Gen > 1 but recovery did NOT forward-complete. Either:
			// - A prior operation completed (completion exists with different ID)
			// - Or completion is missing/corrupt with gen > 1 (ambiguous)
			if comp != nil {
				// Different operation ID completed previously. This is a new
				// forbidden second request.
			} else {
				// No valid completion but gen > 1. This is ambiguous —
				// we cannot prove this request caused the generation advance.
				return "", fmt.Errorf(
					"ambiguous state: generation %d with no valid completion record; "+
						"cannot determine if operation %q already completed or is new",
					bootstrap.Generation, req.OperationID,
				)
			}
		}
	}

	// Perform the actual publication (lock-free internal — we hold the lock).
	action, err := publishTrustedRootLocked(statePath, hooks)
	if err != nil {
		return "", err
	}

	// Reload bootstrap for completion record.
	bootstrap, err = loadActiveTrustGeneration(statePath)
	if err != nil {
		return "", fmt.Errorf("load generation for completion: %w", err)
	}
	layout := newTUFLayout(statePath)
	state, err := loadPublicationState(layout)
	if err != nil {
		return "", fmt.Errorf("load publication state for completion: %w", err)
	}

	// Write completion atomically before removing request.
	newComp := publishCompletion{
		OperationID:    req.OperationID,
		TrustDomainID:  req.TrustDomainID,
		CompletedAt:    time.Now().UTC(),
		Generation:     bootstrap.Generation,
		GenerationID:   bootstrap.GenerationID,
		PublicationID:  state.Active.ID,
		ManifestSHA256: state.Active.ManifestSHA256,
	}
	if err := writeCompletion(statePath, newComp); err != nil {
		return "", err
	}

	// Remove request file last.
	if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("remove request file: %w", err)
	}

	return action, nil
}

// loadTrustDomain loads the immutable trust-domain.json.
func loadTrustDomain(statePath string) (trustDomainManifest, error) {
	data, err := os.ReadFile(filepath.Join(statePath, "trust-domain.json"))
	if err != nil {
		return trustDomainManifest{}, err
	}
	var domain trustDomainManifest
	if err := json.Unmarshal(data, &domain); err != nil {
		return trustDomainManifest{}, err
	}
	return domain, nil
}

// publishTrustedRootLocked is the lock-free internal publish implementation.
// The caller MUST hold the state lock.
// publishTrustedRootLocked is the lock-free internal publish implementation.
// The caller MUST hold the state lock.
func publishTrustedRootLocked(
	statePath string,
	hooks publicationHooks,
) (repositoryAction, error) {
	// Load and validate current trust generation.
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return "", err
	}
	if _, err := ensureRekorShardCatalogLocked(statePath, bootstrap); err != nil {
		return "", fmt.Errorf("ensure Rekor shard catalog: %w", err)
	}

	// Reject repeated invocation: this command is one-shot per trust domain.
	if bootstrap.Generation > 1 {
		return "", fmt.Errorf(
			"publish-trusted-root already completed (generation %d); "+
				"repeated publication is not supported because it would remove prior standby verification material",
			bootstrap.Generation,
		)
	}

	sourceFingerprint, err := fingerprintSource(bootstrap)
	if err != nil {
		return "", err
	}

	layout := newTUFLayout(statePath)
	if err := ensureTUFLayout(layout); err != nil {
		return "", err
	}
	state, err := loadPublicationState(layout)
	if err != nil {
		return "", fmt.Errorf("load TUF publication state for trusted-root publication: %w", err)
	}
	if state.Status != publicationStatusCommitted {
		return "", fmt.Errorf(
			"trusted-root publication requires a committed publication, found status %q",
			state.Status,
		)
	}
	if err := cleanupPublicationTemps(layout); err != nil {
		return "", err
	}
	if err := cleanupUnjournaledCandidate(layout); err != nil {
		return "", err
	}
	if err := validateCommittedPublication(layout, state, sourceFingerprint); err != nil {
		return "", fmt.Errorf("validate committed (pre-publish): %w", err)
	}

	// Advance the trust generation with additive standby material.
	newBootstrap, newGenPath, err := advanceTrustGeneration(statePath, bootstrap)
	if err != nil {
		return "", fmt.Errorf("advance trust generation: %w", err)
	}

	// Build new targets from the advanced generation.
	newSourceFingerprint, err := fingerprintSource(newBootstrap)
	if err != nil {
		return "", err
	}

	// Publish the new targets through the existing transactional framework.
	if err := publishNewTargets(layout, state, newGenPath, newBootstrap, sourceFingerprint, newSourceFingerprint, hooks); err != nil {
		return "", fmt.Errorf("publish new targets: %w", err)
	}

	// Switch active-generation symlink now that TUF publication succeeded.
	if err := switchActiveGeneration(statePath, bootstrap, newBootstrap, newBootstrap.GenerationManifestSHA256); err != nil {
		return "", fmt.Errorf("switch active generation: %w", err)
	}

	return repositoryActionPublished, nil
}

// publishTrustedRootUpdate advances the trust generation by adding inactive
// standby verification material, then publishes new TUF targets that contain
// both old and new verification entries. SigningConfig routing remains unchanged.
// This is the additive trust publication primitive used before any signer is
// activated (Steps 9-13).
func publishTrustedRootUpdate(statePath string) (repositoryAction, error) {
	return publishTrustedRootUpdateWithHooks(statePath, publicationHooks{})
}

func publishTrustedRootUpdateWithHooks(
	statePath string,
	hooks publicationHooks,
) (repositoryAction, error) {
	stateLock, err := acquireStateLock(statePath, 30*time.Second, "tuf-publish-trusted-root")
	if err != nil {
		return "", err
	}
	defer stateLock.release()
	return publishTrustedRootLocked(statePath, hooks)
}

// advanceTrustGeneration creates a new generation N+1 that contains all
// material from generation N plus a standby Rekor verification key. The
// standby key is genuine but inactive — it does not affect live signing.
// If a validated generation N+1 directory already exists (from a prior
// interrupted attempt), it is reused rather than overwritten.
func advanceTrustGeneration(statePath string, current bootstrapManifest) (bootstrapManifest, string, error) {
	if current.Generation < 1 {
		return bootstrapManifest{}, "", fmt.Errorf("invalid current generation %d", current.Generation)
	}
	newGeneration := current.Generation + 1
	newGenerationID := fmt.Sprintf("generation-%08d", newGeneration)
	currentGenerationID := current.GenerationID
	currentGenerationPath := filepath.Join(statePath, "generations", currentGenerationID)
	newGenerationPath := filepath.Join(statePath, "generations", newGenerationID)

	// If the generation N+1 directory already exists (from an interrupted
	// prior attempt), validate and reuse it to ensure deterministic replay.
	if pathExists(newGenerationPath) {
		_, nextBootstrap, _, err := validateNextGenerationForRecovery(statePath, current)
		if err != nil {
			return bootstrapManifest{}, "", fmt.Errorf(
				"pre-existing generation %s failed validation; cannot resume or overwrite: %w",
				newGenerationID, err,
			)
		}
		return nextBootstrap, newGenerationPath, nil
	}

	// Generate standby Rekor key (ECDSA P-256).
	standbyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return bootstrapManifest{}, "", fmt.Errorf("generate standby Rekor key: %w", err)
	}
	standbyDER, err := x509.MarshalPKIXPublicKey(&standbyKey.PublicKey)
	if err != nil {
		return bootstrapManifest{}, "", fmt.Errorf("marshal standby key DER: %w", err)
	}
	standbyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: standbyDER,
	})

	// Create generation directory with all prior material plus standby key.
	if err := os.MkdirAll(filepath.Join(newGenerationPath, "public", "rekor"), 0o755); err != nil {
		return bootstrapManifest{}, "", fmt.Errorf("create new generation public/rekor: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(newGenerationPath, "private"), 0o755); err != nil {
		return bootstrapManifest{}, "", fmt.Errorf("create new generation private: %w", err)
	}

	// Copy all files from prior generation.
	if err := copyDirectory(currentGenerationPath, newGenerationPath); err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, "", fmt.Errorf("copy prior generation material: %w", err)
	}

	// Write standby key.
	standbyKeyPath := filepath.Join(newGenerationPath, "public", "rekor", standbyRekorKeyFile)
	if err := os.WriteFile(standbyKeyPath, standbyPEM, 0o644); err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, "", fmt.Errorf("write standby Rekor key: %w", err)
	}

	// Compute file hashes for new generation.
	newFiles, err := collectGenerationFileHashes(newGenerationPath)
	if err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, "", err
	}

	// Compute standby key hash.
	standbyKeyHash := hashBytes(standbyPEM)

	// Remove prior manifest.json copy (it is read-only from the old generation).
	manifestPath := filepath.Join(newGenerationPath, "manifest.json")
	_ = os.Remove(manifestPath)

	// Write generation manifest.
	now := time.Now().UTC()
	currentGenerationManifest, err := readOIDCGenerationManifest(
		statePath,
		current.GenerationID,
	)
	if err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, "", fmt.Errorf(
			"read current generation OIDC metadata: %w",
			err,
		)
	}
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
		OIDCKeyID:            current.OIDCKeyID,
		OIDCRetainedPrivateKeyPaths: append(
			[]string(nil),
			currentGenerationManifest.OIDCRetainedPrivateKeyPaths...,
		),
		TSARotationOperationID: currentGenerationManifest.TSARotationOperationID,
		TSAPriorGeneration:     currentGenerationManifest.TSAPriorGeneration,
		TSAPriorGenerationID:   currentGenerationManifest.TSAPriorGenerationID,
		TSAPriorRootSHA256:     currentGenerationManifest.TSAPriorRootSHA256,
		TSAPriorLeafSHA256:     currentGenerationManifest.TSAPriorLeafSHA256,

		FulcioRotationOperationID: currentGenerationManifest.FulcioRotationOperationID,
		FulcioPriorGeneration:     currentGenerationManifest.FulcioPriorGeneration,
		FulcioPriorGenerationID:   currentGenerationManifest.FulcioPriorGenerationID,
		FulcioPriorRootSHA256:     currentGenerationManifest.FulcioPriorRootSHA256,

		RekorRotationOperationID:  currentGenerationManifest.RekorRotationOperationID,
		RekorPriorGeneration:      currentGenerationManifest.RekorPriorGeneration,
		RekorPriorGenerationID:    currentGenerationManifest.RekorPriorGenerationID,
		RekorPriorPublicKeySHA256: currentGenerationManifest.RekorPriorPublicKeySHA256,
		RekorPriorShardID:         currentGenerationManifest.RekorPriorShardID,
		RekorPriorBaseURL:         currentGenerationManifest.RekorPriorBaseURL,
		RekorShardID:              currentGenerationManifest.RekorShardID,
		RekorBaseURL:              currentGenerationManifest.RekorBaseURL,
		CtLogRotationOperationID:  currentGenerationManifest.CtLogRotationOperationID,
		CtLogPriorGeneration:      currentGenerationManifest.CtLogPriorGeneration,
		CtLogPriorGenerationID:    currentGenerationManifest.CtLogPriorGenerationID,
		CtLogPriorPublicKeySHA256: currentGenerationManifest.CtLogPriorPublicKeySHA256,
		CtLogPriorShardID:         currentGenerationManifest.CtLogPriorShardID,
		CtLogPriorBaseURL:         currentGenerationManifest.CtLogPriorBaseURL,
		CtLogShardID:              currentGenerationManifest.CtLogShardID,
		CtLogBaseURL:              currentGenerationManifest.CtLogBaseURL,

		Files: newFiles,
	}
	manifestBytes, err := json.MarshalIndent(genManifest, "", "  ")
	if err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, "", fmt.Errorf("marshal generation manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := writeGenerationManifest(manifestPath, manifestBytes); err != nil {
		_ = os.RemoveAll(newGenerationPath)
		return bootstrapManifest{}, "", fmt.Errorf("write generation manifest: %w", err)
	}
	manifestHash := hashBytes(manifestBytes)

	// NOTE: We do NOT update the transition journal or switch the
	// active-generation symlink here. Both are deferred until after TUF
	// publication succeeds, ensuring consistent recovery if publication fails.

	return bootstrapManifest{
		SchemaVersion:            4,
		CreatedAtUTC:             now,
		FulcioRootSHA256:         current.FulcioRootSHA256,
		CtLogPublicKeySHA256:     current.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:     current.RekorPublicKeySHA256,
		TsaRootSHA256:            current.TsaRootSHA256,
		TsaLeafSHA256:            current.TsaLeafSHA256,
		OIDCKeyID:                current.OIDCKeyID,
		TrustDomainID:            current.TrustDomainID,
		Generation:               newGeneration,
		GenerationID:             newGenerationID,
		GenerationManifestSHA256: manifestHash,
		StandbyRekorKeySHA256:    standbyKeyHash,
	}, newGenerationPath, nil
}

// switchActiveGeneration atomically updates the transition journal and switches
// the active-generation symlink. Called only after TUF publication succeeds.
func switchActiveGeneration(statePath string, current bootstrapManifest, newBootstrap bootstrapManifest, manifestHash string) error {
	// Read current journal to get trust-domain reference.
	journalPath := filepath.Join(statePath, "transition", "state.json")
	journalBytes, err := os.ReadFile(journalPath)
	if err != nil {
		return fmt.Errorf("read transition journal: %w", err)
	}
	var journal trustTransitionJournal
	if err := json.Unmarshal(journalBytes, &journal); err != nil {
		return fmt.Errorf("parse transition journal: %w", err)
	}

	domainPath := filepath.Join(statePath, "trust-domain.json")
	domainBytes, err := os.ReadFile(domainPath)
	if err != nil {
		return fmt.Errorf("read trust-domain: %w", err)
	}
	domainHash := hashBytes(domainBytes)

	// Read the new generation manifest from disk (written by advanceTrustGeneration).
	genPath := filepath.Join(statePath, "generations", newBootstrap.GenerationID)
	genManifestBytes, err := os.ReadFile(filepath.Join(genPath, "manifest.json"))
	if err != nil {
		return fmt.Errorf("read new generation manifest: %w", err)
	}
	var genManifest generationManifest
	if err := json.Unmarshal(genManifestBytes, &genManifest); err != nil {
		return fmt.Errorf("parse new generation manifest: %w", err)
	}

	priorRef := &generationReference{
		Generation:     current.Generation,
		GenerationID:   current.GenerationID,
		ManifestSHA256: current.GenerationManifestSHA256,
	}
	operation := "generation-advance"
	transitionID := journal.TransitionID
	// Rotation provenance is carried forward across generations, so a
	// generation is only classified as a given rotation when that rotation
	// actually happened in this step: the prior generation must be the
	// generation being replaced and the rotated material must have changed.
	switch {
	case genManifest.FulcioRotationOperationID != "" &&
		genManifest.FulcioPriorGeneration == current.Generation &&
		genManifest.FulcioRootSHA256 != current.FulcioRootSHA256:
		operation = "fulcio-rotation"
		transitionID = genManifest.FulcioRotationOperationID
	case genManifest.OIDCRotationOperationID != "" &&
		genManifest.OIDCPriorGeneration == current.Generation &&
		genManifest.OIDCKeyID != current.OIDCKeyID:
		operation = "oidc-rotation"
		transitionID = genManifest.OIDCRotationOperationID
	case genManifest.TSARotationOperationID != "" &&
		genManifest.TSAPriorGeneration == current.Generation &&
		genManifest.TsaRootSHA256 != current.TsaRootSHA256 &&
		genManifest.TsaLeafSHA256 != current.TsaLeafSHA256:
		operation = "tsa-rotation"
		transitionID = genManifest.TSARotationOperationID
	case genManifest.RekorRotationOperationID != "" &&
		genManifest.RekorPriorGeneration == current.Generation &&
		genManifest.RekorPublicKeySHA256 != current.RekorPublicKeySHA256:
		operation = "rekor-shard-rotation"
		transitionID = genManifest.RekorRotationOperationID
	case genManifest.CtLogRotationOperationID != "" &&
		genManifest.CtLogPriorGeneration == current.Generation &&
		genManifest.CtLogPublicKeySHA256 != current.CtLogPublicKeySHA256:
		operation = "ct-log-shard-rotation"
		transitionID = genManifest.CtLogRotationOperationID
	}
	now := time.Now().UTC()
	newJournal := trustTransitionJournal{
		SchemaVersion:             trustTransitionSchemaVersion,
		TransitionID:              transitionID,
		Operation:                 operation,
		Status:                    "staged",
		LastCheckpoint:            "active-link-prepared",
		StartedAtUTC:              now,
		UpdatedAtUTC:              now,
		PriorGeneration:           priorRef,
		Candidate:                 generationReference{Generation: newBootstrap.Generation, GenerationID: newBootstrap.GenerationID, ManifestSHA256: manifestHash},
		TrustDomainManifestSHA256: domainHash,
		LegacyManifestSHA256:      journal.LegacyManifestSHA256,
		TrustDomain:               journal.TrustDomain,
		CandidateManifest:         genManifest,
	}
	newJournalBytes, err := json.MarshalIndent(newJournal, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal new journal: %w", err)
	}
	newJournalBytes = append(newJournalBytes, '\n')
	if err := writeAtomicJSON(journalPath, newJournalBytes); err != nil {
		return fmt.Errorf("write transition journal: %w", err)
	}

	// Switch active-generation symlink.
	activeLink := filepath.Join(statePath, "active-generation")
	activeLinkNext := filepath.Join(statePath, "active-generation.next")
	newTarget := filepath.Join("generations", newBootstrap.GenerationID)
	if pathExists(activeLinkNext) {
		target, err := os.Readlink(activeLinkNext)
		if err != nil || target != newTarget {
			return fmt.Errorf("active-generation.next contains ambiguous state")
		}
	} else if err := os.Symlink(newTarget, activeLinkNext); err != nil {
		return fmt.Errorf("create active-generation.next link: %w", err)
	}
	if err := os.Rename(activeLinkNext, activeLink); err != nil {
		_ = os.Remove(activeLinkNext)
		return fmt.Errorf("switch active-generation link: %w", err)
	}
	if err := syncDirectory(statePath); err != nil {
		return err
	}
	newJournal.Status = "committed"
	newJournal.LastCheckpoint = "transition-finalized"
	newJournal.UpdatedAtUTC = time.Now().UTC()
	newJournalBytes, err = json.MarshalIndent(newJournal, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal committed transition journal: %w", err)
	}
	return writeAtomicJSON(journalPath, append(newJournalBytes, '\n'))
}

// publishNewTargets builds TUF targets from the new generation (with additive
// verification material) and publishes them through the transactional framework.
func publishNewTargets(
	layout tufLayout,
	state publicationState,
	generationPath string,
	bootstrap bootstrapManifest,
	priorSourceFingerprint string,
	sourceFingerprint string,
	hooks publicationHooks,
) error {
	if state.Active == nil {
		return fmt.Errorf("committed TUF publication has no active repository")
	}
	activePath := committedPath(layout, state.Active.ID)

	// Copy active to candidate (preserves TUF signing keys and root chain).
	if err := os.Mkdir(layout.candidate, 0o755); err != nil {
		return fmt.Errorf("create TUF publish staging directory: %w", err)
	}
	if err := copyDirectory(activePath, layout.candidate); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return err
	}

	// Build new targets with additive verification material.
	activeTUFTargetsPath := filepath.Join(activePath, "targets")
	targets, err := buildAdditiveTargets(generationPath, bootstrap, activeTUFTargetsPath)
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return err
	}

	// Replace targets in the candidate repository.
	if err := replaceTargetsInRepository(layout.candidate, targets, bootstrap); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("replace targets: %w", err)
	}

	// Update manifest.
	manifest := tufManifest{
		SchemaVersion:     tufSchemaVersion,
		CreatedAtUTC:      time.Now().UTC(),
		UpdatedAtUTC:      time.Now().UTC(),
		SourceFingerprint: sourceFingerprint,
	}
	if err := writeRepositoryManifest(layout.candidate, manifest); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("write manifest: %w", err)
	}
	candidate, err := repositoryReference(layout.candidate, sourceFingerprint)
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("validate candidate reference: %w", err)
	}
	if candidate.ID == state.Active.ID {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("published TUF candidate is identical to active publication")
	}
	if pathExists(committedPath(layout, candidate.ID)) {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("TUF publish candidate %s already exists in committed state", candidate.ID)
	}

	// Begin transactional publication.
	preparing := state
	preparing.Status = publicationStatusPreparing
	preparing.UpdatedAtUTC = time.Now().UTC()
	preparing.Candidate = &candidate
	if err := writePublicationState(layout, preparing); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return err
	}
	if err := runCheckpoint(hooks, checkpointCandidatePrepared); err != nil {
		return rollbackPreparingPublication(layout, preparing, priorSourceFingerprint, err)
	}

	if state.Previous != nil {
		if err := os.Rename(layout.previous, layout.retiredPrevious); err != nil {
			return rollbackPreparingPublication(
				layout,
				preparing,
				priorSourceFingerprint,
				fmt.Errorf("park previous TUF publication during publish: %w", err),
			)
		}
	}
	if err := runCheckpoint(hooks, checkpointHistoryParked); err != nil {
		return rollbackPreparingPublication(layout, preparing, priorSourceFingerprint, err)
	}

	candidatePath := committedPath(layout, candidate.ID)
	if err := os.Rename(layout.candidate, candidatePath); err != nil {
		return rollbackPreparingPublication(
			layout,
			preparing,
			priorSourceFingerprint,
			fmt.Errorf("commit staged TUF publish candidate: %w", err),
		)
	}
	if err := runCheckpoint(hooks, checkpointCandidateCommitted); err != nil {
		return rollbackPreparingPublication(layout, preparing, priorSourceFingerprint, err)
	}
	if err := switchActivePublication(layout, candidate.ID, hooks); err != nil {
		return rollbackPreparingPublication(layout, preparing, priorSourceFingerprint, err)
	}
	if err := runCheckpoint(hooks, checkpointActiveSwitched); err != nil {
		return err
	}
	return finalizePublishPublication(layout, preparing, priorSourceFingerprint, sourceFingerprint, hooks)
}

// finalizePublishPublication is like finalizeRefreshedPublication but handles
// the case where the source fingerprint changed (generation advance). The
// previous publication is validated with priorSourceFingerprint while the new
// candidate uses the new sourceFingerprint.
func finalizePublishPublication(
	layout tufLayout,
	preparing publicationState,
	priorSourceFingerprint string,
	sourceFingerprint string,
	hooks publicationHooks,
) error {
	if preparing.Active == nil || preparing.Candidate == nil {
		return errors.New("published TUF state is missing active or candidate")
	}
	activeID, activeExists, err := readActivePublication(layout.active)
	if err != nil {
		return err
	}
	if !activeExists || activeID != preparing.Candidate.ID {
		return fmt.Errorf(
			"cannot finalize TUF publish because active is %q, expected %q",
			activeID,
			preparing.Candidate.ID,
		)
	}
	if _, _, err := validateExistingRepository(
		committedPath(layout, preparing.Candidate.ID),
		sourceFingerprint,
	); err != nil {
		return fmt.Errorf("validate new candidate: %w", err)
	}

	oldCommitted := committedPath(layout, preparing.Active.ID)
	oldInCommitted := pathExists(oldCommitted)
	oldInHistory := pathExists(layout.previous)
	if oldInCommitted && oldInHistory {
		return errors.New("prior active TUF publication exists in both committed and history state")
	}
	if !oldInCommitted && !oldInHistory {
		return errors.New("prior active TUF publication is missing during commit recovery")
	}
	if oldInCommitted {
		if err := os.Rename(oldCommitted, layout.previous); err != nil {
			return fmt.Errorf("archive prior active TUF publication: %w", err)
		}
	}
	// Validate previous with its OWN source fingerprint (it was created
	// before the generation advance).
	previous, err := repositoryReference(layout.previous, priorSourceFingerprint)
	if err != nil {
		return fmt.Errorf("validate previous publication: %w", err)
	}
	if previous != *preparing.Active {
		return errors.New("archived TUF publication does not match the prior active publication")
	}
	if err := runCheckpoint(hooks, checkpointPreviousArchived); err != nil {
		return err
	}

	if pathExists(layout.retiredPrevious) {
		if preparing.Previous == nil {
			return errors.New("retired TUF history exists without journal metadata")
		}
		retiredManifestData, err := os.ReadFile(filepath.Join(layout.retiredPrevious, "manifest.json"))
		if err != nil {
			return fmt.Errorf("read retired history manifest: %w", err)
		}
		var retiredManifest tufManifest
		if err := json.Unmarshal(retiredManifestData, &retiredManifest); err != nil {
			return fmt.Errorf("parse retired history manifest: %w", err)
		}
		retired, err := repositoryReference(
			layout.retiredPrevious,
			retiredManifest.SourceFingerprint,
		)
		if err != nil {
			return fmt.Errorf("validate retired history: %w", err)
		}
		if retired != *preparing.Previous {
			return errors.New("retired TUF history does not match the publication journal")
		}
		if err := os.RemoveAll(layout.retiredPrevious); err != nil {
			return fmt.Errorf("remove retired TUF history: %w", err)
		}
	} else if preparing.Previous != nil && !oldInHistory {
		return errors.New("previous TUF history disappeared during publication")
	}
	if err := runCheckpoint(hooks, checkpointHistoryRetired); err != nil {
		return err
	}

	committed := publicationState{
		SchemaVersion:       tufLayoutSchemaVersion,
		Status:              publicationStatusCommitted,
		UpdatedAtUTC:        time.Now().UTC(),
		BootstrapRootSHA256: preparing.BootstrapRootSHA256,
		Active:              preparing.Candidate,
		Previous:            preparing.Active,
	}
	// For the final validation, the new candidate uses sourceFingerprint
	// and the previous uses priorSourceFingerprint. We validate each separately.
	if _, _, err := validateExistingRepository(
		committedPath(layout, committed.Active.ID),
		sourceFingerprint,
	); err != nil {
		return fmt.Errorf("final validate new active: %w", err)
	}
	if _, _, err := validateExistingRepository(
		layout.previous,
		priorSourceFingerprint,
	); err != nil {
		return fmt.Errorf("final validate previous: %w", err)
	}
	if err := writePublicationState(layout, committed); err != nil {
		return err
	}
	return nil
}

// buildAdditiveTargets produces TUF targets that preserve all existing
// verification material exactly and append only the new standby Rekor key.
// SigningConfig is preserved byte-for-byte — no routing changes.
// activeTUFTargetsPath points to the current committed TUF targets directory.
func buildAdditiveTargets(generationPath string, bootstrap bootstrapManifest, activeTUFTargetsPath string) ([]tufTarget, error) {
	// Load raw PEM target files from the generation directory (byte-identical
	// copies of prior generation material used as individual TUF targets).
	fulcioPEM, err := os.ReadFile(filepath.Join(generationPath, "public", "fulcio", "root.pem"))
	if err != nil {
		return nil, fmt.Errorf("read Fulcio root: %w", err)
	}
	ctPEM, _, err := loadP256PublicKey(
		filepath.Join(generationPath, "public", "ctlog", "pubkey.pem"),
	)
	if err != nil {
		return nil, fmt.Errorf("load CT log key: %w", err)
	}
	rekorPEM, _, err := loadP256PublicKey(
		filepath.Join(generationPath, "public", "rekor", "signer.pub"),
	)
	if err != nil {
		return nil, fmt.Errorf("load Rekor key: %w", err)
	}
	tsaChainPEM, tsaCertificates, err := loadCertificateChain(
		filepath.Join(generationPath, "public", "tsa", "cert-chain.pem"))
	if err != nil {
		return nil, fmt.Errorf("load TSA certificate chain: %w", err)
	}

	// Load standby Rekor key (added in this generation).
	standbyPEM, standbyDER, err := loadP256PublicKey(
		filepath.Join(generationPath, "public", "rekor", standbyRekorKeyFile),
	)
	if err != nil {
		return nil, fmt.Errorf("load standby Rekor key: %w", err)
	}

	// Load and parse the EXISTING committed TrustedRoot to preserve all entries exactly.
	existingTRBytes, err := os.ReadFile(filepath.Join(activeTUFTargetsPath, "trusted_root.json"))
	if err != nil {
		return nil, fmt.Errorf("read committed trusted_root.json: %w", err)
	}
	existingTR := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(existingTRBytes, existingTR); err != nil {
		return nil, fmt.Errorf("parse committed TrustedRoot: %w", err)
	}

	// Append the standby entry to TrustedRoot.Tlogs. All existing entries
	// (including their time ranges, log IDs, URLs, keys) are preserved exactly.
	standbyStart := time.Now().UTC().Add(365 * 24 * time.Hour)
	existingTR.Tlogs = append(existingTR.Tlogs, newStandbyTransparencyLog(standbyDER, standbyStart))

	// Load committed SigningConfig bytes UNCHANGED — no routing to standby.
	signingConfigBytes, err := os.ReadFile(filepath.Join(activeTUFTargetsPath, "signing_config.v0.2.json"))
	if err != nil {
		return nil, fmt.Errorf("read committed signing_config.v0.2.json: %w", err)
	}
	// Parse for ClientTrustConfig embedding only.
	existingSC := &trustrootv1.SigningConfig{}
	if err := protojson.Unmarshal(signingConfigBytes, existingSC); err != nil {
		return nil, fmt.Errorf("parse committed SigningConfig: %w", err)
	}

	// Build ClientTrustConfig from the modified TrustedRoot + unchanged SigningConfig.
	clientConfig := &trustrootv1.ClientTrustConfig{
		MediaType:     clientTrustConfigMediaType,
		TrustedRoot:   existingTR,
		SigningConfig: existingSC,
	}

	trustedRootJSON, err := protoJSON.Marshal(existingTR)
	if err != nil {
		return nil, fmt.Errorf("marshal TrustedRoot: %w", err)
	}
	clientConfigJSON, err := protoJSON.Marshal(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("marshal ClientTrustConfig: %w", err)
	}
	trustedRootBytes := append(append([]byte(nil), trustedRootJSON...), '\n')
	clientConfigBytes := append(append([]byte(nil), clientConfigJSON...), '\n')

	// Build trust status target.
	statusJSON, err := json.MarshalIndent(
		trustStatusTarget{
			SchemaVersion:            trustStatusSchemaVersion,
			TrustDomainID:            bootstrap.TrustDomainID,
			Generation:               bootstrap.Generation,
			GenerationID:             bootstrap.GenerationID,
			GenerationManifestSHA256: bootstrap.GenerationManifestSHA256,
			TUFRootVersion:           0, // Filled below
			TUFTargetsVersion:        0, // Filled below
			TrustedRootSHA256:        hashBytes(trustedRootBytes),
			SigningConfigSHA256:      hashBytes(signingConfigBytes),
		},
		"",
		"  ",
	)
	if err != nil {
		return nil, fmt.Errorf("marshal trust status: %w", err)
	}
	statusBytes := append(statusJSON, '\n')

	return []tufTarget{
		{
			name:   "fulcio_v1.crt.pem",
			data:   fulcioPEM,
			custom: targetMetadata("Fulcio", fulcioURL),
		},
		{
			name:   "ctfe.pub",
			data:   ctPEM,
			custom: targetMetadata("CTFE", ctLogURL),
		},
		{
			name:   "rekor.pub",
			data:   rekorPEM,
			custom: targetMetadata("Rekor", rekorURL),
		},
		{
			name:   "rekor-standby.pub",
			data:   standbyPEM,
			custom: targetMetadata("Rekor-Standby", rekorURL),
		},
		{
			name:   "tsa.certchain.pem",
			data:   tsaChainPEM,
			custom: targetMetadata("TSA", tsaURL),
		},
		{
			name: "tsa_leaf.crt.pem",
			data: pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: tsaCertificates[0].Raw,
				}),
			custom: targetMetadata("TSA", tsaURL),
		},
		{
			name: "tsa_root.crt.pem",
			data: pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: tsaCertificates[len(tsaCertificates)-1].Raw,
				}),
			custom: targetMetadata("TSA", tsaURL),
		},
		{name: "trusted_root.json", data: trustedRootBytes},
		{name: "signing_config.v0.2.json", data: signingConfigBytes},
		{name: "client_trust_config.json", data: clientConfigBytes},
		{name: trustStatusTargetName, data: statusBytes},
	}, nil
}

// replaceTargetsInRepository replaces all TUF targets in an existing repository
// with new content, re-signs targets metadata, and refreshes snapshot/timestamp.
func replaceTargetsInRepository(tufPath string, targets []tufTarget, bootstrap bootstrapManifest) error {
	store := tuf.FileSystemStore(tufPath, nil)
	repository, err := tuf.NewRepoIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("open TUF repository for target update: %w", err)
	}

	rootVersion, err := repository.RootVersion()
	if err != nil {
		return fmt.Errorf("read root version: %w", err)
	}
	targetsVersion, err := repository.TargetsVersion()
	if err != nil {
		return fmt.Errorf("read targets version: %w", err)
	}
	newTargetsVersion := int(targetsVersion) + 1

	// Write new target files and update the trust_status target with correct versions.
	rootAndTargetsExpires := time.Now().UTC().AddDate(1, 0, 0)
	for i, target := range targets {
		if target.name == trustStatusTargetName {
			// Update the trust status target with the correct TUF versions.
			var status trustStatusTarget
			if err := json.Unmarshal(target.data[:len(target.data)-1], &status); err != nil {
				return fmt.Errorf("parse trust status for version update: %w", err)
			}
			status.TUFRootVersion = int(rootVersion)
			status.TUFTargetsVersion = newTargetsVersion
			statusJSON, err := json.MarshalIndent(status, "", "  ")
			if err != nil {
				return fmt.Errorf("re-marshal trust status: %w", err)
			}
			targets[i].data = append(statusJSON, '\n')
		}

		stagedPath := filepath.Join(tufPath, "staged", "targets", target.name)
		if err := os.MkdirAll(filepath.Dir(stagedPath), 0o755); err != nil {
			return fmt.Errorf("create staged target directory: %w", err)
		}
		if err := os.WriteFile(stagedPath, targets[i].data, 0o644); err != nil {
			return fmt.Errorf("write staged target %s: %w", target.name, err)
		}
		// Also write to public targets for serving.
		publicPath := filepath.Join(tufPath, "targets", target.name)
		if err := os.MkdirAll(filepath.Dir(publicPath), 0o755); err != nil {
			return fmt.Errorf("create public target directory: %w", err)
		}
		if err := os.WriteFile(publicPath, targets[i].data, 0o644); err != nil {
			return fmt.Errorf("write public target %s: %w", target.name, err)
		}
		if err := repository.AddTargetWithExpires(target.name, target.custom, rootAndTargetsExpires); err != nil {
			return fmt.Errorf("add TUF target %s: %w", target.name, err)
		}
	}

	if err := repository.SnapshotWithExpires(time.Now().UTC().Add(30 * 24 * time.Hour)); err != nil {
		return fmt.Errorf("create published TUF snapshot: %w", err)
	}
	if err := repository.TimestampWithExpires(time.Now().UTC().Add(24 * time.Hour)); err != nil {
		return fmt.Errorf("create published TUF timestamp: %w", err)
	}
	if err := repository.Commit(); err != nil {
		return fmt.Errorf("commit published TUF targets: %w", err)
	}
	return nil
}

// newStandbyTransparencyLog creates a transparency log entry for a standby key
// with a future validity start time. The baseURL uses /standby to clearly
// indicate this entry is not yet routable.
func newStandbyTransparencyLog(standbyDER []byte, standbyStart time.Time) *trustrootv1.TransparencyLogInstance {
	logID := sha256.Sum256(standbyDER)
	return &trustrootv1.TransparencyLogInstance{
		BaseUrl:       rekorURL + "/standby",
		HashAlgorithm: commonv1.HashAlgorithm_SHA2_256,
		PublicKey: &commonv1.PublicKey{
			RawBytes:   standbyDER,
			KeyDetails: commonv1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			ValidFor: &commonv1.TimeRange{
				Start: timestamppb.New(standbyStart),
			},
		},
		LogId: &commonv1.LogId{
			KeyId: append([]byte(nil), logID[:]...),
		},
	}
}

// validateNextGenerationForRecovery performs strict validation of a candidate
// generation N+1 directory against the immutable trust-domain state and active
// generation. This MUST be called before any forward-complete or cleanup action
// on a generation directory to prevent operating on tampered/ambiguous state.
func validateNextGenerationForRecovery(
	statePath string,
	activeBootstrap bootstrapManifest,
) (generationManifest, bootstrapManifest, string, error) {
	// Load immutable trust-domain manifest.
	domainPath := filepath.Join(statePath, "trust-domain.json")
	domainBytes, err := os.ReadFile(domainPath)
	if err != nil {
		return generationManifest{}, bootstrapManifest{}, "", fmt.Errorf("read trust-domain for recovery validation: %w", err)
	}
	var domain trustDomainManifest
	if err := json.Unmarshal(domainBytes, &domain); err != nil {
		return generationManifest{}, bootstrapManifest{}, "", fmt.Errorf("parse trust-domain for recovery validation: %w", err)
	}

	expectedGen := activeBootstrap.Generation + 1
	expectedGenID := fmt.Sprintf("generation-%08d", expectedGen)
	nextGenPath := filepath.Join(statePath, "generations", expectedGenID)

	// Read and parse the generation manifest.
	nextManifestPath := filepath.Join(nextGenPath, "manifest.json")
	nextManifestBytes, err := os.ReadFile(nextManifestPath)
	if err != nil {
		return generationManifest{}, bootstrapManifest{}, "", fmt.Errorf("read next-gen manifest: %w", err)
	}
	var nextManifest generationManifest
	if err := json.Unmarshal(nextManifestBytes, &nextManifest); err != nil {
		return generationManifest{}, bootstrapManifest{}, "", fmt.Errorf("parse next-gen manifest: %w", err)
	}
	nextManifestHash := hashBytes(nextManifestBytes)

	// Strict validation against immutable trust-domain identity.
	if nextManifest.TrustDomainID != domain.TrustDomainID {
		return generationManifest{}, bootstrapManifest{}, "", fmt.Errorf(
			"next-generation trust-domain ID %q does not match immutable domain %q",
			nextManifest.TrustDomainID, domain.TrustDomainID,
		)
	}
	if nextManifest.TrustDomainID != activeBootstrap.TrustDomainID {
		return generationManifest{}, bootstrapManifest{}, "", fmt.Errorf(
			"next-generation trust-domain ID %q does not match active bootstrap %q",
			nextManifest.TrustDomainID, activeBootstrap.TrustDomainID,
		)
	}

	// Validate exact generation sequence.
	if nextManifest.Generation != expectedGen {
		return generationManifest{}, bootstrapManifest{}, "", fmt.Errorf(
			"next-generation number %d does not match expected %d",
			nextManifest.Generation, expectedGen,
		)
	}
	if nextManifest.GenerationID != expectedGenID {
		return generationManifest{}, bootstrapManifest{}, "", fmt.Errorf(
			"next-generation ID %q does not match expected %q",
			nextManifest.GenerationID, expectedGenID,
		)
	}

	// Validate file set matches manifest exactly.
	actualFiles, err := collectGenerationFileHashes(nextGenPath)
	if err != nil {
		return generationManifest{}, bootstrapManifest{}, "", fmt.Errorf("collect next-gen files: %w", err)
	}
	if !reflect.DeepEqual(actualFiles, nextManifest.Files) {
		return generationManifest{}, bootstrapManifest{}, "", errors.New(
			"next-generation file set or hashes do not match its manifest",
		)
	}
	if err := validateRekorGenerationMaterial(nextGenPath, nextManifest); err != nil {
		return generationManifest{}, bootstrapManifest{}, "", fmt.Errorf(
			"validate next-generation Rekor material: %w",
			err,
		)
	}

	// Build validated bootstrap for fingerprint computation.
	nextBootstrap := bootstrapManifest{
		SchemaVersion:            4,
		CreatedAtUTC:             nextManifest.CreatedAtUTC,
		FulcioRootSHA256:         nextManifest.FulcioRootSHA256,
		CtLogPublicKeySHA256:     nextManifest.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:     nextManifest.RekorPublicKeySHA256,
		TsaRootSHA256:            nextManifest.TsaRootSHA256,
		TsaLeafSHA256:            nextManifest.TsaLeafSHA256,
		OIDCKeyID:                nextManifest.OIDCKeyID,
		TrustDomainID:            nextManifest.TrustDomainID,
		Generation:               nextManifest.Generation,
		GenerationID:             expectedGenID,
		GenerationManifestSHA256: nextManifestHash,
	}
	nextFingerprint, err := fingerprintSource(nextBootstrap)
	if err != nil {
		return generationManifest{}, bootstrapManifest{}, "", err
	}

	return nextManifest, nextBootstrap, nextFingerprint, nil
}

// cleanupOrphanedGeneration removes a generation directory that was created
// during a cross-generation publish attempt that failed before completion.
// Only removes a directory that passes strict validation against the immutable
// trust-domain identity and expected sequence. Ambiguous or tampered state is
// rejected loudly rather than silently deleted.
func cleanupOrphanedGeneration(statePath string, activeBootstrap bootstrapManifest) error {
	nextGenID := fmt.Sprintf("generation-%08d", activeBootstrap.Generation+1)
	nextGenPath := filepath.Join(statePath, "generations", nextGenID)
	if !pathExists(nextGenPath) {
		return nil
	}
	// The active symlink should NOT point here (it points to the current gen).
	activeGenID, err := readActiveGeneration(filepath.Join(statePath, "active-generation"))
	if err != nil {
		return fmt.Errorf("cannot determine active generation during orphan cleanup: %w", err)
	}
	if activeGenID == nextGenID {
		return nil // It IS the active generation; not orphaned.
	}

	// Strict validation: only remove if it matches the immutable trust-domain
	// and expected generation sequence. If validation fails (tampered/ambiguous),
	// return an error rather than silently deleting unknown state.
	_, _, _, validErr := validateNextGenerationForRecovery(statePath, activeBootstrap)
	if validErr != nil {
		return fmt.Errorf(
			"orphaned generation %s failed validation and cannot be safely removed: %w",
			nextGenID, validErr,
		)
	}

	return os.RemoveAll(nextGenPath)
}

// tryForwardCompleteGeneration handles the crash window where TUF publication
// committed with generation N+1's fingerprint, but the generation symlink and
// transition journal were not updated. It detects this by finding an orphaned
// generation N+1 directory whose fingerprint matches the committed TUF
// publication, then completes the switch.
func tryForwardCompleteGeneration(
	statePath string,
	layout tufLayout,
	state publicationState,
	activeBootstrap bootstrapManifest,
) (bool, error) {
	// Look for a generation N+1 directory.
	nextGenID := fmt.Sprintf("generation-%08d", activeBootstrap.Generation+1)
	nextGenPath := filepath.Join(statePath, "generations", nextGenID)
	if !pathExists(nextGenPath) {
		return false, nil
	}

	// Strict validation against immutable trust-domain and expected sequence.
	_, nextBootstrap, nextFingerprint, err := validateNextGenerationForRecovery(statePath, activeBootstrap)
	if err != nil {
		return false, fmt.Errorf("cross-gen recovery validation failed: %w", err)
	}
	nextManifestHash := nextBootstrap.GenerationManifestSHA256

	// Validate that the committed TUF active publication matches the next generation.
	// We only check the active reference (not previous, which has the old gen's fingerprint).
	if err := validateCommittedState(state); err != nil {
		return false, err
	}
	activeID, exists, err := readActivePublication(layout.active)
	if err != nil || !exists || activeID != state.Active.ID {
		return false, fmt.Errorf("active publication mismatch during cross-gen recovery")
	}
	if err := validateReference(
		committedPath(layout, state.Active.ID),
		*state.Active,
		nextFingerprint,
	); err != nil {
		// The TUF publication doesn't match gen N+1 either — genuinely broken.
		return false, err
	}

	// Forward-complete: switch the generation symlink and journal.
	if err := switchActiveGeneration(statePath, activeBootstrap, nextBootstrap, nextManifestHash); err != nil {
		return false, err
	}
	return true, nil
}
