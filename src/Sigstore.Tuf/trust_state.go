package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const (
	trustStateSchemaVersion      = 5
	trustTransitionSchemaVersion = 1
	initialGeneration            = 1
	initialGenerationID          = "generation-00000001"

	// generationManifestMode matches the read-only mode the C# bootstrapper
	// gives immutable generation manifests, so a generation written by this
	// worker satisfies the same invariant when C# validates it.
	generationManifestMode = 0o444
)

type trustDomainManifest struct {
	SchemaVersion int       `json:"schemaVersion"`
	TrustDomainID string    `json:"trustDomainId"`
	CreatedAtUTC  time.Time `json:"createdAtUtc"`
	CtLogStateID  string    `json:"ctLogStateId"`
	RekorStateID  string    `json:"rekorStateId"`
}

type generationManifest struct {
	SchemaVersion               int               `json:"schemaVersion"`
	Generation                  int               `json:"generation"`
	GenerationID                string            `json:"generationId"`
	TrustDomainID               string            `json:"trustDomainId"`
	CreatedAtUTC                time.Time         `json:"createdAtUtc"`
	SourceSchemaVersion         int               `json:"sourceSchemaVersion"`
	SourceManifestSHA256        *string           `json:"sourceManifestSha256"`
	FulcioRootSHA256            string            `json:"fulcioRootSha256"`
	CtLogPublicKeySHA256        string            `json:"ctLogPublicKeySha256"`
	RekorPublicKeySHA256        string            `json:"rekorPublicKeySha256"`
	TsaRootSHA256               string            `json:"tsaRootSha256"`
	TsaLeafSHA256               string            `json:"tsaLeafSha256"`
	OIDCKeyID                   string            `json:"oidcKeyId"`
	OIDCRotationOperationID     string            `json:"oidcRotationOperationId,omitempty"`
	OIDCPriorGeneration         int               `json:"oidcPriorGeneration,omitempty"`
	OIDCPriorGenerationID       string            `json:"oidcPriorGenerationId,omitempty"`
	OIDCPriorKeyID              string            `json:"oidcPriorKeyId,omitempty"`
	OIDCOverlapExpiresAtUTC     *time.Time        `json:"oidcOverlapExpiresAtUtc,omitempty"`
	OIDCRetainedPrivateKeyPaths []string          `json:"oidcRetainedPrivateKeyPaths,omitempty"`
	TSARotationOperationID      string            `json:"tsaRotationOperationId,omitempty"`
	TSAPriorGeneration          int               `json:"tsaPriorGeneration,omitempty"`
	TSAPriorGenerationID        string            `json:"tsaPriorGenerationId,omitempty"`
	TSAPriorRootSHA256          string            `json:"tsaPriorRootSha256,omitempty"`
	TSAPriorLeafSHA256          string            `json:"tsaPriorLeafSha256,omitempty"`
	FulcioRotationOperationID   string            `json:"fulcioRotationOperationId,omitempty"`
	FulcioPriorGeneration       int               `json:"fulcioPriorGeneration,omitempty"`
	FulcioPriorGenerationID     string            `json:"fulcioPriorGenerationId,omitempty"`
	FulcioPriorRootSHA256       string            `json:"fulcioPriorRootSha256,omitempty"`
	RekorRotationOperationID    string            `json:"rekorRotationOperationId,omitempty"`
	RekorPriorGeneration        int               `json:"rekorPriorGeneration,omitempty"`
	RekorPriorGenerationID      string            `json:"rekorPriorGenerationId,omitempty"`
	RekorPriorPublicKeySHA256   string            `json:"rekorPriorPublicKeySha256,omitempty"`
	RekorPriorShardID           string            `json:"rekorPriorShardId,omitempty"`
	RekorPriorBaseURL           string            `json:"rekorPriorBaseUrl,omitempty"`
	RekorShardID                string            `json:"rekorShardId,omitempty"`
	RekorBaseURL                string            `json:"rekorBaseUrl,omitempty"`
	CtLogRotationOperationID    string            `json:"ctLogRotationOperationId,omitempty"`
	CtLogPriorGeneration        int               `json:"ctLogPriorGeneration,omitempty"`
	CtLogPriorGenerationID      string            `json:"ctLogPriorGenerationId,omitempty"`
	CtLogPriorPublicKeySHA256   string            `json:"ctLogPriorPublicKeySha256,omitempty"`
	CtLogPriorShardID           string            `json:"ctLogPriorShardId,omitempty"`
	CtLogPriorBaseURL           string            `json:"ctLogPriorBaseUrl,omitempty"`
	CtLogShardID                string            `json:"ctLogShardId,omitempty"`
	CtLogBaseURL                string            `json:"ctLogBaseUrl,omitempty"`
	Files                       map[string]string `json:"files"`
}

type generationReference struct {
	Generation     int    `json:"generation"`
	GenerationID   string `json:"generationId"`
	ManifestSHA256 string `json:"manifestSha256"`
}

type trustTransitionJournal struct {
	SchemaVersion             int                  `json:"schemaVersion"`
	TransitionID              string               `json:"transitionId,omitempty"`
	Operation                 string               `json:"operation,omitempty"`
	Status                    string               `json:"status"`
	LastCheckpoint            string               `json:"lastCheckpoint"`
	StartedAtUTC              time.Time            `json:"startedAtUtc,omitempty"`
	UpdatedAtUTC              time.Time            `json:"updatedAtUtc,omitempty"`
	PriorGeneration           *generationReference `json:"priorGeneration"`
	Candidate                 generationReference  `json:"candidate"`
	TrustDomainManifestSHA256 string               `json:"trustDomainManifestSha256"`
	LegacyManifestSHA256      *string              `json:"legacyManifestSha256,omitempty"`
	TrustDomain               trustDomainManifest  `json:"trustDomain"`
	CandidateManifest         generationManifest   `json:"candidateManifest"`
	Failure                   *string              `json:"failure,omitempty"`
}

// writeGenerationManifest writes an immutable generation manifest and then
// explicitly applies its read-only mode.
//
// The mode argument to os.WriteFile is only a creation hint: it is ignored
// when the file already exists, and it is not honored at all by some
// filesystems this state directory legitimately lives on — notably Docker
// Desktop bind mounts on macOS, which materialize host files as 0644
// regardless of what was requested. The C# bootstrapper enforces that
// generation manifests are read-only, so the mode is corrected explicitly
// here, before the manifest is validated and before the staged generation is
// renamed into its committed location.
func writeGenerationManifest(path string, data []byte) error {
	if _, err := os.Stat(path); err == nil {
		// An interrupted attempt can leave a read-only manifest behind.
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("prepare generation manifest for rewrite: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect generation manifest: %w", err)
	}
	if err := os.WriteFile(path, data, generationManifestMode); err != nil {
		return fmt.Errorf("write generation manifest: %w", err)
	}
	if err := os.Chmod(path, generationManifestMode); err != nil {
		return fmt.Errorf("set generation manifest mode: %w", err)
	}
	return nil
}

func loadActiveTrustGeneration(statePath string) (bootstrapManifest, error) {
	domainPath := filepath.Join(statePath, "trust-domain.json")
	domainBytes, err := os.ReadFile(domainPath)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("read trust-domain manifest: %w", err)
	}
	var domain trustDomainManifest
	if err := json.Unmarshal(domainBytes, &domain); err != nil {
		return bootstrapManifest{}, fmt.Errorf("parse trust-domain manifest: %w", err)
	}
	if domain.SchemaVersion != trustStateSchemaVersion {
		return bootstrapManifest{}, fmt.Errorf(
			"trust-domain schema %d is unsupported; expected %d",
			domain.SchemaVersion,
			trustStateSchemaVersion,
		)
	}

	journalPath := filepath.Join(statePath, "transition", "state.json")
	journalBytes, err := os.ReadFile(journalPath)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("read trust transition journal: %w", err)
	}
	var journal trustTransitionJournal
	if err := json.Unmarshal(journalBytes, &journal); err != nil {
		return bootstrapManifest{}, fmt.Errorf("parse trust transition journal: %w", err)
	}
	if journal.SchemaVersion != trustTransitionSchemaVersion {
		return bootstrapManifest{}, fmt.Errorf(
			"trust transition schema %d is unsupported; expected %d",
			journal.SchemaVersion,
			trustTransitionSchemaVersion,
		)
	}
	if journal.Status != "committed" && journal.Status != "recovered" {
		return bootstrapManifest{}, fmt.Errorf(
			"trust transition status %q is not stable",
			journal.Status,
		)
	}
	if journal.LastCheckpoint != "transition-finalized" {
		return bootstrapManifest{}, fmt.Errorf(
			"trust transition stopped at checkpoint %q",
			journal.LastCheckpoint,
		)
	}
	if journal.PriorGeneration != nil && journal.Candidate.Generation <= journal.PriorGeneration.Generation {
		return bootstrapManifest{}, fmt.Errorf(
			"candidate generation %d must be greater than prior generation %d",
			journal.Candidate.Generation,
			journal.PriorGeneration.Generation,
		)
	}
	if journal.PriorGeneration != nil &&
		journal.Candidate.Generation != journal.PriorGeneration.Generation+1 {
		return bootstrapManifest{}, fmt.Errorf(
			"candidate generation %d must immediately follow prior generation %d",
			journal.Candidate.Generation,
			journal.PriorGeneration.Generation,
		)
	}
	if journal.TrustDomainManifestSHA256 != hashBytes(domainBytes) {
		return bootstrapManifest{}, errors.New(
			"trust-domain manifest does not match the transition journal",
		)
	}
	if !trustDomainEqual(journal.TrustDomain, domain) {
		return bootstrapManifest{}, errors.New(
			"journaled trust-domain identity does not match the immutable manifest",
		)
	}

	generationID, err := readActiveGeneration(
		filepath.Join(statePath, "active-generation"),
	)
	if err != nil {
		return bootstrapManifest{}, err
	}
	if generationID != journal.Candidate.GenerationID {
		return bootstrapManifest{}, fmt.Errorf(
			"active generation %q does not match journaled candidate %q",
			generationID,
			journal.Candidate.GenerationID,
		)
	}
	generationPath := filepath.Join(statePath, "generations", generationID)
	manifestPath := filepath.Join(generationPath, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("read generation manifest: %w", err)
	}
	if hashBytes(manifestBytes) != journal.Candidate.ManifestSHA256 {
		return bootstrapManifest{}, errors.New(
			"active generation manifest does not match the transition journal",
		)
	}
	var generation generationManifest
	if err := json.Unmarshal(manifestBytes, &generation); err != nil {
		return bootstrapManifest{}, fmt.Errorf("parse generation manifest: %w", err)
	}
	if err := validateGenerationState(
		statePath,
		generationPath,
		domain,
		generation,
	); err != nil {
		return bootstrapManifest{}, err
	}
	if !reflect.DeepEqual(journal.CandidateManifest, generation) {
		return bootstrapManifest{}, errors.New(
			"journaled candidate manifest does not match the active generation",
		)
	}

	return bootstrapManifest{
		SchemaVersion:            4,
		CreatedAtUTC:             generation.CreatedAtUTC,
		FulcioRootSHA256:         generation.FulcioRootSHA256,
		CtLogPublicKeySHA256:     generation.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:     generation.RekorPublicKeySHA256,
		TsaRootSHA256:            generation.TsaRootSHA256,
		TsaLeafSHA256:            generation.TsaLeafSHA256,
		OIDCKeyID:                generation.OIDCKeyID,
		TrustDomainID:            domain.TrustDomainID,
		Generation:               generation.Generation,
		GenerationID:             generation.GenerationID,
		GenerationManifestSHA256: journal.Candidate.ManifestSHA256,
	}, nil
}

// loadBootstrapFromGeneration constructs a bootstrapManifest from a generation
// directory for fingerprint computation. Used for prior-generation fingerprint
// derivation during recovery validation.
func loadBootstrapFromGeneration(statePath, generationPath, generationID string) (bootstrapManifest, error) {
	manifestPath := filepath.Join(generationPath, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return bootstrapManifest{}, err
	}
	var gen generationManifest
	if err := json.Unmarshal(manifestBytes, &gen); err != nil {
		return bootstrapManifest{}, err
	}
	domainPath := filepath.Join(statePath, "trust-domain.json")
	domainBytes, err := os.ReadFile(domainPath)
	if err != nil {
		return bootstrapManifest{}, err
	}
	var domain trustDomainManifest
	if err := json.Unmarshal(domainBytes, &domain); err != nil {
		return bootstrapManifest{}, err
	}
	return bootstrapManifest{
		SchemaVersion:        4,
		CreatedAtUTC:         gen.CreatedAtUTC,
		FulcioRootSHA256:     gen.FulcioRootSHA256,
		CtLogPublicKeySHA256: gen.CtLogPublicKeySHA256,
		RekorPublicKeySHA256: gen.RekorPublicKeySHA256,
		TsaRootSHA256:        gen.TsaRootSHA256,
		TsaLeafSHA256:        gen.TsaLeafSHA256,
		OIDCKeyID:            gen.OIDCKeyID,
		TrustDomainID:        domain.TrustDomainID,
		Generation:           gen.Generation,
		GenerationID:         generationID,
	}, nil
}

func validateGenerationState(
	statePath string,
	generationPath string,
	domain trustDomainManifest,
	generation generationManifest,
) error {
	if generation.SchemaVersion != trustStateSchemaVersion {
		return fmt.Errorf(
			"generation schema %d is unsupported; expected %d",
			generation.SchemaVersion,
			trustStateSchemaVersion,
		)
	}
	if generation.Generation < initialGeneration {
		return fmt.Errorf(
			"generation %d is invalid; must be >= %d",
			generation.Generation,
			initialGeneration,
		)
	}
	expectedGenerationID := fmt.Sprintf("generation-%08d", generation.Generation)
	if generation.GenerationID != expectedGenerationID {
		return fmt.Errorf(
			"generation ID %q does not match generation %d",
			generation.GenerationID,
			generation.Generation,
		)
	}
	if generation.TrustDomainID != domain.TrustDomainID {
		return errors.New("generation trust-domain identity does not match")
	}
	if generation.Generation == initialGeneration && !generation.CreatedAtUTC.Equal(domain.CreatedAtUTC) {
		return errors.New("initial generation creation time does not match trust-domain identity")
	}
	if generation.SourceSchemaVersion != 4 &&
		generation.SourceSchemaVersion != trustStateSchemaVersion {
		return fmt.Errorf(
			"generation source schema %d is unsupported",
			generation.SourceSchemaVersion,
		)
	}
	if generation.SourceSchemaVersion == 4 {
		if generation.SourceManifestSHA256 == nil ||
			validateSHA256(*generation.SourceManifestSHA256) != nil {
			return errors.New("migrated generation has an invalid schema-4 manifest hash")
		}
	} else if generation.SourceManifestSHA256 != nil {
		return errors.New("fresh generation unexpectedly references a schema-4 manifest")
	}

	actualFiles, err := collectGenerationFileHashes(generationPath)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actualFiles, generation.Files) {
		return errors.New("active generation file set or hashes do not match its manifest")
	}
	if err := validateOIDCGenerationMaterial(generationPath, generation); err != nil {
		return fmt.Errorf("validate OIDC generation material: %w", err)
	}
	if err := validateTSAGenerationMaterial(generationPath, generation); err != nil {
		return fmt.Errorf("validate TSA generation material: %w", err)
	}
	if err := validateFulcioGenerationMaterial(generationPath, generation); err != nil {
		return fmt.Errorf("validate Fulcio generation material: %w", err)
	}
	if err := validateRekorGenerationMaterial(generationPath, generation); err != nil {
		return fmt.Errorf("validate Rekor generation material: %w", err)
	}
	if err := validateCtLogGenerationMaterial(generationPath, generation); err != nil {
		return fmt.Errorf("validate CT log generation material: %w", err)
	}
	ctState, err := os.ReadFile(filepath.Join(statePath, "data", "ctlog", "bootstrap-state"))
	if err != nil {
		return fmt.Errorf("read CT log state identity: %w", err)
	}
	if string(ctState) != domain.CtLogStateID {
		return errors.New("CT log state identity does not match the trust domain")
	}
	rekorState, err := os.ReadFile(filepath.Join(statePath, "data", "rekor", "bootstrap-state"))
	if err != nil {
		return fmt.Errorf("read Rekor state identity: %w", err)
	}
	if string(rekorState) != domain.RekorStateID {
		return errors.New("Rekor state identity does not match the trust domain")
	}
	return nil
}

func collectGenerationFileHashes(
	generationPath string,
) (map[string]string, error) {
	files := map[string]string{}
	for _, directory := range []string{"private", "public"} {
		root := filepath.Join(generationPath, directory)
		err := filepath.WalkDir(root, func(
			path string,
			entry fs.DirEntry,
			walkErr error,
		) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				return fmt.Errorf("unsupported generation state file type at %s", path)
			}
			hash, err := hashFile(path)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(generationPath, path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(relative)] = hash
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("hash generation %s files: %w", directory, err)
		}
	}
	return files, nil
}

func readActiveGeneration(path string) (string, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return "", fmt.Errorf("read active generation link: %w", err)
	}
	if filepath.IsAbs(target) || filepath.Clean(target) != target {
		return "", fmt.Errorf("active generation link has unsafe target %q", target)
	}
	directory, generationID := filepath.Split(target)
	if strings.TrimSuffix(filepath.Clean(directory), string(filepath.Separator)) != "generations" {
		return "", fmt.Errorf("active generation link has unsafe target %q", target)
	}
	if !strings.HasPrefix(generationID, "generation-") {
		return "", fmt.Errorf("active generation link has unexpected ID format %q", generationID)
	}
	return generationID, nil
}

func hashBytes(data []byte) string {
	sum := sha256Bytes(data)
	return fmt.Sprintf("%x", sum)
}

func sha256Bytes(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// trustDomainEqual compares two trustDomainManifest values semantically.
// Unlike reflect.DeepEqual, it uses time.Equal() for CreatedAtUTC so that
// equivalent timestamps with different timezone representations (e.g., "Z"
// vs "+00:00") are treated as equal.
func trustDomainEqual(a, b trustDomainManifest) bool {
	return a.SchemaVersion == b.SchemaVersion &&
		a.TrustDomainID == b.TrustDomainID &&
		a.CreatedAtUTC.Equal(b.CreatedAtUTC) &&
		a.CtLogStateID == b.CtLogStateID &&
		a.RekorStateID == b.RekorStateID
}
