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
)

type trustDomainManifest struct {
	SchemaVersion int       `json:"schemaVersion"`
	TrustDomainID string    `json:"trustDomainId"`
	CreatedAtUTC  time.Time `json:"createdAtUtc"`
	CtLogStateID  string    `json:"ctLogStateId"`
	RekorStateID  string    `json:"rekorStateId"`
}

type generationManifest struct {
	SchemaVersion        int               `json:"schemaVersion"`
	Generation           int               `json:"generation"`
	GenerationID         string            `json:"generationId"`
	TrustDomainID        string            `json:"trustDomainId"`
	CreatedAtUTC         time.Time         `json:"createdAtUtc"`
	SourceSchemaVersion  int               `json:"sourceSchemaVersion"`
	SourceManifestSHA256 *string           `json:"sourceManifestSha256"`
	FulcioRootSHA256     string            `json:"fulcioRootSha256"`
	CtLogPublicKeySHA256 string            `json:"ctLogPublicKeySha256"`
	RekorPublicKeySHA256 string            `json:"rekorPublicKeySha256"`
	TsaRootSHA256        string            `json:"tsaRootSha256"`
	TsaLeafSHA256        string            `json:"tsaLeafSha256"`
	OIDCKeyID            string            `json:"oidcKeyId"`
	Files                map[string]string `json:"files"`
}

type generationReference struct {
	Generation     int    `json:"generation"`
	GenerationID   string `json:"generationId"`
	ManifestSHA256 string `json:"manifestSha256"`
}

type trustTransitionJournal struct {
	SchemaVersion             int                  `json:"schemaVersion"`
	Status                    string               `json:"status"`
	LastCheckpoint            string               `json:"lastCheckpoint"`
	PriorGeneration           *generationReference `json:"priorGeneration"`
	Candidate                 generationReference  `json:"candidate"`
	TrustDomainManifestSHA256 string               `json:"trustDomainManifestSha256"`
	TrustDomain               trustDomainManifest  `json:"trustDomain"`
	CandidateManifest         generationManifest   `json:"candidateManifest"`
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
	if journal.PriorGeneration != nil {
		return bootstrapManifest{}, errors.New(
			"Step 4 does not support a prior trust generation or live rotation",
		)
	}
	if journal.TrustDomainManifestSHA256 != hashBytes(domainBytes) {
		return bootstrapManifest{}, errors.New(
			"trust-domain manifest does not match the transition journal",
		)
	}
	if !reflect.DeepEqual(journal.TrustDomain, domain) {
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
	if generation.Generation != initialGeneration ||
		generation.GenerationID != initialGenerationID {
		return errors.New(
			"Step 4 supports only generation 1; rotation is not implemented",
		)
	}
	if generation.TrustDomainID != domain.TrustDomainID {
		return errors.New("generation trust-domain identity does not match")
	}
	if !generation.CreatedAtUTC.Equal(domain.CreatedAtUTC) {
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
	if strings.TrimSuffix(filepath.Clean(directory), string(filepath.Separator)) != "generations" ||
		generationID != initialGenerationID {
		return "", fmt.Errorf("active generation link has unsafe target %q", target)
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
