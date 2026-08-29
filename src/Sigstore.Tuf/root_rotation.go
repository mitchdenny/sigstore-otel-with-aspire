package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const rootRotationSchemaVersion = 1

var rootRotationOperationIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type tufRootRotationRequest struct {
	SchemaVersion                     int    `json:"schemaVersion"`
	OperationID                       string `json:"operationId"`
	TrustDomainID                     string `json:"trustDomainId"`
	StartingGeneration                int    `json:"startingGeneration"`
	StartingGenerationID              string `json:"startingGenerationId"`
	StartingGenerationManifestSHA256  string `json:"startingGenerationManifestSha256"`
	StartingRootVersion               int    `json:"startingRootVersion"`
	StartingPublicationID             string `json:"startingPublicationId"`
	StartingPublicationManifestSHA256 string `json:"startingPublicationManifestSha256"`
}

type tufRootRotationCompletion struct {
	SchemaVersion                     int       `json:"schemaVersion"`
	OperationID                       string    `json:"operationId"`
	TrustDomainID                     string    `json:"trustDomainId"`
	Generation                        int       `json:"generation"`
	GenerationID                      string    `json:"generationId"`
	GenerationManifestSHA256          string    `json:"generationManifestSha256"`
	PreviousRootVersion               int       `json:"previousRootVersion"`
	RootVersion                       int       `json:"rootVersion"`
	TargetsVersion                    int       `json:"targetsVersion"`
	PreviousPublicationID             string    `json:"previousPublicationId"`
	PreviousPublicationManifestSHA256 string    `json:"previousPublicationManifestSha256"`
	PublicationID                     string    `json:"publicationId"`
	PublicationManifestSHA256         string    `json:"publicationManifestSha256"`
	TrustedRootSHA256                 string    `json:"trustedRootSha256"`
	SigningConfigSHA256               string    `json:"signingConfigSha256"`
	CompletedAtUTC                    time.Time `json:"completedAtUtc"`
}

type tufMetadataVersionEnvelope struct {
	Signed struct {
		Version int `json:"version"`
	} `json:"signed"`
}

func dispatchTUFRootRotation(
	statePath string,
	requestPath string,
	hooks publicationHooks,
) (repositoryAction, error) {
	request, err := loadTUFRootRotationRequest(requestPath)
	if err != nil {
		return "", err
	}

	stateLock, err := acquireStateLock(statePath, 30*time.Second, "tuf-root-rotation")
	if err != nil {
		return "", err
	}
	defer stateLock.release()

	if _, err := recoverTUFStateLocked(statePath, hooks); err != nil {
		return "", fmt.Errorf("recover TUF state before root rotation: %w", err)
	}

	completionDir := filepath.Join(
		statePath,
		"tuf-root-rotations",
		request.OperationID,
	)
	completionPath := filepath.Join(completionDir, "completion.json")
	if pathExists(completionPath) {
		completion, err := loadTUFRootRotationCompletion(completionPath)
		if err != nil {
			return "", err
		}
		if completion.OperationID != request.OperationID {
			return "", fmt.Errorf("root rotation completion operationId does not match request")
		}
		if err := validateTUFRootRotationCompletion(statePath, completion); err != nil {
			return "", fmt.Errorf("validate replayed root rotation completion: %w", err)
		}
		if err := removeTUFRootRotationRequest(requestPath); err != nil {
			return "", err
		}
		return repositoryActionRotated, nil
	}

	rootVersion, publication, bootstrap, err := loadLiveTUFRootRotationState(statePath)
	if err != nil {
		return "", err
	}
	if err := validateTUFRootRotationRequestAgainstState(
		request,
		rootVersion,
		publication,
		bootstrap,
	); err != nil {
		if rootVersion != request.StartingRootVersion+1 {
			return "", err
		}
		if err := validateCompletedTUFRootRotationState(
			request,
			publication,
			bootstrap,
		); err != nil {
			return "", fmt.Errorf("root rotation state is ambiguous after recovery: %w", err)
		}
	} else {
		if _, err := rotateTUFRootKeyLocked(statePath, hooks); err != nil {
			return "", err
		}
	}

	completion, err := buildTUFRootRotationCompletion(statePath, request)
	if err != nil {
		return "", err
	}
	completionJSON, err := json.MarshalIndent(completion, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode root rotation completion: %w", err)
	}
	completionJSON = append(completionJSON, '\n')
	if err := os.MkdirAll(completionDir, 0o755); err != nil {
		return "", fmt.Errorf("create root rotation completion directory: %w", err)
	}
	if err := writeAtomicJSON(completionPath, completionJSON); err != nil {
		return "", fmt.Errorf("write root rotation completion: %w", err)
	}
	if err := runCheckpoint(hooks, "root-completion-written"); err != nil {
		return "", err
	}
	if err := removeTUFRootRotationRequest(requestPath); err != nil {
		return "", err
	}
	return repositoryActionRotated, nil
}

func loadTUFRootRotationRequest(path string) (tufRootRotationRequest, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return tufRootRotationRequest{}, fmt.Errorf("read root rotation request: %w", err)
	}
	var request tufRootRotationRequest
	if err := decodeStrictJSON(payload, &request); err != nil {
		return tufRootRotationRequest{}, fmt.Errorf("decode root rotation request: %w", err)
	}
	if request.SchemaVersion != rootRotationSchemaVersion {
		return tufRootRotationRequest{}, fmt.Errorf(
			"root rotation request schemaVersion must be %d",
			rootRotationSchemaVersion,
		)
	}
	if !rootRotationOperationIDPattern.MatchString(request.OperationID) {
		return tufRootRotationRequest{}, fmt.Errorf("root rotation operationId is invalid")
	}
	if request.TrustDomainID == "" {
		return tufRootRotationRequest{}, fmt.Errorf("root rotation trustDomainId is required")
	}
	if request.StartingGeneration < 1 ||
		request.StartingGenerationID != fmt.Sprintf(
			"generation-%08d",
			request.StartingGeneration,
		) {
		return tufRootRotationRequest{}, fmt.Errorf(
			"root rotation starting generation binding is invalid",
		)
	}
	if err := validateSHA256(request.StartingGenerationManifestSHA256); err != nil {
		return tufRootRotationRequest{}, fmt.Errorf(
			"root rotation starting manifest hash: %w",
			err,
		)
	}
	if request.StartingRootVersion < 1 {
		return tufRootRotationRequest{}, fmt.Errorf(
			"root rotation starting root version must be positive",
		)
	}
	if err := validatePublicationReference(publicationReference{
		ID:             request.StartingPublicationID,
		ManifestSHA256: request.StartingPublicationManifestSHA256,
	}); err != nil {
		return tufRootRotationRequest{}, fmt.Errorf(
			"root rotation starting publication binding: %w",
			err,
		)
	}
	return request, nil
}

func loadTUFRootRotationCompletion(path string) (tufRootRotationCompletion, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return tufRootRotationCompletion{}, fmt.Errorf(
			"read root rotation completion: %w",
			err,
		)
	}
	var completion tufRootRotationCompletion
	if err := decodeStrictJSON(payload, &completion); err != nil {
		return tufRootRotationCompletion{}, fmt.Errorf(
			"decode root rotation completion: %w",
			err,
		)
	}
	if completion.SchemaVersion != rootRotationSchemaVersion ||
		!rootRotationOperationIDPattern.MatchString(completion.OperationID) ||
		completion.TrustDomainID == "" ||
		completion.Generation < 1 ||
		completion.GenerationID != fmt.Sprintf("generation-%08d", completion.Generation) ||
		completion.PreviousRootVersion < 1 ||
		completion.RootVersion != completion.PreviousRootVersion+1 ||
		completion.TargetsVersion < 1 ||
		completion.CompletedAtUTC.IsZero() {
		return tufRootRotationCompletion{}, fmt.Errorf(
			"root rotation completion is invalid",
		)
	}
	for name, value := range map[string]string{
		"generation manifest": completion.GenerationManifestSHA256,
		"trusted root":        completion.TrustedRootSHA256,
		"signing config":      completion.SigningConfigSHA256,
	} {
		if err := validateSHA256(value); err != nil {
			return tufRootRotationCompletion{}, fmt.Errorf(
				"root rotation completion %s hash: %w",
				name,
				err,
			)
		}
	}
	if err := validatePublicationReference(publicationReference{
		ID:             completion.PreviousPublicationID,
		ManifestSHA256: completion.PreviousPublicationManifestSHA256,
	}); err != nil {
		return tufRootRotationCompletion{}, fmt.Errorf(
			"root rotation previous publication: %w",
			err,
		)
	}
	if err := validatePublicationReference(publicationReference{
		ID:             completion.PublicationID,
		ManifestSHA256: completion.PublicationManifestSHA256,
	}); err != nil {
		return tufRootRotationCompletion{}, fmt.Errorf(
			"root rotation publication: %w",
			err,
		)
	}
	return completion, nil
}

func loadLiveTUFRootRotationState(
	statePath string,
) (int, publicationState, bootstrapManifest, error) {
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return 0, publicationState{}, bootstrapManifest{}, fmt.Errorf(
			"load active trust generation: %w",
			err,
		)
	}
	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return 0, publicationState{}, bootstrapManifest{}, fmt.Errorf(
			"load TUF publication state: %w",
			err,
		)
	}
	if publication.Status != publicationStatusCommitted || publication.Active == nil {
		return 0, publicationState{}, bootstrapManifest{}, fmt.Errorf(
			"TUF publication must be committed before root rotation",
		)
	}
	rootVersion, err := readTUFMetadataVersion(
		filepath.Join(
			committedPath(layout, publication.Active.ID),
			"repository",
			"root.json",
		),
	)
	if err != nil {
		return 0, publicationState{}, bootstrapManifest{}, fmt.Errorf(
			"read active root version: %w",
			err,
		)
	}
	return rootVersion, publication, bootstrap, nil
}

func validateTUFRootRotationRequestAgainstState(
	request tufRootRotationRequest,
	rootVersion int,
	publication publicationState,
	bootstrap bootstrapManifest,
) error {
	if bootstrap.TrustDomainID != request.TrustDomainID ||
		bootstrap.Generation != request.StartingGeneration ||
		bootstrap.GenerationID != request.StartingGenerationID ||
		bootstrap.GenerationManifestSHA256 != request.StartingGenerationManifestSHA256 {
		return fmt.Errorf("root rotation request does not match the active trust generation")
	}
	if rootVersion != request.StartingRootVersion {
		return fmt.Errorf(
			"root rotation request expected root version %d but active version is %d",
			request.StartingRootVersion,
			rootVersion,
		)
	}
	if publication.Active == nil ||
		publication.Active.ID != request.StartingPublicationID ||
		publication.Active.ManifestSHA256 != request.StartingPublicationManifestSHA256 {
		return fmt.Errorf("root rotation request does not match the active TUF publication")
	}
	return nil
}

func validateCompletedTUFRootRotationState(
	request tufRootRotationRequest,
	publication publicationState,
	bootstrap bootstrapManifest,
) error {
	if bootstrap.TrustDomainID != request.TrustDomainID ||
		bootstrap.Generation != request.StartingGeneration ||
		bootstrap.GenerationID != request.StartingGenerationID ||
		bootstrap.GenerationManifestSHA256 != request.StartingGenerationManifestSHA256 {
		return fmt.Errorf("active trust generation changed during root rotation")
	}
	if publication.Active == nil || publication.Previous == nil {
		return fmt.Errorf("root rotation publication history is incomplete")
	}
	if publication.Previous.ID != request.StartingPublicationID ||
		publication.Previous.ManifestSHA256 !=
			request.StartingPublicationManifestSHA256 {
		return fmt.Errorf("root rotation previous publication does not match the request")
	}
	return nil
}

func buildTUFRootRotationCompletion(
	statePath string,
	request tufRootRotationRequest,
) (tufRootRotationCompletion, error) {
	rootVersion, publication, bootstrap, err := loadLiveTUFRootRotationState(statePath)
	if err != nil {
		return tufRootRotationCompletion{}, err
	}
	if rootVersion != request.StartingRootVersion+1 {
		return tufRootRotationCompletion{}, fmt.Errorf(
			"root rotation expected version %d but active version is %d",
			request.StartingRootVersion+1,
			rootVersion,
		)
	}
	if err := validateCompletedTUFRootRotationState(
		request,
		publication,
		bootstrap,
	); err != nil {
		return tufRootRotationCompletion{}, err
	}
	layout := newTUFLayout(statePath)
	activePath := committedPath(layout, publication.Active.ID)
	targetsVersion, err := readTUFMetadataVersion(
		filepath.Join(activePath, "repository", "targets.json"),
	)
	if err != nil {
		return tufRootRotationCompletion{}, fmt.Errorf(
			"read active targets version: %w",
			err,
		)
	}
	trustedRoot, err := os.ReadFile(filepath.Join(activePath, "targets", "trusted_root.json"))
	if err != nil {
		return tufRootRotationCompletion{}, fmt.Errorf("read active trusted root: %w", err)
	}
	signingConfig, err := os.ReadFile(
		filepath.Join(activePath, "targets", "signing_config.v0.2.json"),
	)
	if err != nil {
		return tufRootRotationCompletion{}, fmt.Errorf("read active signing config: %w", err)
	}
	return tufRootRotationCompletion{
		SchemaVersion:                     rootRotationSchemaVersion,
		OperationID:                       request.OperationID,
		TrustDomainID:                     bootstrap.TrustDomainID,
		Generation:                        bootstrap.Generation,
		GenerationID:                      bootstrap.GenerationID,
		GenerationManifestSHA256:          bootstrap.GenerationManifestSHA256,
		PreviousRootVersion:               request.StartingRootVersion,
		RootVersion:                       rootVersion,
		TargetsVersion:                    targetsVersion,
		PreviousPublicationID:             request.StartingPublicationID,
		PreviousPublicationManifestSHA256: request.StartingPublicationManifestSHA256,
		PublicationID:                     publication.Active.ID,
		PublicationManifestSHA256:         publication.Active.ManifestSHA256,
		TrustedRootSHA256:                 hashBytes(trustedRoot),
		SigningConfigSHA256:               hashBytes(signingConfig),
		CompletedAtUTC:                    time.Now().UTC(),
	}, nil
}

func validateTUFRootRotationCompletion(
	statePath string,
	completion tufRootRotationCompletion,
) error {
	rootVersion, publication, bootstrap, err := loadLiveTUFRootRotationState(statePath)
	if err != nil {
		return err
	}
	if bootstrap.TrustDomainID != completion.TrustDomainID ||
		bootstrap.Generation != completion.Generation ||
		bootstrap.GenerationID != completion.GenerationID ||
		bootstrap.GenerationManifestSHA256 != completion.GenerationManifestSHA256 ||
		rootVersion != completion.RootVersion ||
		publication.Active == nil ||
		publication.Active.ID != completion.PublicationID ||
		publication.Active.ManifestSHA256 != completion.PublicationManifestSHA256 ||
		publication.Previous == nil ||
		publication.Previous.ID != completion.PreviousPublicationID ||
		publication.Previous.ManifestSHA256 != completion.PreviousPublicationManifestSHA256 {
		return fmt.Errorf("root rotation completion does not match active state")
	}
	layout := newTUFLayout(statePath)
	activePath := committedPath(layout, publication.Active.ID)
	targetsVersion, err := readTUFMetadataVersion(
		filepath.Join(activePath, "repository", "targets.json"),
	)
	if err != nil {
		return err
	}
	trustedRoot, err := os.ReadFile(filepath.Join(activePath, "targets", "trusted_root.json"))
	if err != nil {
		return err
	}
	signingConfig, err := os.ReadFile(
		filepath.Join(activePath, "targets", "signing_config.v0.2.json"),
	)
	if err != nil {
		return err
	}
	if targetsVersion != completion.TargetsVersion ||
		hashBytes(trustedRoot) != completion.TrustedRootSHA256 ||
		hashBytes(signingConfig) != completion.SigningConfigSHA256 {
		return fmt.Errorf(
			"root rotation completion content hashes do not match active state",
		)
	}
	return nil
}

func readTUFMetadataVersion(path string) (int, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var metadata tufMetadataVersionEnvelope
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return 0, err
	}
	if metadata.Signed.Version < 1 {
		return 0, fmt.Errorf("metadata version must be positive")
	}
	return metadata.Signed.Version, nil
}

func removeTUFRootRotationRequest(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove root rotation request: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}
