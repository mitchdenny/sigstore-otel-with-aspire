package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	trustrootv1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	tufLayoutSchemaVersion = 1

	publicationStatusCommitted = "committed"
	publicationStatusPreparing = "preparing"
)

type repositoryAction string

const (
	repositoryActionCreated   repositoryAction = "Created"
	repositoryActionRecovered repositoryAction = "Recovered"
	repositoryActionRefreshed repositoryAction = "Refreshed"
)

type publicationReference struct {
	ID             string `json:"id"`
	ManifestSHA256 string `json:"manifestSha256"`
}

type publicationState struct {
	SchemaVersion       int                   `json:"schemaVersion"`
	Status              string                `json:"status"`
	UpdatedAtUTC        time.Time             `json:"updatedAtUtc"`
	BootstrapRootSHA256 string                `json:"bootstrapRootSha256"`
	Active              *publicationReference `json:"active,omitempty"`
	Candidate           *publicationReference `json:"candidate,omitempty"`
	Previous            *publicationReference `json:"previous,omitempty"`
}

type publicationCheckpoint string

const (
	checkpointCandidatePrepared  publicationCheckpoint = "candidate-prepared"
	checkpointBootstrapPrepared  publicationCheckpoint = "bootstrap-prepared"
	checkpointBootstrapWritten   publicationCheckpoint = "bootstrap-written"
	checkpointHistoryParked      publicationCheckpoint = "history-parked"
	checkpointCandidateCommitted publicationCheckpoint = "candidate-committed"
	checkpointActiveLinkPrepared publicationCheckpoint = "active-link-prepared"
	checkpointActiveSwitched     publicationCheckpoint = "active-switched"
	checkpointPreviousArchived   publicationCheckpoint = "previous-archived"
	checkpointHistoryRetired     publicationCheckpoint = "history-retired"
)

type publicationHooks struct {
	checkpoint func(publicationCheckpoint) error
}

// The root directory is a stable bind-mount boundary. A complete candidate is
// staged, moved under committed, then selected by atomically replacing active.
// In preparing state, active selecting the old publication means roll back;
// active selecting the candidate means finish forward. History retains only
// the publication that immediately preceded active.
type tufLayout struct {
	root            string
	bootstrap       string
	bootstrapRoot   string
	active          string
	activeNext      string
	committed       string
	history         string
	previous        string
	staging         string
	candidate       string
	retiredPrevious string
	publication     string
	state           string
}

func newTUFLayout(statePath string) tufLayout {
	root := filepath.Join(statePath, "tuf")
	return tufLayout{
		root:            root,
		bootstrap:       filepath.Join(root, "bootstrap"),
		bootstrapRoot:   filepath.Join(root, "bootstrap", "root.json"),
		active:          filepath.Join(root, "active"),
		activeNext:      filepath.Join(root, "active.next"),
		committed:       filepath.Join(root, "committed"),
		history:         filepath.Join(root, "history"),
		previous:        filepath.Join(root, "history", "previous"),
		staging:         filepath.Join(root, "staging"),
		candidate:       filepath.Join(root, "staging", "candidate"),
		retiredPrevious: filepath.Join(root, "staging", "retired-previous"),
		publication:     filepath.Join(root, "publication"),
		state:           filepath.Join(root, "publication", "state.json"),
	}
}

func ensureTUFRepository(statePath string) (repositoryAction, error) {
	return ensureTUFRepositoryWithHooks(statePath, publicationHooks{})
}

func ensureTUFRepositoryWithHooks(
	statePath string,
	hooks publicationHooks,
) (repositoryAction, error) {
	stateLock, err := acquireStateLock(statePath, 30*time.Second, "tuf-publication")
	if err != nil {
		return "", err
	}
	defer stateLock.release()

	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return "", err
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
	if errors.Is(err, os.ErrNotExist) {
		if err := prepareUnpublishedLayout(layout); err != nil {
			return "", err
		}
		if err := createInitialPublication(
			layout,
			statePath,
			bootstrap,
			sourceFingerprint,
			hooks,
		); err != nil {
			return "", err
		}
		return repositoryActionCreated, nil
	}
	if err != nil {
		return "", err
	}

	if state.Status == publicationStatusPreparing {
		initial := state.Active == nil
		if err := recoverPreparingPublication(layout, state, sourceFingerprint, hooks); err != nil {
			return "", err
		}
		if initial {
			return repositoryActionCreated, nil
		}
		return repositoryActionRecovered, nil
	}
	if state.Status != publicationStatusCommitted {
		return "", fmt.Errorf("TUF publication status %q is unsupported", state.Status)
	}
	if err := cleanupPublicationTemps(layout); err != nil {
		return "", err
	}
	if err := cleanupUnjournaledCandidate(layout); err != nil {
		return "", err
	}
	if err := validateCommittedPublication(layout, state, sourceFingerprint); err != nil {
		return "", err
	}
	if err := refreshPublication(layout, state, sourceFingerprint, hooks); err != nil {
		return "", err
	}
	return repositoryActionRefreshed, nil
}

func createInitialPublication(
	layout tufLayout,
	statePath string,
	bootstrap bootstrapManifest,
	sourceFingerprint string,
	hooks publicationHooks,
) error {
	targets, err := buildSigstoreTargets(statePath, bootstrap)
	if err != nil {
		return err
	}
	if err := os.Mkdir(layout.candidate, 0o755); err != nil {
		return fmt.Errorf("create initial TUF staging directory: %w", err)
	}
	if err := writePublicTargets(layout.candidate, targets); err != nil {
		return err
	}
	if err := createTUFRepository(layout.candidate, targets); err != nil {
		return err
	}

	now := time.Now().UTC()
	manifest := tufManifest{
		SchemaVersion:     tufSchemaVersion,
		CreatedAtUTC:      now,
		UpdatedAtUTC:      now,
		SourceFingerprint: sourceFingerprint,
	}
	if err := writeRepositoryManifest(layout.candidate, manifest); err != nil {
		return err
	}
	candidate, err := repositoryReference(layout.candidate, sourceFingerprint)
	if err != nil {
		return err
	}
	rootPath := filepath.Join(layout.candidate, "repository", "root.json")
	bootstrapHash, err := validateInitialRoot(rootPath)
	if err != nil {
		return err
	}
	state := publicationState{
		SchemaVersion:       tufLayoutSchemaVersion,
		Status:              publicationStatusPreparing,
		UpdatedAtUTC:        time.Now().UTC(),
		BootstrapRootSHA256: bootstrapHash,
		Candidate:           &candidate,
	}
	if err := writePublicationState(layout, state); err != nil {
		return err
	}
	if err := runCheckpoint(hooks, checkpointCandidatePrepared); err != nil {
		return err
	}
	if err := ensureBootstrapRoot(layout, rootPath, bootstrapHash, hooks); err != nil {
		return err
	}
	if err := runCheckpoint(hooks, checkpointBootstrapWritten); err != nil {
		return err
	}

	candidatePath := committedPath(layout, candidate.ID)
	if err := os.Rename(layout.candidate, candidatePath); err != nil {
		return fmt.Errorf("commit initial TUF candidate: %w", err)
	}
	if err := runCheckpoint(hooks, checkpointCandidateCommitted); err != nil {
		return err
	}
	if err := switchActivePublication(layout, candidate.ID, hooks); err != nil {
		return err
	}
	if err := runCheckpoint(hooks, checkpointActiveSwitched); err != nil {
		return err
	}
	return finalizeInitialPublication(layout, state, sourceFingerprint)
}

func refreshPublication(
	layout tufLayout,
	state publicationState,
	sourceFingerprint string,
	hooks publicationHooks,
) error {
	if state.Active == nil {
		return errors.New("committed TUF publication has no active repository")
	}
	activePath := committedPath(layout, state.Active.ID)
	manifest, _, err := validateExistingRepository(activePath, sourceFingerprint)
	if err != nil {
		return err
	}
	if err := os.Mkdir(layout.candidate, 0o755); err != nil {
		return fmt.Errorf("create TUF refresh staging directory: %w", err)
	}
	if err := copyDirectory(activePath, layout.candidate); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return err
	}
	if err := refreshTUFRepository(layout.candidate); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return err
	}

	manifest.UpdatedAtUTC = time.Now().UTC()
	if err := writeRepositoryManifest(layout.candidate, manifest); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return err
	}
	candidate, err := repositoryReference(layout.candidate, sourceFingerprint)
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return err
	}
	if candidate.ID == state.Active.ID {
		_ = os.RemoveAll(layout.candidate)
		return errors.New("refreshed TUF publication is identical to the active publication")
	}
	if pathExists(committedPath(layout, candidate.ID)) {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("TUF candidate %s already exists in committed state", candidate.ID)
	}

	preparing := state
	preparing.Status = publicationStatusPreparing
	preparing.UpdatedAtUTC = time.Now().UTC()
	preparing.Candidate = &candidate
	if err := writePublicationState(layout, preparing); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return err
	}
	if err := runCheckpoint(hooks, checkpointCandidatePrepared); err != nil {
		return rollbackPreparingPublication(layout, preparing, sourceFingerprint, err)
	}

	if state.Previous != nil {
		if err := os.Rename(layout.previous, layout.retiredPrevious); err != nil {
			return rollbackPreparingPublication(
				layout,
				preparing,
				sourceFingerprint,
				fmt.Errorf("park previous TUF publication: %w", err),
			)
		}
	}
	if err := runCheckpoint(hooks, checkpointHistoryParked); err != nil {
		return rollbackPreparingPublication(layout, preparing, sourceFingerprint, err)
	}

	candidatePath := committedPath(layout, candidate.ID)
	if err := os.Rename(layout.candidate, candidatePath); err != nil {
		return rollbackPreparingPublication(
			layout,
			preparing,
			sourceFingerprint,
			fmt.Errorf("commit staged TUF publication: %w", err),
		)
	}
	if err := runCheckpoint(hooks, checkpointCandidateCommitted); err != nil {
		return rollbackPreparingPublication(layout, preparing, sourceFingerprint, err)
	}
	if err := switchActivePublication(layout, candidate.ID, hooks); err != nil {
		return rollbackPreparingPublication(layout, preparing, sourceFingerprint, err)
	}

	// The active symlink replacement is the commit point. From here recovery
	// completes forward because nginx can only see the fully validated candidate.
	if err := runCheckpoint(hooks, checkpointActiveSwitched); err != nil {
		return err
	}
	return finalizeRefreshedPublication(layout, preparing, sourceFingerprint, hooks)
}

func recoverPreparingPublication(
	layout tufLayout,
	state publicationState,
	sourceFingerprint string,
	hooks publicationHooks,
) error {
	if err := validatePreparingState(state); err != nil {
		return err
	}
	activeID, activeExists, err := readActivePublication(layout.active)
	if err != nil {
		return err
	}
	if state.Active == nil {
		return recoverInitialPublication(
			layout,
			state,
			sourceFingerprint,
			activeID,
			activeExists,
			hooks,
		)
	}
	if !activeExists {
		return errors.New("active TUF publication disappeared during refresh recovery")
	}
	switch activeID {
	case state.Active.ID:
		return rollbackPreparingPublication(layout, state, sourceFingerprint, nil)
	case state.Candidate.ID:
		return finalizeRefreshedPublication(layout, state, sourceFingerprint, hooks)
	default:
		return fmt.Errorf(
			"active TUF publication %q matches neither the prior %q nor candidate %q",
			activeID,
			state.Active.ID,
			state.Candidate.ID,
		)
	}
}

func recoverInitialPublication(
	layout tufLayout,
	state publicationState,
	sourceFingerprint string,
	activeID string,
	activeExists bool,
	hooks publicationHooks,
) error {
	candidatePath, err := locateCandidate(layout, *state.Candidate)
	if err != nil {
		return err
	}
	if err := validateReference(candidatePath, *state.Candidate, sourceFingerprint); err != nil {
		return err
	}
	rootPath := filepath.Join(candidatePath, "repository", "root.json")
	if err := ensureBootstrapRoot(
		layout,
		rootPath,
		state.BootstrapRootSHA256,
		publicationHooks{},
	); err != nil {
		return err
	}

	committedCandidate := committedPath(layout, state.Candidate.ID)
	if candidatePath == layout.candidate {
		if err := os.Rename(layout.candidate, committedCandidate); err != nil {
			return fmt.Errorf("recover initial committed TUF publication: %w", err)
		}
	}
	if activeExists {
		if activeID != state.Candidate.ID {
			return fmt.Errorf(
				"initial TUF active publication %q does not match candidate %q",
				activeID,
				state.Candidate.ID,
			)
		}
	} else if err := switchActivePublication(
		layout,
		state.Candidate.ID,
		publicationHooks{},
	); err != nil {
		return err
	}
	if err := runCheckpoint(hooks, checkpointActiveSwitched); err != nil {
		return err
	}
	return finalizeInitialPublication(layout, state, sourceFingerprint)
}

func finalizeInitialPublication(
	layout tufLayout,
	preparing publicationState,
	sourceFingerprint string,
) error {
	if preparing.Candidate == nil {
		return errors.New("initial TUF publication has no candidate")
	}
	committed := publicationState{
		SchemaVersion:       tufLayoutSchemaVersion,
		Status:              publicationStatusCommitted,
		UpdatedAtUTC:        time.Now().UTC(),
		BootstrapRootSHA256: preparing.BootstrapRootSHA256,
		Active:              preparing.Candidate,
	}
	if err := validateCommittedContents(layout, committed, sourceFingerprint); err != nil {
		return err
	}
	return writePublicationState(layout, committed)
}

func finalizeRefreshedPublication(
	layout tufLayout,
	preparing publicationState,
	sourceFingerprint string,
	hooks publicationHooks,
) error {
	if preparing.Active == nil || preparing.Candidate == nil {
		return errors.New("refreshed TUF publication is missing active or candidate state")
	}
	activeID, activeExists, err := readActivePublication(layout.active)
	if err != nil {
		return err
	}
	if !activeExists || activeID != preparing.Candidate.ID {
		return fmt.Errorf(
			"cannot finalize TUF publication because active is %q, expected %q",
			activeID,
			preparing.Candidate.ID,
		)
	}
	if _, _, err := validateExistingRepository(
		committedPath(layout, preparing.Candidate.ID),
		sourceFingerprint,
	); err != nil {
		return err
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
	previous, err := repositoryReference(layout.previous, sourceFingerprint)
	if err != nil {
		return err
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
		retired, err := repositoryReference(layout.retiredPrevious, sourceFingerprint)
		if err != nil {
			return err
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
	if err := validateCommittedContents(layout, committed, sourceFingerprint); err != nil {
		return err
	}
	return writePublicationState(layout, committed)
}

func rollbackPreparingPublication(
	layout tufLayout,
	preparing publicationState,
	sourceFingerprint string,
	cause error,
) error {
	if preparing.Active == nil || preparing.Candidate == nil {
		if cause != nil {
			return cause
		}
		return errors.New("cannot roll back an incomplete initial TUF publication")
	}
	activeID, activeExists, err := readActivePublication(layout.active)
	if err != nil {
		return combinePublicationErrors(cause, err)
	}
	if !activeExists || activeID != preparing.Active.ID {
		return combinePublicationErrors(
			cause,
			fmt.Errorf(
				"cannot roll back TUF publication because active is %q, expected %q",
				activeID,
				preparing.Active.ID,
			),
		)
	}
	if err := removeExpectedActiveNext(layout, preparing.Candidate.ID); err != nil {
		return combinePublicationErrors(cause, err)
	}

	stagedCandidate := pathExists(layout.candidate)
	committedCandidatePath := committedPath(layout, preparing.Candidate.ID)
	committedCandidate := pathExists(committedCandidatePath)
	if stagedCandidate && committedCandidate {
		return combinePublicationErrors(
			cause,
			errors.New("TUF candidate exists in both staging and committed state"),
		)
	}
	if stagedCandidate {
		if _, err := repositoryReference(layout.candidate, sourceFingerprint); err != nil {
			return combinePublicationErrors(cause, err)
		}
		if err := os.RemoveAll(layout.candidate); err != nil {
			return combinePublicationErrors(cause, fmt.Errorf("remove staged TUF candidate: %w", err))
		}
	}
	if committedCandidate {
		if _, err := repositoryReference(committedCandidatePath, sourceFingerprint); err != nil {
			return combinePublicationErrors(cause, err)
		}
		if err := os.RemoveAll(committedCandidatePath); err != nil {
			return combinePublicationErrors(cause, fmt.Errorf("remove committed TUF candidate: %w", err))
		}
	}

	historyExists := pathExists(layout.previous)
	retiredExists := pathExists(layout.retiredPrevious)
	if historyExists && retiredExists {
		return combinePublicationErrors(
			cause,
			errors.New("TUF history exists in both previous and retired state"),
		)
	}
	if preparing.Previous == nil {
		if historyExists || retiredExists {
			return combinePublicationErrors(
				cause,
				errors.New("unexpected TUF history exists while rolling back first refresh"),
			)
		}
	} else {
		switch {
		case retiredExists:
			retired, err := repositoryReference(layout.retiredPrevious, sourceFingerprint)
			if err != nil {
				return combinePublicationErrors(cause, err)
			}
			if retired != *preparing.Previous {
				return combinePublicationErrors(
					cause,
					errors.New("retired TUF history does not match the publication journal"),
				)
			}
			if err := os.Rename(layout.retiredPrevious, layout.previous); err != nil {
				return combinePublicationErrors(
					cause,
					fmt.Errorf("restore previous TUF history: %w", err),
				)
			}
		case historyExists:
			previous, err := repositoryReference(layout.previous, sourceFingerprint)
			if err != nil {
				return combinePublicationErrors(cause, err)
			}
			if previous != *preparing.Previous {
				return combinePublicationErrors(
					cause,
					errors.New("previous TUF history does not match the publication journal"),
				)
			}
		default:
			return combinePublicationErrors(
				cause,
				errors.New("previous TUF history is missing during rollback"),
			)
		}
	}

	committed := publicationState{
		SchemaVersion:       tufLayoutSchemaVersion,
		Status:              publicationStatusCommitted,
		UpdatedAtUTC:        time.Now().UTC(),
		BootstrapRootSHA256: preparing.BootstrapRootSHA256,
		Active:              preparing.Active,
		Previous:            preparing.Previous,
	}
	if err := validateCommittedContents(layout, committed, sourceFingerprint); err != nil {
		return combinePublicationErrors(cause, err)
	}
	if err := writePublicationState(layout, committed); err != nil {
		return combinePublicationErrors(cause, err)
	}
	return cause
}

func validateCommittedPublication(
	layout tufLayout,
	state publicationState,
	sourceFingerprint string,
) error {
	if err := validateCommittedState(state); err != nil {
		return err
	}
	return validateCommittedContents(layout, state, sourceFingerprint)
}

func validateCommittedContents(
	layout tufLayout,
	state publicationState,
	sourceFingerprint string,
) error {
	if state.Active == nil {
		return errors.New("committed TUF publication has no active repository")
	}
	if err := validateBootstrapRoot(
		layout.bootstrapRoot,
		state.BootstrapRootSHA256,
	); err != nil {
		return err
	}
	activeID, exists, err := readActivePublication(layout.active)
	if err != nil {
		return err
	}
	if !exists || activeID != state.Active.ID {
		return fmt.Errorf(
			"active TUF publication is %q, expected %q",
			activeID,
			state.Active.ID,
		)
	}
	if err := validateReference(
		committedPath(layout, state.Active.ID),
		*state.Active,
		sourceFingerprint,
	); err != nil {
		return err
	}

	if state.Previous == nil {
		if pathExists(layout.previous) {
			return errors.New("TUF history exists without publication metadata")
		}
	} else if err := validateReference(
		layout.previous,
		*state.Previous,
		sourceFingerprint,
	); err != nil {
		return err
	}
	if err := ensureOnlyEntries(
		layout.committed,
		map[string]bool{state.Active.ID: true},
	); err != nil {
		return fmt.Errorf("validate committed TUF directory: %w", err)
	}
	if err := ensureOnlyEntries(layout.staging, nil); err != nil {
		return fmt.Errorf("validate TUF staging directory: %w", err)
	}
	if pathExists(layout.activeNext) {
		return errors.New("unexpected TUF active.next link exists in committed state")
	}
	if err := ensureOnlyEntries(
		layout.bootstrap,
		map[string]bool{"root.json": true},
	); err != nil {
		return fmt.Errorf("validate immutable TUF bootstrap directory: %w", err)
	}
	historyEntries := map[string]bool{}
	if state.Previous != nil {
		historyEntries["previous"] = true
	}
	if err := ensureOnlyEntries(layout.history, historyEntries); err != nil {
		return fmt.Errorf("validate TUF history directory: %w", err)
	}
	if err := ensureOnlyEntries(
		layout.publication,
		map[string]bool{"state.json": true},
	); err != nil {
		return fmt.Errorf("validate TUF publication directory: %w", err)
	}
	if err := ensureOnlyEntries(
		layout.root,
		map[string]bool{
			"active":      true,
			"bootstrap":   true,
			"committed":   true,
			"history":     true,
			"publication": true,
			"staging":     true,
		},
	); err != nil {
		return fmt.Errorf("validate stable TUF parent: %w", err)
	}
	return nil
}

func validateExistingRepository(
	repositoryPath string,
	sourceFingerprint string,
) (tufManifest, string, error) {
	manifestPath := filepath.Join(repositoryPath, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return tufManifest{}, "", fmt.Errorf("read TUF manifest: %w", err)
	}
	var manifest tufManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return tufManifest{}, "", fmt.Errorf("parse TUF manifest: %w", err)
	}
	if manifest.SchemaVersion != tufSchemaVersion {
		return tufManifest{}, "", fmt.Errorf(
			"TUF schema %d is unsupported; expected %d",
			manifest.SchemaVersion,
			tufSchemaVersion,
		)
	}
	if manifest.SourceFingerprint != sourceFingerprint {
		return tufManifest{}, "", errors.New(
			"TUF source material changed; delete the entire Sigstore state directory to create a new trust domain",
		)
	}

	actualFiles, err := collectFileHashes(repositoryPath)
	if err != nil {
		return tufManifest{}, "", err
	}
	if len(actualFiles) != len(manifest.Files) {
		return tufManifest{}, "", errors.New("TUF repository file set does not match the manifest")
	}
	for name, actual := range actualFiles {
		expected, ok := manifest.Files[name]
		if !ok || actual != expected {
			return tufManifest{}, "", fmt.Errorf("TUF file %s does not match the manifest", name)
		}
	}

	trustedRootJSON, err := os.ReadFile(filepath.Join(repositoryPath, "targets", "trusted_root.json"))
	if err != nil {
		return tufManifest{}, "", err
	}
	if err := protojson.Unmarshal(trustedRootJSON, &trustrootv1.TrustedRoot{}); err != nil {
		return tufManifest{}, "", fmt.Errorf("parse existing TrustedRoot: %w", err)
	}
	signingConfigJSON, err := os.ReadFile(
		filepath.Join(repositoryPath, "targets", "signing_config.v0.2.json"),
	)
	if err != nil {
		return tufManifest{}, "", err
	}
	if err := protojson.Unmarshal(signingConfigJSON, &trustrootv1.SigningConfig{}); err != nil {
		return tufManifest{}, "", fmt.Errorf("parse existing SigningConfig: %w", err)
	}
	manifestHash, err := hashFile(manifestPath)
	if err != nil {
		return tufManifest{}, "", fmt.Errorf("hash TUF manifest: %w", err)
	}
	return manifest, manifestHash, nil
}

func writeRepositoryManifest(repositoryPath string, manifest tufManifest) error {
	files, err := collectFileHashes(repositoryPath)
	if err != nil {
		return err
	}
	manifest.Files = files
	return writeJSON(filepath.Join(repositoryPath, "manifest.json"), manifest, 0o644)
}

func repositoryReference(
	repositoryPath string,
	sourceFingerprint string,
) (publicationReference, error) {
	_, manifestHash, err := validateExistingRepository(repositoryPath, sourceFingerprint)
	if err != nil {
		return publicationReference{}, err
	}
	return publicationReference{
		ID:             publicationID(manifestHash),
		ManifestSHA256: manifestHash,
	}, nil
}

func validateReference(
	path string,
	expected publicationReference,
	sourceFingerprint string,
) error {
	if err := validatePublicationReference(expected); err != nil {
		return err
	}
	actual, err := repositoryReference(path, sourceFingerprint)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf(
			"TUF publication at %s has reference %+v, expected %+v",
			path,
			actual,
			expected,
		)
	}
	return nil
}

func collectFileHashes(basePath string) (map[string]string, error) {
	files := map[string]string{}
	for _, directory := range []string{"keys", "repository", "targets"} {
		root := filepath.Join(basePath, directory)
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				return fmt.Errorf("unsupported TUF state file type at %s", path)
			}
			hash, err := hashFile(path)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(basePath, path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(relative)] = hash
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("hash TUF %s files: %w", directory, err)
		}
	}
	return files, nil
}

func copyDirectory(sourcePath, destinationPath string) error {
	return filepath.WalkDir(sourcePath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relativePath, err := filepath.Rel(sourcePath, path)
		if err != nil {
			return err
		}
		if relativePath == "." {
			return nil
		}
		destination := filepath.Join(destinationPath, relativePath)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.MkdirAll(destination, info.Mode().Perm())
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported TUF state file type at %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(destination, data, info.Mode().Perm()); err != nil {
			return err
		}
		return nil
	})
}

func ensureTUFLayout(layout tufLayout) error {
	for _, directory := range []string{
		layout.root,
		layout.bootstrap,
		layout.committed,
		layout.history,
		layout.staging,
		layout.publication,
	} {
		if err := ensureRealDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func ensureRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o755); err != nil {
			return fmt.Errorf("create TUF layout directory %s: %w", path, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect TUF layout directory %s: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("TUF layout path %s must be a real directory", path)
	}
	return nil
}

func prepareUnpublishedLayout(layout tufLayout) error {
	if err := cleanupPublicationTemps(layout); err != nil {
		return err
	}
	if pathExists(layout.candidate) {
		if err := os.RemoveAll(layout.candidate); err != nil {
			return fmt.Errorf("remove abandoned unjournaled TUF candidate: %w", err)
		}
	}
	if pathExists(layout.retiredPrevious) ||
		pathExists(layout.active) ||
		pathExists(layout.activeNext) ||
		pathExists(layout.bootstrapRoot) {
		return errors.New(
			"TUF state has durable publication data but no publication journal; reset the entire AppHost state",
		)
	}
	for _, directory := range []string{layout.committed, layout.history, layout.staging} {
		if err := ensureOnlyEntries(directory, nil); err != nil {
			return fmt.Errorf(
				"TUF state has unjournaled data in %s; reset the entire AppHost state: %w",
				directory,
				err,
			)
		}
	}
	return nil
}

func loadPublicationState(layout tufLayout) (publicationState, error) {
	data, err := os.ReadFile(layout.state)
	if err != nil {
		return publicationState{}, err
	}
	var state publicationState
	if err := json.Unmarshal(data, &state); err != nil {
		return publicationState{}, fmt.Errorf("parse TUF publication state: %w", err)
	}
	if state.SchemaVersion != tufLayoutSchemaVersion {
		return publicationState{}, fmt.Errorf(
			"TUF layout schema %d is unsupported; expected %d",
			state.SchemaVersion,
			tufLayoutSchemaVersion,
		)
	}
	return state, nil
}

func writePublicationState(layout tufLayout, state publicationState) error {
	state.UpdatedAtUTC = time.Now().UTC()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal TUF publication state: %w", err)
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(layout.publication, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary TUF publication state: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o644); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set temporary TUF publication state mode: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary TUF publication state: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync temporary TUF publication state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary TUF publication state: %w", err)
	}
	if err := os.Rename(tempPath, layout.state); err != nil {
		return fmt.Errorf("publish TUF publication state: %w", err)
	}
	return nil
}

func cleanupPublicationTemps(layout tufLayout) error {
	entries, err := os.ReadDir(layout.publication)
	if err != nil {
		return fmt.Errorf("read TUF publication metadata: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".state-") ||
			!strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		if err := os.Remove(filepath.Join(layout.publication, entry.Name())); err != nil {
			return fmt.Errorf("remove abandoned TUF publication temporary file: %w", err)
		}
	}
	return nil
}

func cleanupUnjournaledCandidate(layout tufLayout) error {
	if !pathExists(layout.candidate) {
		return nil
	}
	if err := os.RemoveAll(layout.candidate); err != nil {
		return fmt.Errorf("remove abandoned unjournaled TUF candidate: %w", err)
	}
	return nil
}

func validateCommittedState(state publicationState) error {
	if state.SchemaVersion != tufLayoutSchemaVersion {
		return fmt.Errorf("unexpected TUF layout schema %d", state.SchemaVersion)
	}
	if state.Status != publicationStatusCommitted {
		return fmt.Errorf("unexpected committed TUF status %q", state.Status)
	}
	if state.Candidate != nil {
		return errors.New("committed TUF publication still contains candidate metadata")
	}
	if state.Active == nil {
		return errors.New("committed TUF publication has no active reference")
	}
	if err := validateSHA256(state.BootstrapRootSHA256); err != nil {
		return fmt.Errorf("validate immutable TUF bootstrap hash: %w", err)
	}
	if err := validatePublicationReference(*state.Active); err != nil {
		return fmt.Errorf("validate active TUF publication reference: %w", err)
	}
	if state.Previous != nil {
		if err := validatePublicationReference(*state.Previous); err != nil {
			return fmt.Errorf("validate previous TUF publication reference: %w", err)
		}
		if state.Previous.ID == state.Active.ID {
			return errors.New("active and previous TUF publications must differ")
		}
	}
	return nil
}

func validatePreparingState(state publicationState) error {
	if state.SchemaVersion != tufLayoutSchemaVersion {
		return fmt.Errorf("unexpected TUF layout schema %d", state.SchemaVersion)
	}
	if state.Status != publicationStatusPreparing {
		return fmt.Errorf("unexpected preparing TUF status %q", state.Status)
	}
	if state.Candidate == nil {
		return errors.New("preparing TUF publication has no candidate reference")
	}
	if err := validateSHA256(state.BootstrapRootSHA256); err != nil {
		return fmt.Errorf("validate immutable TUF bootstrap hash: %w", err)
	}
	if err := validatePublicationReference(*state.Candidate); err != nil {
		return fmt.Errorf("validate TUF candidate reference: %w", err)
	}
	if state.Active == nil {
		if state.Previous != nil {
			return errors.New("initial TUF publication cannot have previous history")
		}
		return nil
	}
	if err := validatePublicationReference(*state.Active); err != nil {
		return fmt.Errorf("validate prior active TUF publication reference: %w", err)
	}
	if state.Candidate.ID == state.Active.ID {
		return errors.New("TUF candidate and prior active publication must differ")
	}
	if state.Previous != nil {
		if err := validatePublicationReference(*state.Previous); err != nil {
			return fmt.Errorf("validate prior TUF history reference: %w", err)
		}
	}
	return nil
}

func validatePublicationReference(reference publicationReference) error {
	if err := validateSHA256(reference.ManifestSHA256); err != nil {
		return err
	}
	if reference.ID != publicationID(reference.ManifestSHA256) {
		return fmt.Errorf(
			"publication ID %q does not match manifest hash %q",
			reference.ID,
			reference.ManifestSHA256,
		)
	}
	return nil
}

func publicationID(manifestHash string) string {
	return "sha256-" + manifestHash
}

func validateSHA256(value string) error {
	if len(value) != 64 {
		return fmt.Errorf("SHA-256 value %q must contain 64 hexadecimal characters", value)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("SHA-256 value %q is invalid", value)
	}
	return nil
}

func validateInitialRoot(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read initial TUF root: %w", err)
	}
	var envelope struct {
		Signed struct {
			Type    string `json:"_type"`
			Version int    `json:"version"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return "", fmt.Errorf("parse initial TUF root: %w", err)
	}
	if envelope.Signed.Type != "root" || envelope.Signed.Version != 1 {
		return "", fmt.Errorf(
			"initial TUF bootstrap root must be root version 1, found type %q version %d",
			envelope.Signed.Type,
			envelope.Signed.Version,
		)
	}
	return hashFile(path)
}

func ensureBootstrapRoot(
	layout tufLayout,
	sourcePath string,
	expectedHash string,
	hooks publicationHooks,
) error {
	if pathExists(layout.bootstrapRoot) {
		return validateBootstrapRoot(layout.bootstrapRoot, expectedHash)
	}
	sourceHash, err := validateInitialRoot(sourcePath)
	if err != nil {
		return err
	}
	if sourceHash != expectedHash {
		return errors.New("initial TUF root does not match the publication journal")
	}

	pending := filepath.Join(layout.bootstrap, ".root.json.pending")
	if pathExists(pending) {
		pendingHash, err := hashFile(pending)
		if err != nil {
			return fmt.Errorf("hash pending immutable TUF bootstrap root: %w", err)
		}
		if pendingHash != expectedHash {
			return errors.New("pending immutable TUF bootstrap root is ambiguous")
		}
	} else {
		data, err := os.ReadFile(sourcePath)
		if err != nil {
			return fmt.Errorf("read initial TUF root for bootstrap copy: %w", err)
		}
		if err := os.WriteFile(pending, data, 0o444); err != nil {
			return fmt.Errorf("write pending immutable TUF bootstrap root: %w", err)
		}
		if err := runCheckpoint(hooks, checkpointBootstrapPrepared); err != nil {
			return err
		}
	}
	if pathExists(layout.bootstrapRoot) {
		return errors.New("immutable TUF bootstrap root appeared during initial publication")
	}
	if err := os.Rename(pending, layout.bootstrapRoot); err != nil {
		return fmt.Errorf("publish immutable TUF bootstrap root: %w", err)
	}
	return validateBootstrapRoot(layout.bootstrapRoot, expectedHash)
}

func validateBootstrapRoot(path, expectedHash string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect immutable TUF bootstrap root: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 {
		return errors.New("immutable TUF bootstrap root must be a read-only regular file")
	}
	actualHash, err := validateInitialRoot(path)
	if err != nil {
		return err
	}
	if actualHash != expectedHash {
		return errors.New("immutable TUF bootstrap root does not match the publication journal")
	}
	return nil
}

func switchActivePublication(
	layout tufLayout,
	publicationID string,
	hooks publicationHooks,
) error {
	if err := validatePublicationReference(publicationReference{
		ID:             publicationID,
		ManifestSHA256: strings.TrimPrefix(publicationID, "sha256-"),
	}); err != nil {
		return fmt.Errorf("validate active TUF publication ID: %w", err)
	}
	if pathExists(layout.activeNext) {
		nextID, _, err := readActivePublication(layout.activeNext)
		if err != nil {
			return err
		}
		if nextID != publicationID {
			return fmt.Errorf("TUF active.next points to %q, expected %q", nextID, publicationID)
		}
	} else if err := os.Symlink(
		filepath.Join("committed", publicationID),
		layout.activeNext,
	); err != nil {
		return fmt.Errorf("create next active TUF publication link: %w", err)
	}
	if err := runCheckpoint(hooks, checkpointActiveLinkPrepared); err != nil {
		return err
	}
	if err := os.Rename(layout.activeNext, layout.active); err != nil {
		return fmt.Errorf("switch active TUF publication: %w", err)
	}
	return nil
}

func readActivePublication(path string) (string, bool, error) {
	target, err := os.Readlink(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read active TUF publication link %s: %w", path, err)
	}
	if filepath.IsAbs(target) {
		return "", false, fmt.Errorf("active TUF publication link %s must be relative", path)
	}
	clean := filepath.Clean(target)
	directory, id := filepath.Split(clean)
	if filepath.Clean(directory) != "committed" || id == "" {
		return "", false, fmt.Errorf("active TUF publication link %s has unsafe target %q", path, target)
	}
	if err := validatePublicationReference(publicationReference{
		ID:             id,
		ManifestSHA256: strings.TrimPrefix(id, "sha256-"),
	}); err != nil {
		return "", false, fmt.Errorf("validate active TUF publication link %s: %w", path, err)
	}
	return id, true, nil
}

func removeExpectedActiveNext(layout tufLayout, candidateID string) error {
	nextID, exists, err := readActivePublication(layout.activeNext)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if nextID != candidateID {
		return fmt.Errorf("TUF active.next points to %q, expected %q", nextID, candidateID)
	}
	if err := os.Remove(layout.activeNext); err != nil {
		return fmt.Errorf("remove rolled-back TUF active.next link: %w", err)
	}
	return nil
}

func locateCandidate(
	layout tufLayout,
	candidate publicationReference,
) (string, error) {
	staged := pathExists(layout.candidate)
	committedPath := committedPath(layout, candidate.ID)
	committed := pathExists(committedPath)
	switch {
	case staged && committed:
		return "", errors.New("TUF candidate exists in both staging and committed state")
	case staged:
		return layout.candidate, nil
	case committed:
		return committedPath, nil
	default:
		return "", errors.New("journaled TUF candidate is missing")
	}
}

func committedPath(layout tufLayout, publicationID string) string {
	return filepath.Join(layout.committed, publicationID)
}

func ensureOnlyEntries(path string, allowed map[string]bool) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if allowed == nil || !allowed[entry.Name()] {
			return fmt.Errorf("unexpected entry %q", entry.Name())
		}
	}
	if len(entries) != len(allowed) {
		return fmt.Errorf("found %d entries, expected %d", len(entries), len(allowed))
	}
	return nil
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func runCheckpoint(hooks publicationHooks, checkpoint publicationCheckpoint) error {
	if hooks.checkpoint == nil {
		return nil
	}
	if err := hooks.checkpoint(checkpoint); err != nil {
		return fmt.Errorf("TUF publication checkpoint %s: %w", checkpoint, err)
	}
	return nil
}

func combinePublicationErrors(cause, recovery error) error {
	if cause == nil {
		return recovery
	}
	if recovery == nil {
		return cause
	}
	return fmt.Errorf("%w (rollback failed: %v)", cause, recovery)
}
