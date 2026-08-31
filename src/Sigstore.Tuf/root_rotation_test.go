package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTUFRootRotationRequestReplaysExactlyOnceAfterWorkerTermination(t *testing.T) {
	for _, checkpoint := range []publicationCheckpoint{
		checkpointActiveSwitched,
		publicationCheckpoint("root-completion-written"),
	} {
		t.Run(string(checkpoint), func(t *testing.T) {
			statePath := newTestState(t)
			if _, err := ensureTUFRepository(statePath); err != nil {
				t.Fatal(err)
			}
			requestPath := writeTUFRootRotationTestRequest(
				t,
				statePath,
				strings.Repeat("a", 32),
			)

			failOnce := true
			injected := errors.New("injected worker termination")
			_, err := dispatchTUFRootRotation(
				statePath,
				requestPath,
				publicationHooks{
					checkpoint: func(observed publicationCheckpoint) error {
						if failOnce && observed == checkpoint {
							failOnce = false
							return injected
						}
						return nil
					},
				},
			)
			if !errors.Is(err, injected) {
				t.Fatalf("first dispatch error = %v, want %v", err, injected)
			}
			if !pathExists(requestPath) {
				t.Fatal("interrupted root rotation removed its replay request")
			}

			if _, err := dispatchTUFRootRotation(
				statePath,
				requestPath,
				publicationHooks{},
			); err != nil {
				t.Fatal(err)
			}
			if pathExists(requestPath) {
				t.Fatal("successful replay did not remove its request")
			}
			rootVersion, _, _, err := loadLiveTUFRootRotationState(statePath)
			if err != nil {
				t.Fatal(err)
			}
			if rootVersion != 2 {
				t.Fatalf("root version after replay = %d, want 2", rootVersion)
			}
			if readMetadataVersion(t, newTUFLayout(statePath).bootstrapRoot) != 1 {
				t.Fatal("root rotation changed the immutable bootstrap root")
			}

			completionPath := filepath.Join(
				statePath,
				"tuf-root-rotations",
				strings.Repeat("a", 32),
				"completion.json",
			)
			completion, err := loadTUFRootRotationCompletion(completionPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateTUFRootRotationCompletion(statePath, completion); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTUFRootRotationRejectsTamperedRequestWithoutMutation(t *testing.T) {
	statePath := newTestState(t)
	if _, err := ensureTUFRepository(statePath); err != nil {
		t.Fatal(err)
	}
	requestPath := writeTUFRootRotationTestRequest(
		t,
		statePath,
		strings.Repeat("b", 32),
	)
	request, err := loadTUFRootRotationRequest(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	request.StartingGenerationManifestSHA256 = strings.Repeat("0", 64)
	writeTUFRootRotationRequest(t, requestPath, request)

	if _, err := dispatchTUFRootRotation(
		statePath,
		requestPath,
		publicationHooks{},
	); err == nil || !strings.Contains(err.Error(), "active trust generation") {
		t.Fatalf("dispatch error = %v, want generation-binding rejection", err)
	}
	rootVersion, _, _, err := loadLiveTUFRootRotationState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if rootVersion != 1 {
		t.Fatalf("root version after rejected request = %d, want 1", rootVersion)
	}
	if !pathExists(requestPath) {
		t.Fatal("rejected request was removed")
	}
}

func TestTUFRootRotationRejectsTamperedCompletionOnReplay(t *testing.T) {
	statePath := newTestState(t)
	if _, err := ensureTUFRepository(statePath); err != nil {
		t.Fatal(err)
	}
	operationID := strings.Repeat("c", 32)
	requestPath := writeTUFRootRotationTestRequest(t, statePath, operationID)
	failOnce := true
	_, err := dispatchTUFRootRotation(
		statePath,
		requestPath,
		publicationHooks{
			checkpoint: func(observed publicationCheckpoint) error {
				if failOnce && observed == publicationCheckpoint("root-completion-written") {
					failOnce = false
					return errors.New("injected worker termination")
				}
				return nil
			},
		},
	)
	if err == nil {
		t.Fatal("first dispatch unexpectedly succeeded")
	}

	completionPath := filepath.Join(
		statePath,
		"tuf-root-rotations",
		operationID,
		"completion.json",
	)
	completion, err := loadTUFRootRotationCompletion(completionPath)
	if err != nil {
		t.Fatal(err)
	}
	completion.TrustedRootSHA256 = strings.Repeat("0", 64)
	payload, err := json.MarshalIndent(completion, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(completionPath, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := dispatchTUFRootRotation(
		statePath,
		requestPath,
		publicationHooks{},
	); err == nil || !strings.Contains(err.Error(), "content hashes") {
		t.Fatalf("replay error = %v, want completion hash rejection", err)
	}
	rootVersion, _, _, err := loadLiveTUFRootRotationState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if rootVersion != 2 {
		t.Fatalf("root version after rejected replay = %d, want 2", rootVersion)
	}
	if !pathExists(requestPath) {
		t.Fatal("rejected replay removed its request")
	}
}

func writeTUFRootRotationTestRequest(
	t *testing.T,
	statePath string,
	operationID string,
) string {
	t.Helper()
	rootVersion, publication, bootstrap, err := loadLiveTUFRootRotationState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	request := tufRootRotationRequest{
		SchemaVersion:                     rootRotationSchemaVersion,
		OperationID:                       operationID,
		TrustDomainID:                     bootstrap.TrustDomainID,
		StartingGeneration:                bootstrap.Generation,
		StartingGenerationID:              bootstrap.GenerationID,
		StartingGenerationManifestSHA256:  bootstrap.GenerationManifestSHA256,
		StartingRootVersion:               rootVersion,
		StartingPublicationID:             publication.Active.ID,
		StartingPublicationManifestSHA256: publication.Active.ManifestSHA256,
	}
	requestPath := filepath.Join(statePath, "rotate-root.request")
	writeTUFRootRotationRequest(t, requestPath, request)
	return requestPath
}

func writeTUFRootRotationRequest(
	t *testing.T,
	path string,
	request tufRootRotationRequest,
) {
	t.Helper()
	payload, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
