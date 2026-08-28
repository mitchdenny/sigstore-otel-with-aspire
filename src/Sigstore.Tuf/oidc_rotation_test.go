package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOIDCRotationAppendsKeysAndPreservesImmutableHistory(t *testing.T) {
	statePath := newOIDCRotationTestState(t)
	generationOne := readTree(t, filepath.Join(
		statePath,
		"generations",
		initialGenerationID,
	))

	first := writeOIDCRotationTestRequest(t, statePath, "11111111111111111111111111111111")
	if action, err := dispatchOidcRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("first action = %q, want %q", action, repositoryActionPublished)
	}
	assertOIDCRotationGeneration(t, statePath, 2, 2, first.OperationID)
	if current := readTree(t, filepath.Join(
		statePath,
		"generations",
		initialGenerationID,
	)); !reflect.DeepEqual(current, generationOne) {
		t.Fatal("first rotation mutated generation 1")
	}

	second := writeOIDCRotationTestRequest(t, statePath, "22222222222222222222222222222222")
	if action, err := dispatchOidcRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("second action = %q, want %q", action, repositoryActionPublished)
	}
	assertOIDCRotationGeneration(t, statePath, 3, 3, second.OperationID)
	if current := readTree(t, filepath.Join(
		statePath,
		"generations",
		initialGenerationID,
	)); !reflect.DeepEqual(current, generationOne) {
		t.Fatal("second rotation mutated generation 1")
	}

	completion := readOIDCRotationTestCompletion(t, statePath)
	if len(completion.JwksKeyIDs) != 3 {
		t.Fatalf("JWKS key count = %d, want 3", len(completion.JwksKeyIDs))
	}
	if len(completion.RetainedKeyPaths) != 2 {
		t.Fatalf("retained key count = %d, want 2", len(completion.RetainedKeyPaths))
	}
	for _, retained := range completion.RetainedKeyPaths {
		if _, err := os.Stat(filepath.Join(
			statePath,
			"generations",
			completion.NewGenerationID,
			filepath.FromSlash(retained),
		)); err != nil {
			t.Fatalf("retained key %q: %v", retained, err)
		}
	}
}

func TestOIDCRotationCompletionReplayDoesNotAdvanceAgain(t *testing.T) {
	statePath := newOIDCRotationTestState(t)
	request := writeOIDCRotationTestRequest(
		t,
		statePath,
		"33333333333333333333333333333333",
	)
	if _, err := dispatchOidcRotation(statePath); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(
		filepath.Join(statePath, oidcRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if action, err := dispatchOidcRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("replay action = %q, want %q", action, repositoryActionPublished)
	}
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if active.Generation != 2 {
		t.Fatalf("replay advanced generation to %d", active.Generation)
	}
}

func TestOIDCRotationRecoversEveryCommittedBoundaryExactlyOnce(t *testing.T) {
	checkpoints := []publicationCheckpoint{
		"oidc-generation-committed",
		"oidc-tuf-committed",
		"oidc-generation-switched",
		"oidc-completion-written",
	}
	for index, checkpoint := range checkpoints {
		t.Run(string(checkpoint), func(t *testing.T) {
			statePath := newOIDCRotationTestState(t)
			operationID := fmt.Sprintf("%032x", index+10)
			request := writeOIDCRotationTestRequest(t, statePath, operationID)
			crashed := false
			func() {
				defer func() {
					if recover() != nil {
						crashed = true
					}
				}()
				_, err := dispatchOidcRotationWithHooks(
					statePath,
					publicationHooks{
						checkpoint: func(observed publicationCheckpoint) error {
							if observed == checkpoint {
								panic("simulated process interruption")
							}
							return nil
						},
					},
				)
				if err != nil {
					t.Fatalf("rotation failed before checkpoint %s: %v", checkpoint, err)
				}
			}()
			if !crashed {
				t.Fatalf("rotation did not reach checkpoint %s", checkpoint)
			}
			if _, err := dispatchOidcRotation(statePath); err != nil {
				t.Fatalf("recover checkpoint %s: %v", checkpoint, err)
			}
			assertOIDCRotationGeneration(t, statePath, 2, 2, request.OperationID)
			if _, err := os.Stat(filepath.Join(
				statePath,
				"generations",
				"generation-00000003",
			)); !os.IsNotExist(err) {
				t.Fatalf("checkpoint %s created a duplicate generation", checkpoint)
			}
		})
	}
}

func TestOIDCRotationRejectsRequestForAnotherTrustDomain(t *testing.T) {
	statePath := newOIDCRotationTestState(t)
	request := writeOIDCRotationTestRequest(
		t,
		statePath,
		"44444444444444444444444444444444",
	)
	request.TrustDomainID = "sha256-" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := writeJSON(
		filepath.Join(statePath, oidcRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := dispatchOidcRotation(statePath); err == nil {
		t.Fatal("rotation accepted a request for another trust domain")
	}
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if active.Generation != 1 {
		t.Fatalf("invalid request advanced generation to %d", active.Generation)
	}
}

func TestValidateAndReuseOIDCGenerationValidatesCompleteMaterial(t *testing.T) {
	t.Run("valid generation", func(t *testing.T) {
		statePath := newOIDCRotationTestState(t)
		current, request, nextPath, nextID := createReusableOIDCGeneration(
			t,
			statePath,
			"55555555555555555555555555555555",
		)

		reused, err := validateAndReuseOidcGeneration(
			statePath,
			current,
			nextPath,
			nextID,
			current.Generation+1,
			request,
		)
		if err != nil {
			t.Fatal(err)
		}
		if reused.GenerationID != nextID {
			t.Fatalf("reused generation ID = %q, want %q", reused.GenerationID, nextID)
		}
	})

	t.Run("empty material", func(t *testing.T) {
		statePath := newOIDCRotationTestState(t)
		current, request, nextPath, nextID := createReusableOIDCGeneration(
			t,
			statePath,
			"66666666666666666666666666666666",
		)
		manifest, err := readOIDCGenerationManifest(statePath, nextID)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Files = map[string]string{}
		for _, directory := range []string{"private", "public"} {
			path := filepath.Join(nextPath, directory)
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := writeJSON(
			filepath.Join(nextPath, "manifest.json"),
			manifest,
			0o644,
		); err != nil {
			t.Fatal(err)
		}

		_, err = validateAndReuseOidcGeneration(
			statePath,
			current,
			nextPath,
			nextID,
			current.Generation+1,
			request,
		)
		if err == nil {
			t.Fatal("reused generation with empty material was accepted")
		}
		if !strings.Contains(err.Error(), "jwks.json") {
			t.Fatalf("strict OIDC validation did not reject empty material: %v", err)
		}
	})
}

func createReusableOIDCGeneration(
	t *testing.T,
	statePath string,
	operationID string,
) (bootstrapManifest, oidcRotationRequest, string, string) {
	t.Helper()
	current, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	request := writeOIDCRotationTestRequest(t, statePath, operationID)
	next, err := rotateOidcGeneration(statePath, current, request)
	if err != nil {
		t.Fatal(err)
	}
	return current, request, filepath.Join(
		statePath,
		"generations",
		next.GenerationID,
	), next.GenerationID
}

func newOIDCRotationTestState(t *testing.T) string {
	t.Helper()
	statePath := newTestState(t)
	if _, err := ensureTUFRepository(statePath); err != nil {
		t.Fatal(err)
	}
	return statePath
}

func writeOIDCRotationTestRequest(
	t *testing.T,
	statePath string,
	operationID string,
) oidcRotationRequest {
	t.Helper()
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	request := oidcRotationRequest{
		SchemaVersion:        oidcRotationSchema,
		OperationID:          operationID,
		TrustDomainID:        active.TrustDomainID,
		StartingGeneration:   active.Generation,
		StartingGenerationID: active.GenerationID,
		StartingOIDCKeyID:    active.OIDCKeyID,
	}
	if err := writeJSON(
		filepath.Join(statePath, oidcRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return request
}

func readOIDCRotationTestCompletion(
	t *testing.T,
	statePath string,
) oidcRotationCompletion {
	t.Helper()
	data := readTestFile(t, filepath.Join(
		statePath,
		oidcRotationCompletionFile,
	))
	var completion oidcRotationCompletion
	if err := json.Unmarshal(data, &completion); err != nil {
		t.Fatal(err)
	}
	return completion
}

func assertOIDCRotationGeneration(
	t *testing.T,
	statePath string,
	generation int,
	keyCount int,
	operationID string,
) {
	t.Helper()
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if active.Generation != generation {
		t.Fatalf("active generation = %d, want %d", active.Generation, generation)
	}
	manifest, err := readOIDCGenerationManifest(statePath, active.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.OIDCRotationOperationID != operationID {
		t.Fatalf(
			"generation operation = %q, want %q",
			manifest.OIDCRotationOperationID,
			operationID,
		)
	}
	if len(manifest.OIDCRetainedPrivateKeyPaths) != keyCount-1 {
		t.Fatalf(
			"retained key count = %d, want %d",
			len(manifest.OIDCRetainedPrivateKeyPaths),
			keyCount-1,
		)
	}
	if err := validateOIDCGenerationMaterial(
		filepath.Join(statePath, "generations", active.GenerationID),
		manifest,
	); err != nil {
		t.Fatal(err)
	}
	var keys jwks
	data := readTestFile(t, filepath.Join(
		statePath,
		"generations",
		active.GenerationID,
		"public",
		"oidc",
		"jwks.json",
	))
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != keyCount {
		t.Fatalf("JWKS key count = %d, want %d", len(keys.Keys), keyCount)
	}
}

func readTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
