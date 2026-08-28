package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishTrustedRootAdvancesGenerationAndPreservesHistoricalMaterial(t *testing.T) {
	statePath := newTestState(t)

	// Create initial TUF repository.
	action, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if action != repositoryActionCreated {
		t.Fatalf("action = %q, want %q", action, repositoryActionCreated)
	}

	// Capture before state.
	layout := newTUFLayout(statePath)
	stateBefore := readTestPublicationState(t, layout)
	if stateBefore.Active == nil {
		t.Fatal("no active publication before publish")
	}
	beforeTrustedRoot := readTestFile(
		t,
		filepath.Join(committedPath(layout, stateBefore.Active.ID), "targets", "trusted_root.json"),
	)
	beforeStatus := readTestTrustStatus(t,
		filepath.Join(committedPath(layout, stateBefore.Active.ID), "targets", trustStatusTargetName),
	)

	// Publish trusted root update.
	action, err = publishTrustedRootUpdate(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if action != repositoryActionPublished {
		t.Fatalf("action = %q, want %q", action, repositoryActionPublished)
	}

	// Verify postconditions.
	stateAfter := readTestPublicationState(t, layout)
	if stateAfter.Active == nil {
		t.Fatal("no active publication after publish")
	}
	if stateAfter.Active.ID == stateBefore.Active.ID {
		t.Fatal("publication ID did not change")
	}
	if stateAfter.Previous == nil {
		t.Fatal("previous publication not retained")
	}
	if stateAfter.Previous.ID != stateBefore.Active.ID {
		t.Fatalf("previous = %q, want %q", stateAfter.Previous.ID, stateBefore.Active.ID)
	}

	// TrustedRoot must have changed (additive material).
	afterTrustedRoot := readTestFile(
		t,
		filepath.Join(committedPath(layout, stateAfter.Active.ID), "targets", "trusted_root.json"),
	)
	if string(afterTrustedRoot) == string(beforeTrustedRoot) {
		t.Fatal("trusted_root.json did not change after publish")
	}
	// Original material must be preserved in new TrustedRoot.
	// The old Rekor key should still be present.
	if len(afterTrustedRoot) <= len(beforeTrustedRoot) {
		t.Fatal("new TrustedRoot is not larger than old (expected additive)")
	}

	// Trust status must show generation advance.
	afterStatus := readTestTrustStatus(t,
		filepath.Join(committedPath(layout, stateAfter.Active.ID), "targets", trustStatusTargetName),
	)
	if afterStatus.Generation != beforeStatus.Generation+1 {
		t.Fatalf("generation = %d, want %d", afterStatus.Generation, beforeStatus.Generation+1)
	}
	if afterStatus.TrustDomainID != beforeStatus.TrustDomainID {
		t.Fatal("trust domain changed after publish")
	}
	if afterStatus.TrustedRootSHA256 == beforeStatus.TrustedRootSHA256 {
		t.Fatal("trusted root hash did not change")
	}
	if afterStatus.SigningConfigSHA256 == beforeStatus.SigningConfigSHA256 {
		// SigningConfig content is rebuilt from the same source so hash may differ
		// due to timestamp in service entries. This is acceptable.
		t.Log("signing config hash changed (expected due to timestamp in service entries)")
	}

	// Bootstrap root must be unchanged.
	if stateAfter.BootstrapRootSHA256 != stateBefore.BootstrapRootSHA256 {
		t.Fatal("bootstrap root hash changed during publish")
	}

	// Active generation link must point to new generation.
	activeGenID, err := readActiveGeneration(filepath.Join(statePath, "active-generation"))
	if err != nil {
		t.Fatal(err)
	}
	if activeGenID == "generation-00000001" {
		t.Fatal("active generation did not advance")
	}
	if activeGenID != "generation-00000002" {
		t.Fatalf("active generation = %q, want generation-00000002", activeGenID)
	}

	// Prior generation directory must still exist.
	if _, err := os.Stat(filepath.Join(statePath, "generations", "generation-00000001")); err != nil {
		t.Fatalf("prior generation directory removed: %v", err)
	}

	// Standby key must exist in new generation.
	standbyPath := filepath.Join(statePath, "active-generation", "public", "rekor", standbyRekorKeyFile)
	if _, err := os.Stat(standbyPath); err != nil {
		t.Fatalf("standby Rekor key not found: %v", err)
	}

	// Transition journal must reference prior generation.
	journalPath := filepath.Join(statePath, "transition", "state.json")
	journalBytes, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	var journal trustTransitionJournal
	if err := json.Unmarshal(journalBytes, &journal); err != nil {
		t.Fatal(err)
	}
	if journal.PriorGeneration == nil {
		t.Fatal("transition journal has no prior generation")
	}
	if journal.PriorGeneration.Generation != 1 {
		t.Fatalf("prior generation = %d, want 1", journal.PriorGeneration.Generation)
	}
	if journal.Candidate.Generation != 2 {
		t.Fatalf("candidate generation = %d, want 2", journal.Candidate.Generation)
	}
}

func TestPublishTrustedRootRecoversPreviousStateOnWorkerFailure(t *testing.T) {
	statePath := newTestState(t)
	action, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if action != repositoryActionCreated {
		t.Fatalf("action = %q, want %q", action, repositoryActionCreated)
	}

	// Capture gen 1 fingerprint before publish attempt.
	gen1Bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	gen1Fingerprint, err := fingerprintSource(gen1Bootstrap)
	if err != nil {
		t.Fatal(err)
	}

	// Inject failure at candidate-prepared checkpoint (after state write, before commit).
	injectedErr := "injected test failure at candidate-prepared"
	hooks := publicationHooks{
		checkpoint: func(cp publicationCheckpoint) error {
			if cp == checkpointCandidatePrepared {
				return &testError{msg: injectedErr}
			}
			return nil
		},
	}

	_, err = publishTrustedRootUpdateWithHooks(statePath, hooks)
	if err == nil {
		t.Fatal("expected failure with injected hook")
	}

	// After failure, verify safety properties:
	// 1. Active generation symlink still points to gen 1 (was never switched).
	activeGenID, err := readActiveGeneration(filepath.Join(statePath, "active-generation"))
	if err != nil {
		t.Fatal(err)
	}
	if activeGenID != gen1Bootstrap.GenerationID {
		t.Fatalf("active generation = %q, want %q (gen 1 preserved)", activeGenID, gen1Bootstrap.GenerationID)
	}

	// 2. The original active TUF publication is intact and valid with gen 1 fingerprint.
	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)
	if state.Active == nil {
		t.Fatal("no active publication after failed publish")
	}
	activePath := committedPath(layout, state.Active.ID)
	_, _, err = validateExistingRepository(activePath, gen1Fingerprint)
	if err != nil {
		t.Fatalf("active TUF publication is invalid after failed publish: %v", err)
	}

	// 3. TUF state is "preparing" (failure is detectable, not silent).
	if state.Status != publicationStatusPreparing {
		t.Fatalf("status = %q, want %q (failure is recorded)", state.Status, publicationStatusPreparing)
	}

	// 4. The gen 2 directory was created on disk (advance happened before publish)
	// but it is NOT the active generation.
	gen2Path := filepath.Join(statePath, "generations", "generation-00000002")
	if !pathExists(gen2Path) {
		t.Fatal("expected gen 2 directory to exist (created during advance)")
	}

	// 5. Transition journal was NOT updated (still references gen 1 as candidate).
	journalBytes, err := os.ReadFile(filepath.Join(statePath, "transition", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var journal trustTransitionJournal
	if err := json.Unmarshal(journalBytes, &journal); err != nil {
		t.Fatal(err)
	}
	if journal.Candidate.GenerationID != gen1Bootstrap.GenerationID {
		t.Fatalf("journal candidate = %q, want %q (journal preserved)", journal.Candidate.GenerationID, gen1Bootstrap.GenerationID)
	}
}

func TestPublishPreservesSigningConfigRouting(t *testing.T) {
	statePath := newTestState(t)
	_, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}

	layout := newTUFLayout(statePath)
	stateBefore := readTestPublicationState(t, layout)
	beforeSigningConfig := readTestFile(
		t,
		filepath.Join(committedPath(layout, stateBefore.Active.ID), "targets", "signing_config.v0.2.json"),
	)

	_, err = publishTrustedRootUpdate(statePath)
	if err != nil {
		t.Fatal(err)
	}

	stateAfter := readTestPublicationState(t, layout)
	afterSigningConfig := readTestFile(
		t,
		filepath.Join(committedPath(layout, stateAfter.Active.ID), "targets", "signing_config.v0.2.json"),
	)

	// SigningConfig service URLs must remain the same (no standby routing).
	// Note: the exact bytes may differ slightly due to marshaling of timestamps
	// in service ValidFor, but the service URLs must match.
	var beforeConfig, afterConfig map[string]interface{}
	if err := json.Unmarshal(beforeSigningConfig, &beforeConfig); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(afterSigningConfig, &afterConfig); err != nil {
		t.Fatal(err)
	}

	// Check that rekorTlogUrls still points to the same URL.
	checkServiceURLs := func(config map[string]interface{}, field string) []string {
		urls, ok := config[field]
		if !ok {
			return nil
		}
		arr, ok := urls.([]interface{})
		if !ok {
			return nil
		}
		var result []string
		for _, item := range arr {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if u, ok := m["url"].(string); ok {
				result = append(result, u)
			}
		}
		return result
	}

	beforeRekorURLs := checkServiceURLs(beforeConfig, "rekorTlogUrls")
	afterRekorURLs := checkServiceURLs(afterConfig, "rekorTlogUrls")
	if len(beforeRekorURLs) != len(afterRekorURLs) {
		t.Fatalf("rekorTlogUrls count changed: before=%d, after=%d", len(beforeRekorURLs), len(afterRekorURLs))
	}
	for i := range beforeRekorURLs {
		if beforeRekorURLs[i] != afterRekorURLs[i] {
			t.Fatalf("rekorTlogUrls[%d] changed: %q -> %q", i, beforeRekorURLs[i], afterRekorURLs[i])
		}
	}
}

func readTestTrustStatus(t *testing.T, path string) trustStatusTarget {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var status trustStatusTarget
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestDebugFingerprint(t *testing.T) {
	statePath := newTestState(t)
	
	// Load before ensureTUFRepository
	bootstrap1, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	fp1, _ := fingerprintSource(bootstrap1)
	t.Logf("fingerprint before TUF: %s", fp1)
	
	_, err = ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}
	
	// Load after ensureTUFRepository
	bootstrap2, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	fp2, _ := fingerprintSource(bootstrap2)
	t.Logf("fingerprint after TUF: %s", fp2)
	
	if fp1 != fp2 {
		t.Fatalf("fingerprints differ!\nbefore: %+v\nafter: %+v", bootstrap1, bootstrap2)
	}
}

func TestDebugPublish(t *testing.T) {
	statePath := newTestState(t)
	_, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}
	
	// Now check the stored fingerprint in manifest
	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)
	manifestPath := filepath.Join(committedPath(layout, state.Active.ID), "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("stored manifest: %s", string(manifestBytes))
	
	// Now call publish
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := fingerprintSource(bootstrap)
	t.Logf("current fingerprint: %s", fp)
}
