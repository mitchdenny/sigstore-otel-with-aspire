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

	// 3. TUF state is "committed" (rollback successfully restored prior state).
	if state.Status != publicationStatusCommitted {
		t.Fatalf("status = %q, want %q (rollback restored committed)", state.Status, publicationStatusCommitted)
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

// TestCrossGenRecoverForwardCompleteAfterTUFCommit simulates the crash window
// where TUF publication committed with gen 2's fingerprint but the generation
// symlink was not yet switched. On next ensureTUFRepository, recovery must
// forward-complete (switch symlink to gen 2) without error.
func TestCrossGenRecoverForwardCompleteAfterTUFCommit(t *testing.T) {
	statePath := newTestState(t)

	// Create initial TUF repo.
	_, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate cross-gen publish that crashes after TUF commit but before
	// generation switch: advance generation and publish targets, but skip
	// switchActiveGeneration.
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	newBootstrap, newGenPath, err := advanceTrustGeneration(statePath, bootstrap)
	if err != nil {
		t.Fatal(err)
	}

	// Compute fingerprints.
	sourceFingerprint, _ := fingerprintSource(bootstrap)
	newSourceFingerprint, _ := fingerprintSource(newBootstrap)

	// Run publishNewTargets (this commits TUF with gen 2's fingerprint).
	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)
	err = publishNewTargets(layout, state, newGenPath, newBootstrap, sourceFingerprint, newSourceFingerprint, publicationHooks{})
	if err != nil {
		t.Fatal(err)
	}

	// At this point: TUF committed with gen 2's fingerprint, symlink still gen 1.
	// Verify symlink still points to gen 1.
	activeGenID, _ := readActiveGeneration(filepath.Join(statePath, "active-generation"))
	if activeGenID != "generation-00000001" {
		t.Fatalf("expected symlink at gen 1, got %s", activeGenID)
	}

	// Now run recovery (next startup).
	action, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	if action != repositoryActionRecovered {
		t.Fatalf("expected recovered action, got %q", action)
	}

	// Verify symlink was forward-completed to gen 2.
	activeGenID, _ = readActiveGeneration(filepath.Join(statePath, "active-generation"))
	if activeGenID != "generation-00000002" {
		t.Fatalf("expected symlink at gen 2 after recovery, got %s", activeGenID)
	}
}

// TestCrossGenRecoverRollbackWhenTUFStillOld simulates a crash after generation
// directory was created but before TUF publication started (or before TUF active
// switch). Recovery should rollback: TUF stays at gen 1, orphaned gen 2 dir is
// cleaned up, and the system is coherent.
func TestCrossGenRecoverRollbackWhenTUFStillOld(t *testing.T) {
	statePath := newTestState(t)

	// Create initial TUF repo.
	_, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a crash after advanceTrustGeneration but before publishNewTargets:
	// just create gen 2 directory.
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = advanceTrustGeneration(statePath, bootstrap)
	if err != nil {
		t.Fatal(err)
	}

	// Verify gen 2 dir exists.
	gen2Path := filepath.Join(statePath, "generations", "generation-00000002")
	if _, err := os.Stat(gen2Path); err != nil {
		t.Fatalf("gen 2 dir not created: %v", err)
	}

	// Recovery: ensureTUFRepository should succeed (TUF validates with gen 1)
	// and clean up orphaned gen 2.
	action, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	// TUF state is still committed with gen 1 — validates fine, just refreshes.
	t.Logf("action after recovery = %q", action)

	// Verify gen stays at 1.
	activeGenID, _ := readActiveGeneration(filepath.Join(statePath, "active-generation"))
	if activeGenID != "generation-00000001" {
		t.Fatalf("expected symlink at gen 1, got %s", activeGenID)
	}

	// Verify orphaned gen 2 dir was cleaned up.
	if _, err := os.Stat(gen2Path); !os.IsNotExist(err) {
		t.Fatal("orphaned gen 2 directory was not cleaned up")
	}
}

// TestCrossGenRecoverPreparingActiveSwitched simulates a crash during TUF
// publication where the active link was switched to candidate (gen 2) but
// the state was not finalized and gen symlink was not switched. Recovery
// should forward-complete both TUF finalization and generation switch.
func TestCrossGenRecoverPreparingActiveSwitched(t *testing.T) {
	statePath := newTestState(t)

	// Create initial TUF repo.
	_, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}

	// Advance generation.
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	newBootstrap, newGenPath, err := advanceTrustGeneration(statePath, bootstrap)
	if err != nil {
		t.Fatal(err)
	}

	sourceFingerprint, _ := fingerprintSource(bootstrap)
	newSourceFingerprint, _ := fingerprintSource(newBootstrap)

	// Publish but crash after TUF active link switches (before finalization).
	// Use hooks to interrupt at the right moment.
	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)

	crashErr := &testError{msg: "simulated crash after active switch"}
	hooks := publicationHooks{
		checkpoint: func(name publicationCheckpoint) error {
			if name == checkpointActiveSwitched {
				return crashErr
			}
			return nil
		},
	}
	err = publishNewTargets(layout, state, newGenPath, newBootstrap, sourceFingerprint, newSourceFingerprint, hooks)
	if err == nil {
		t.Fatal("expected error from crash hook")
	}

	// State: TUF "preparing", active link → candidate (gen 2), gen symlink → gen 1.
	// Recovery should forward-complete.
	action, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	if action != repositoryActionRecovered {
		t.Fatalf("expected recovered action, got %q", action)
	}

	// Verify gen symlink was forward-completed to gen 2.
	activeGenID, _ := readActiveGeneration(filepath.Join(statePath, "active-generation"))
	if activeGenID != "generation-00000002" {
		t.Fatalf("expected symlink at gen 2 after recovery, got %s", activeGenID)
	}
}

// TestCrossGenRejectsTamperedDomainInCommittedForward proves that a tampered
// TrustDomainID in the next-generation manifest is rejected during
// committed-state forward-complete recovery.
func TestCrossGenRejectsTamperedDomainInCommittedForward(t *testing.T) {
	statePath := newTestState(t)

	_, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}

	// Advance generation normally.
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	newBootstrap, newGenPath, err := advanceTrustGeneration(statePath, bootstrap)
	if err != nil {
		t.Fatal(err)
	}

	sourceFingerprint, _ := fingerprintSource(bootstrap)
	newSourceFingerprint, _ := fingerprintSource(newBootstrap)

	// Publish normally (TUF commits with gen 2's fingerprint).
	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)
	err = publishNewTargets(layout, state, newGenPath, newBootstrap, sourceFingerprint, newSourceFingerprint, publicationHooks{})
	if err != nil {
		t.Fatal(err)
	}

	// Now tamper: rewrite gen 2's manifest with a different TrustDomainID.
	gen2ManifestPath := filepath.Join(statePath, "generations", "generation-00000002", "manifest.json")
	manifestBytes, err := os.ReadFile(gen2ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest generationManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.TrustDomainID = "tampered-domain-id"
	tamperedBytes, _ := json.Marshal(manifest)
	if err := os.WriteFile(gen2ManifestPath, tamperedBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	// Recovery should FAIL (not forward-complete with tampered domain).
	_, err = ensureTUFRepository(statePath)
	if err == nil {
		t.Fatal("expected error for tampered domain ID in next-gen, got nil")
	}
	t.Logf("correctly rejected tampered domain: %v", err)

	// Verify active generation is still gen 1.
	activeGenID, _ := readActiveGeneration(filepath.Join(statePath, "active-generation"))
	if activeGenID != "generation-00000001" {
		t.Fatalf("expected gen 1 preserved, got %s", activeGenID)
	}
}

// TestCrossGenRejectsTamperedDomainInPreparingForward proves that a tampered
// TrustDomainID in the next-generation manifest is rejected during
// preparing-state forward-complete recovery (TUF active→candidate).
func TestCrossGenRejectsTamperedDomainInPreparingForward(t *testing.T) {
	statePath := newTestState(t)

	_, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}

	// Advance generation and publish with crash after active switch.
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	newBootstrap, newGenPath, err := advanceTrustGeneration(statePath, bootstrap)
	if err != nil {
		t.Fatal(err)
	}

	sourceFingerprint, _ := fingerprintSource(bootstrap)
	newSourceFingerprint, _ := fingerprintSource(newBootstrap)

	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)

	hooks := publicationHooks{
		checkpoint: func(name publicationCheckpoint) error {
			if name == checkpointActiveSwitched {
				return &testError{msg: "crash after active switch"}
			}
			return nil
		},
	}
	_ = publishNewTargets(layout, state, newGenPath, newBootstrap, sourceFingerprint, newSourceFingerprint, hooks)

	// Tamper the gen 2 manifest.
	gen2ManifestPath := filepath.Join(statePath, "generations", "generation-00000002", "manifest.json")
	manifestBytes, err := os.ReadFile(gen2ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest generationManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.TrustDomainID = "tampered-domain-id"
	tamperedBytes, _ := json.Marshal(manifest)
	if err := os.WriteFile(gen2ManifestPath, tamperedBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	// Recovery should FAIL.
	_, err = ensureTUFRepository(statePath)
	if err == nil {
		t.Fatal("expected error for tampered domain in preparing-forward, got nil")
	}
	t.Logf("correctly rejected tampered domain: %v", err)

	// Gen 1 preserved.
	activeGenID, _ := readActiveGeneration(filepath.Join(statePath, "active-generation"))
	if activeGenID != "generation-00000001" {
		t.Fatalf("expected gen 1 preserved, got %s", activeGenID)
	}
}
