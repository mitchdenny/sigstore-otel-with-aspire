package main

import "testing"

// TestEnsureAfterCrossGenPublish proves that ensureTUFRepository handles
// the post-cross-generation state correctly. After a gen1→gen2 publish,
// the previous publication has gen1's fingerprint. A subsequent ensure
// (which performs a refresh) must validate the retired previous using
// self-consistent validation, not the current gen2 fingerprint.
func TestEnsureAfterCrossGenPublish(t *testing.T) {
	statePath := newTestState(t)
	_, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = publishTrustedRootUpdate(statePath)
	if err != nil {
		t.Fatal(err)
	}
	// Ensure must handle gen2 state with cross-gen previous.
	action, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatalf("ensure after cross-gen publish failed: %v", err)
	}
	if action != repositoryActionRefreshed {
		t.Errorf("expected refreshed action, got %s", action)
	}
}
