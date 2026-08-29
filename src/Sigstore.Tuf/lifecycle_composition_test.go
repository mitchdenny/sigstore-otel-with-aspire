package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	trustrootv1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestCompleteLifecyclePreservesHistoryAndExactTransitions(t *testing.T) {
	statePath := newCtRotationTestState(t)
	layout := newTUFLayout(statePath)
	trustDomain := mustActiveLifecycleGeneration(t, statePath).TrustDomainID
	bootstrapRoot := readTestFile(t, layout.bootstrapRoot)
	history := captureLifecycleGeneration(t, statePath, nil)

	assertLifecycleTransition(t, statePath, 1, 1, 1, 1, 1)

	if action, err := ensureTUFRepository(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionRefreshed {
		t.Fatalf("refresh action = %q, want %q", action, repositoryActionRefreshed)
	}
	assertLifecycleTransition(t, statePath, 1, 1, 1, 2, 2)
	assertLifecycleHistory(t, statePath, history)

	rootRequest := writeTUFRootRotationTestRequest(
		t,
		statePath,
		"14000000000000000000000000000001",
	)
	if action, err := dispatchTUFRootRotation(
		statePath,
		rootRequest,
		publicationHooks{},
	); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionRotated {
		t.Fatalf("root rotation action = %q, want %q", action, repositoryActionRotated)
	}
	assertLifecycleTransition(t, statePath, 1, 2, 2, 3, 3)
	assertLifecycleHistory(t, statePath, history)

	writeTestPublishRequest(
		t,
		statePath,
		"14000000000000000000000000000002",
	)
	if action, err := dispatchPublishRequest(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("trusted-root action = %q, want %q", action, repositoryActionPublished)
	}
	assertLifecycleTransition(t, statePath, 2, 2, 3, 4, 4)
	assertLifecycleHistory(t, statePath, history)
	history = captureLifecycleGeneration(t, statePath, history)

	writeOIDCRotationTestRequest(
		t,
		statePath,
		"14000000000000000000000000000003",
	)
	if action, err := dispatchOidcRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("OIDC action = %q, want %q", action, repositoryActionPublished)
	}
	assertLifecycleTransition(t, statePath, 3, 2, 4, 5, 5)
	assertLifecycleHistory(t, statePath, history)
	history = captureLifecycleGeneration(t, statePath, history)

	_, tsaMaterial := stageTsaRotation(
		t,
		statePath,
		1400,
		"14000000000000000000000000000004",
	)
	if action, err := dispatchTsaRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("TSA action = %q, want %q", action, repositoryActionPublished)
	}
	assertLifecycleTransition(t, statePath, 4, 2, 5, 6, 6)
	assertLifecycleHistory(t, statePath, history)
	history = captureLifecycleGeneration(t, statePath, history)

	if _, _, err := ensureRuntimeBaselineProjection(statePath); err != nil {
		t.Fatal(err)
	}
	_, fulcioMaterial := stageFulcioRotation(
		t,
		statePath,
		1401,
		"14000000000000000000000000000005",
	)
	if action, err := dispatchFulcioRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("Fulcio action = %q, want %q", action, repositoryActionPublished)
	}
	promoteFulcioRuntimeProjection(t, statePath)
	assertLifecycleTransition(t, statePath, 5, 2, 6, 7, 7)
	assertLifecycleHistory(t, statePath, history)
	history = captureLifecycleGeneration(t, statePath, history)

	rekorRequest := stageRekorRotation(
		t,
		statePath,
		"14000000000000000000000000000006",
		"14000000-0000-0000-0000-000000000006",
	)
	if action, err := dispatchRekorRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("Rekor action = %q, want %q", action, repositoryActionPublished)
	}
	assertLifecycleTransition(t, statePath, 6, 2, 7, 8, 8)
	assertLifecycleHistory(t, statePath, history)
	history = captureLifecycleGeneration(t, statePath, history)

	if _, _, err := ensureRuntimeBaselineProjection(statePath); err != nil {
		t.Fatal(err)
	}
	ctRequest := stageCtRotation(
		t,
		statePath,
		"14000000000000000000000000000007",
		"14000000-0000-0000-0000-000000000007",
	)
	if action, err := dispatchCtRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("CT action = %q, want %q", action, repositoryActionPublished)
	}
	assertLifecycleTransition(t, statePath, 7, 2, 8, 9, 9)
	assertLifecycleHistory(t, statePath, history)
	history = captureLifecycleGeneration(t, statePath, history)

	active := mustActiveLifecycleGeneration(t, statePath)
	if active.TrustDomainID != trustDomain {
		t.Fatal("complete lifecycle changed the trust domain")
	}
	if !bytes.Equal(bootstrapRoot, readTestFile(t, layout.bootstrapRoot)) ||
		readMetadataVersion(t, layout.bootstrapRoot) != 1 {
		t.Fatal("complete lifecycle changed the immutable bootstrap root")
	}
	if len(history) != 7 {
		t.Fatalf("retained generation count = %d, want 7", len(history))
	}
	assertLifecycleGenerationDirectories(t, statePath, 7)

	trustedRoot := readActiveTrustedRoot(t, statePath)
	if len(trustedRoot.CertificateAuthorities) != 2 {
		t.Fatalf(
			"Fulcio authority count = %d, want 2",
			len(trustedRoot.CertificateAuthorities),
		)
	}
	if len(trustedRoot.TimestampAuthorities) != 2 {
		t.Fatalf(
			"TSA authority count = %d, want 2",
			len(trustedRoot.TimestampAuthorities),
		)
	}
	if len(trustedRoot.Tlogs) != 3 {
		t.Fatalf("Rekor tlog count = %d, want 3", len(trustedRoot.Tlogs))
	}
	if len(trustedRoot.Ctlogs) != 2 {
		t.Fatalf("CT log count = %d, want 2", len(trustedRoot.Ctlogs))
	}
	assertTsaAuthorityPresent(
		t,
		trustedRoot,
		hashDER(tsaMaterial.rootCert.Raw),
		hashDER(tsaMaterial.leafCert.Raw),
	)
	fulcioFingerprints := activeFulcioFingerprints(t, statePath)
	if len(fulcioFingerprints) != 2 ||
		fulcioFingerprints[1] != hashDER(fulcioMaterial.certificate.Raw) {
		t.Fatalf("unexpected retained Fulcio fingerprints: %v", fulcioFingerprints)
	}

	signingConfig := &trustrootv1.SigningConfig{}
	if err := protojson.Unmarshal(
		readActiveTargets(t, statePath, "signing_config.v0.2.json"),
		signingConfig,
	); err != nil {
		t.Fatal(err)
	}
	if len(signingConfig.RekorTlogUrls) != 1 ||
		signingConfig.RekorTlogUrls[0].GetUrl() != rekorSecondaryURL {
		t.Fatalf("unexpected final Rekor routing: %+v", signingConfig.RekorTlogUrls)
	}
	if active.RekorPublicKeySHA256 != rekorRequest.CandidatePublicKeySHA256 ||
		active.CtLogPublicKeySHA256 != ctRequest.CandidatePublicKeySHA256 {
		t.Fatal("final active shard selections do not match the committed rotations")
	}
	if countActiveTsaPrivateFiles(t, statePath) != 2 ||
		countActiveFulcioPrivateFiles(t, statePath) != 2 {
		t.Fatal("complete lifecycle allowed active TSA or Fulcio secrets to grow")
	}
}

func assertLifecycleTransition(
	t *testing.T,
	statePath string,
	generation int,
	rootVersion int,
	targetsVersion int,
	snapshotVersion int,
	timestampVersion int,
) {
	t.Helper()
	active := mustActiveLifecycleGeneration(t, statePath)
	if active.Generation != generation ||
		active.GenerationID != lifecycleGenerationID(generation) {
		t.Fatalf(
			"active generation = %d/%s, want %d/%s",
			active.Generation,
			active.GenerationID,
			generation,
			lifecycleGenerationID(generation),
		)
	}
	layout := newTUFLayout(statePath)
	publication := readTestPublicationState(t, layout)
	activePath := committedPath(layout, publication.Active.ID)
	for _, expected := range []struct {
		name    string
		version int
	}{
		{"root.json", rootVersion},
		{"targets.json", targetsVersion},
		{"snapshot.json", snapshotVersion},
		{"timestamp.json", timestampVersion},
	} {
		if got := readMetadataVersion(
			t,
			filepath.Join(activePath, "repository", expected.name),
		); got != expected.version {
			t.Fatalf(
				"%s version = %d, want %d at generation %d",
				expected.name,
				got,
				expected.version,
				generation,
			)
		}
	}
	statusPayload := readTestFile(
		t,
		filepath.Join(activePath, "targets", trustStatusTargetName),
	)
	var status trustStatusTarget
	if err := json.Unmarshal(statusPayload, &status); err != nil {
		t.Fatal(err)
	}
	if status.TrustDomainID != active.TrustDomainID ||
		status.Generation != generation ||
		status.GenerationID != active.GenerationID ||
		status.GenerationManifestSHA256 != active.GenerationManifestSHA256 ||
		status.TUFRootVersion != rootVersion ||
		status.TUFTargetsVersion != targetsVersion {
		t.Fatalf("trust status does not match the expected transition: %+v", status)
	}
	assertCommittedLayout(t, statePath)
}

func mustActiveLifecycleGeneration(
	t *testing.T,
	statePath string,
) bootstrapManifest {
	t.Helper()
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	return active
}

func captureLifecycleGeneration(
	t *testing.T,
	statePath string,
	history map[string]map[string][]byte,
) map[string]map[string][]byte {
	t.Helper()
	if history == nil {
		history = map[string]map[string][]byte{}
	}
	active := mustActiveLifecycleGeneration(t, statePath)
	if _, exists := history[active.GenerationID]; !exists {
		history[active.GenerationID] = readTree(
			t,
			generationPathFor(statePath, active.GenerationID),
		)
	}
	return history
}

func assertLifecycleHistory(
	t *testing.T,
	statePath string,
	history map[string]map[string][]byte,
) {
	t.Helper()
	for generation, expected := range history {
		actual := readTree(t, generationPathFor(statePath, generation))
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("historical generation %s changed", generation)
		}
	}
}

func assertLifecycleGenerationDirectories(
	t *testing.T,
	statePath string,
	count int,
) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(statePath, "generations"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) != count {
		t.Fatalf("generation directories = %v, want %d entries", names, count)
	}
	for index, name := range names {
		if name != lifecycleGenerationID(index+1) {
			t.Fatalf("generation directory %d = %q", index+1, name)
		}
		assertGenerationManifestReadOnly(t, statePath, name)
	}
}

func lifecycleGenerationID(generation int) string {
	return fmt.Sprintf("generation-%08d", generation)
}
