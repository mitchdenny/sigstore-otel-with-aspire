package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInitialCreationUsesStableLayoutAndVersionOneBootstrap(t *testing.T) {
	statePath := newTestState(t)

	action, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if action != repositoryActionCreated {
		t.Fatalf("action = %q, want %q", action, repositoryActionCreated)
	}

	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)
	if state.Status != publicationStatusCommitted {
		t.Fatalf("status = %q, want %q", state.Status, publicationStatusCommitted)
	}
	if state.Active == nil || state.Previous != nil || state.Candidate != nil {
		t.Fatalf("unexpected initial publication state: %+v", state)
	}
	activeID, exists, err := readActivePublication(layout.active)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || activeID != state.Active.ID {
		t.Fatalf("active = %q (%t), want %q", activeID, exists, state.Active.ID)
	}

	activeRoot := readTestFile(
		t,
		filepath.Join(committedPath(layout, state.Active.ID), "repository", "root.json"),
	)
	bootstrapRoot := readTestFile(t, layout.bootstrapRoot)
	if !bytes.Equal(activeRoot, bootstrapRoot) {
		t.Fatal("immutable bootstrap root differs from the initial repository root")
	}
	if version := readMetadataVersion(t, layout.bootstrapRoot); version != 1 {
		t.Fatalf("bootstrap root version = %d, want 1", version)
	}
	info, err := os.Stat(layout.bootstrapRoot)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("bootstrap root mode = %o, want read-only", info.Mode().Perm())
	}
	assertCommittedLayout(t, statePath)
}

func TestMetadataRefreshPublishesAtomicallyAndRetainsPrevious(t *testing.T) {
	statePath := newTestState(t)
	if _, err := ensureTUFRepository(statePath); err != nil {
		t.Fatal(err)
	}

	layout := newTUFLayout(statePath)
	parentBefore, err := os.Stat(layout.root)
	if err != nil {
		t.Fatal(err)
	}
	before := readTestPublicationState(t, layout)
	bootstrapBefore := readTestFile(t, layout.bootstrapRoot)
	activeBefore := committedPath(layout, before.Active.ID)
	snapshotBefore := readTestMetadata(t, filepath.Join(activeBefore, "repository", "snapshot.json"))
	timestampBefore := readTestMetadata(t, filepath.Join(activeBefore, "repository", "timestamp.json"))

	action, err := ensureTUFRepository(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if action != repositoryActionRefreshed {
		t.Fatalf("action = %q, want %q", action, repositoryActionRefreshed)
	}

	parentAfter, err := os.Stat(layout.root)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(parentBefore, parentAfter) {
		t.Fatal("stable TUF parent was replaced during refresh")
	}
	after := readTestPublicationState(t, layout)
	if after.Active == nil || after.Active.ID == before.Active.ID {
		t.Fatal("refresh did not publish a new active repository")
	}
	if after.Previous == nil || *after.Previous != *before.Active {
		t.Fatalf("previous = %+v, want prior active %+v", after.Previous, before.Active)
	}

	activeAfter := committedPath(layout, after.Active.ID)
	snapshotAfter := readTestMetadata(t, filepath.Join(activeAfter, "repository", "snapshot.json"))
	timestampAfter := readTestMetadata(t, filepath.Join(activeAfter, "repository", "timestamp.json"))
	if snapshotAfter.Version != snapshotBefore.Version+1 {
		t.Fatalf(
			"snapshot version = %d, want %d",
			snapshotAfter.Version,
			snapshotBefore.Version+1,
		)
	}
	if timestampAfter.Version != timestampBefore.Version+1 {
		t.Fatalf(
			"timestamp version = %d, want %d",
			timestampAfter.Version,
			timestampBefore.Version+1,
		)
	}
	if snapshotAfter.Hash == snapshotBefore.Hash {
		t.Fatal("snapshot bytes did not change during refresh")
	}
	if timestampAfter.Hash == timestampBefore.Hash {
		t.Fatal("timestamp bytes did not change during refresh")
	}
	if !bytes.Equal(bootstrapBefore, readTestFile(t, layout.bootstrapRoot)) {
		t.Fatal("refresh changed the immutable bootstrap root")
	}
	historySnapshot := readTestMetadata(
		t,
		filepath.Join(layout.previous, "repository", "snapshot.json"),
	)
	if historySnapshot.Hash != snapshotBefore.Hash {
		t.Fatal("history does not contain the prior committed repository")
	}
	assertCommittedLayout(t, statePath)
}

func TestImmutableBootstrapRootIsNotReplaced(t *testing.T) {
	statePath := newTestState(t)
	if _, err := ensureTUFRepository(statePath); err != nil {
		t.Fatal(err)
	}
	layout := newTUFLayout(statePath)
	before, err := os.Stat(layout.bootstrapRoot)
	if err != nil {
		t.Fatal(err)
	}
	beforeBytes := readTestFile(t, layout.bootstrapRoot)

	for range 3 {
		if _, err := ensureTUFRepository(statePath); err != nil {
			t.Fatal(err)
		}
	}

	after, err := os.Stat(layout.bootstrapRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("immutable bootstrap root inode changed")
	}
	if !bytes.Equal(beforeBytes, readTestFile(t, layout.bootstrapRoot)) {
		t.Fatal("immutable bootstrap root bytes changed")
	}
	assertCommittedLayout(t, statePath)
}

func TestInjectedPublicationFailureRollsBack(t *testing.T) {
	statePath := newTestState(t)
	if _, err := ensureTUFRepository(statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureTUFRepository(statePath); err != nil {
		t.Fatal(err)
	}
	layout := newTUFLayout(statePath)
	before := readTestPublicationState(t, layout)
	bootstrapBefore := readTestFile(t, layout.bootstrapRoot)
	activeSnapshotBefore := readTestFile(
		t,
		filepath.Join(
			committedPath(layout, before.Active.ID),
			"repository",
			"snapshot.json",
		),
	)
	injected := errors.New("injected publication failure")

	_, err := ensureTUFRepositoryWithHooks(
		statePath,
		publicationHooks{
			checkpoint: func(checkpoint publicationCheckpoint) error {
				if checkpoint == checkpointCandidateCommitted {
					return injected
				}
				return nil
			},
		},
	)
	if !errors.Is(err, injected) {
		t.Fatalf("error = %v, want injected failure", err)
	}

	after := readTestPublicationState(t, layout)
	if after.Status != publicationStatusCommitted {
		t.Fatalf("status = %q, want committed rollback", after.Status)
	}
	if *after.Active != *before.Active {
		t.Fatalf("active = %+v, want %+v", after.Active, before.Active)
	}
	if *after.Previous != *before.Previous {
		t.Fatalf("previous = %+v, want %+v", after.Previous, before.Previous)
	}
	activeSnapshotAfter := readTestFile(
		t,
		filepath.Join(
			committedPath(layout, after.Active.ID),
			"repository",
			"snapshot.json",
		),
	)
	if !bytes.Equal(activeSnapshotBefore, activeSnapshotAfter) {
		t.Fatal("failed publication changed the active repository")
	}
	if !bytes.Equal(bootstrapBefore, readTestFile(t, layout.bootstrapRoot)) {
		t.Fatal("failed publication changed the immutable bootstrap root")
	}
	assertCommittedLayout(t, statePath)
}

func TestInterruptedInitialPublicationRecoversForward(t *testing.T) {
	checkpoints := []publicationCheckpoint{
		checkpointCandidatePrepared,
		checkpointBootstrapPrepared,
		checkpointBootstrapWritten,
		checkpointCandidateCommitted,
		checkpointActiveLinkPrepared,
		checkpointActiveSwitched,
	}
	for _, checkpoint := range checkpoints {
		t.Run(string(checkpoint), func(t *testing.T) {
			statePath := newTestState(t)
			runUntilCrash(t, statePath, checkpoint)

			layout := newTUFLayout(statePath)
			preparing := readTestPublicationState(t, layout)
			if preparing.Status != publicationStatusPreparing || preparing.Active != nil {
				t.Fatalf("unexpected interrupted initial state: %+v", preparing)
			}
			action, err := ensureTUFRepository(statePath)
			if err != nil {
				t.Fatal(err)
			}
			if action != repositoryActionCreated {
				t.Fatalf("action = %q, want %q", action, repositoryActionCreated)
			}
			committed := readTestPublicationState(t, layout)
			if committed.Active == nil || committed.Active.ID != preparing.Candidate.ID {
				t.Fatalf("recovered active = %+v, want candidate %+v", committed.Active, preparing.Candidate)
			}
			assertCommittedLayout(t, statePath)
		})
	}
}

func TestInterruptedRefreshRecoversDeterministically(t *testing.T) {
	tests := []struct {
		checkpoint publicationCheckpoint
		committed  bool
	}{
		{checkpointCandidatePrepared, false},
		{checkpointHistoryParked, false},
		{checkpointCandidateCommitted, false},
		{checkpointActiveLinkPrepared, false},
		{checkpointActiveSwitched, true},
		{checkpointPreviousArchived, true},
		{checkpointHistoryRetired, true},
	}
	for _, test := range tests {
		t.Run(string(test.checkpoint), func(t *testing.T) {
			statePath := newTestState(t)
			if _, err := ensureTUFRepository(statePath); err != nil {
				t.Fatal(err)
			}
			if _, err := ensureTUFRepository(statePath); err != nil {
				t.Fatal(err)
			}
			layout := newTUFLayout(statePath)
			before := readTestPublicationState(t, layout)
			bootstrapBefore := readTestFile(t, layout.bootstrapRoot)

			runUntilCrash(t, statePath, test.checkpoint)
			preparing := readTestPublicationState(t, layout)
			if preparing.Status != publicationStatusPreparing {
				t.Fatalf("status = %q, want preparing", preparing.Status)
			}
			action, err := ensureTUFRepository(statePath)
			if err != nil {
				t.Fatal(err)
			}
			if action != repositoryActionRecovered {
				t.Fatalf("action = %q, want %q", action, repositoryActionRecovered)
			}

			after := readTestPublicationState(t, layout)
			if test.committed {
				if *after.Active != *preparing.Candidate {
					t.Fatalf("active = %+v, want candidate %+v", after.Active, preparing.Candidate)
				}
				if after.Previous == nil || *after.Previous != *before.Active {
					t.Fatalf("previous = %+v, want prior active %+v", after.Previous, before.Active)
				}
			} else {
				if *after.Active != *before.Active {
					t.Fatalf("active = %+v, want rolled back %+v", after.Active, before.Active)
				}
				if *after.Previous != *before.Previous {
					t.Fatalf("previous = %+v, want %+v", after.Previous, before.Previous)
				}
			}
			if !bytes.Equal(bootstrapBefore, readTestFile(t, layout.bootstrapRoot)) {
				t.Fatal("recovery changed the immutable bootstrap root")
			}
			assertCommittedLayout(t, statePath)
		})
	}
}

func TestRefreshRejectsCommittedFileCorruption(t *testing.T) {
	statePath := newTestState(t)
	if _, err := ensureTUFRepository(statePath); err != nil {
		t.Fatal(err)
	}
	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)
	target := filepath.Join(
		committedPath(layout, state.Active.ID),
		"targets",
		"trusted_root.json",
	)
	if err := os.WriteFile(target, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := ensureTUFRepository(statePath); err == nil {
		t.Fatal("refresh accepted a corrupted committed target")
	}
}

func TestGenerationAwareStatePreservesSchema4SourceFingerprint(t *testing.T) {
	statePath := newTestState(t)
	legacyData := readTestFile(
		t,
		filepath.Join(
			statePath,
			"migration",
			"bootstrap-manifest.schema-4.json",
		),
	)
	var legacy bootstrapManifest
	if err := json.Unmarshal(legacyData, &legacy); err != nil {
		t.Fatal(err)
	}
	before, err := fingerprintSource(legacy)
	if err != nil {
		t.Fatal(err)
	}

	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	after, err := fingerprintSource(active)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("source fingerprint changed across schema-4 migration: %s != %s", before, after)
	}
}

func TestGenerationStateRejectsUnexpectedFile(t *testing.T) {
	statePath := newTestState(t)
	writeTestFile(
		t,
		filepath.Join(
			statePath,
			"generations",
			initialGenerationID,
			"public",
			"unexpected.pem",
		),
		[]byte("unexpected"),
	)

	if _, err := ensureTUFRepository(statePath); err == nil {
		t.Fatal("TUF initialization accepted an unexpected generation file")
	}
}

func TestSharedStateLockContentionAndRecovery(t *testing.T) {
	statePath := t.TempDir()
	holder, err := acquireStateLock(statePath, time.Second, "test-holder")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireStateLock(
		statePath,
		100*time.Millisecond,
		"test-contender",
	); err == nil {
		t.Fatal("contending state operation unexpectedly acquired the lock")
	}
	holder.release()

	recovered, err := acquireStateLock(
		statePath,
		time.Second,
		"test-recovered",
	)
	if err != nil {
		t.Fatal(err)
	}
	recovered.release()
}

type testMetadata struct {
	Version int
	Hash    string
}

func readTestMetadata(t *testing.T, path string) testMetadata {
	t.Helper()
	data := readTestFile(t, path)
	var envelope struct {
		Signed struct {
			Version int `json:"version"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return testMetadata{
		Version: envelope.Signed.Version,
		Hash:    hex.EncodeToString(sum[:]),
	}
}

func readMetadataVersion(t *testing.T, path string) int {
	t.Helper()
	return readTestMetadata(t, path).Version
}

func readTestPublicationState(t *testing.T, layout tufLayout) publicationState {
	t.Helper()
	state, err := loadPublicationState(layout)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertCommittedLayout(t *testing.T, statePath string) {
	t.Helper()
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	sourceFingerprint, err := fingerprintSource(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)
	if err := validateCommittedPublication(layout, state, sourceFingerprint); err != nil {
		t.Fatal(err)
	}
}

func runUntilCrash(
	t *testing.T,
	statePath string,
	wanted publicationCheckpoint,
) {
	t.Helper()
	crashed := false
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				crashed = true
			}
		}()
		_, err := ensureTUFRepositoryWithHooks(
			statePath,
			publicationHooks{
				checkpoint: func(checkpoint publicationCheckpoint) error {
					if checkpoint == wanted {
						panic("simulated process interruption")
					}
					return nil
				},
			},
		)
		if err != nil {
			t.Fatalf("publication failed before checkpoint %s: %v", wanted, err)
		}
	}()
	if !crashed {
		t.Fatalf("publication did not reach checkpoint %s", wanted)
	}
}

func newTestState(t *testing.T) string {
	t.Helper()
	statePath := t.TempDir()
	generationPath := filepath.Join(
		statePath,
		"generations",
		initialGenerationID,
	)
	createdAt := time.Date(2026, time.August, 27, 0, 0, 0, 0, time.UTC)

	fulcioKey := newTestKey(t)
	fulcioDER := createTestCertificate(
		t,
		&x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{Organization: []string{"Test Fulcio"}, CommonName: "Fulcio Root"},
			NotBefore:             createdAt.Add(-time.Hour),
			NotAfter:              createdAt.AddDate(1, 0, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		},
		nil,
		fulcioKey,
		fulcioKey,
	)
	fulcioPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fulcioDER})
	writeTestFile(t, filepath.Join(generationPath, "public", "fulcio", "root.pem"), fulcioPEM)

	ctPEM := testPublicKeyPEM(t, newTestKey(t))
	writeTestFile(t, filepath.Join(generationPath, "public", "ctlog", "pubkey.pem"), ctPEM)
	rekorPEM := testPublicKeyPEM(t, newTestKey(t))
	writeTestFile(t, filepath.Join(generationPath, "public", "rekor", "signer.pub"), rekorPEM)

	tsaRootKey := newTestKey(t)
	tsaRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{Organization: []string{"Test TSA"}, CommonName: "TSA Root"},
		NotBefore:             createdAt.Add(-time.Hour),
		NotAfter:              createdAt.AddDate(1, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	tsaRootDER := createTestCertificate(
		t,
		tsaRootTemplate,
		nil,
		tsaRootKey,
		tsaRootKey,
	)
	tsaRootCertificate, err := x509.ParseCertificate(tsaRootDER)
	if err != nil {
		t.Fatal(err)
	}
	tsaLeafKey := newTestKey(t)
	tsaLeafDER := createTestCertificate(
		t,
		&x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{Organization: []string{"Test TSA"}, CommonName: "TSA Leaf"},
			NotBefore:    createdAt.Add(-time.Hour),
			NotAfter:     createdAt.AddDate(0, 6, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		},
		tsaRootCertificate,
		tsaLeafKey,
		tsaRootKey,
	)
	tsaChain := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tsaLeafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tsaRootDER})...,
	)
	writeTestFile(t, filepath.Join(generationPath, "public", "tsa", "cert-chain.pem"), tsaChain)
	writeTestFile(t, filepath.Join(generationPath, "private", "test.key"), []byte("test private material\n"))
	writeTestFile(
		t,
		filepath.Join(statePath, "data", "ctlog", "bootstrap-state"),
		[]byte("test-ct-log-state"),
	)
	writeTestFile(
		t,
		filepath.Join(statePath, "data", "rekor", "bootstrap-state"),
		[]byte("test-rekor-state"),
	)

	manifest := bootstrapManifest{
		SchemaVersion:        4,
		CreatedAtUTC:         createdAt,
		FulcioRootSHA256:     testHash(fulcioPEM),
		CtLogPublicKeySHA256: testHash(ctPEM),
		RekorPublicKeySHA256: testHash(rekorPEM),
		TsaRootSHA256:        testHash(tsaRootDER),
		TsaLeafSHA256:        testHash(tsaLeafDER),
		OIDCKeyID:            "test-oidc-key",
	}
	if err := os.MkdirAll(
		filepath.Join(statePath, "migration"),
		0o755,
	); err != nil {
		t.Fatal(err)
	}
	legacyManifestPath := filepath.Join(
		statePath,
		"migration",
		"bootstrap-manifest.schema-4.json",
	)
	if err := writeJSON(
		legacyManifestPath,
		manifest,
		0o444,
	); err != nil {
		t.Fatal(err)
	}
	domain := trustDomainManifest{
		SchemaVersion: trustStateSchemaVersion,
		TrustDomainID: "sha256-" + strings.Repeat("a", 64),
		CreatedAtUTC:  createdAt,
		CtLogStateID:  "test-ct-log-state",
		RekorStateID:  "test-rekor-state",
	}
	sourceManifestHash, err := hashFile(legacyManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	generation := generationManifest{
		SchemaVersion:        trustStateSchemaVersion,
		Generation:           initialGeneration,
		GenerationID:         initialGenerationID,
		TrustDomainID:        domain.TrustDomainID,
		CreatedAtUTC:         createdAt,
		SourceSchemaVersion:  4,
		SourceManifestSHA256: &sourceManifestHash,
		FulcioRootSHA256:     manifest.FulcioRootSHA256,
		CtLogPublicKeySHA256: manifest.CtLogPublicKeySHA256,
		RekorPublicKeySHA256: manifest.RekorPublicKeySHA256,
		TsaRootSHA256:        manifest.TsaRootSHA256,
		TsaLeafSHA256:        manifest.TsaLeafSHA256,
		OIDCKeyID:            manifest.OIDCKeyID,
	}
	files, err := collectGenerationFileHashes(generationPath)
	if err != nil {
		t.Fatal(err)
	}
	generation.Files = files
	if err := writeJSON(
		filepath.Join(generationPath, "manifest.json"),
		generation,
		0o444,
	); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(
		filepath.Join(statePath, "trust-domain.json"),
		domain,
		0o444,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(
		filepath.Join("generations", initialGenerationID),
		filepath.Join(statePath, "active-generation"),
	); err != nil {
		t.Fatal(err)
	}
	generationManifestHash, err := hashFile(
		filepath.Join(generationPath, "manifest.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	domainManifestHash, err := hashFile(
		filepath.Join(statePath, "trust-domain.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	journal := trustTransitionJournal{
		SchemaVersion:  trustTransitionSchemaVersion,
		Status:         "committed",
		LastCheckpoint: "transition-finalized",
		Candidate: generationReference{
			Generation:     initialGeneration,
			GenerationID:   initialGenerationID,
			ManifestSHA256: generationManifestHash,
		},
		TrustDomainManifestSHA256: domainManifestHash,
		TrustDomain:               domain,
		CandidateManifest:         generation,
	}
	if err := os.MkdirAll(
		filepath.Join(statePath, "transition"),
		0o755,
	); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(
		filepath.Join(statePath, "transition", "state.json"),
		journal,
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	return statePath
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func createTestCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	key *ecdsa.PrivateKey,
	signer *ecdsa.PrivateKey,
) []byte {
	t.Helper()
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		parent,
		&key.PublicKey,
		signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func testPublicKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func testHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
