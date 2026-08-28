package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	trustrootv1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// newFulcioRotationTestState builds a fresh trust-state fixture, publishes its
// initial TUF repository, and materializes the component-scoped runtime
// projection the C# bootstrapper is responsible for creating in production.
func newFulcioRotationTestState(t *testing.T) string {
	t.Helper()
	statePath := newTestState(t)
	if _, err := ensureTUFRepository(statePath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureRuntimeBaselineProjection(statePath); err != nil {
		t.Fatal(err)
	}
	return statePath
}

// fulcioCandidateMaterial holds a freshly generated, not-yet-installed Fulcio
// certificate authority plus the encrypted private key material needed to
// build a rotation candidate directory exactly as the C# host would.
type fulcioCandidateMaterial struct {
	certificate *x509.Certificate
	certPEM     []byte
	password    []byte
	key         *ecdsa.PrivateKey
}

func newFulcioCandidateMaterial(
	t *testing.T,
	serial int64,
	createdAt time.Time,
) fulcioCandidateMaterial {
	t.Helper()
	key := newTestKey(t)
	der := createTestCertificate(
		t,
		&x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject: pkix.Name{
				Organization: []string{"Test Fulcio"},
				CommonName:   fmt.Sprintf("Fulcio Root %d", serial),
			},
			NotBefore:             createdAt.Add(-time.Hour),
			NotAfter:              createdAt.AddDate(10, 0, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageDigitalSignature |
				x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign,
		},
		nil,
		key,
		key,
	)
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return fulcioCandidateMaterial{
		certificate: certificate,
		certPEM:     pemEncodeCertificate(der),
		password:    []byte(fmt.Sprintf("fulcio-candidate-password-%d", serial)),
		key:         key,
	}
}

// writeFulcioRotationCandidateFiles writes exactly the three files C# is
// contracted to produce under fulcio-rotation/<operationId>/candidate/.
func writeFulcioRotationCandidateFiles(
	t *testing.T,
	statePath string,
	operationID string,
	material fulcioCandidateMaterial,
) {
	t.Helper()
	candidatePath := filepath.Join(statePath, fulcioRotationDirectory, operationID, "candidate")
	writeTestFile(t, filepath.Join(candidatePath, "public", "fulcio", "root.pem"), material.certPEM)
	writeTestFile(t, filepath.Join(candidatePath, "private", "fulcio", "password"), material.password)
	writeTestFile(
		t,
		filepath.Join(candidatePath, "private", "fulcio", "root.key"),
		mustMarshalEncryptedECDSAKey(t, material.key, material.password),
	)
}

func writeFulcioRotationTestRequest(
	t *testing.T,
	statePath string,
	operationID string,
	material fulcioCandidateMaterial,
) fulcioRotationRequest {
	t.Helper()
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	request := fulcioRotationRequest{
		SchemaVersion:             fulcioRotationSchemaVersion,
		OperationID:               operationID,
		TrustDomainID:             active.TrustDomainID,
		StartingGeneration:        active.Generation,
		StartingGenerationID:      active.GenerationID,
		StartingFulcioRootSHA256:  active.FulcioRootSHA256,
		CandidateFulcioRootSHA256: hashDER(material.certificate.Raw),
	}
	if err := writeJSON(
		filepath.Join(statePath, fulcioRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return request
}

func stageFulcioRotation(
	t *testing.T,
	statePath string,
	serial int64,
	operationID string,
) (fulcioRotationRequest, fulcioCandidateMaterial) {
	t.Helper()
	material := newFulcioCandidateMaterial(t, serial, time.Now().UTC())
	writeFulcioRotationCandidateFiles(t, statePath, operationID, material)
	request := writeFulcioRotationTestRequest(t, statePath, operationID, material)
	return request, material
}

// promoteFulcioRuntimeProjection emulates the Hosting promotion step that runs
// after clients and Tesseract have restarted and the old CA has been proven:
// the staged projection is copied onto the stable runtime/fulcio path and the
// stage is consumed. The authoritative implementation lives in the C#
// bootstrapper (ActivateFulcioRuntimeProjection); this mirrors its effect so
// the worker's own lifecycle can be exercised end to end.
func promoteFulcioRuntimeProjection(t *testing.T, statePath string) {
	t.Helper()
	stagePath := runtimeComponentPath(statePath, runtimeFulcioNextComponent)
	fulcioPath := runtimeComponentPath(statePath, runtimeFulcioComponent)
	entries, err := os.ReadDir(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data := readTestFile(t, filepath.Join(stagePath, entry.Name()))
		mode := os.FileMode(0o644)
		if entry.Name() == runtimeFulcioRootKeyFile ||
			entry.Name() == runtimeFulcioPasswordFile {
			mode = 0o600
		}
		if err := writeRuntimeProjectionFile(
			filepath.Join(fulcioPath, entry.Name()),
			data,
			mode,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(stagePath); err != nil {
		t.Fatal(err)
	}
}

func readFulcioRotationTestCompletion(t *testing.T, statePath string) fulcioRotationCompletion {
	t.Helper()
	data := readTestFile(t, filepath.Join(statePath, fulcioRotationCompletionFile))
	var completion fulcioRotationCompletion
	if err := json.Unmarshal(data, &completion); err != nil {
		t.Fatal(err)
	}
	return completion
}

// activeFulcioFingerprints returns the ordered Fulcio certificate-authority
// fingerprints carried by the committed TrustedRoot.
func activeFulcioFingerprints(t *testing.T, statePath string) []string {
	t.Helper()
	entries, err := readActiveFulcioTrustEntries(statePath)
	if err != nil {
		t.Fatal(err)
	}
	fingerprints := make([]string, 0, len(entries))
	for _, entry := range entries {
		fingerprints = append(fingerprints, entry.fingerprint)
	}
	return fingerprints
}

func runtimeFile(t *testing.T, statePath, component, name string) []byte {
	t.Helper()
	return readTestFile(t, filepath.Join(statePath, runtimeDirectory, component, name))
}

func runtimeEntryNames(t *testing.T, statePath, component string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(statePath, runtimeDirectory, component))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func countActiveFulcioPrivateFiles(t *testing.T, statePath string) int {
	t.Helper()
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(
		statePath,
		"generations",
		active.GenerationID,
		"private",
		"fulcio",
	))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func assertFulcioRotationGeneration(
	t *testing.T,
	statePath string,
	generation int,
	operationID string,
	priorGeneration int,
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
	if manifest.FulcioRotationOperationID != operationID {
		t.Fatalf(
			"generation Fulcio operation = %q, want %q",
			manifest.FulcioRotationOperationID,
			operationID,
		)
	}
	if manifest.FulcioPriorGeneration != priorGeneration {
		t.Fatalf(
			"generation Fulcio prior generation = %d, want %d",
			manifest.FulcioPriorGeneration,
			priorGeneration,
		)
	}
	if err := validateFulcioGenerationMaterial(
		filepath.Join(statePath, "generations", active.GenerationID),
		manifest,
	); err != nil {
		t.Fatal(err)
	}
}

// assertGenerationManifestReadOnly asserts a committed generation manifest
// carries the read-only mode the C# bootstrapper requires. The Go worker must
// apply that mode explicitly, because os.WriteFile's creation mode is only a
// hint and is ignored outright by some bind-mounted filesystems.
func assertGenerationManifestReadOnly(t *testing.T, statePath, generationID string) {
	t.Helper()
	path := filepath.Join(generationPathFor(statePath, generationID), "manifest.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != generationManifestMode {
		t.Fatalf("generation manifest mode = %o, want %o", got, generationManifestMode)
	}
}

// TestWriteGenerationManifestCorrectsModeExplicitly reproduces the failure
// mode observed on a Docker Desktop bind mount, where the mode passed to
// os.WriteFile is not applied and the manifest lands as 0644. Starting from a
// pre-existing file makes the behaviour deterministic on any filesystem,
// because os.WriteFile never changes the mode of a file that already exists.
func TestWriteGenerationManifestCorrectsModeExplicitly(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		prepare func(t *testing.T, path string)
	}{
		{
			name:    "fresh file",
			prepare: func(*testing.T, string) {},
		},
		{
			name: "filesystem materialized the manifest as 0644",
			prepare: func(t *testing.T, path string) {
				writeTestFile(t, path, []byte("stale\n"))
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "read-only manifest left by an interrupted attempt",
			prepare: func(t *testing.T, path string) {
				writeTestFile(t, path, []byte("stale\n"))
				if err := os.Chmod(path, generationManifestMode); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			testCase.prepare(t, path)

			data := []byte("{\"schemaVersion\": 5}\n")
			if err := writeGenerationManifest(path, data); err != nil {
				t.Fatal(err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != generationManifestMode {
				t.Fatalf("manifest mode = %o, want %o", got, generationManifestMode)
			}
			if got := readTestFile(t, path); string(got) != string(data) {
				t.Fatalf("manifest contents = %q, want %q", got, data)
			}
		})
	}
}

func TestFulcioRotationAppendsAuthorityAndPreservesRoutingAndNonFulcioTargets(t *testing.T) {
	statePath := newFulcioRotationTestState(t)
	layout := newTUFLayout(statePath)

	before := readTestPublicationState(t, layout)
	activeBefore := committedPath(layout, before.Active.ID)
	rootBefore := readTestMetadata(t, filepath.Join(activeBefore, "repository", "root.json"))
	ctfeBefore := readTestFile(t, filepath.Join(activeBefore, "targets", "ctfe.pub"))
	rekorBefore := readTestFile(t, filepath.Join(activeBefore, "targets", "rekor.pub"))
	tsaChainBefore := readTestFile(t, filepath.Join(activeBefore, "targets", "tsa.certchain.pem"))
	tsaLeafBefore := readTestFile(t, filepath.Join(activeBefore, "targets", "tsa_leaf.crt.pem"))
	tsaRootBefore := readTestFile(t, filepath.Join(activeBefore, "targets", "tsa_root.crt.pem"))
	signingConfigBefore := readTestFile(
		t,
		filepath.Join(activeBefore, "targets", "signing_config.v0.2.json"),
	)
	targetsBefore := readTestMetadata(t, filepath.Join(activeBefore, "repository", "targets.json"))
	snapshotBefore := readTestMetadata(t, filepath.Join(activeBefore, "repository", "snapshot.json"))
	timestampBefore := readTestMetadata(t, filepath.Join(activeBefore, "repository", "timestamp.json"))
	bootstrapBefore := readTestFile(t, layout.bootstrapRoot)

	fingerprintsBefore := activeFulcioFingerprints(t, statePath)
	if len(fingerprintsBefore) != 1 {
		t.Fatalf("initial Fulcio authority count = %d, want 1", len(fingerprintsBefore))
	}

	_, material := stageFulcioRotation(t, statePath, 100, "10000000000000000000000000000001")
	action, err := dispatchFulcioRotation(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if action != repositoryActionPublished {
		t.Fatalf("action = %q, want %q", action, repositoryActionPublished)
	}

	assertFulcioRotationGeneration(t, statePath, 2, "10000000000000000000000000000001", 1)
	assertGenerationManifestReadOnly(t, statePath, "generation-00000002")

	fingerprintsAfter := activeFulcioFingerprints(t, statePath)
	if len(fingerprintsAfter) != 2 {
		t.Fatalf("post-rotation Fulcio authority count = %d, want 2", len(fingerprintsAfter))
	}
	if fingerprintsAfter[0] != fingerprintsBefore[0] {
		t.Fatal("Fulcio rotation did not preserve the prior certificate authority first")
	}
	if fingerprintsAfter[1] != hashDER(material.certificate.Raw) {
		t.Fatal("Fulcio rotation did not append the candidate certificate authority last")
	}

	after := readTestPublicationState(t, layout)
	activeAfter := committedPath(layout, after.Active.ID)
	if got := readTestFile(t, filepath.Join(activeAfter, "targets", fulcioTargetName)); string(got) != string(material.certPEM) {
		t.Fatal("fulcio_v1.crt.pem was not replaced with the rotated root")
	}
	for _, unchanged := range []struct {
		name   string
		before []byte
	}{
		{"ctfe.pub", ctfeBefore},
		{"rekor.pub", rekorBefore},
		{"tsa.certchain.pem", tsaChainBefore},
		{"tsa_leaf.crt.pem", tsaLeafBefore},
		{"tsa_root.crt.pem", tsaRootBefore},
		{"signing_config.v0.2.json", signingConfigBefore},
	} {
		got := readTestFile(t, filepath.Join(activeAfter, "targets", unchanged.name))
		if string(got) != string(unchanged.before) {
			t.Fatalf("%s bytes changed during Fulcio rotation", unchanged.name)
		}
	}

	rootAfter := readTestMetadata(t, filepath.Join(activeAfter, "repository", "root.json"))
	if rootAfter.Version != rootBefore.Version || rootAfter.Hash != rootBefore.Hash {
		t.Fatal("TUF root was changed by a Fulcio rotation")
	}
	targetsAfter := readTestMetadata(t, filepath.Join(activeAfter, "repository", "targets.json"))
	if targetsAfter.Version != targetsBefore.Version+1 {
		t.Fatalf("targets version = %d, want %d", targetsAfter.Version, targetsBefore.Version+1)
	}
	snapshotAfter := readTestMetadata(t, filepath.Join(activeAfter, "repository", "snapshot.json"))
	if snapshotAfter.Version != snapshotBefore.Version+1 {
		t.Fatalf("snapshot version = %d, want %d", snapshotAfter.Version, snapshotBefore.Version+1)
	}
	timestampAfter := readTestMetadata(t, filepath.Join(activeAfter, "repository", "timestamp.json"))
	if timestampAfter.Version != timestampBefore.Version+1 {
		t.Fatalf("timestamp version = %d, want %d", timestampAfter.Version, timestampBefore.Version+1)
	}
	if string(readTestFile(t, layout.bootstrapRoot)) != string(bootstrapBefore) {
		t.Fatal("immutable bootstrap root changed during Fulcio rotation")
	}

	completion := readFulcioRotationTestCompletion(t, statePath)
	if completion.FulcioTrustEntryCount != 2 {
		t.Fatalf("completion Fulcio authority count = %d, want 2", completion.FulcioTrustEntryCount)
	}
	if completion.PublicationID != after.Active.ID ||
		completion.PublicationManifestSHA256 != after.Active.ManifestSHA256 {
		t.Fatal("completion does not bind the active TUF publication")
	}
	if strings.Join(completion.AcceptedRootFingerprints, ",") != strings.Join(fingerprintsAfter, ",") {
		t.Fatal("completion accepted-root fingerprints do not match the active TrustedRoot")
	}
	if pathExists(filepath.Join(statePath, fulcioRotationRequestFile)) {
		t.Fatal("rotation request file was not removed after completion")
	}
	if pathExists(filepath.Join(
		statePath,
		fulcioRotationDirectory,
		"10000000000000000000000000000001",
		"candidate",
		"private",
	)) {
		t.Fatal("completed rotation retained its private candidate material")
	}
}

func TestFulcioRotationUpdatesRuntimeProjectionAndPreservesCtKey(t *testing.T) {
	statePath := newFulcioRotationTestState(t)

	ctKeyBefore := runtimeFile(t, statePath, runtimeTesseractComponent, runtimeTesseractKeyFile)
	rootBefore := runtimeFile(t, statePath, runtimeFulcioComponent, runtimeFulcioRootCertFile)
	acceptedBefore := runtimeFile(t, statePath, runtimeTesseractComponent, runtimeAcceptedRootsFile)

	_, material := stageFulcioRotation(t, statePath, 200, "20000000000000000000000000000001")
	if _, err := dispatchFulcioRotation(statePath); err != nil {
		t.Fatal(err)
	}

	if got := runtimeEntryNames(t, statePath, runtimeFulcioComponent); strings.Join(got, ",") !=
		"ctlog.pub,password,root.key,root.pem" {
		t.Fatalf("runtime/fulcio entries = %v", got)
	}
	if got := runtimeEntryNames(t, statePath, runtimeTesseractComponent); strings.Join(got, ",") !=
		"accepted-roots.pem,privkey.pem" {
		t.Fatalf("runtime/tesseract entries = %v", got)
	}

	if string(runtimeFile(t, statePath, runtimeTesseractComponent, runtimeTesseractKeyFile)) !=
		string(ctKeyBefore) {
		t.Fatal("Fulcio rotation changed the projected CT log signing key")
	}

	// The worker must NOT activate the new CA: Fulcio keeps serving the old
	// root until Hosting promotes after the old-CA proof.
	if string(runtimeFile(t, statePath, runtimeFulcioComponent, runtimeFulcioRootCertFile)) !=
		string(rootBefore) {
		t.Fatal("the worker activated the rotated Fulcio root before promotion")
	}
	if got := runtimeEntryNames(t, statePath, runtimeFulcioNextComponent); strings.Join(got, ",") !=
		"ctlog.pub,password,root.key,root.pem" {
		t.Fatalf("runtime/fulcio.next entries = %v", got)
	}

	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	generationPath := filepath.Join(statePath, "generations", active.GenerationID)
	priorGenerationPath := filepath.Join(statePath, "generations", "generation-00000001")
	for _, projected := range []struct {
		name   string
		source string
	}{
		{runtimeFulcioRootCertFile, fulcioRootCertRelPath},
		{runtimeFulcioRootKeyFile, fulcioRootKeyRelPath},
		{runtimeFulcioPasswordFile, fulcioPasswordRelPath},
		{runtimeFulcioCtLogKeyFile, ctLogPublicKeyRelPath},
	} {
		if string(runtimeFile(t, statePath, runtimeFulcioNextComponent, projected.name)) !=
			string(readTestFile(t, filepath.Join(
				generationPath,
				filepath.FromSlash(projected.source),
			))) {
			t.Fatalf("staged runtime/fulcio.next/%s does not match the rotated generation", projected.name)
		}
		if string(runtimeFile(t, statePath, runtimeFulcioComponent, projected.name)) !=
			string(readTestFile(t, filepath.Join(
				priorGenerationPath,
				filepath.FromSlash(projected.source),
			))) {
			t.Fatalf("active runtime/fulcio/%s no longer serves the prior generation", projected.name)
		}
	}
	if string(runtimeFile(t, statePath, runtimeFulcioNextComponent, runtimeFulcioRootCertFile)) !=
		string(material.certPEM) {
		t.Fatal("the staged Fulcio projection is not the rotated candidate")
	}

	acceptedAfter := runtimeFile(t, statePath, runtimeTesseractComponent, runtimeAcceptedRootsFile)
	expected := string(acceptedBefore) + string(material.certPEM)
	if string(acceptedAfter) != expected {
		t.Fatal("accepted-roots.pem is not the prior root followed by the rotated root")
	}
	if err := validateAcceptedRootsBundleBytes(acceptedAfter, active.FulcioRootSHA256); err != nil {
		t.Fatal(err)
	}
	completion := readFulcioRotationTestCompletion(t, statePath)
	if completion.AcceptedRootsSHA256 != hashBytes(acceptedAfter) {
		t.Fatal("completion acceptedRootsSha256 does not match the projected bundle")
	}
	if completion.ActiveFulcioRuntimeRootSHA256 != completion.PriorFulcioRootSHA256 ||
		completion.StagedFulcioRuntimeRootSHA256 != completion.NewFulcioRootSHA256 {
		t.Fatal("completion does not bind the pre-activation runtime condition")
	}

	// Promotion is the only step that activates the new CA.
	promoteFulcioRuntimeProjection(t, statePath)
	if string(runtimeFile(t, statePath, runtimeFulcioComponent, runtimeFulcioRootCertFile)) !=
		string(material.certPEM) {
		t.Fatal("promotion did not activate the rotated Fulcio root")
	}
	if pathExists(filepath.Join(statePath, runtimeDirectory, runtimeFulcioNextComponent)) {
		t.Fatal("promotion did not consume the staged projection")
	}
}

func TestFulcioRotationRepeatAppendsDeterministicallyAndBoundsActiveSecrets(t *testing.T) {
	statePath := newFulcioRotationTestState(t)
	generationOnePath := filepath.Join(statePath, "generations", "generation-00000001")
	generationOneRoot := readTestFile(t, filepath.Join(
		generationOnePath,
		filepath.FromSlash(fulcioRootCertRelPath),
	))

	_, first := stageFulcioRotation(t, statePath, 300, "30000000000000000000000000000001")
	if action, err := dispatchFulcioRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("first rotation action = %q, want %q", action, repositoryActionPublished)
	}
	assertFulcioRotationGeneration(t, statePath, 2, "30000000000000000000000000000001", 1)
	if count := countActiveFulcioPrivateFiles(t, statePath); count != 2 {
		t.Fatalf("generation 2 private/fulcio file count = %d, want 2 (root.key + password)", count)
	}

	// A second rotation is refused while the first is still awaiting the
	// Hosting promotion that activates its CA.
	stageFulcioRotation(t, statePath, 350, "35000000000000000000000000000001")
	if _, err := dispatchFulcioRotation(statePath); err == nil {
		t.Fatal("rotation started while a previous promotion was still pending")
	}
	if err := os.Remove(filepath.Join(statePath, fulcioRotationRequestFile)); err != nil {
		t.Fatal(err)
	}
	promoteFulcioRuntimeProjection(t, statePath)

	_, second := stageFulcioRotation(t, statePath, 400, "40000000000000000000000000000001")
	if action, err := dispatchFulcioRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("second rotation action = %q, want %q", action, repositoryActionPublished)
	}
	assertFulcioRotationGeneration(t, statePath, 3, "40000000000000000000000000000001", 2)
	assertGenerationManifestReadOnly(t, statePath, "generation-00000003")
	if count := countActiveFulcioPrivateFiles(t, statePath); count != 2 {
		t.Fatalf(
			"generation 3 private/fulcio file count = %d, want 2 (repeat rotation must not grow active secrets)",
			count,
		)
	}

	fingerprints := activeFulcioFingerprints(t, statePath)
	if len(fingerprints) != 3 {
		t.Fatalf("Fulcio authority count after two rotations = %d, want 3", len(fingerprints))
	}
	if fingerprints[1] != hashDER(first.certificate.Raw) ||
		fingerprints[2] != hashDER(second.certificate.Raw) {
		t.Fatal("repeated rotation did not append history in deterministic order")
	}
	seen := map[string]bool{}
	for _, fingerprint := range fingerprints {
		if seen[fingerprint] {
			t.Fatal("repeated rotation produced duplicate accepted roots")
		}
		seen[fingerprint] = true
	}

	// Immutable prior generations remain intact as rollback history.
	if string(readTestFile(t, filepath.Join(
		generationOnePath,
		filepath.FromSlash(fulcioRootCertRelPath),
	))) != string(generationOneRoot) {
		t.Fatal("rotation mutated the immutable prior generation's Fulcio root")
	}
	if !pathExists(filepath.Join(generationOnePath, filepath.FromSlash(fulcioRootKeyRelPath))) {
		t.Fatal("rotation deleted the immutable prior generation's Fulcio root key")
	}

	accepted := runtimeFile(t, statePath, runtimeTesseractComponent, runtimeAcceptedRootsFile)
	if !strings.HasSuffix(string(accepted), string(second.certPEM)) {
		t.Fatal("accepted-roots.pem does not end with the newest root")
	}
	if string(runtimeFile(t, statePath, runtimeFulcioComponent, runtimeFulcioRootCertFile)) !=
		string(first.certPEM) {
		t.Fatal("the second rotation activated its CA before promotion")
	}
	if string(runtimeFile(t, statePath, runtimeFulcioNextComponent, runtimeFulcioRootCertFile)) !=
		string(second.certPEM) {
		t.Fatal("the second rotation did not stage its CA")
	}
}

func TestFulcioRotationRejectsTamperedCandidate(t *testing.T) {
	t.Run("candidate fingerprint mismatch", func(t *testing.T) {
		statePath := newFulcioRotationTestState(t)
		material := newFulcioCandidateMaterial(t, 500, time.Now().UTC())
		operationID := "50000000000000000000000000000001"
		writeFulcioRotationCandidateFiles(t, statePath, operationID, material)
		request := writeFulcioRotationTestRequest(t, statePath, operationID, material)
		request.CandidateFulcioRootSHA256 = hashDER([]byte("not-a-real-certificate"))
		if err := writeJSON(filepath.Join(statePath, fulcioRotationRequestFile), request, 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := dispatchFulcioRotation(statePath); err == nil {
			t.Fatal("rotation accepted a request/candidate fingerprint mismatch")
		}
		active, err := loadActiveTrustGeneration(statePath)
		if err != nil {
			t.Fatal(err)
		}
		if active.Generation != 1 {
			t.Fatalf("tampered candidate advanced generation to %d", active.Generation)
		}
	})

	t.Run("extra file in candidate directory", func(t *testing.T) {
		statePath := newFulcioRotationTestState(t)
		material := newFulcioCandidateMaterial(t, 510, time.Now().UTC())
		operationID := "51000000000000000000000000000001"
		writeFulcioRotationCandidateFiles(t, statePath, operationID, material)
		candidatePath := filepath.Join(statePath, fulcioRotationDirectory, operationID, "candidate")
		writeTestFile(
			t,
			filepath.Join(candidatePath, "public", "fulcio", "extra.pem"),
			material.certPEM,
		)
		writeFulcioRotationTestRequest(t, statePath, operationID, material)

		if _, err := dispatchFulcioRotation(statePath); err == nil {
			t.Fatal("rotation accepted a candidate with an unexpected extra file")
		} else if !strings.Contains(err.Error(), "files") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("root key does not match certificate", func(t *testing.T) {
		statePath := newFulcioRotationTestState(t)
		material := newFulcioCandidateMaterial(t, 520, time.Now().UTC())
		operationID := "52000000000000000000000000000001"
		writeFulcioRotationCandidateFiles(t, statePath, operationID, material)
		candidatePath := filepath.Join(statePath, fulcioRotationDirectory, operationID, "candidate")
		writeTestFile(
			t,
			filepath.Join(candidatePath, "private", "fulcio", "root.key"),
			mustMarshalEncryptedECDSAKey(t, newTestKey(t), material.password),
		)
		writeFulcioRotationTestRequest(t, statePath, operationID, material)

		if _, err := dispatchFulcioRotation(statePath); err == nil {
			t.Fatal("rotation accepted a root key that does not match its certificate")
		} else if !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		statePath := newFulcioRotationTestState(t)
		material := newFulcioCandidateMaterial(t, 525, time.Now().UTC())
		operationID := "52500000000000000000000000000001"
		writeFulcioRotationCandidateFiles(t, statePath, operationID, material)
		candidatePath := filepath.Join(statePath, fulcioRotationDirectory, operationID, "candidate")
		writeTestFile(
			t,
			filepath.Join(candidatePath, "private", "fulcio", "password"),
			[]byte("a-different-password"),
		)
		writeFulcioRotationTestRequest(t, statePath, operationID, material)

		if _, err := dispatchFulcioRotation(statePath); err == nil {
			t.Fatal("rotation accepted a candidate whose password does not decrypt its key")
		}
	})

	t.Run("certificate is not a certificate authority", func(t *testing.T) {
		statePath := newFulcioRotationTestState(t)
		key := newTestKey(t)
		der := createTestCertificate(
			t,
			&x509.Certificate{
				SerialNumber:          big.NewInt(530),
				Subject:               pkix.Name{Organization: []string{"Test Fulcio"}, CommonName: "Bad Fulcio"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().AddDate(1, 0, 0),
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageDigitalSignature,
			},
			nil,
			key,
			key,
		)
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		material := fulcioCandidateMaterial{
			certificate: certificate,
			certPEM:     pemEncodeCertificate(der),
			password:    []byte("bad-ca-password"),
			key:         key,
		}
		operationID := "53000000000000000000000000000001"
		writeFulcioRotationCandidateFiles(t, statePath, operationID, material)
		writeFulcioRotationTestRequest(t, statePath, operationID, material)

		if _, err := dispatchFulcioRotation(statePath); err == nil {
			t.Fatal("rotation accepted a non-CA Fulcio certificate")
		} else if !strings.Contains(err.Error(), "CA") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("certificate has the wrong key usage", func(t *testing.T) {
		statePath := newFulcioRotationTestState(t)
		key := newTestKey(t)
		der := createTestCertificate(
			t,
			&x509.Certificate{
				SerialNumber:          big.NewInt(540),
				Subject:               pkix.Name{Organization: []string{"Test Fulcio"}, CommonName: "Bad Fulcio Usage"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().AddDate(1, 0, 0),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			},
			nil,
			key,
			key,
		)
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		material := fulcioCandidateMaterial{
			certificate: certificate,
			certPEM:     pemEncodeCertificate(der),
			password:    []byte("bad-usage-password"),
			key:         key,
		}
		operationID := "54000000000000000000000000000001"
		writeFulcioRotationCandidateFiles(t, statePath, operationID, material)
		writeFulcioRotationTestRequest(t, statePath, operationID, material)

		if _, err := dispatchFulcioRotation(statePath); err == nil {
			t.Fatal("rotation accepted a Fulcio certificate with the wrong key usage")
		} else if !strings.Contains(err.Error(), "key usage") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestFulcioRotationRejectsRequestForAnotherTrustDomain(t *testing.T) {
	statePath := newFulcioRotationTestState(t)
	material := newFulcioCandidateMaterial(t, 600, time.Now().UTC())
	operationID := "60000000000000000000000000000001"
	writeFulcioRotationCandidateFiles(t, statePath, operationID, material)
	request := writeFulcioRotationTestRequest(t, statePath, operationID, material)
	request.TrustDomainID = "sha256-" + strings.Repeat("b", 64)
	if err := writeJSON(filepath.Join(statePath, fulcioRotationRequestFile), request, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := dispatchFulcioRotation(statePath); err == nil {
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

func TestFulcioRotationCompletionReplayIsIdempotent(t *testing.T) {
	statePath := newFulcioRotationTestState(t)
	request, _ := stageFulcioRotation(t, statePath, 700, "70000000000000000000000000000001")
	if action, err := dispatchFulcioRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("first action = %q, want %q", action, repositoryActionPublished)
	}
	completionBefore := readTestFile(t, filepath.Join(statePath, fulcioRotationCompletionFile))
	acceptedBefore := runtimeFile(t, statePath, runtimeTesseractComponent, runtimeAcceptedRootsFile)

	if err := writeJSON(
		filepath.Join(statePath, fulcioRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	action, err := dispatchFulcioRotation(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if action != repositoryActionPublished {
		t.Fatalf("replay action = %q, want %q", action, repositoryActionPublished)
	}
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if active.Generation != 2 {
		t.Fatalf("replay advanced generation to %d", active.Generation)
	}
	if string(readTestFile(t, filepath.Join(statePath, fulcioRotationCompletionFile))) !=
		string(completionBefore) {
		t.Fatal("idempotent replay changed the durable completion record")
	}
	if string(runtimeFile(t, statePath, runtimeTesseractComponent, runtimeAcceptedRootsFile)) !=
		string(acceptedBefore) {
		t.Fatal("idempotent replay changed the accepted-root projection")
	}
	if pathExists(filepath.Join(statePath, fulcioRotationRequestFile)) {
		t.Fatal("idempotent replay did not remove the request file")
	}
	if pathExists(filepath.Join(statePath, "generations", "generation-00000003")) {
		t.Fatal("idempotent replay created a duplicate generation")
	}
}

func TestFulcioRotationRejectsTamperedCompletionReplay(t *testing.T) {
	statePath := newFulcioRotationTestState(t)
	request, _ := stageFulcioRotation(t, statePath, 800, "80000000000000000000000000000001")
	if _, err := dispatchFulcioRotation(statePath); err != nil {
		t.Fatal(err)
	}

	completion := readFulcioRotationTestCompletion(t, statePath)
	completion.FulcioTrustEntryCount += 5
	completion.AcceptedRootFingerprints = append(
		completion.AcceptedRootFingerprints,
		strings.Repeat("c", 64),
		strings.Repeat("d", 64),
		strings.Repeat("e", 64),
		strings.Repeat("f", 64),
		strings.Repeat("a", 64),
	)
	if err := writeJSON(
		filepath.Join(statePath, fulcioRotationCompletionFile),
		completion,
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(
		filepath.Join(statePath, fulcioRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := dispatchFulcioRotation(statePath); err == nil {
		t.Fatal("rotation replay accepted a tampered completion record")
	}
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if active.Generation != 2 {
		t.Fatalf("tampered completion replay changed the active generation to %d", active.Generation)
	}
}

func TestFulcioRotationRejectsTamperedTrustedRootOnReplay(t *testing.T) {
	statePath := newFulcioRotationTestState(t)
	request, _ := stageFulcioRotation(t, statePath, 810, "81000000000000000000000000000001")
	if _, err := dispatchFulcioRotation(statePath); err != nil {
		t.Fatal(err)
	}

	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)
	trustedRootPath := filepath.Join(
		committedPath(layout, state.Active.ID),
		"targets",
		"trusted_root.json",
	)
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(readTestFile(t, trustedRootPath), trustedRoot); err != nil {
		t.Fatal(err)
	}
	// Drop the prior certificate authority, simulating a TrustedRoot that no
	// longer additively preserves rotation history.
	trustedRoot.CertificateAuthorities = trustedRoot.CertificateAuthorities[1:]
	tampered, err := protojson.Marshal(trustedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustedRootPath, append(tampered, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeJSON(
		filepath.Join(statePath, fulcioRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := dispatchFulcioRotation(statePath); err == nil {
		t.Fatal("rotation replay accepted a tampered trusted_root.json")
	}
}

func TestFulcioRotationRejectsTamperedRuntimeProjectionOnReplay(t *testing.T) {
	for _, tamper := range []struct {
		name string
		mut  func(t *testing.T, statePath string)
	}{
		{
			name: "extra file",
			mut: func(t *testing.T, statePath string) {
				writeTestFile(
					t,
					filepath.Join(statePath, runtimeDirectory, runtimeFulcioComponent, "stray.pem"),
					[]byte("stray\n"),
				)
			},
		},
		{
			name: "unrelated accepted root",
			mut: func(t *testing.T, statePath string) {
				material := newFulcioCandidateMaterial(t, 999, time.Now().UTC())
				path := filepath.Join(
					statePath,
					runtimeDirectory,
					runtimeTesseractComponent,
					runtimeAcceptedRootsFile,
				)
				existing := readTestFile(t, path)
				if err := os.WriteFile(
					path,
					append(append([]byte(nil), existing...), material.certPEM...),
					0o644,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "duplicated accepted root",
			mut: func(t *testing.T, statePath string) {
				path := filepath.Join(
					statePath,
					runtimeDirectory,
					runtimeTesseractComponent,
					runtimeAcceptedRootsFile,
				)
				existing := readTestFile(t, path)
				if err := os.WriteFile(
					path,
					append(append([]byte(nil), existing...), existing...),
					0o644,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed bundle",
			mut: func(t *testing.T, statePath string) {
				path := filepath.Join(
					statePath,
					runtimeDirectory,
					runtimeTesseractComponent,
					runtimeAcceptedRootsFile,
				)
				existing := readTestFile(t, path)
				if err := os.WriteFile(
					path,
					append(append([]byte(nil), existing...), []byte("not pem\n")...),
					0o644,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "tampered staged projection",
			mut: func(t *testing.T, statePath string) {
				material := newFulcioCandidateMaterial(t, 998, time.Now().UTC())
				if err := os.WriteFile(
					filepath.Join(
						runtimeComponentPath(statePath, runtimeFulcioNextComponent),
						runtimeFulcioRootCertFile,
					),
					material.certPEM,
					0o644,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "extra file in staged projection",
			mut: func(t *testing.T, statePath string) {
				writeTestFile(
					t,
					filepath.Join(
						runtimeComponentPath(statePath, runtimeFulcioNextComponent),
						"stray.pem",
					),
					[]byte("stray\n"),
				)
			},
		},
		{
			name: "stale projected fulcio key",
			mut: func(t *testing.T, statePath string) {
				path := filepath.Join(
					statePath,
					runtimeDirectory,
					runtimeFulcioComponent,
					runtimeFulcioRootKeyFile,
				)
				if err := os.WriteFile(path, []byte("tampered\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tamper.name, func(t *testing.T) {
			statePath := newFulcioRotationTestState(t)
			request, _ := stageFulcioRotation(t, statePath, 820, "82000000000000000000000000000001")
			if _, err := dispatchFulcioRotation(statePath); err != nil {
				t.Fatal(err)
			}
			tamper.mut(t, statePath)
			if err := writeJSON(
				filepath.Join(statePath, fulcioRotationRequestFile),
				request,
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			if _, err := dispatchFulcioRotation(statePath); err == nil {
				t.Fatal("rotation replay accepted a tampered runtime projection")
			}
		})
	}
}

func TestValidateAndReuseFulcioGenerationValidatesCompleteMaterial(t *testing.T) {
	t.Run("valid generation", func(t *testing.T) {
		statePath := newFulcioRotationTestState(t)
		current, request, nextPath, nextID := createReusableFulcioGeneration(
			t,
			statePath,
			900,
			"90000000000000000000000000000001",
		)
		reused, err := validateAndReuseFulcioGeneration(
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
		statePath := newFulcioRotationTestState(t)
		current, request, nextPath, nextID := createReusableFulcioGeneration(
			t,
			statePath,
			910,
			"91000000000000000000000000000001",
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
		if err := writeJSON(filepath.Join(nextPath, "manifest.json"), manifest, 0o644); err != nil {
			t.Fatal(err)
		}

		if _, err := validateAndReuseFulcioGeneration(
			statePath,
			current,
			nextPath,
			nextID,
			current.Generation+1,
			request,
		); err == nil {
			t.Fatal("reused generation with empty material was accepted")
		}
	})

	t.Run("tampered certificate hash", func(t *testing.T) {
		statePath := newFulcioRotationTestState(t)
		current, request, nextPath, nextID := createReusableFulcioGeneration(
			t,
			statePath,
			920,
			"92000000000000000000000000000001",
		)
		manifest, err := readOIDCGenerationManifest(statePath, nextID)
		if err != nil {
			t.Fatal(err)
		}
		manifest.FulcioRootSHA256 = hashDER([]byte("tampered"))
		if err := writeJSON(filepath.Join(nextPath, "manifest.json"), manifest, 0o644); err != nil {
			t.Fatal(err)
		}

		if _, err := validateAndReuseFulcioGeneration(
			statePath,
			current,
			nextPath,
			nextID,
			current.Generation+1,
			request,
		); err == nil {
			t.Fatal("reused generation with a tampered manifest hash was accepted")
		}
	})

	t.Run("generation bound to another operation", func(t *testing.T) {
		statePath := newFulcioRotationTestState(t)
		current, request, nextPath, nextID := createReusableFulcioGeneration(
			t,
			statePath,
			930,
			"93000000000000000000000000000001",
		)
		request.OperationID = "93000000000000000000000000000002"
		if _, err := validateAndReuseFulcioGeneration(
			statePath,
			current,
			nextPath,
			nextID,
			current.Generation+1,
			request,
		); err == nil {
			t.Fatal("reused generation bound to a different operation was accepted")
		}
	})
}

func createReusableFulcioGeneration(
	t *testing.T,
	statePath string,
	serial int64,
	operationID string,
) (bootstrapManifest, fulcioRotationRequest, string, string) {
	t.Helper()
	current, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := stageFulcioRotation(t, statePath, serial, operationID)
	next, err := rotateFulcioGeneration(statePath, current, request)
	if err != nil {
		t.Fatal(err)
	}
	return current, request, filepath.Join(statePath, "generations", next.GenerationID), next.GenerationID
}

func TestFulcioRotationRecoversEveryCommittedBoundaryExactlyOnce(t *testing.T) {
	checkpoints := []publicationCheckpoint{
		"fulcio-generation-committed",
		checkpointCandidatePrepared,
		checkpointHistoryParked,
		checkpointCandidateCommitted,
		checkpointActiveSwitched,
		"fulcio-tuf-committed",
		"fulcio-generation-switched",
		"fulcio-runtime-projected",
		"fulcio-completion-written",
	}
	for index, checkpoint := range checkpoints {
		t.Run(string(checkpoint), func(t *testing.T) {
			statePath := newFulcioRotationTestState(t)
			operationID := fmt.Sprintf("%032x", index+1000)
			request, material := stageFulcioRotation(t, statePath, int64(1000+index), operationID)
			priorRoot := runtimeFile(t, statePath, runtimeFulcioComponent, runtimeFulcioRootCertFile)

			crashed := false
			func() {
				defer func() {
					if recover() != nil {
						crashed = true
					}
				}()
				_, err := dispatchFulcioRotationWithHooks(
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

			// The active Fulcio projection must never change without an
			// explicit Hosting promotion, at any interruption point.
			if string(runtimeFile(
				t,
				statePath,
				runtimeFulcioComponent,
				runtimeFulcioRootCertFile,
			)) != string(priorRoot) {
				t.Fatalf(
					"checkpoint %s activated the rotated CA without promotion",
					checkpoint,
				)
			}

			if _, err := dispatchFulcioRotation(statePath); err != nil {
				t.Fatalf("recover checkpoint %s: %v", checkpoint, err)
			}
			assertFulcioRotationGeneration(t, statePath, 2, request.OperationID, 1)
			if pathExists(filepath.Join(statePath, "generations", "generation-00000003")) {
				t.Fatalf("checkpoint %s created a duplicate generation", checkpoint)
			}
			if pathExists(filepath.Join(statePath, fulcioRotationRequestFile)) {
				t.Fatalf("checkpoint %s recovery did not remove the request file", checkpoint)
			}
			fingerprints := activeFulcioFingerprints(t, statePath)
			if len(fingerprints) != 2 {
				t.Fatalf(
					"checkpoint %s: Fulcio authority count = %d, want 2",
					checkpoint,
					len(fingerprints),
				)
			}
			if string(runtimeFile(
				t,
				statePath,
				runtimeFulcioComponent,
				runtimeFulcioRootCertFile,
			)) != string(priorRoot) {
				t.Fatalf("checkpoint %s recovery activated the rotated CA early", checkpoint)
			}
			if string(runtimeFile(
				t,
				statePath,
				runtimeFulcioNextComponent,
				runtimeFulcioRootCertFile,
			)) != string(material.certPEM) {
				t.Fatalf("checkpoint %s recovery did not stage the rotated Fulcio root", checkpoint)
			}
			accepted := runtimeFile(t, statePath, runtimeTesseractComponent, runtimeAcceptedRootsFile)
			if string(accepted) != string(priorRoot)+string(material.certPEM) {
				t.Fatalf("checkpoint %s recovery produced a wrong accepted-root bundle", checkpoint)
			}
		})
	}
}

// TestFulcioRotationRepairsPartialRuntimeProjection simulates a crash that
// left the projection half written after the active-generation switch: the
// staged CA was only partially materialized and the Tesseract accepted-root
// bundle never landed. Replaying the operation-bound request must repair the
// whole projection without ever activating the new CA.
func TestFulcioRotationRepairsPartialRuntimeProjection(t *testing.T) {
	statePath := newFulcioRotationTestState(t)
	operationID := "aa000000000000000000000000000001"
	request, material := stageFulcioRotation(t, statePath, 1100, operationID)
	priorRoot := runtimeFile(t, statePath, runtimeFulcioComponent, runtimeFulcioRootCertFile)
	priorAccepted := runtimeFile(t, statePath, runtimeTesseractComponent, runtimeAcceptedRootsFile)

	crashed := false
	func() {
		defer func() {
			if recover() != nil {
				crashed = true
			}
		}()
		if _, err := dispatchFulcioRotationWithHooks(
			statePath,
			publicationHooks{
				checkpoint: func(observed publicationCheckpoint) error {
					if observed == publicationCheckpoint("fulcio-generation-switched") {
						panic("simulated process interruption")
					}
					return nil
				},
			},
		); err != nil {
			t.Fatal(err)
		}
	}()
	if !crashed {
		t.Fatal("rotation did not reach the generation switch")
	}

	// Emulate a partially applied projection: the stage directory exists with
	// only one of its four files, and the accepted-root bundle is stale.
	stagePath := runtimeComponentPath(statePath, runtimeFulcioNextComponent)
	if err := os.MkdirAll(stagePath, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(stagePath, runtimeFulcioRootCertFile), material.certPEM)
	if err := os.WriteFile(
		filepath.Join(
			runtimeComponentPath(statePath, runtimeTesseractComponent),
			runtimeAcceptedRootsFile,
		),
		priorAccepted,
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := dispatchFulcioRotation(statePath); err != nil {
		t.Fatal(err)
	}
	assertFulcioRotationGeneration(t, statePath, 2, request.OperationID, 1)
	if got := runtimeEntryNames(t, statePath, runtimeFulcioNextComponent); strings.Join(got, ",") !=
		"ctlog.pub,password,root.key,root.pem" {
		t.Fatalf("runtime/fulcio.next entries after repair = %v", got)
	}
	if string(runtimeFile(t, statePath, runtimeFulcioComponent, runtimeFulcioRootCertFile)) !=
		string(priorRoot) {
		t.Fatal("repair activated the rotated CA without promotion")
	}
	accepted := runtimeFile(t, statePath, runtimeTesseractComponent, runtimeAcceptedRootsFile)
	if string(accepted) != string(priorRoot)+string(material.certPEM) {
		t.Fatal("recovery did not repair the accepted-root bundle")
	}
	completion := readFulcioRotationTestCompletion(t, statePath)
	if completion.AcceptedRootsSHA256 != hashBytes(accepted) {
		t.Fatal("completion does not bind the repaired accepted-root bundle")
	}
}

func TestFulcioRotationPreservesOidcAndTsaProvenance(t *testing.T) {
	statePath := newFulcioRotationTestState(t)
	tsaRequest, _ := stageTsaRotation(t, statePath, 1200, "bb000000000000000000000000000001")
	if _, err := dispatchTsaRotation(statePath); err != nil {
		t.Fatal(err)
	}
	oidcRequest := writeOIDCRotationTestRequest(t, statePath, "bc000000000000000000000000000001")
	if _, err := dispatchOidcRotation(statePath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureRuntimeBaselineProjection(statePath); err != nil {
		t.Fatal(err)
	}

	beforeFulcio, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	beforeFulcioManifest, err := readOIDCGenerationManifest(statePath, beforeFulcio.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	fulcioRequest, _ := stageFulcioRotation(t, statePath, 1210, "bd000000000000000000000000000001")
	if _, err := dispatchFulcioRotation(statePath); err != nil {
		t.Fatal(err)
	}

	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := readOIDCGenerationManifest(statePath, active.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.FulcioRotationOperationID != fulcioRequest.OperationID ||
		manifest.TSARotationOperationID != tsaRequest.OperationID {
		t.Fatal("Fulcio rotation did not preserve TSA rotation provenance")
	}
	if manifest.OIDCRotationOperationID != "" {
		t.Fatal(
			"Fulcio rotation must not claim the prior generation's OIDC rotation identity",
		)
	}
	if len(manifest.OIDCRetainedPrivateKeyPaths) !=
		len(beforeFulcioManifest.OIDCRetainedPrivateKeyPaths) {
		t.Fatal("Fulcio rotation did not preserve retained OIDC private keys")
	}
	_ = oidcRequest
	if active.TsaRootSHA256 != beforeFulcio.TsaRootSHA256 ||
		active.TsaLeafSHA256 != beforeFulcio.TsaLeafSHA256 ||
		active.OIDCKeyID != beforeFulcio.OIDCKeyID ||
		active.CtLogPublicKeySHA256 != beforeFulcio.CtLogPublicKeySHA256 ||
		active.RekorPublicKeySHA256 != beforeFulcio.RekorPublicKeySHA256 {
		t.Fatal("Fulcio rotation changed non-Fulcio trust material")
	}
	if pathExists(filepath.Join(
		statePath,
		"generations",
		active.GenerationID,
		filepath.FromSlash(tsaRootKeyRelPath),
	)) {
		t.Fatal("Fulcio rotation restored a retired TSA root private key")
	}
	domain, err := loadTrustDomain(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGenerationState(
		statePath,
		filepath.Join(statePath, "generations", active.GenerationID),
		domain,
		manifest,
	); err != nil {
		t.Fatalf("validate combined Fulcio/OIDC/TSA generation: %v", err)
	}
}

// TestFulcioRotationRejectsUnrelatedTrustedRootEntry proves the additive trust
// build refuses to extend a TrustedRoot whose Fulcio entries do not use the
// canonical Fulcio URL.
func TestFulcioRotationRejectsUnrelatedTrustedRootEntry(t *testing.T) {
	statePath := newFulcioRotationTestState(t)
	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)
	trustedRootPath := filepath.Join(
		committedPath(layout, state.Active.ID),
		"targets",
		"trusted_root.json",
	)
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(readTestFile(t, trustedRootPath), trustedRoot); err != nil {
		t.Fatal(err)
	}
	trustedRoot.CertificateAuthorities[0].Uri = "http://attacker.invalid"
	tampered, err := protojson.Marshal(trustedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustedRootPath, append(tampered, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	stageFulcioRotation(t, statePath, 1300, "be000000000000000000000000000001")
	if _, err := dispatchFulcioRotation(statePath); err == nil {
		t.Fatal("rotation extended a TrustedRoot carrying an unrelated Fulcio URI")
	}
}

// TestAcceptedRootsBundleIsDeterministic asserts the projected bundle is a
// pure function of TrustedRoot entry order.
func TestAcceptedRootsBundleIsDeterministic(t *testing.T) {
	statePath := newFulcioRotationTestState(t)
	stageFulcioRotation(t, statePath, 1400, "bf000000000000000000000000000001")
	if _, err := dispatchFulcioRotation(statePath); err != nil {
		t.Fatal(err)
	}
	first, firstFingerprints, err := ensureFulcioRotationRuntimeProjection(
		statePath,
		"generation-00000001",
	)
	if err != nil {
		t.Fatal(err)
	}
	second, secondFingerprints, err := ensureFulcioRotationRuntimeProjection(
		statePath,
		"generation-00000001",
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) ||
		strings.Join(firstFingerprints, ",") != strings.Join(secondFingerprints, ",") {
		t.Fatal("accepted-root projection is not deterministic")
	}
	entries, err := readActiveFulcioTrustEntries(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var expected strings.Builder
	for _, entry := range entries {
		expected.Write(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: entry.certificate.Raw,
		}))
	}
	if string(first) != expected.String() {
		t.Fatal("accepted-root bundle does not follow TrustedRoot entry order")
	}
}
