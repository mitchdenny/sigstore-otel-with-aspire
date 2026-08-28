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
	"strings"
	"testing"
	"time"

	trustrootv1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// newTsaRotationTestState builds a fresh trust-state fixture and publishes
// its initial TUF repository, mirroring newOIDCRotationTestState.
func newTsaRotationTestState(t *testing.T) string {
	t.Helper()
	statePath := newTestState(t)
	if _, err := ensureTUFRepository(statePath); err != nil {
		t.Fatal(err)
	}
	return statePath
}

// tsaCandidateMaterial holds a freshly generated, not-yet-installed TSA
// root+leaf certificate pair plus the encrypted private key material needed
// to build a rotation candidate directory exactly as the C# host would.
type tsaCandidateMaterial struct {
	rootCert *x509.Certificate
	leafCert *x509.Certificate
	rootPEM  []byte
	leafPEM  []byte
	chainPEM []byte
	password []byte
	leafKey  *ecdsa.PrivateKey
}

func newTsaCandidateMaterial(t *testing.T, serial int64, createdAt time.Time) tsaCandidateMaterial {
	t.Helper()
	rootKey := newTestKey(t)
	rootDER := createTestCertificate(
		t,
		&x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject: pkix.Name{
				Organization: []string{"Test TSA"},
				CommonName:   fmt.Sprintf("TSA Root %d", serial),
			},
			NotBefore:             createdAt.Add(-time.Hour),
			NotAfter:              createdAt.AddDate(1, 0, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		},
		nil,
		rootKey,
		rootKey,
	)
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey := newTestKey(t)
	leafDER := createTestCertificate(
		t,
		&x509.Certificate{
			SerialNumber: big.NewInt(serial + 1),
			Subject: pkix.Name{
				Organization: []string{"Test TSA"},
				CommonName:   fmt.Sprintf("TSA Leaf %d", serial),
			},
			NotBefore:             createdAt.Add(-time.Hour),
			NotAfter:              createdAt.AddDate(0, 6, 0),
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			ExtraExtensions:       []pkix.Extension{mustMarshalCriticalTimestampingEKU(t)},
		},
		rootCert,
		leafKey,
		rootKey,
	)
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pemEncodeCertificate(rootDER)
	leafPEM := pemEncodeCertificate(leafDER)
	chainPEM := append(append([]byte{}, leafPEM...), rootPEM...)
	return tsaCandidateMaterial{
		rootCert: rootCert,
		leafCert: leafCert,
		rootPEM:  rootPEM,
		leafPEM:  leafPEM,
		chainPEM: chainPEM,
		password: []byte(fmt.Sprintf("candidate-password-%d", serial)),
		leafKey:  leafKey,
	}
}

// writeTsaRotationCandidateFiles writes exactly the five files C# is
// contracted to produce under tsa-rotation/<operationId>/candidate/: the
// encrypted signer key (for the supplied leaf key/password), the shared
// password, and the leaf/root/chain public certificates. Deliberately no
// root.key: candidate material never carries a new root private key.
func writeTsaRotationCandidateFiles(
	t *testing.T,
	statePath string,
	operationID string,
	material tsaCandidateMaterial,
) {
	t.Helper()
	candidatePath := filepath.Join(statePath, tsaRotationDirectory, operationID, "candidate")
	writeTestFile(t, filepath.Join(candidatePath, "public", "tsa", "root.pem"), material.rootPEM)
	writeTestFile(t, filepath.Join(candidatePath, "public", "tsa", "leaf.pem"), material.leafPEM)
	writeTestFile(t, filepath.Join(candidatePath, "public", "tsa", "cert-chain.pem"), material.chainPEM)
	writeTestFile(t, filepath.Join(candidatePath, "private", "tsa", "password"), material.password)
	writeTestFile(
		t,
		filepath.Join(candidatePath, "private", "tsa", "signer.key"),
		mustMarshalEncryptedECDSAKey(t, material.leafKey, material.password),
	)
}

func writeTsaRotationTestRequest(
	t *testing.T,
	statePath string,
	operationID string,
	material tsaCandidateMaterial,
) tsaRotationRequest {
	t.Helper()
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	request := tsaRotationRequest{
		SchemaVersion:          tsaRotationSchemaVersion,
		OperationID:            operationID,
		TrustDomainID:          active.TrustDomainID,
		StartingGeneration:     active.Generation,
		StartingGenerationID:   active.GenerationID,
		StartingTsaRootSHA256:  active.TsaRootSHA256,
		StartingTsaLeafSHA256:  active.TsaLeafSHA256,
		CandidateTsaRootSHA256: hashDER(material.rootCert.Raw),
		CandidateTsaLeafSHA256: hashDER(material.leafCert.Raw),
	}
	if err := writeJSON(
		filepath.Join(statePath, tsaRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return request
}

// stageTsaRotation generates a new TSA candidate, writes it to disk, and
// writes a matching rotation request, returning both for further use or
// tampering by the caller.
func stageTsaRotation(
	t *testing.T,
	statePath string,
	serial int64,
	operationID string,
) (tsaRotationRequest, tsaCandidateMaterial) {
	t.Helper()
	material := newTsaCandidateMaterial(t, serial, time.Now().UTC())
	writeTsaRotationCandidateFiles(t, statePath, operationID, material)
	request := writeTsaRotationTestRequest(t, statePath, operationID, material)
	return request, material
}

func readTsaRotationTestCompletion(t *testing.T, statePath string) tsaRotationCompletion {
	t.Helper()
	data := readTestFile(t, filepath.Join(statePath, tsaRotationCompletionFile))
	var completion tsaRotationCompletion
	if err := json.Unmarshal(data, &completion); err != nil {
		t.Fatal(err)
	}
	return completion
}

func readActiveTrustedRoot(t *testing.T, statePath string) *trustrootv1.TrustedRoot {
	t.Helper()
	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)
	if state.Active == nil {
		t.Fatal("no active TUF publication")
	}
	data := readTestFile(
		t,
		filepath.Join(committedPath(layout, state.Active.ID), "targets", "trusted_root.json"),
	)
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(data, trustedRoot); err != nil {
		t.Fatal(err)
	}
	return trustedRoot
}

func assertTsaAuthorityPresent(t *testing.T, trustedRoot *trustrootv1.TrustedRoot, rootHash, leafHash string) {
	t.Helper()
	for _, authority := range trustedRoot.TimestampAuthorities {
		gotRoot, gotLeaf, err := timestampAuthorityFingerprints(authority)
		if err != nil {
			t.Fatal(err)
		}
		if gotRoot == rootHash && gotLeaf == leafHash {
			return
		}
	}
	t.Fatalf("trusted_root.json does not contain TSA authority root=%s leaf=%s", rootHash, leafHash)
}

func assertTsaRotationGeneration(
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
	if manifest.TSARotationOperationID != operationID {
		t.Fatalf(
			"generation TSA operation = %q, want %q",
			manifest.TSARotationOperationID,
			operationID,
		)
	}
	if manifest.TSAPriorGeneration != priorGeneration {
		t.Fatalf(
			"generation TSA prior generation = %d, want %d",
			manifest.TSAPriorGeneration,
			priorGeneration,
		)
	}
	if err := validateTSAGenerationMaterial(
		filepath.Join(statePath, "generations", active.GenerationID),
		manifest,
	); err != nil {
		t.Fatal(err)
	}
}

// countActiveTsaPrivateFiles returns the number of files under the active
// generation's private/tsa directory, used to assert that repeated rotations
// never grow the active private TSA secret set.
func countActiveTsaPrivateFiles(t *testing.T, statePath string) int {
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
		"tsa",
	))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestTsaRotationAppendsAuthorityAndPreservesOldTsaAndNonTsaEntries(t *testing.T) {
	statePath := newTsaRotationTestState(t)
	layout := newTUFLayout(statePath)

	before := readTestPublicationState(t, layout)
	activeBefore := committedPath(layout, before.Active.ID)
	rootBefore := readTestMetadata(t, filepath.Join(activeBefore, "repository", "root.json"))
	fulcioBefore := readTestFile(t, filepath.Join(activeBefore, "targets", "fulcio_v1.crt.pem"))
	ctfeBefore := readTestFile(t, filepath.Join(activeBefore, "targets", "ctfe.pub"))
	rekorBefore := readTestFile(t, filepath.Join(activeBefore, "targets", "rekor.pub"))
	signingConfigBefore := readTestFile(t, filepath.Join(activeBefore, "targets", "signing_config.v0.2.json"))
	targetsVersionBefore := readTestMetadata(t, filepath.Join(activeBefore, "repository", "targets.json"))
	snapshotBefore := readTestMetadata(t, filepath.Join(activeBefore, "repository", "snapshot.json"))
	timestampBefore := readTestMetadata(t, filepath.Join(activeBefore, "repository", "timestamp.json"))
	bootstrapBefore := readTestFile(t, layout.bootstrapRoot)

	trustedRootBefore := readActiveTrustedRoot(t, statePath)
	if len(trustedRootBefore.TimestampAuthorities) != 1 {
		t.Fatalf("initial TSA authority count = %d, want 1", len(trustedRootBefore.TimestampAuthorities))
	}
	oldRootHash, oldLeafHash, err := timestampAuthorityFingerprints(trustedRootBefore.TimestampAuthorities[0])
	if err != nil {
		t.Fatal(err)
	}

	_, material := stageTsaRotation(t, statePath, 100, "10000000000000000000000000000001")
	action, err := dispatchTsaRotation(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if action != repositoryActionPublished {
		t.Fatalf("action = %q, want %q", action, repositoryActionPublished)
	}

	assertTsaRotationGeneration(t, statePath, 2, "10000000000000000000000000000001", 1)

	trustedRootAfter := readActiveTrustedRoot(t, statePath)
	if len(trustedRootAfter.TimestampAuthorities) != 2 {
		t.Fatalf("post-rotation TSA authority count = %d, want 2", len(trustedRootAfter.TimestampAuthorities))
	}
	assertTsaAuthorityPresent(t, trustedRootAfter, oldRootHash, oldLeafHash)
	assertTsaAuthorityPresent(t, trustedRootAfter, hashDER(material.rootCert.Raw), hashDER(material.leafCert.Raw))

	after := readTestPublicationState(t, layout)
	activeAfter := committedPath(layout, after.Active.ID)
	if got := readTestFile(t, filepath.Join(activeAfter, "targets", "fulcio_v1.crt.pem")); string(got) != string(fulcioBefore) {
		t.Fatal("fulcio target bytes changed during TSA rotation")
	}
	if got := readTestFile(t, filepath.Join(activeAfter, "targets", "ctfe.pub")); string(got) != string(ctfeBefore) {
		t.Fatal("ctlog target bytes changed during TSA rotation")
	}
	if got := readTestFile(t, filepath.Join(activeAfter, "targets", "rekor.pub")); string(got) != string(rekorBefore) {
		t.Fatal("rekor target bytes changed during TSA rotation")
	}
	if got := readTestFile(t, filepath.Join(activeAfter, "targets", "signing_config.v0.2.json")); string(got) != string(signingConfigBefore) {
		t.Fatal("signing_config.v0.2.json bytes changed during TSA rotation (TSA URL/routing must be unchanged)")
	}

	rootAfter := readTestMetadata(t, filepath.Join(activeAfter, "repository", "root.json"))
	if rootAfter.Version != rootBefore.Version || rootAfter.Hash != rootBefore.Hash {
		t.Fatal("TUF root was changed by a TSA rotation")
	}
	targetsVersionAfter := readTestMetadata(t, filepath.Join(activeAfter, "repository", "targets.json"))
	if targetsVersionAfter.Version != targetsVersionBefore.Version+1 {
		t.Fatalf(
			"targets version = %d, want %d",
			targetsVersionAfter.Version,
			targetsVersionBefore.Version+1,
		)
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
		t.Fatal("immutable bootstrap root changed during TSA rotation")
	}

	completion := readTsaRotationTestCompletion(t, statePath)
	if completion.TsaTrustEntryCount != 2 {
		t.Fatalf("completion TSA authority count = %d, want 2", completion.TsaTrustEntryCount)
	}
	if completion.PublicationID != after.Active.ID {
		t.Fatalf("completion publication ID = %q, want %q", completion.PublicationID, after.Active.ID)
	}
	if completion.PublicationManifestSHA256 != after.Active.ManifestSHA256 {
		t.Fatal("completion publication manifest hash does not match the active publication")
	}
	if pathExists(filepath.Join(statePath, tsaRotationRequestFile)) {
		t.Fatal("rotation request file was not removed after completion")
	}
}

func TestTsaRotationNToNPlusOneAndRepeatBoundsActiveSecrets(t *testing.T) {
	statePath := newTsaRotationTestState(t)

	generationOnePath := filepath.Join(statePath, "generations", "generation-00000001")
	if !pathExists(filepath.Join(generationOnePath, "private", "tsa", "root.key")) {
		t.Fatal("initial generation is missing its TSA root key")
	}

	_, firstMaterial := stageTsaRotation(t, statePath, 200, "20000000000000000000000000000001")
	if action, err := dispatchTsaRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("first rotation action = %q, want %q", action, repositoryActionPublished)
	}
	assertTsaRotationGeneration(t, statePath, 2, "20000000000000000000000000000001", 1)
	if count := countActiveTsaPrivateFiles(t, statePath); count != 2 {
		t.Fatalf("generation 2 private/tsa file count = %d, want 2 (signer.key + password)", count)
	}
	if pathExists(filepath.Join(statePath, "generations", "generation-00000002", "private", "tsa", "root.key")) {
		t.Fatal("rotated generation 2 must not retain a root private key")
	}

	// Generation 1 must remain byte-for-byte immutable, including its root key.
	if !pathExists(filepath.Join(generationOnePath, "private", "tsa", "root.key")) {
		t.Fatal("rotation deleted the immutable prior generation's root key")
	}

	_, secondMaterial := stageTsaRotation(t, statePath, 300, "30000000000000000000000000000001")
	if action, err := dispatchTsaRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("second rotation action = %q, want %q", action, repositoryActionPublished)
	}
	assertTsaRotationGeneration(t, statePath, 3, "30000000000000000000000000000001", 2)
	if count := countActiveTsaPrivateFiles(t, statePath); count != 2 {
		t.Fatalf(
			"generation 3 private/tsa file count = %d, want 2 (repeated rotation must not grow active secrets)",
			count,
		)
	}

	trustedRoot := readActiveTrustedRoot(t, statePath)
	if len(trustedRoot.TimestampAuthorities) != 3 {
		t.Fatalf("TSA authority count after two rotations = %d, want 3", len(trustedRoot.TimestampAuthorities))
	}
	assertTsaAuthorityPresent(t, trustedRoot, hashDER(firstMaterial.rootCert.Raw), hashDER(firstMaterial.leafCert.Raw))
	assertTsaAuthorityPresent(t, trustedRoot, hashDER(secondMaterial.rootCert.Raw), hashDER(secondMaterial.leafCert.Raw))
}

func TestOidcRotationAfterTsaRotationPreservesActiveTsaState(t *testing.T) {
	statePath := newTsaRotationTestState(t)
	request, _ := stageTsaRotation(
		t,
		statePath,
		3100,
		"abababababababababababababababab",
	)
	if _, err := dispatchTsaRotation(statePath); err != nil {
		t.Fatal(err)
	}
	tsaCompletion := readTsaRotationTestCompletion(t, statePath)

	oidcRequest := writeOIDCRotationTestRequest(
		t,
		statePath,
		"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
	)
	if _, err := dispatchOidcRotation(statePath); err != nil {
		t.Fatal(err)
	}

	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if active.Generation != request.StartingGeneration+2 {
		t.Fatalf("active generation = %d, want %d", active.Generation, request.StartingGeneration+2)
	}
	if active.TsaRootSHA256 != tsaCompletion.NewTsaRootSHA256 ||
		active.TsaLeafSHA256 != tsaCompletion.NewTsaLeafSHA256 {
		t.Fatal("OIDC rotation changed the active TSA chain")
	}
	manifest, err := readOIDCGenerationManifest(statePath, active.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.OIDCRotationOperationID != oidcRequest.OperationID ||
		manifest.TSARotationOperationID != request.OperationID ||
		manifest.TSAPriorGeneration != request.StartingGeneration ||
		manifest.TSAPriorGenerationID != request.StartingGenerationID {
		t.Fatal("OIDC rotation did not preserve TSA rotation provenance")
	}
	if pathExists(filepath.Join(
		statePath,
		"generations",
		active.GenerationID,
		filepath.FromSlash(tsaRootKeyRelPath),
	)) {
		t.Fatal("OIDC rotation restored a retired TSA root private key")
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
		t.Fatalf("validate combined OIDC/TSA generation: %v", err)
	}
}

func TestTsaRotationExactChainAndKeyMatching(t *testing.T) {
	t.Run("signer key does not match leaf certificate", func(t *testing.T) {
		statePath := newTsaRotationTestState(t)
		material := newTsaCandidateMaterial(t, 400, time.Now().UTC())
		operationID := "40000000000000000000000000000001"
		writeTsaRotationCandidateFiles(t, statePath, operationID, material)
		// Overwrite the signer key with an unrelated key/password pair so it
		// no longer matches the leaf certificate's public key.
		wrongKey := newTestKey(t)
		candidatePath := filepath.Join(statePath, tsaRotationDirectory, operationID, "candidate")
		writeTestFile(
			t,
			filepath.Join(candidatePath, "private", "tsa", "signer.key"),
			mustMarshalEncryptedECDSAKey(t, wrongKey, material.password),
		)
		writeTsaRotationTestRequest(t, statePath, operationID, material)

		if _, err := dispatchTsaRotation(statePath); err == nil {
			t.Fatal("rotation accepted a signer key that does not match the leaf certificate")
		} else if !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("chain file has wrong order", func(t *testing.T) {
		statePath := newTsaRotationTestState(t)
		material := newTsaCandidateMaterial(t, 410, time.Now().UTC())
		operationID := "41000000000000000000000000000001"
		writeTsaRotationCandidateFiles(t, statePath, operationID, material)
		candidatePath := filepath.Join(statePath, tsaRotationDirectory, operationID, "candidate")
		reversedChain := append(append([]byte{}, material.rootPEM...), material.leafPEM...)
		writeTestFile(t, filepath.Join(candidatePath, "public", "tsa", "cert-chain.pem"), reversedChain)
		writeTsaRotationTestRequest(t, statePath, operationID, material)

		if _, err := dispatchTsaRotation(statePath); err == nil {
			t.Fatal("rotation accepted a certificate chain with the wrong order")
		} else if !strings.Contains(err.Error(), "chain") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("chain file does not match standalone certificates", func(t *testing.T) {
		statePath := newTsaRotationTestState(t)
		material := newTsaCandidateMaterial(t, 420, time.Now().UTC())
		operationID := "42000000000000000000000000000001"
		writeTsaRotationCandidateFiles(t, statePath, operationID, material)
		other := newTsaCandidateMaterial(t, 421, time.Now().UTC())
		candidatePath := filepath.Join(statePath, tsaRotationDirectory, operationID, "candidate")
		writeTestFile(t, filepath.Join(candidatePath, "public", "tsa", "cert-chain.pem"), other.chainPEM)
		writeTsaRotationTestRequest(t, statePath, operationID, material)

		if _, err := dispatchTsaRotation(statePath); err == nil {
			t.Fatal("rotation accepted a chain file that does not match the standalone certificates")
		} else if !strings.Contains(err.Error(), "chain") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestTsaRotationRejectsTamperedCandidate(t *testing.T) {
	t.Run("candidate fingerprint mismatch", func(t *testing.T) {
		statePath := newTsaRotationTestState(t)
		material := newTsaCandidateMaterial(t, 500, time.Now().UTC())
		operationID := "50000000000000000000000000000001"
		writeTsaRotationCandidateFiles(t, statePath, operationID, material)
		request := writeTsaRotationTestRequest(t, statePath, operationID, material)
		request.CandidateTsaRootSHA256 = hashDER([]byte("not-a-real-certificate"))
		if err := writeJSON(filepath.Join(statePath, tsaRotationRequestFile), request, 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := dispatchTsaRotation(statePath); err == nil {
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
		statePath := newTsaRotationTestState(t)
		material := newTsaCandidateMaterial(t, 510, time.Now().UTC())
		operationID := "51000000000000000000000000000001"
		writeTsaRotationCandidateFiles(t, statePath, operationID, material)
		candidatePath := filepath.Join(statePath, tsaRotationDirectory, operationID, "candidate")
		// The candidate must never carry a new root private key.
		writeTestFile(
			t,
			filepath.Join(candidatePath, "private", "tsa", "root.key"),
			mustMarshalEncryptedECDSAKey(t, newTestKey(t), material.password),
		)
		writeTsaRotationTestRequest(t, statePath, operationID, material)

		if _, err := dispatchTsaRotation(statePath); err == nil {
			t.Fatal("rotation accepted a candidate with an unexpected root.key file")
		} else if !strings.Contains(err.Error(), "files") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("leaf certificate not critical timestamping EKU", func(t *testing.T) {
		statePath := newTsaRotationTestState(t)
		rootKey := newTestKey(t)
		rootDER := createTestCertificate(
			t,
			&x509.Certificate{
				SerialNumber:          big.NewInt(520),
				Subject:               pkix.Name{Organization: []string{"Test TSA"}, CommonName: "Bad TSA Root"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().AddDate(1, 0, 0),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			},
			nil,
			rootKey,
			rootKey,
		)
		rootCert, err := x509.ParseCertificate(rootDER)
		if err != nil {
			t.Fatal(err)
		}
		leafKey := newTestKey(t)
		// No ExtraExtensions override: crypto/x509 marshals ExtKeyUsage as
		// non-critical here, which the worker must reject.
		leafDER := createTestCertificate(
			t,
			&x509.Certificate{
				SerialNumber:          big.NewInt(521),
				Subject:               pkix.Name{Organization: []string{"Test TSA"}, CommonName: "Bad TSA Leaf"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().AddDate(0, 6, 0),
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			},
			rootCert,
			leafKey,
			rootKey,
		)
		leafCert, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatal(err)
		}
		rootPEM := pemEncodeCertificate(rootDER)
		leafPEM := pemEncodeCertificate(leafDER)
		material := tsaCandidateMaterial{
			rootCert: rootCert,
			leafCert: leafCert,
			rootPEM:  rootPEM,
			leafPEM:  leafPEM,
			chainPEM: append(append([]byte{}, leafPEM...), rootPEM...),
			password: []byte("bad-leaf-password"),
			leafKey:  leafKey,
		}
		operationID := "52000000000000000000000000000001"
		writeTsaRotationCandidateFiles(t, statePath, operationID, material)
		writeTsaRotationTestRequest(t, statePath, operationID, material)

		if _, err := dispatchTsaRotation(statePath); err == nil {
			t.Fatal("rotation accepted a leaf certificate without a critical timestamping EKU")
		} else if !strings.Contains(err.Error(), "critical") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestTsaRotationRejectsTamperedCompletionReplay(t *testing.T) {
	statePath := newTsaRotationTestState(t)
	request, _ := stageTsaRotation(t, statePath, 600, "60000000000000000000000000000001")
	if _, err := dispatchTsaRotation(statePath); err != nil {
		t.Fatal(err)
	}

	completionPath := filepath.Join(statePath, tsaRotationCompletionFile)
	completion := readTsaRotationTestCompletion(t, statePath)
	completion.TsaTrustEntryCount = completion.TsaTrustEntryCount + 5
	if err := writeJSON(completionPath, completion, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeJSON(
		filepath.Join(statePath, tsaRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := dispatchTsaRotation(statePath); err == nil {
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

func TestTsaRotationRejectsTamperedTrustedRootOnReplay(t *testing.T) {
	statePath := newTsaRotationTestState(t)
	request, _ := stageTsaRotation(t, statePath, 610, "61000000000000000000000000000001")
	if _, err := dispatchTsaRotation(statePath); err != nil {
		t.Fatal(err)
	}

	layout := newTUFLayout(statePath)
	state := readTestPublicationState(t, layout)
	trustedRootPath := filepath.Join(committedPath(layout, state.Active.ID), "targets", "trusted_root.json")
	data := readTestFile(t, trustedRootPath)
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(data, trustedRoot); err != nil {
		t.Fatal(err)
	}
	// Drop the old TSA authority, simulating a corrupted/tampered TrustedRoot
	// that no longer additively preserves the prior authority.
	trustedRoot.TimestampAuthorities = trustedRoot.TimestampAuthorities[1:]
	tamperedJSON, err := protojson.Marshal(trustedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustedRootPath, append(tamperedJSON, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeJSON(
		filepath.Join(statePath, tsaRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := dispatchTsaRotation(statePath); err == nil {
		t.Fatal("rotation replay accepted a tampered trusted_root.json")
	}
}

func TestTsaRotationCompletionReplayIsIdempotent(t *testing.T) {
	statePath := newTsaRotationTestState(t)
	request, _ := stageTsaRotation(t, statePath, 700, "70000000000000000000000000000001")
	if action, err := dispatchTsaRotation(statePath); err != nil {
		t.Fatal(err)
	} else if action != repositoryActionPublished {
		t.Fatalf("first action = %q, want %q", action, repositoryActionPublished)
	}
	completionBefore := readTsaRotationTestCompletion(t, statePath)

	if err := writeJSON(
		filepath.Join(statePath, tsaRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	action, err := dispatchTsaRotation(statePath)
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
	completionAfter := readTsaRotationTestCompletion(t, statePath)
	if completionAfter != completionBefore {
		t.Fatal("idempotent replay changed the durable completion record")
	}
	if pathExists(filepath.Join(statePath, tsaRotationRequestFile)) {
		t.Fatal("idempotent replay did not remove the request file")
	}
	if pathExists(filepath.Join(statePath, "generations", "generation-00000003")) {
		t.Fatal("idempotent replay created a duplicate generation")
	}
}

func TestTsaRotationRejectsRequestForAnotherTrustDomain(t *testing.T) {
	statePath := newTsaRotationTestState(t)
	material := newTsaCandidateMaterial(t, 800, time.Now().UTC())
	operationID := "80000000000000000000000000000001"
	writeTsaRotationCandidateFiles(t, statePath, operationID, material)
	request := writeTsaRotationTestRequest(t, statePath, operationID, material)
	request.TrustDomainID = "sha256-" + strings.Repeat("b", 64)
	if err := writeJSON(
		filepath.Join(statePath, tsaRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := dispatchTsaRotation(statePath); err == nil {
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

func TestValidateAndReuseTsaGenerationValidatesCompleteMaterial(t *testing.T) {
	t.Run("valid generation", func(t *testing.T) {
		statePath := newTsaRotationTestState(t)
		current, request, nextPath, nextID := createReusableTsaGeneration(
			t,
			statePath,
			900,
			"90000000000000000000000000000001",
		)
		reused, err := validateAndReuseTsaGeneration(
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
		statePath := newTsaRotationTestState(t)
		current, request, nextPath, nextID := createReusableTsaGeneration(
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

		_, err = validateAndReuseTsaGeneration(
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
	})

	t.Run("tampered certificate hash", func(t *testing.T) {
		statePath := newTsaRotationTestState(t)
		current, request, nextPath, nextID := createReusableTsaGeneration(
			t,
			statePath,
			920,
			"92000000000000000000000000000001",
		)
		manifest, err := readOIDCGenerationManifest(statePath, nextID)
		if err != nil {
			t.Fatal(err)
		}
		manifest.TsaRootSHA256 = hashDER([]byte("tampered"))
		if err := writeJSON(filepath.Join(nextPath, "manifest.json"), manifest, 0o644); err != nil {
			t.Fatal(err)
		}

		_, err = validateAndReuseTsaGeneration(
			statePath,
			current,
			nextPath,
			nextID,
			current.Generation+1,
			request,
		)
		if err == nil {
			t.Fatal("reused generation with a tampered manifest hash was accepted")
		}
	})
}

func createReusableTsaGeneration(
	t *testing.T,
	statePath string,
	serial int64,
	operationID string,
) (bootstrapManifest, tsaRotationRequest, string, string) {
	t.Helper()
	current, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := stageTsaRotation(t, statePath, serial, operationID)
	next, err := rotateTsaGeneration(statePath, current, request)
	if err != nil {
		t.Fatal(err)
	}
	return current, request, filepath.Join(statePath, "generations", next.GenerationID), next.GenerationID
}

func TestTsaRotationRecoversEveryCommittedBoundaryExactlyOnce(t *testing.T) {
	checkpoints := []publicationCheckpoint{
		"tsa-generation-committed",
		checkpointCandidatePrepared,
		checkpointHistoryParked,
		checkpointCandidateCommitted,
		checkpointActiveSwitched,
		"tsa-tuf-committed",
		"tsa-generation-switched",
		"tsa-completion-written",
	}
	for index, checkpoint := range checkpoints {
		t.Run(string(checkpoint), func(t *testing.T) {
			statePath := newTsaRotationTestState(t)
			operationID := fmt.Sprintf("%032x", index+1000)
			request, _ := stageTsaRotation(t, statePath, int64(1000+index), operationID)

			crashed := false
			func() {
				defer func() {
					if recover() != nil {
						crashed = true
					}
				}()
				_, err := dispatchTsaRotationWithHooks(
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

			if _, err := dispatchTsaRotation(statePath); err != nil {
				t.Fatalf("recover checkpoint %s: %v", checkpoint, err)
			}
			assertTsaRotationGeneration(t, statePath, 2, request.OperationID, 1)
			if pathExists(filepath.Join(statePath, "generations", "generation-00000003")) {
				t.Fatalf("checkpoint %s created a duplicate generation", checkpoint)
			}
			if pathExists(filepath.Join(statePath, tsaRotationRequestFile)) {
				t.Fatalf("checkpoint %s recovery did not remove the request file", checkpoint)
			}
			trustedRoot := readActiveTrustedRoot(t, statePath)
			if len(trustedRoot.TimestampAuthorities) != 2 {
				t.Fatalf(
					"checkpoint %s: TSA authority count = %d, want 2",
					checkpoint,
					len(trustedRoot.TimestampAuthorities),
				)
			}
		})
	}
}

// pemEncodeCertificate is a tiny convenience wrapper kept local to this file
// so it reads clearly at each call site above.
func pemEncodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
