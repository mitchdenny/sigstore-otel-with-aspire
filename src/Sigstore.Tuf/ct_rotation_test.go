package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	trustrootv1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// errCtSimulatedInterrupt models a process that dies exactly at one
// committed durable boundary, so replay can be proven to converge.
var errCtSimulatedInterrupt = errors.New("simulated CT rotation interruption")

func newCtRotationTestState(t *testing.T) string {
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

// stageCtRotation materializes exactly what the hosting command stages
// before it starts the worker: the isolated candidate signer, the
// secondary shard's own storage identity and metadata, the least-privilege
// secondary runtime projection, the staged Fulcio CT selection, and the
// durable worker request.
func stageCtRotation(
	t *testing.T,
	statePath, operationID, stateID string,
) ctRotationRequest {
	t.Helper()
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	key := newTestKey(t)
	privatePEM := testECPrivateKeyPEM(t, key)
	publicPEM := testPublicKeyPEM(t, key)
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := hashBytes(publicDER)
	createdAt := time.Now().UTC()
	candidatePath := filepath.Join(
		statePath,
		ctRotationDirectory,
		operationID,
		"candidate",
	)
	writeTestFile(
		t,
		filepath.Join(candidatePath, filepath.FromSlash(ctLogPrivateKeyRelPath)),
		privatePEM,
	)
	writeTestFile(
		t,
		filepath.Join(candidatePath, filepath.FromSlash(ctLogPublicKeyRelPath)),
		publicPEM,
	)
	dataPath := filepath.Join(statePath, filepath.FromSlash(ctSecondaryDataPath))
	writeTestFile(t, filepath.Join(dataPath, ctCandidateStateFileName), []byte(stateID))
	runtimePath := filepath.Join(statePath, filepath.FromSlash(ctSecondaryRuntimeDir))
	writeTestFile(t, filepath.Join(runtimePath, runtimeTesseractKeyFile), privatePEM)
	acceptedRoots, acceptedSHA256, acceptedFingerprints, err := acceptedRootsIdentity(
		ctShardAcceptedRootsPath(statePath, "primary"),
	)
	if err != nil {
		t.Fatal(err)
	}

	metadata := ctShardMetadata{
		SchemaVersion:   ctShardMetadataSchema,
		OperationID:     operationID,
		TrustDomainID:   active.TrustDomainID,
		ShardID:         ctShardID(digest),
		Slot:            "secondary",
		BaseURL:         ctSecondaryURL,
		Origin:          ctSecondaryOrigin,
		PublicKeySHA256: digest,
		LogIDSHA256:     digest,
		StateID:         stateID,
		DataPath:        ctSecondaryDataPath,
		ResourceName:    ctSecondaryResourceName,
		CreatedAtUTC:    createdAt,

		AcceptedRootsSHA256:      acceptedSHA256,
		AcceptedRootCount:        len(acceptedFingerprints),
		AcceptedRootFingerprints: acceptedFingerprints,
	}
	if err := writeJSON(
		filepath.Join(dataPath, ctShardMetadataFileName),
		metadata,
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(runtimePath, runtimeAcceptedRootsFile), acceptedRoots)
	// Staging is additive: the immutable secondary key is written beside
	// the primary key and the single selection manifest still names the
	// primary shard, so Fulcio remains wholly bound to it until promotion.
	writeTestFile(
		t,
		filepath.Join(
			statePath,
			filepath.FromSlash(ctFulcioRuntimeDir),
			ctRuntimeSecondaryKeyFile,
		),
		publicPEM,
	)

	request := ctRotationRequest{
		SchemaVersion:                    ctRotationSchemaVersion,
		OperationID:                      operationID,
		TrustDomainID:                    active.TrustDomainID,
		StartingGeneration:               active.Generation,
		StartingGenerationID:             active.GenerationID,
		StartingGenerationManifestSHA256: active.GenerationManifestSHA256,
		StartingCtLogPublicKeySHA256:     active.CtLogPublicKeySHA256,
		PriorShardID:                     ctShardID(active.CtLogPublicKeySHA256),
		PriorShardURL:                    ctLogURL,
		CandidateShardID:                 ctShardID(digest),
		CandidateShardURL:                ctSecondaryURL,
		CandidateOrigin:                  ctSecondaryOrigin,
		CandidatePublicKeySHA256:         digest,
		CandidateStateID:                 stateID,
		CandidateCreatedAtUTC:            createdAt,
	}
	if err := writeJSON(
		filepath.Join(statePath, ctRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return request
}

func readActiveTargets(t *testing.T, statePath, name string) []byte {
	t.Helper()
	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(
		committedPath(layout, publication.Active.ID),
		"targets",
		filepath.FromSlash(name),
	))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCtLogIDAndShardIDUseSPKISHA256(t *testing.T) {
	key := newTestKey(t)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := hashBytes(der)
	entry := newTransparencyLog(ctSecondaryURL, der, time.Now().UTC())
	got, err := transparencyLogDigest(entry)
	if err != nil {
		t.Fatal(err)
	}
	if got != digest || ctShardID(got) != "sha256-"+digest {
		t.Fatalf("digest = %q, shard = %q", got, ctShardID(got))
	}
}

func TestCtRotationAppendsTrustAdditivelyAndPreservesSigningConfig(t *testing.T) {
	statePath := newCtRotationTestState(t)
	before, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	signingConfigBefore := readActiveTargets(t, statePath, "signing_config.v0.2.json")
	trustedRootBefore := readActiveTargets(t, statePath, "trusted_root.json")
	primaryPubKeyBefore, err := os.ReadFile(filepath.Join(
		generationPathFor(statePath, before.GenerationID),
		filepath.FromSlash(ctLogPublicKeyRelPath),
	))
	if err != nil {
		t.Fatal(err)
	}

	request := stageCtRotation(
		t,
		statePath,
		"11111111111111111111111111111111",
		"11111111-1111-1111-1111-111111111111",
	)
	if _, err := dispatchCtRotation(statePath); err != nil {
		t.Fatal(err)
	}

	after, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != before.Generation+1 {
		t.Fatalf("generation = %d, expected %d", after.Generation, before.Generation+1)
	}
	if after.CtLogPublicKeySHA256 != request.CandidatePublicKeySHA256 {
		t.Fatal("the rotated generation does not carry the candidate CT signer")
	}
	if after.FulcioRootSHA256 != before.FulcioRootSHA256 ||
		after.RekorPublicKeySHA256 != before.RekorPublicKeySHA256 ||
		after.TsaRootSHA256 != before.TsaRootSHA256 ||
		after.TsaLeafSHA256 != before.TsaLeafSHA256 ||
		after.OIDCKeyID != before.OIDCKeyID {
		t.Fatal("non-CT trust material changed across the rotation")
	}

	// SigningConfig is byte-for-byte unchanged: certificate transparency
	// is not a signing-service selector.
	if !bytes.Equal(signingConfigBefore, readActiveTargets(t, statePath, "signing_config.v0.2.json")) {
		t.Fatal("SigningConfig changed during a CT log shard rotation")
	}
	trustedRootAfter := readActiveTargets(t, statePath, "trusted_root.json")
	if bytes.Equal(trustedRootBefore, trustedRootAfter) {
		t.Fatal("TrustedRoot did not change")
	}
	oldRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(trustedRootBefore, oldRoot); err != nil {
		t.Fatal(err)
	}
	newRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(trustedRootAfter, newRoot); err != nil {
		t.Fatal(err)
	}
	if len(newRoot.Ctlogs) != len(oldRoot.Ctlogs)+1 {
		t.Fatalf("ctlogs = %d, expected %d", len(newRoot.Ctlogs), len(oldRoot.Ctlogs)+1)
	}
	firstDigest, err := transparencyLogDigest(newRoot.Ctlogs[0])
	if err != nil {
		t.Fatal(err)
	}
	lastDigest, err := transparencyLogDigest(newRoot.Ctlogs[len(newRoot.Ctlogs)-1])
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != request.StartingCtLogPublicKeySHA256 ||
		newRoot.Ctlogs[0].GetBaseUrl() != ctLogURL {
		t.Fatal("the historical CT shard entry was not preserved verbatim")
	}
	if lastDigest != request.CandidatePublicKeySHA256 ||
		newRoot.Ctlogs[len(newRoot.Ctlogs)-1].GetBaseUrl() != ctSecondaryURL {
		t.Fatal("the secondary CT shard entry was not appended")
	}
	if len(newRoot.Tlogs) != len(oldRoot.Tlogs) ||
		len(newRoot.CertificateAuthorities) != len(oldRoot.CertificateAuthorities) ||
		len(newRoot.TimestampAuthorities) != len(oldRoot.TimestampAuthorities) {
		t.Fatal("a non-CT TrustedRoot section changed")
	}

	// Both per-shard targets are published and the active ctfe.pub points
	// at the new shard.
	if !bytes.Equal(readActiveTargets(t, statePath, ctPrimaryTargetName), primaryPubKeyBefore) {
		t.Fatal("the primary CT target does not carry the historical signer")
	}
	newPubKey, err := os.ReadFile(filepath.Join(
		generationPathFor(statePath, after.GenerationID),
		filepath.FromSlash(ctLogPublicKeyRelPath),
	))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readActiveTargets(t, statePath, ctSecondaryTargetName), newPubKey) ||
		!bytes.Equal(readActiveTargets(t, statePath, "ctfe.pub"), newPubKey) {
		t.Fatal("the secondary CT targets do not carry the candidate signer")
	}

	catalog, err := loadCtShardCatalog(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Shards) != 2 ||
		catalog.Shards[0].Status != "historical" ||
		catalog.Shards[1].Status != "active" ||
		catalog.ActiveShardID != request.CandidateShardID ||
		catalog.Shards[0].StateID == catalog.Shards[1].StateID {
		t.Fatalf("shard catalog was not switched: %+v", catalog)
	}
	completion, err := loadCtRotationCompletion(statePath)
	if err != nil || completion == nil {
		t.Fatalf("completion = %v, err = %v", completion, err)
	}
	if completion.NewTrustedRootCtlogCount != completion.PriorTrustedRootCtlogCount+1 {
		t.Fatal("completion does not describe an additive CT publication")
	}
	if pathExists(filepath.Join(statePath, ctRotationRequestFile)) {
		t.Fatal("the worker request was not consumed")
	}
}

func TestCtRotationLeavesThePrimaryShardImmutable(t *testing.T) {
	statePath := newCtRotationTestState(t)
	before, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	primaryGenerationPath := generationPathFor(statePath, before.GenerationID)
	primaryPrivate, err := os.ReadFile(filepath.Join(
		primaryGenerationPath,
		filepath.FromSlash(ctLogPrivateKeyRelPath),
	))
	if err != nil {
		t.Fatal(err)
	}
	primaryRuntime, err := os.ReadFile(filepath.Join(
		runtimeComponentPath(statePath, runtimeTesseractComponent),
		runtimeTesseractKeyFile,
	))
	if err != nil {
		t.Fatal(err)
	}
	primaryState, err := readStateMarker(
		filepath.Join(statePath, filepath.FromSlash(ctPrimaryDataPath)),
	)
	if err != nil {
		t.Fatal(err)
	}

	_ = stageCtRotation(
		t,
		statePath,
		"22222222222222222222222222222222",
		"22222222-2222-2222-2222-222222222222",
	)
	if _, err := dispatchCtRotation(statePath); err != nil {
		t.Fatal(err)
	}

	afterPrivate, err := os.ReadFile(filepath.Join(
		primaryGenerationPath,
		filepath.FromSlash(ctLogPrivateKeyRelPath),
	))
	if err != nil {
		t.Fatal(err)
	}
	afterRuntime, err := os.ReadFile(filepath.Join(
		runtimeComponentPath(statePath, runtimeTesseractComponent),
		runtimeTesseractKeyFile,
	))
	if err != nil {
		t.Fatal(err)
	}
	afterState, err := readStateMarker(
		filepath.Join(statePath, filepath.FromSlash(ctPrimaryDataPath)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(primaryPrivate, afterPrivate) {
		t.Fatal("the historical CT generation signer changed")
	}
	if !bytes.Equal(primaryRuntime, afterRuntime) {
		t.Fatal("the running primary shard's projected signer changed")
	}
	if primaryState != afterState {
		t.Fatal("the primary shard storage identity changed")
	}
	if !bytes.Equal(primaryRuntime, primaryPrivate) {
		t.Fatal("the primary shard is not still bound to its own generation")
	}
}

func TestCtRotationRejectsMalformedOrForeignRequests(t *testing.T) {
	base := stageCtRotation(
		t,
		newCtRotationTestState(t),
		"33333333333333333333333333333333",
		"33333333-3333-3333-3333-333333333333",
	)
	for name, mutate := range map[string]func(request *ctRotationRequest){
		"bad schema":           func(r *ctRotationRequest) { r.SchemaVersion = 2 },
		"bad operation id":     func(r *ctRotationRequest) { r.OperationID = "NOTHEX" },
		"unchanged signer":     func(r *ctRotationRequest) { r.CandidatePublicKeySHA256 = r.StartingCtLogPublicKeySHA256 },
		"foreign shard url":    func(r *ctRotationRequest) { r.CandidateShardURL = "http://evil.localhost" },
		"foreign origin":       func(r *ctRotationRequest) { r.CandidateOrigin = "evil.localhost" },
		"prior url rewritten":  func(r *ctRotationRequest) { r.PriorShardURL = ctSecondaryURL },
		"non-utc created time": func(r *ctRotationRequest) { r.CandidateCreatedAtUTC = time.Now().In(time.FixedZone("x", 3600)) },
		"bad state id":         func(r *ctRotationRequest) { r.CandidateStateID = "not-a-uuid" },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			if err := validateCtRotationRequest(request); err == nil {
				t.Fatal("malformed request was accepted")
			}
		})
	}
}

func TestCtRotationRejectsForeignTrustDomainAndSecondOperation(t *testing.T) {
	statePath := newCtRotationTestState(t)
	request := stageCtRotation(
		t,
		statePath,
		"44444444444444444444444444444444",
		"44444444-4444-4444-4444-444444444444",
	)
	foreign := request
	foreign.TrustDomainID = "sha256-" + hashBytes([]byte("foreign"))
	if err := writeJSON(
		filepath.Join(statePath, ctRotationRequestFile),
		foreign,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := dispatchCtRotation(statePath); err == nil {
		t.Fatal("a request for another trust domain was accepted")
	}

	if err := writeJSON(
		filepath.Join(statePath, ctRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := dispatchCtRotation(statePath); err != nil {
		t.Fatal(err)
	}

	// A second, different bounded rotation is rejected without mutation.
	catalogPath := filepath.Join(statePath, filepath.FromSlash(ctShardCatalogPath))
	catalogBefore := readTestFile(t, catalogPath)
	second := stageCtRotation(
		t,
		statePath,
		"55555555555555555555555555555555",
		"55555555-5555-5555-5555-555555555555",
	)
	_ = second
	if _, err := dispatchCtRotation(statePath); err == nil {
		t.Fatal("a second bounded CT rotation was accepted")
	}
	if !bytes.Equal(catalogBefore, readTestFile(t, catalogPath)) {
		t.Fatal("the rejected second rotation mutated the shard catalog")
	}
}

func TestCtRotationCompletionReplayIsIdempotent(t *testing.T) {
	statePath := newCtRotationTestState(t)
	request := stageCtRotation(
		t,
		statePath,
		"66666666666666666666666666666666",
		"66666666-6666-6666-6666-666666666666",
	)
	if _, err := dispatchCtRotation(statePath); err != nil {
		t.Fatal(err)
	}
	trustedRoot := readActiveTargets(t, statePath, "trusted_root.json")
	catalogPath := filepath.Join(statePath, filepath.FromSlash(ctShardCatalogPath))
	catalog := readTestFile(t, catalogPath)

	if err := writeJSON(
		filepath.Join(statePath, ctRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	action, err := dispatchCtRotation(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if action != repositoryActionPublished {
		t.Fatalf("replay action = %q", action)
	}
	if !bytes.Equal(trustedRoot, readActiveTargets(t, statePath, "trusted_root.json")) {
		t.Fatal("replay changed the committed TrustedRoot")
	}
	if !bytes.Equal(catalog, readTestFile(t, catalogPath)) {
		t.Fatal("replay changed the shard catalog")
	}
}

func TestCtRotationRejectsTamperedCandidateAndProjections(t *testing.T) {
	for name, tamper := range map[string]func(t *testing.T, statePath string){
		"extra candidate file": func(t *testing.T, statePath string) {
			writeTestFile(
				t,
				filepath.Join(
					statePath,
					ctRotationDirectory,
					"77777777777777777777777777777777",
					"candidate",
					"extra",
				),
				[]byte("x"),
			)
		},
		"secondary reuses primary storage identity": func(t *testing.T, statePath string) {
			primary, err := readStateMarker(
				filepath.Join(statePath, filepath.FromSlash(ctPrimaryDataPath)),
			)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(
				t,
				filepath.Join(
					statePath,
					filepath.FromSlash(ctSecondaryDataPath),
					ctCandidateStateFileName,
				),
				[]byte(primary),
			)
		},
		"secondary accepts different roots": func(t *testing.T, statePath string) {
			writeTestFile(
				t,
				filepath.Join(
					statePath,
					filepath.FromSlash(ctSecondaryRuntimeDir),
					runtimeAcceptedRootsFile,
				),
				[]byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"),
			)
		},
		"staged fulcio selection is a different key": func(t *testing.T, statePath string) {
			key := newTestKey(t)
			writeTestFile(
				t,
				filepath.Join(
					statePath,
					filepath.FromSlash(ctFulcioRuntimeDir),
					ctRuntimeSecondaryKeyFile,
				),
				testPublicKeyPEM(t, key),
			)
		},
		"fulcio selection manifest mixes selector and origin": func(t *testing.T, statePath string) {
			writeTestFile(
				t,
				filepath.Join(
					statePath,
					filepath.FromSlash(ctFulcioRuntimeDir),
					ctRuntimeSelectionFileName,
				),
				[]byte(ctRuntimeSelectionHeader+"\nprimary\n"+ctSecondaryOrigin+"\nprimary.pub\n"),
			)
		},
		"fulcio selection manifest is truncated": func(t *testing.T, statePath string) {
			writeTestFile(
				t,
				filepath.Join(
					statePath,
					filepath.FromSlash(ctFulcioRuntimeDir),
					ctRuntimeSelectionFileName,
				),
				[]byte(ctRuntimeSelectionHeader+"\nprimary\n"),
			)
		},
		"secondary shard accepted roots are truncated": func(t *testing.T, statePath string) {
			bundle, err := os.ReadFile(ctShardAcceptedRootsPath(statePath, "secondary"))
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(
				t,
				ctShardAcceptedRootsPath(statePath, "secondary"),
				bundle[:len(bundle)/2],
			)
		},
	} {
		t.Run(name, func(t *testing.T) {
			statePath := newCtRotationTestState(t)
			_ = stageCtRotation(
				t,
				statePath,
				"77777777777777777777777777777777",
				"77777777-7777-7777-7777-777777777777",
			)
			tamper(t, statePath)
			if _, err := dispatchCtRotation(statePath); err == nil {
				t.Fatal("a tampered CT rotation was accepted")
			}
			if _, err := loadCtRotationCompletion(statePath); err != nil {
				t.Fatalf("rejected rotation left ambiguous completion state: %v", err)
			}
		})
	}
}

func TestCtRotationRecoversEveryCommittedBoundaryExactlyOnce(t *testing.T) {
	for _, boundary := range []string{
		"ct-candidate-validated",
		"ct-generation-committed",
		"candidate-prepared",
		"history-parked",
		"candidate-committed",
		"active-switched",
		"ct-tuf-committed",
		"ct-generation-switched",
		"ct-shard-activated",
		"ct-catalog-switched",
		"ct-completion-written",
	} {
		t.Run(boundary, func(t *testing.T) {
			statePath := newCtRotationTestState(t)
			request := stageCtRotation(
				t,
				statePath,
				"88888888888888888888888888888888",
				"88888888-8888-8888-8888-888888888888",
			)
			interrupted := false
			hooks := publicationHooks{
				checkpoint: func(checkpoint publicationCheckpoint) error {
					if string(checkpoint) == boundary && !interrupted {
						interrupted = true
						return errCtSimulatedInterrupt
					}
					return nil
				},
			}
			if _, err := dispatchCtRotationWithHooks(statePath, hooks); err == nil {
				t.Fatalf("boundary %q did not interrupt", boundary)
			}
			if !interrupted {
				t.Fatalf("boundary %q was never reached", boundary)
			}
			if !pathExists(filepath.Join(statePath, ctRotationRequestFile)) {
				if err := writeJSON(
					filepath.Join(statePath, ctRotationRequestFile),
					request,
					0o600,
				); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := dispatchCtRotation(statePath); err != nil {
				t.Fatalf("replay after %q failed: %v", boundary, err)
			}
			active, err := loadActiveTrustGeneration(statePath)
			if err != nil {
				t.Fatal(err)
			}
			if active.Generation != request.StartingGeneration+1 ||
				active.CtLogPublicKeySHA256 != request.CandidatePublicKeySHA256 {
				t.Fatalf("replay after %q did not converge: %+v", boundary, active)
			}
			catalog, err := loadCtShardCatalog(statePath)
			if err != nil {
				t.Fatal(err)
			}
			if len(catalog.Shards) != 2 ||
				catalog.ActiveShardID != request.CandidateShardID {
				t.Fatalf("replay after %q left an ambiguous catalog", boundary)
			}
			generations, err := os.ReadDir(filepath.Join(statePath, "generations"))
			if err != nil {
				t.Fatal(err)
			}
			if len(generations) != request.StartingGeneration+1 {
				t.Fatalf(
					"replay after %q created %d generations",
					boundary,
					len(generations),
				)
			}
		})
	}
}

// TestExistingRotationsPreserveCtMetadata proves the CT shard rotation
// composes with the other bounded rotations: once the certificate
// transparency provenance is recorded in an immutable generation, every
// later rotation carries it forward unchanged.
func TestExistingRotationsPreserveCtMetadata(t *testing.T) {
	statePath := newCtRotationTestState(t)
	request := stageCtRotation(
		t,
		statePath,
		"99999999999999999999999999999998",
		"99999999-9999-9999-9999-999999999998",
	)
	if _, err := dispatchCtRotation(statePath); err != nil {
		t.Fatal(err)
	}
	assertCtMetadata := func() {
		t.Helper()
		active, err := loadActiveTrustGeneration(statePath)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := readOIDCGenerationManifest(statePath, active.GenerationID)
		if err != nil {
			t.Fatal(err)
		}
		if manifest.CtLogRotationOperationID != request.OperationID ||
			manifest.CtLogPriorGeneration != request.StartingGeneration ||
			manifest.CtLogPriorGenerationID != request.StartingGenerationID ||
			manifest.CtLogPriorPublicKeySHA256 != request.StartingCtLogPublicKeySHA256 ||
			manifest.CtLogPriorShardID != request.PriorShardID ||
			manifest.CtLogPriorBaseURL != request.PriorShardURL ||
			manifest.CtLogShardID != request.CandidateShardID ||
			manifest.CtLogBaseURL != request.CandidateShardURL {
			t.Fatalf("CT metadata was not preserved: %+v", manifest)
		}
	}
	assertCtMetadata()

	stageTsaRotation(t, statePath, 8100, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc")
	if _, err := dispatchTsaRotation(statePath); err != nil {
		t.Fatal(err)
	}
	assertCtMetadata()

	if _, _, err := ensureRuntimeBaselineProjection(statePath); err != nil {
		t.Fatal(err)
	}
	stageFulcioRotation(t, statePath, 9100, "ccccccccccccccccccccccccccccccce")
	if _, err := dispatchFulcioRotation(statePath); err != nil {
		t.Fatal(err)
	}
	assertCtMetadata()

	// The historical primary shard is still the one the running Tesseract
	// serves, even several generations later.
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := readOIDCGenerationManifest(statePath, active.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := os.ReadFile(filepath.Join(
		runtimeComponentPath(statePath, runtimeTesseractComponent),
		runtimeTesseractKeyFile,
	))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(filepath.Join(
		ctServingGenerationPath(statePath, manifest),
		filepath.FromSlash(ctLogPrivateKeyRelPath),
	))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(projected, expected) {
		t.Fatal("the primary CT shard projection drifted after later rotations")
	}
}
