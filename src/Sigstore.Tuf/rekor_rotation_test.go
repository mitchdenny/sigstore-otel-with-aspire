package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	trustrootv1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func newRekorRotationTestState(t *testing.T) string {
	t.Helper()
	statePath := newTestState(t)
	if _, err := ensureTUFRepository(statePath); err != nil {
		t.Fatal(err)
	}
	return statePath
}

func stageRekorRotation(
	t *testing.T,
	statePath, operationID, stateID string,
) rekorRotationRequest {
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
		rekorRotationDirectory,
		operationID,
		"candidate",
	)
	writeTestFile(
		t,
		filepath.Join(candidatePath, filepath.FromSlash(rekorSignerPrivateRelPath)),
		privatePEM,
	)
	writeTestFile(
		t,
		filepath.Join(candidatePath, filepath.FromSlash(rekorSignerPublicRelPath)),
		publicPEM,
	)
	dataPath := filepath.Join(statePath, filepath.FromSlash(rekorSecondaryDataPath))
	writeTestFile(t, filepath.Join(dataPath, rekorCandidateStateFileName), []byte(stateID))
	metadata := rekorShardMetadata{
		SchemaVersion:   rekorShardMetadataSchema,
		OperationID:     operationID,
		TrustDomainID:   active.TrustDomainID,
		ShardID:         rekorShardID(digest),
		Slot:            "secondary",
		BaseURL:         rekorSecondaryURL,
		Origin:          rekorSecondaryOrigin,
		PublicKeySHA256: digest,
		LogIDSHA256:     digest,
		StateID:         stateID,
		DataPath:        rekorSecondaryDataPath,
		ResourceName:    rekorSecondaryResourceName,
		CreatedAtUTC:    createdAt,
	}
	if err := writeJSON(
		filepath.Join(dataPath, rekorShardMetadataFileName),
		metadata,
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	writeTestFile(
		t,
		filepath.Join(statePath, filepath.FromSlash(rekorSecondaryRuntimePath)),
		privatePEM,
	)
	request := rekorRotationRequest{
		SchemaVersion:                    rekorRotationSchemaVersion,
		OperationID:                      operationID,
		TrustDomainID:                    active.TrustDomainID,
		StartingGeneration:               active.Generation,
		StartingGenerationID:             active.GenerationID,
		StartingGenerationManifestSHA256: active.GenerationManifestSHA256,
		StartingRekorPublicKeySHA256:     active.RekorPublicKeySHA256,
		PriorShardID:                     rekorShardID(active.RekorPublicKeySHA256),
		PriorShardURL:                    rekorURL,
		CandidateShardID:                 rekorShardID(digest),
		CandidateShardURL:                rekorSecondaryURL,
		CandidateOrigin:                  rekorSecondaryOrigin,
		CandidatePublicKeySHA256:         digest,
		CandidateStateID:                 stateID,
		CandidateCreatedAtUTC:            createdAt,
	}
	if err := writeJSON(
		filepath.Join(statePath, rekorRotationRequestFile),
		request,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return request
}

func TestRekorLogIDAndShardIDUseSPKISHA256(t *testing.T) {
	key := newTestKey(t)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := hashBytes(der)
	entry := newTransparencyLog(rekorSecondaryURL, der, time.Now().UTC())
	got, err := transparencyLogDigest(entry)
	if err != nil {
		t.Fatal(err)
	}
	if got != digest || rekorShardID(got) != "sha256-"+digest {
		t.Fatalf("digest = %q, shard = %q", got, rekorShardID(got))
	}
}

func TestRekorCatalogInitializationRejectsTampering(t *testing.T) {
	statePath := newRekorRotationTestState(t)
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loadRekorShardCatalog(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Shards) != 1 ||
		catalog.Shards[0].ShardID != rekorShardID(active.RekorPublicKeySHA256) {
		t.Fatalf("unexpected catalog: %+v", catalog)
	}
	catalog.Shards[0].BaseURL = "http://attacker.invalid"
	if err := writeRekorShardCatalog(statePath, catalog); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureTUFRepository(statePath); err == nil {
		t.Fatal("tampered Rekor catalog was accepted")
	}
}

func TestRekorShardRotationCommitsExclusiveRouteAndReplays(t *testing.T) {
	statePath := newRekorRotationTestState(t)
	request := stageRekorRotation(
		t,
		statePath,
		"0123456789abcdef0123456789abcdef",
		"12345678-1234-1234-1234-123456789abc",
	)
	priorPath := generationPathFor(statePath, request.StartingGenerationID)
	priorFiles, err := collectGenerationFileHashes(priorPath)
	if err != nil {
		t.Fatal(err)
	}
	action, err := dispatchRekorRotation(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if action != repositoryActionPublished {
		t.Fatalf("action = %q", action)
	}
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if active.Generation != request.StartingGeneration+1 ||
		active.RekorPublicKeySHA256 != request.CandidatePublicKeySHA256 {
		t.Fatalf("unexpected active generation: %+v", active)
	}
	nextFiles, err := collectGenerationFileHashes(generationPathFor(statePath, active.GenerationID))
	if err != nil {
		t.Fatal(err)
	}
	for path, hash := range priorFiles {
		if path == rekorSignerPrivateRelPath || path == rekorSignerPublicRelPath {
			if nextFiles[path] == hash {
				t.Fatalf("Rekor signer %q did not change", path)
			}
			continue
		}
		if nextFiles[path] != hash {
			t.Fatalf("non-Rekor file %q changed", path)
		}
	}
	catalog, err := loadRekorShardCatalog(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Shards) != 2 ||
		catalog.Shards[0].Status != "historical" ||
		catalog.Shards[1].Status != "active" {
		t.Fatalf("unexpected rotated catalog: %+v", catalog)
	}
	metadataPath := filepath.Join(
		statePath,
		filepath.FromSlash(rekorSecondaryDataPath),
		rekorShardMetadataFileName,
	)
	var shardMetadata rekorShardMetadata
	if err := json.Unmarshal(readTestFile(t, metadataPath), &shardMetadata); err != nil {
		t.Fatal(err)
	}
	if shardMetadata.ActivatedAtUTC == nil ||
		shardMetadata.Status != "active" ||
		!shardMetadata.ActivatedAtUTC.Equal(catalog.Shards[1].ActivatedAtUTC) {
		t.Fatalf("secondary shard activation metadata does not match catalog: %+v", shardMetadata)
	}

	layout := newTUFLayout(statePath)
	publication := readTestPublicationState(t, layout)
	targetsPath := filepath.Join(committedPath(layout, publication.Active.ID), "targets")
	trustedRootData := readTestFile(t, filepath.Join(targetsPath, "trusted_root.json"))
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(trustedRootData, trustedRoot); err != nil {
		t.Fatal(err)
	}
	if len(trustedRoot.Tlogs) != 2 {
		t.Fatalf("tlog count = %d, want 2", len(trustedRoot.Tlogs))
	}
	signingConfigData := readTestFile(t, filepath.Join(targetsPath, "signing_config.v0.2.json"))
	signingConfig := &trustrootv1.SigningConfig{}
	if err := protojson.Unmarshal(signingConfigData, signingConfig); err != nil {
		t.Fatal(err)
	}
	if len(signingConfig.RekorTlogUrls) != 1 ||
		signingConfig.RekorTlogUrls[0].GetUrl() != rekorSecondaryURL {
		t.Fatalf("unexpected Rekor signing route: %+v", signingConfig.RekorTlogUrls)
	}
	if !bytes.Equal(
		readTestFile(t, filepath.Join(targetsPath, filepath.FromSlash(rekorPrimaryTargetName))),
		readTestFile(t, filepath.Join(priorPath, filepath.FromSlash(rekorSignerPublicRelPath))),
	) {
		t.Fatal("primary historical target changed")
	}
	completion, err := loadRekorRotationCompletion(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if completion == nil ||
		completion.OperationID != request.OperationID ||
		completion.PriorGenerationManifestSHA256 != request.StartingGenerationManifestSHA256 ||
		completion.PriorPublicKeySHA256 != request.StartingRekorPublicKeySHA256 ||
		completion.NewPublicKeySHA256 != request.CandidatePublicKeySHA256 ||
		completion.PriorShardID != request.PriorShardID ||
		completion.NewShardID != request.CandidateShardID ||
		completion.NewStateID != request.CandidateStateID ||
		completion.ActiveSigningConfigURL != rekorSecondaryURL ||
		completion.Action != string(repositoryActionPublished) {
		t.Fatalf("unexpected exact Rekor completion: %+v", completion)
	}

	if err := writeJSON(filepath.Join(statePath, rekorRotationRequestFile), request, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dispatchRekorRotation(statePath); err != nil {
		t.Fatalf("same-operation replay failed: %v", err)
	}
}

func TestRekorShardRotationRejectsDifferentOperationWithoutMutation(t *testing.T) {
	statePath := newRekorRotationTestState(t)
	request := stageRekorRotation(
		t,
		statePath,
		"11111111111111111111111111111111",
		"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	)
	if _, err := dispatchRekorRotation(statePath); err != nil {
		t.Fatal(err)
	}

	beforeCatalog := readTestFile(
		t,
		filepath.Join(statePath, filepath.FromSlash(rekorShardCatalogPath)),
	)
	beforeActive, err := os.Readlink(filepath.Join(statePath, "active-generation"))
	if err != nil {
		t.Fatal(err)
	}
	request.OperationID = "22222222222222222222222222222222"
	if err := writeJSON(filepath.Join(statePath, rekorRotationRequestFile), request, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dispatchRekorRotation(statePath); err == nil {
		t.Fatal("different Rekor rotation operation was accepted")
	}
	afterCatalog := readTestFile(
		t,
		filepath.Join(statePath, filepath.FromSlash(rekorShardCatalogPath)),
	)
	afterActive, err := os.Readlink(filepath.Join(statePath, "active-generation"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeCatalog, afterCatalog) || beforeActive != afterActive {
		t.Fatal("rejected Rekor rotation mutated active state")
	}
}

func TestRekorRotationPreservesExistingAndStandbyTlogs(t *testing.T) {
	statePath := newRekorRotationTestState(t)
	if _, err := publishTrustedRootUpdate(statePath); err != nil {
		t.Fatal(err)
	}
	before := readActiveTrustedRoot(t, statePath)
	if len(before.Tlogs) != 2 {
		t.Fatalf("pre-rotation tlog count = %d, want active plus standby", len(before.Tlogs))
	}
	beforeJSON := make([][]byte, len(before.Tlogs))
	for index, entry := range before.Tlogs {
		data, err := protojson.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		beforeJSON[index] = data
	}
	stageRekorRotation(
		t,
		statePath,
		"33333333333333333333333333333333",
		"33333333-3333-3333-3333-333333333333",
	)
	if _, err := dispatchRekorRotation(statePath); err != nil {
		t.Fatal(err)
	}
	after := readActiveTrustedRoot(t, statePath)
	if len(after.Tlogs) != len(before.Tlogs)+1 {
		t.Fatalf("post-rotation tlog count = %d", len(after.Tlogs))
	}
	for index := range before.Tlogs {
		data, err := protojson.Marshal(after.Tlogs[index])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, beforeJSON[index]) {
			t.Fatalf("existing tlog entry %d changed during rotation", index)
		}
	}
}

func TestRekorCandidateTamperingIsRejected(t *testing.T) {
	cases := map[string]func(*testing.T, string, rekorRotationRequest){
		"signer": func(t *testing.T, statePath string, request rekorRotationRequest) {
			writeTestFile(
				t,
				filepath.Join(
					statePath,
					rekorRotationDirectory,
					request.OperationID,
					"candidate",
					filepath.FromSlash(rekorSignerPrivateRelPath),
				),
				testECPrivateKeyPEM(t, newTestKey(t)),
			)
		},
		"runtime": func(t *testing.T, statePath string, _ rekorRotationRequest) {
			writeTestFile(
				t,
				filepath.Join(statePath, filepath.FromSlash(rekorSecondaryRuntimePath)),
				[]byte("tampered"),
			)
		},
		"state": func(t *testing.T, statePath string, _ rekorRotationRequest) {
			writeTestFile(
				t,
				filepath.Join(
					statePath,
					filepath.FromSlash(rekorSecondaryDataPath),
					rekorCandidateStateFileName,
				),
				[]byte("ffffffff-ffff-ffff-ffff-ffffffffffff"),
			)
		},
		"url": func(t *testing.T, statePath string, request rekorRotationRequest) {
			path := filepath.Join(
				statePath,
				filepath.FromSlash(rekorSecondaryDataPath),
				rekorShardMetadataFileName,
			)
			var metadata rekorShardMetadata
			if err := json.Unmarshal(readTestFile(t, path), &metadata); err != nil {
				t.Fatal(err)
			}
			metadata.BaseURL = fmt.Sprintf("%s/tampered", request.CandidateShardURL)
			if err := writeJSON(path, metadata, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			statePath := newRekorRotationTestState(t)
			request := stageRekorRotation(
				t,
				statePath,
				"abcdefabcdefabcdefabcdefabcdefab",
				"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
			)
			tamper(t, statePath, request)
			if _, err := dispatchRekorRotation(statePath); err == nil {
				t.Fatal("tampered Rekor candidate was accepted")
			}
			active, err := loadActiveTrustGeneration(statePath)
			if err != nil {
				t.Fatal(err)
			}
			if active.Generation != request.StartingGeneration {
				t.Fatal("candidate tampering changed the active generation")
			}
		})
	}
}

func TestRekorRotationRecoversEveryCommittedBoundary(t *testing.T) {
	checkpoints := []publicationCheckpoint{
		"rekor-generation-committed",
		checkpointCandidatePrepared,
		checkpointHistoryParked,
		checkpointCandidateCommitted,
		checkpointActiveSwitched,
		"rekor-tuf-committed",
		"rekor-generation-switched",
		"rekor-shard-activated",
		"rekor-catalog-switched",
		"rekor-completion-written",
	}

	for index, checkpoint := range checkpoints {
		t.Run(string(checkpoint), func(t *testing.T) {
			statePath := newRekorRotationTestState(t)
			request := stageRekorRotation(
				t,
				statePath,
				fmt.Sprintf("%032x", index+100),
				fmt.Sprintf("12345678-1234-1234-1234-%012x", index+100),
			)
			injected := fmt.Errorf("injected failure at %s", checkpoint)
			_, err := dispatchRekorRotationWithHooks(
				statePath,
				publicationHooks{checkpoint: func(observed publicationCheckpoint) error {
					if observed == checkpoint {
						return injected
					}
					return nil
				}},
			)
			if !errors.Is(err, injected) {
				t.Fatalf("error = %v, want injected failure", err)
			}
			if _, err := dispatchRekorRotation(statePath); err != nil {
				t.Fatalf("recover Rekor rotation: %v", err)
			}
			completion, err := loadRekorRotationCompletion(statePath)
			if err != nil {
				t.Fatal(err)
			}
			if completion == nil ||
				completion.OperationID != request.OperationID ||
				completion.NewGeneration != request.StartingGeneration+1 {
				t.Fatalf("unexpected completion: %+v", completion)
			}
			if err := validateRekorCompletionAgainstState(statePath, completion); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRekorActivatedShardMetadataTamperingRejectsReplay(t *testing.T) {
	statePath := newRekorRotationTestState(t)
	request := stageRekorRotation(
		t,
		statePath,
		"dddddddddddddddddddddddddddddddd",
		"dddddddd-dddd-dddd-dddd-dddddddddddd",
	)
	if _, err := dispatchRekorRotation(statePath); err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(
		statePath,
		filepath.FromSlash(rekorSecondaryDataPath),
		rekorShardMetadataFileName,
	)
	var metadata rekorShardMetadata
	if err := json.Unmarshal(readTestFile(t, metadataPath), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.ActivatedAtUTC == nil || metadata.Status != "active" {
		t.Fatalf("secondary shard was not durably activated: %+v", metadata)
	}
	metadata.Status = "historical"
	if err := writeJSON(metadataPath, metadata, 0o644); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(statePath, filepath.FromSlash(rekorShardCatalogPath))
	catalogBefore := readTestFile(t, catalogPath)
	if err := writeJSON(filepath.Join(statePath, rekorRotationRequestFile), request, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dispatchRekorRotation(statePath); err == nil {
		t.Fatal("replay accepted tampered secondary shard activation metadata")
	}
	if !bytes.Equal(catalogBefore, readTestFile(t, catalogPath)) {
		t.Fatal("failed replay mutated the shard catalog")
	}
}

func TestExistingRotationsPreserveRekorMetadata(t *testing.T) {
	statePath := newRekorRotationTestState(t)
	if _, _, err := ensureRuntimeBaselineProjection(statePath); err != nil {
		t.Fatal(err)
	}
	rekorRequest := stageRekorRotation(
		t,
		statePath,
		"99999999999999999999999999999999",
		"99999999-9999-9999-9999-999999999999",
	)
	if _, err := dispatchRekorRotation(statePath); err != nil {
		t.Fatal(err)
	}
	assertRekorMetadata := func() {
		t.Helper()
		active, err := loadActiveTrustGeneration(statePath)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := readOIDCGenerationManifest(statePath, active.GenerationID)
		if err != nil {
			t.Fatal(err)
		}
		if manifest.RekorRotationOperationID != rekorRequest.OperationID ||
			manifest.RekorPriorGeneration != rekorRequest.StartingGeneration ||
			manifest.RekorPriorGenerationID != rekorRequest.StartingGenerationID ||
			manifest.RekorPriorPublicKeySHA256 != rekorRequest.StartingRekorPublicKeySHA256 ||
			manifest.RekorPriorShardID != rekorRequest.PriorShardID ||
			manifest.RekorPriorBaseURL != rekorRequest.PriorShardURL ||
			manifest.RekorShardID != rekorRequest.CandidateShardID ||
			manifest.RekorBaseURL != rekorRequest.CandidateShardURL {
			t.Fatalf("Rekor metadata was not preserved: %+v", manifest)
		}
	}
	assertRekorMetadata()

	writeOIDCRotationTestRequest(t, statePath, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if _, err := dispatchOidcRotation(statePath); err != nil {
		t.Fatal(err)
	}
	assertRekorMetadata()

	stageTsaRotation(t, statePath, 8000, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if _, err := dispatchTsaRotation(statePath); err != nil {
		t.Fatal(err)
	}
	assertRekorMetadata()

	if _, _, err := ensureRuntimeBaselineProjection(statePath); err != nil {
		t.Fatal(err)
	}
	stageFulcioRotation(t, statePath, 9000, "cccccccccccccccccccccccccccccccc")
	if _, err := dispatchFulcioRotation(statePath); err != nil {
		t.Fatal(err)
	}
	assertRekorMetadata()
}
