package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	commonv1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	trustrootv1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	rekorRotationRequestFile      = "rotate-rekor-shard.request"
	rekorRotationCompletionFile   = "rotate-rekor-shard.completed"
	rekorRotationDirectory        = "rekor-shard-rotation"
	rekorRotationSchemaVersion    = 1
	rekorRotationCompletionSchema = 1
	rekorShardCatalogSchema       = 1
	rekorShardMetadataSchema      = 1

	rekorPrimaryOrigin          = "rekor-sigstore.dev.localhost"
	rekorSecondaryURL           = "http://rekor-secondary-sigstore.dev.localhost:3000"
	rekorSecondaryOrigin        = "rekor-secondary-sigstore.dev.localhost"
	rekorPrimaryDataPath        = "data/rekor"
	rekorSecondaryDataPath      = "data/rekor-shards/secondary"
	rekorPrimaryResourceName    = "rekor-server"
	rekorSecondaryResourceName  = "rekor-server-secondary"
	rekorShardCatalogPath       = "data/rekor-shards/state.json"
	rekorSecondaryRuntimePath   = "runtime/rekor-secondary/signer.key"
	rekorSignerPrivateRelPath   = "private/rekor/signer.key"
	rekorSignerPublicRelPath    = "public/rekor/signer.pub"
	rekorPrimaryTargetName      = "rekor-shards/primary.pub"
	rekorSecondaryTargetName    = "rekor-shards/secondary.pub"
	rekorCandidateStateFileName = "bootstrap-state"
	rekorShardMetadataFileName  = "shard.json"
)

var (
	rekorOperationIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	rekorStateIDPattern     = regexp.MustCompile(
		`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`,
	)
)

type rekorShardCatalog struct {
	SchemaVersion int          `json:"schemaVersion"`
	TrustDomainID string       `json:"trustDomainId"`
	ActiveShardID string       `json:"activeShardId"`
	UpdatedAtUTC  time.Time    `json:"updatedAtUtc"`
	Shards        []rekorShard `json:"shards"`
}

type rekorShard struct {
	ShardID         string    `json:"shardId"`
	Slot            string    `json:"slot"`
	BaseURL         string    `json:"baseUrl"`
	Origin          string    `json:"origin"`
	PublicKeySHA256 string    `json:"publicKeySha256"`
	LogIDSHA256     string    `json:"logIdSha256"`
	StateID         string    `json:"stateId"`
	DataPath        string    `json:"dataPath"`
	ResourceName    string    `json:"resourceName"`
	CreatedAtUTC    time.Time `json:"createdAtUtc"`
	ActivatedAtUTC  time.Time `json:"activatedAtUtc"`
	Status          string    `json:"status"`
}

type rekorShardMetadata struct {
	SchemaVersion   int        `json:"schemaVersion"`
	OperationID     string     `json:"operationId"`
	TrustDomainID   string     `json:"trustDomainId"`
	ShardID         string     `json:"shardId"`
	Slot            string     `json:"slot"`
	BaseURL         string     `json:"baseUrl"`
	Origin          string     `json:"origin"`
	PublicKeySHA256 string     `json:"publicKeySha256"`
	LogIDSHA256     string     `json:"logIdSha256"`
	StateID         string     `json:"stateId"`
	DataPath        string     `json:"dataPath"`
	ResourceName    string     `json:"resourceName"`
	CreatedAtUTC    time.Time  `json:"createdAtUtc"`
	ActivatedAtUTC  *time.Time `json:"activatedAtUtc,omitempty"`
	Status          string     `json:"status,omitempty"`
}

type rekorRotationRequest struct {
	SchemaVersion                    int       `json:"schemaVersion"`
	OperationID                      string    `json:"operationId"`
	TrustDomainID                    string    `json:"trustDomainId"`
	StartingGeneration               int       `json:"startingGeneration"`
	StartingGenerationID             string    `json:"startingGenerationId"`
	StartingGenerationManifestSHA256 string    `json:"startingGenerationManifestSha256"`
	StartingRekorPublicKeySHA256     string    `json:"startingRekorPublicKeySha256"`
	PriorShardID                     string    `json:"priorShardId"`
	PriorShardURL                    string    `json:"priorShardUrl"`
	CandidateShardID                 string    `json:"candidateShardId"`
	CandidateShardURL                string    `json:"candidateShardUrl"`
	CandidateOrigin                  string    `json:"candidateOrigin"`
	CandidatePublicKeySHA256         string    `json:"candidatePublicKeySha256"`
	CandidateStateID                 string    `json:"candidateStateId"`
	CandidateCreatedAtUTC            time.Time `json:"candidateCreatedAtUtc"`
}

type rekorRotationCompletion struct {
	SchemaVersion                 int       `json:"schemaVersion"`
	OperationID                   string    `json:"operationId"`
	TrustDomainID                 string    `json:"trustDomainId"`
	CompletedAtUTC                time.Time `json:"completedAtUtc"`
	PriorGeneration               int       `json:"priorGeneration"`
	PriorGenerationID             string    `json:"priorGenerationId"`
	PriorGenerationManifestSHA256 string    `json:"priorGenerationManifestSha256"`
	PriorPublicKeySHA256          string    `json:"priorPublicKeySha256"`
	PriorShardID                  string    `json:"priorShardId"`
	PriorBaseURL                  string    `json:"priorBaseUrl"`
	PriorStateID                  string    `json:"priorStateId"`
	NewGeneration                 int       `json:"newGeneration"`
	NewGenerationID               string    `json:"newGenerationId"`
	GenerationManifestSHA256      string    `json:"generationManifestSha256"`
	NewPublicKeySHA256            string    `json:"newPublicKeySha256"`
	NewShardID                    string    `json:"newShardId"`
	NewBaseURL                    string    `json:"newBaseUrl"`
	NewStateID                    string    `json:"newStateId"`
	PublicationID                 string    `json:"publicationId"`
	PublicationManifestSHA256     string    `json:"publicationManifestSha256"`
	TrustedRootSHA256             string    `json:"trustedRootSha256"`
	SigningConfigSHA256           string    `json:"signingConfigSha256"`
	PriorTrustedRootTlogCount     int       `json:"priorTrustedRootTlogCount"`
	NewTrustedRootTlogCount       int       `json:"newTrustedRootTlogCount"`
	ActiveSigningConfigURL        string    `json:"activeSigningConfigUrl"`
	Action                        string    `json:"action"`
}

func rekorShardID(publicKeySHA256 string) string {
	return "sha256-" + publicKeySHA256
}

func decodeStrictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains more than one value")
		}
		return err
	}
	return nil
}

func ensureRekorShardCatalogLocked(
	statePath string,
	bootstrap bootstrapManifest,
) (*rekorShardCatalog, error) {
	catalog, err := loadRekorShardCatalog(statePath)
	if err == nil {
		if err := validateRekorShardCatalog(statePath, catalog, bootstrap); err != nil {
			return nil, err
		}
		return catalog, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return nil, fmt.Errorf("read active generation for Rekor shard catalog: %w", err)
	}
	if generation.RekorRotationOperationID != "" {
		return nil, errors.New("rotated Rekor generation is missing its shard catalog")
	}
	generationPath := generationPathFor(statePath, bootstrap.GenerationID)
	_, _, digest, err := loadRekorGenerationKeyPair(generationPath)
	if err != nil {
		return nil, err
	}
	if digest != bootstrap.RekorPublicKeySHA256 {
		return nil, errors.New("active Rekor public key does not match the generation manifest")
	}
	domain, err := loadTrustDomain(statePath)
	if err != nil {
		return nil, fmt.Errorf("load trust domain for Rekor shard catalog: %w", err)
	}
	primaryDataPath := filepath.Join(statePath, filepath.FromSlash(rekorPrimaryDataPath))
	if err := requireRealDirectory(primaryDataPath); err != nil {
		return nil, err
	}
	stateID, err := readStateMarker(primaryDataPath)
	if err != nil {
		return nil, fmt.Errorf("read primary Rekor state marker: %w", err)
	}
	if stateID != domain.RekorStateID {
		return nil, errors.New("primary Rekor state does not match the immutable trust domain")
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(statePath, filepath.FromSlash(rekorShardCatalogPath))), 0o755); err != nil {
		return nil, fmt.Errorf("create Rekor shard catalog directory: %w", err)
	}
	catalog = &rekorShardCatalog{
		SchemaVersion: rekorShardCatalogSchema,
		TrustDomainID: domain.TrustDomainID,
		ActiveShardID: rekorShardID(digest),
		UpdatedAtUTC:  time.Now().UTC(),
		Shards: []rekorShard{{
			ShardID:         rekorShardID(digest),
			Slot:            "primary",
			BaseURL:         rekorURL,
			Origin:          rekorPrimaryOrigin,
			PublicKeySHA256: digest,
			LogIDSHA256:     digest,
			StateID:         stateID,
			DataPath:        rekorPrimaryDataPath,
			ResourceName:    rekorPrimaryResourceName,
			CreatedAtUTC:    domain.CreatedAtUTC,
			ActivatedAtUTC:  domain.CreatedAtUTC,
			Status:          "active",
		}},
	}
	if err := writeRekorShardCatalog(statePath, catalog); err != nil {
		return nil, err
	}
	return catalog, nil
}

func loadRekorShardCatalog(statePath string) (*rekorShardCatalog, error) {
	path := filepath.Join(statePath, filepath.FromSlash(rekorShardCatalogPath))
	if err := requireRegularFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var catalog rekorShardCatalog
	if err := decodeStrictJSON(data, &catalog); err != nil {
		return nil, fmt.Errorf("parse Rekor shard catalog: %w", err)
	}
	return &catalog, nil
}

func writeRekorShardCatalog(statePath string, catalog *rekorShardCatalog) error {
	data, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal Rekor shard catalog: %w", err)
	}
	return writeAtomicJSON(
		filepath.Join(statePath, filepath.FromSlash(rekorShardCatalogPath)),
		append(data, '\n'),
	)
}

func validateRekorShardCatalog(
	statePath string,
	catalog *rekorShardCatalog,
	bootstrap bootstrapManifest,
) error {
	if catalog.SchemaVersion != rekorShardCatalogSchema ||
		catalog.TrustDomainID != bootstrap.TrustDomainID ||
		catalog.UpdatedAtUTC.IsZero() ||
		!isUTC(catalog.UpdatedAtUTC) ||
		(len(catalog.Shards) != 1 && len(catalog.Shards) != 2) {
		return errors.New("Rekor shard catalog has malformed durable state")
	}
	domain, err := loadTrustDomain(statePath)
	if err != nil {
		return err
	}
	generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return err
	}
	_, _, activeDigest, err := loadRekorGenerationKeyPair(
		generationPathFor(statePath, bootstrap.GenerationID),
	)
	if err != nil {
		return err
	}
	if activeDigest != bootstrap.RekorPublicKeySHA256 {
		return errors.New("active Rekor generation fingerprint is inconsistent")
	}

	primary := catalog.Shards[0]
	if err := validateCatalogShard(primary); err != nil {
		return fmt.Errorf("validate primary Rekor shard: %w", err)
	}
	if primary.Slot != "primary" ||
		primary.BaseURL != rekorURL ||
		primary.Origin != rekorPrimaryOrigin ||
		primary.DataPath != rekorPrimaryDataPath ||
		primary.ResourceName != rekorPrimaryResourceName ||
		primary.StateID != domain.RekorStateID ||
		!primary.CreatedAtUTC.Equal(domain.CreatedAtUTC) ||
		!primary.ActivatedAtUTC.Equal(domain.CreatedAtUTC) {
		return errors.New("primary Rekor shard catalog entry does not match the immutable trust domain")
	}
	primaryDataPath := filepath.Join(statePath, filepath.FromSlash(primary.DataPath))
	if err := requireRealDirectory(primaryDataPath); err != nil {
		return err
	}
	primaryState, err := readStateMarker(primaryDataPath)
	if err != nil || primaryState != primary.StateID {
		return errors.New("primary Rekor shard state marker does not match the catalog")
	}

	if len(catalog.Shards) == 1 {
		if catalog.ActiveShardID != primary.ShardID ||
			primary.Status != "active" ||
			generation.RekorRotationOperationID != "" ||
			primary.PublicKeySHA256 != activeDigest {
			return errors.New("single-shard Rekor catalog does not match the active primary generation")
		}
		return nil
	}

	secondary := catalog.Shards[1]
	if err := validateCatalogShard(secondary); err != nil {
		return fmt.Errorf("validate secondary Rekor shard: %w", err)
	}
	if primary.Status != "historical" ||
		secondary.Status != "active" ||
		catalog.ActiveShardID != secondary.ShardID ||
		secondary.Slot != "secondary" ||
		secondary.BaseURL != rekorSecondaryURL ||
		secondary.Origin != rekorSecondaryOrigin ||
		secondary.DataPath != rekorSecondaryDataPath ||
		secondary.ResourceName != rekorSecondaryResourceName ||
		secondary.PublicKeySHA256 != activeDigest ||
		generation.RekorRotationOperationID == "" ||
		generation.RekorPriorPublicKeySHA256 != primary.PublicKeySHA256 ||
		generation.RekorPriorShardID != primary.ShardID ||
		generation.RekorPriorBaseURL != primary.BaseURL ||
		generation.RekorShardID != secondary.ShardID ||
		generation.RekorBaseURL != secondary.BaseURL {
		return errors.New("rotated Rekor shard catalog does not match the active generation")
	}
	if err := validateSecondaryShardState(
		statePath,
		generation.RekorRotationOperationID,
		catalog.TrustDomainID,
		secondary,
		generationPathFor(statePath, bootstrap.GenerationID),
	); err != nil {
		return err
	}
	return nil
}

func validateCatalogShard(shard rekorShard) error {
	if validateSHA256(shard.PublicKeySHA256) != nil ||
		shard.LogIDSHA256 != shard.PublicKeySHA256 ||
		shard.ShardID != rekorShardID(shard.PublicKeySHA256) ||
		shard.StateID == "" ||
		shard.CreatedAtUTC.IsZero() ||
		shard.ActivatedAtUTC.IsZero() ||
		!isUTC(shard.CreatedAtUTC) ||
		!isUTC(shard.ActivatedAtUTC) ||
		shard.ActivatedAtUTC.Before(shard.CreatedAtUTC) ||
		(shard.Status != "active" && shard.Status != "historical") {
		return errors.New("shard entry is malformed")
	}
	return nil
}

func isUTC(value time.Time) bool {
	_, offset := value.Zone()
	return offset == 0
}

func readStateMarker(dataPath string) (string, error) {
	path := filepath.Join(dataPath, rekorCandidateStateFileName)
	if err := requireRegularFile(path); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func validateRekorRotationRequest(request rekorRotationRequest) error {
	if request.SchemaVersion != rekorRotationSchemaVersion ||
		!rekorOperationIDPattern.MatchString(request.OperationID) ||
		request.TrustDomainID == "" ||
		request.StartingGeneration < initialGeneration ||
		request.StartingGenerationID != fmt.Sprintf("generation-%08d", request.StartingGeneration) ||
		validateSHA256(request.StartingGenerationManifestSHA256) != nil ||
		validateSHA256(request.StartingRekorPublicKeySHA256) != nil ||
		validateSHA256(request.CandidatePublicKeySHA256) != nil ||
		request.PriorShardID != rekorShardID(request.StartingRekorPublicKeySHA256) ||
		request.PriorShardURL != rekorURL ||
		request.CandidateShardID != rekorShardID(request.CandidatePublicKeySHA256) ||
		request.CandidateShardURL != rekorSecondaryURL ||
		request.CandidateOrigin != rekorSecondaryOrigin ||
		request.CandidatePublicKeySHA256 == request.StartingRekorPublicKeySHA256 ||
		!rekorStateIDPattern.MatchString(request.CandidateStateID) ||
		request.CandidateCreatedAtUTC.IsZero() ||
		!isUTC(request.CandidateCreatedAtUTC) {
		return errors.New("Rekor shard rotation request has malformed durable state")
	}
	return nil
}

func validateRekorCandidateState(statePath string, request rekorRotationRequest) error {
	candidatePath := filepath.Join(
		statePath,
		rekorRotationDirectory,
		request.OperationID,
		"candidate",
	)
	expected := map[string]bool{
		rekorSignerPrivateRelPath: true,
		rekorSignerPublicRelPath:  true,
	}
	actual := map[string]bool{}
	err := filepath.WalkDir(candidatePath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("candidate Rekor entry %q must not be a symbolic link", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("candidate Rekor entry %q is not a regular file", path)
		}
		relative, err := filepath.Rel(candidatePath, path)
		if err != nil {
			return err
		}
		actual[filepath.ToSlash(relative)] = true
		return nil
	})
	if err != nil {
		return fmt.Errorf("inspect Rekor rotation candidate: %w", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("Rekor rotation candidate file set %v does not match %v", actual, expected)
	}
	privatePEM, publicPEM, digest, err := loadRekorKeyPair(
		filepath.Join(candidatePath, filepath.FromSlash(rekorSignerPrivateRelPath)),
		filepath.Join(candidatePath, filepath.FromSlash(rekorSignerPublicRelPath)),
	)
	if err != nil {
		return fmt.Errorf("validate candidate Rekor key pair: %w", err)
	}
	if digest != request.CandidatePublicKeySHA256 {
		return errors.New("candidate Rekor key does not match the request fingerprint")
	}
	secondary := rekorShard{
		ShardID:         request.CandidateShardID,
		Slot:            "secondary",
		BaseURL:         request.CandidateShardURL,
		Origin:          request.CandidateOrigin,
		PublicKeySHA256: request.CandidatePublicKeySHA256,
		LogIDSHA256:     request.CandidatePublicKeySHA256,
		StateID:         request.CandidateStateID,
		DataPath:        rekorSecondaryDataPath,
		ResourceName:    rekorSecondaryResourceName,
		CreatedAtUTC:    request.CandidateCreatedAtUTC,
	}
	if err := validateSecondaryShardFiles(
		statePath,
		request.OperationID,
		request.TrustDomainID,
		secondary,
		privatePEM,
		publicPEM,
	); err != nil {
		return err
	}
	return nil
}

func validateSecondaryShardState(
	statePath, operationID, trustDomainID string,
	shard rekorShard,
	activeGenerationPath string,
) error {
	privatePEM, err := os.ReadFile(filepath.Join(
		activeGenerationPath,
		filepath.FromSlash(rekorSignerPrivateRelPath),
	))
	if err != nil {
		return err
	}
	publicPEM, err := os.ReadFile(filepath.Join(
		activeGenerationPath,
		filepath.FromSlash(rekorSignerPublicRelPath),
	))
	if err != nil {
		return err
	}
	return validateSecondaryShardFiles(
		statePath,
		operationID,
		trustDomainID,
		shard,
		privatePEM,
		publicPEM,
	)
}

func validateSecondaryShardFiles(
	statePath, operationID, trustDomainID string,
	shard rekorShard,
	expectedPrivatePEM, expectedPublicPEM []byte,
) error {
	dataPath := filepath.Join(statePath, filepath.FromSlash(rekorSecondaryDataPath))
	if err := requireRealDirectory(dataPath); err != nil {
		return err
	}
	stateID, err := readStateMarker(dataPath)
	if err != nil {
		return fmt.Errorf("read secondary Rekor state marker: %w", err)
	}
	if stateID != shard.StateID {
		return errors.New("secondary Rekor state marker does not match its identity")
	}
	metadataPath := filepath.Join(dataPath, rekorShardMetadataFileName)
	if err := requireRegularFile(metadataPath); err != nil {
		return err
	}
	metadataData, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("read secondary Rekor shard metadata: %w", err)
	}
	var metadata rekorShardMetadata
	if err := decodeStrictJSON(metadataData, &metadata); err != nil {
		return fmt.Errorf("parse secondary Rekor shard metadata: %w", err)
	}
	if metadata.SchemaVersion != rekorShardMetadataSchema ||
		metadata.OperationID != operationID ||
		metadata.TrustDomainID != trustDomainID ||
		metadata.ShardID != shard.ShardID ||
		metadata.Slot != "secondary" ||
		metadata.BaseURL != rekorSecondaryURL ||
		metadata.Origin != rekorSecondaryOrigin ||
		metadata.PublicKeySHA256 != shard.PublicKeySHA256 ||
		metadata.LogIDSHA256 != shard.PublicKeySHA256 ||
		metadata.StateID != shard.StateID ||
		metadata.DataPath != rekorSecondaryDataPath ||
		metadata.ResourceName != rekorSecondaryResourceName ||
		!isUTC(metadata.CreatedAtUTC) ||
		!metadata.CreatedAtUTC.Equal(shard.CreatedAtUTC) {
		return errors.New("secondary Rekor shard metadata does not match the rotation")
	}
	switch shard.Status {
	case "":
		if (metadata.ActivatedAtUTC == nil) != (metadata.Status == "") {
			return errors.New("secondary Rekor shard metadata contains a partial activation")
		}
		if metadata.ActivatedAtUTC != nil {
			if metadata.Status != "active" ||
				!isUTC(*metadata.ActivatedAtUTC) ||
				metadata.ActivatedAtUTC.Before(metadata.CreatedAtUTC) {
				return errors.New("secondary Rekor shard metadata has an invalid recovered activation")
			}
		}
	case "active":
		if metadata.ActivatedAtUTC == nil ||
			metadata.Status != "active" ||
			!isUTC(*metadata.ActivatedAtUTC) ||
			!metadata.ActivatedAtUTC.Equal(shard.ActivatedAtUTC) {
			return errors.New("secondary Rekor shard activation does not match the active catalog")
		}
	default:
		return errors.New("secondary Rekor shard catalog status is invalid")
	}
	runtimePath := filepath.Join(statePath, filepath.FromSlash(rekorSecondaryRuntimePath))
	if err := requireRealDirectory(filepath.Dir(runtimePath)); err != nil {
		return err
	}
	runtimeEntries, err := os.ReadDir(filepath.Dir(runtimePath))
	if err != nil {
		return fmt.Errorf("read secondary Rekor runtime projection: %w", err)
	}
	if len(runtimeEntries) != 1 ||
		runtimeEntries[0].Name() != filepath.Base(runtimePath) ||
		!runtimeEntries[0].Type().IsRegular() {
		return errors.New("secondary Rekor runtime projection has an unexpected entry set")
	}
	if err := requireRegularFile(runtimePath); err != nil {
		return err
	}
	runtimeKey, err := os.ReadFile(runtimePath)
	if err != nil {
		return fmt.Errorf("read secondary Rekor runtime key: %w", err)
	}
	if !bytes.Equal(runtimeKey, expectedPrivatePEM) {
		return errors.New("secondary Rekor runtime key is not the candidate signer")
	}
	_, candidatePublic, digest, err := loadRekorKeyPair(runtimePath, filepath.Join(
		statePath,
		rekorRotationDirectory,
		operationID,
		"candidate",
		filepath.FromSlash(rekorSignerPublicRelPath),
	))
	if err != nil {
		return fmt.Errorf("validate secondary Rekor runtime key: %w", err)
	}
	if digest != shard.PublicKeySHA256 || !bytes.Equal(candidatePublic, expectedPublicPEM) {
		return errors.New("secondary Rekor runtime signer identity is inconsistent")
	}
	return nil
}

func requireRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Rekor state path %q must be a real directory", path)
	}
	return nil
}

func requireRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Rekor state path %q must be a regular file", path)
	}
	return nil
}

func loadRekorGenerationKeyPair(generationPath string) ([]byte, []byte, string, error) {
	return loadRekorKeyPair(
		filepath.Join(generationPath, filepath.FromSlash(rekorSignerPrivateRelPath)),
		filepath.Join(generationPath, filepath.FromSlash(rekorSignerPublicRelPath)),
	)
}

func loadRekorKeyPair(privatePath, publicPath string) ([]byte, []byte, string, error) {
	privatePEM, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("read Rekor private key: %w", err)
	}
	privateKey, err := parseRekorPrivateKey(privatePEM)
	if err != nil {
		return nil, nil, "", err
	}
	publicPEM, publicDER, err := loadP256PublicKey(publicPath)
	if err != nil {
		return nil, nil, "", err
	}
	privateDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, "", err
	}
	if !bytes.Equal(privateDER, publicDER) {
		return nil, nil, "", errors.New("Rekor private and public keys do not match")
	}
	return privatePEM, publicPEM, hashBytes(publicDER), nil
}

func parseRekorPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("Rekor private key is not exactly one PEM block")
	}
	var parsed any
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unexpected Rekor private key PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse Rekor private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("Rekor private key must be ECDSA P-256")
	}
	return key, nil
}

func validateRekorGenerationMaterial(
	generationPath string,
	manifest generationManifest,
) error {
	_, _, digest, err := loadRekorGenerationKeyPair(generationPath)
	if err != nil {
		return err
	}
	if digest != manifest.RekorPublicKeySHA256 {
		return errors.New("Rekor public key fingerprint does not match the generation manifest")
	}
	for path := range manifest.Files {
		if strings.HasPrefix(path, "private/rekor/") && path != rekorSignerPrivateRelPath {
			return fmt.Errorf("unexpected Rekor private generation file %q", path)
		}
	}
	if _, ok := manifest.Files[rekorSignerPrivateRelPath]; !ok {
		return errors.New("Rekor generation is missing its signer private key")
	}
	if _, ok := manifest.Files[rekorSignerPublicRelPath]; !ok {
		return errors.New("Rekor generation is missing its signer public key")
	}
	if manifest.RekorRotationOperationID == "" {
		if manifest.RekorPriorGeneration != 0 ||
			manifest.RekorPriorGenerationID != "" ||
			manifest.RekorPriorPublicKeySHA256 != "" ||
			manifest.RekorPriorShardID != "" ||
			manifest.RekorPriorBaseURL != "" ||
			manifest.RekorShardID != "" ||
			manifest.RekorBaseURL != "" {
			return errors.New("generation contains partial Rekor rotation metadata")
		}
		return nil
	}
	if !rekorOperationIDPattern.MatchString(manifest.RekorRotationOperationID) ||
		manifest.RekorPriorGeneration < initialGeneration ||
		manifest.RekorPriorGeneration >= manifest.Generation ||
		manifest.RekorPriorGenerationID != fmt.Sprintf(
			"generation-%08d",
			manifest.RekorPriorGeneration,
		) ||
		validateSHA256(manifest.RekorPriorPublicKeySHA256) != nil ||
		manifest.RekorPriorPublicKeySHA256 == manifest.RekorPublicKeySHA256 ||
		manifest.RekorPriorShardID != rekorShardID(manifest.RekorPriorPublicKeySHA256) ||
		manifest.RekorPriorBaseURL != rekorURL ||
		manifest.RekorShardID != rekorShardID(manifest.RekorPublicKeySHA256) ||
		manifest.RekorBaseURL != rekorSecondaryURL {
		return errors.New("rotated generation has invalid Rekor operation metadata")
	}
	return nil
}

func rotateRekorGeneration(
	statePath string,
	current bootstrapManifest,
	request rekorRotationRequest,
) (bootstrapManifest, error) {
	newGeneration := current.Generation + 1
	newGenerationID := fmt.Sprintf("generation-%08d", newGeneration)
	currentPath := generationPathFor(statePath, current.GenerationID)
	newPath := generationPathFor(statePath, newGenerationID)
	if pathExists(newPath) {
		return validateAndReuseRekorGeneration(
			statePath,
			current,
			request,
			newPath,
			newGeneration,
			newGenerationID,
		)
	}
	currentManifest, err := readOIDCGenerationManifest(statePath, current.GenerationID)
	if err != nil {
		return bootstrapManifest{}, err
	}
	candidatePath := filepath.Join(
		statePath,
		rekorRotationDirectory,
		request.OperationID,
		"candidate",
	)
	stagingPath := filepath.Join(
		statePath,
		rekorRotationDirectory,
		request.OperationID,
		newGenerationID+".staging",
	)
	if err := os.RemoveAll(stagingPath); err != nil {
		return bootstrapManifest{}, err
	}
	if err := os.MkdirAll(stagingPath, 0o755); err != nil {
		return bootstrapManifest{}, err
	}
	if err := copyDirectory(currentPath, stagingPath); err != nil {
		_ = os.RemoveAll(stagingPath)
		return bootstrapManifest{}, err
	}
	if err := os.Remove(filepath.Join(stagingPath, "manifest.json")); err != nil {
		_ = os.RemoveAll(stagingPath)
		return bootstrapManifest{}, err
	}
	for _, relative := range []string{rekorSignerPrivateRelPath, rekorSignerPublicRelPath} {
		data, err := os.ReadFile(filepath.Join(candidatePath, filepath.FromSlash(relative)))
		if err != nil {
			_ = os.RemoveAll(stagingPath)
			return bootstrapManifest{}, err
		}
		mode := os.FileMode(0o644)
		if relative == rekorSignerPrivateRelPath {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(stagingPath, filepath.FromSlash(relative)), data, mode); err != nil {
			_ = os.RemoveAll(stagingPath)
			return bootstrapManifest{}, err
		}
	}
	files, err := collectGenerationFileHashes(stagingPath)
	if err != nil {
		_ = os.RemoveAll(stagingPath)
		return bootstrapManifest{}, err
	}
	now := time.Now().UTC()
	manifest := generationManifest{
		SchemaVersion:               trustStateSchemaVersion,
		Generation:                  newGeneration,
		GenerationID:                newGenerationID,
		TrustDomainID:               current.TrustDomainID,
		CreatedAtUTC:                now,
		SourceSchemaVersion:         trustStateSchemaVersion,
		FulcioRootSHA256:            current.FulcioRootSHA256,
		CtLogPublicKeySHA256:        current.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:        request.CandidatePublicKeySHA256,
		TsaRootSHA256:               current.TsaRootSHA256,
		TsaLeafSHA256:               current.TsaLeafSHA256,
		OIDCKeyID:                   current.OIDCKeyID,
		OIDCRotationOperationID:     currentManifest.OIDCRotationOperationID,
		OIDCPriorGeneration:         currentManifest.OIDCPriorGeneration,
		OIDCPriorGenerationID:       currentManifest.OIDCPriorGenerationID,
		OIDCPriorKeyID:              currentManifest.OIDCPriorKeyID,
		OIDCOverlapExpiresAtUTC:     currentManifest.OIDCOverlapExpiresAtUTC,
		OIDCRetainedPrivateKeyPaths: append([]string(nil), currentManifest.OIDCRetainedPrivateKeyPaths...),
		TSARotationOperationID:      currentManifest.TSARotationOperationID,
		TSAPriorGeneration:          currentManifest.TSAPriorGeneration,
		TSAPriorGenerationID:        currentManifest.TSAPriorGenerationID,
		TSAPriorRootSHA256:          currentManifest.TSAPriorRootSHA256,
		TSAPriorLeafSHA256:          currentManifest.TSAPriorLeafSHA256,
		FulcioRotationOperationID:   currentManifest.FulcioRotationOperationID,
		FulcioPriorGeneration:       currentManifest.FulcioPriorGeneration,
		FulcioPriorGenerationID:     currentManifest.FulcioPriorGenerationID,
		FulcioPriorRootSHA256:       currentManifest.FulcioPriorRootSHA256,
		RekorRotationOperationID:    request.OperationID,
		RekorPriorGeneration:        current.Generation,
		RekorPriorGenerationID:      current.GenerationID,
		RekorPriorPublicKeySHA256:   current.RekorPublicKeySHA256,
		RekorPriorShardID:           request.PriorShardID,
		RekorPriorBaseURL:           request.PriorShardURL,
		RekorShardID:                request.CandidateShardID,
		RekorBaseURL:                request.CandidateShardURL,
		Files:                       files,
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		_ = os.RemoveAll(stagingPath)
		return bootstrapManifest{}, err
	}
	manifestData = append(manifestData, '\n')
	if err := writeGenerationManifest(filepath.Join(stagingPath, "manifest.json"), manifestData); err != nil {
		_ = os.RemoveAll(stagingPath)
		return bootstrapManifest{}, err
	}
	if err := validateRekorGenerationMaterial(stagingPath, manifest); err != nil {
		_ = os.RemoveAll(stagingPath)
		return bootstrapManifest{}, err
	}
	if err := validateOnlyRekorSignerChanged(currentPath, stagingPath); err != nil {
		_ = os.RemoveAll(stagingPath)
		return bootstrapManifest{}, err
	}
	if err := os.Rename(stagingPath, newPath); err != nil {
		return bootstrapManifest{}, err
	}
	if err := syncDirectory(filepath.Dir(newPath)); err != nil {
		return bootstrapManifest{}, err
	}
	return bootstrapManifest{
		SchemaVersion:            4,
		CreatedAtUTC:             now,
		FulcioRootSHA256:         current.FulcioRootSHA256,
		CtLogPublicKeySHA256:     current.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:     request.CandidatePublicKeySHA256,
		TsaRootSHA256:            current.TsaRootSHA256,
		TsaLeafSHA256:            current.TsaLeafSHA256,
		OIDCKeyID:                current.OIDCKeyID,
		TrustDomainID:            current.TrustDomainID,
		Generation:               newGeneration,
		GenerationID:             newGenerationID,
		GenerationManifestSHA256: hashBytes(manifestData),
	}, nil
}

func validateAndReuseRekorGeneration(
	statePath string,
	current bootstrapManifest,
	request rekorRotationRequest,
	newPath string,
	newGeneration int,
	newGenerationID string,
) (bootstrapManifest, error) {
	manifestData, err := os.ReadFile(filepath.Join(newPath, "manifest.json"))
	if err != nil {
		return bootstrapManifest{}, err
	}
	var manifest generationManifest
	if err := decodeStrictJSON(manifestData, &manifest); err != nil {
		return bootstrapManifest{}, err
	}
	if manifest.SchemaVersion != trustStateSchemaVersion ||
		manifest.Generation != newGeneration ||
		manifest.GenerationID != newGenerationID ||
		manifest.TrustDomainID != current.TrustDomainID ||
		manifest.RekorRotationOperationID != request.OperationID ||
		manifest.RekorPriorGeneration != request.StartingGeneration ||
		manifest.RekorPriorGenerationID != request.StartingGenerationID ||
		manifest.RekorPriorPublicKeySHA256 != request.StartingRekorPublicKeySHA256 ||
		manifest.RekorPriorShardID != request.PriorShardID ||
		manifest.RekorPriorBaseURL != request.PriorShardURL ||
		manifest.RekorPublicKeySHA256 != request.CandidatePublicKeySHA256 ||
		manifest.RekorShardID != request.CandidateShardID ||
		manifest.RekorBaseURL != request.CandidateShardURL {
		return bootstrapManifest{}, errors.New("pre-existing Rekor generation is not bound to this request")
	}
	actual, err := collectGenerationFileHashes(newPath)
	if err != nil {
		return bootstrapManifest{}, err
	}
	if !reflect.DeepEqual(actual, manifest.Files) {
		return bootstrapManifest{}, errors.New("pre-existing Rekor generation does not match its manifest")
	}
	if err := validateRekorGenerationMaterial(newPath, manifest); err != nil {
		return bootstrapManifest{}, err
	}
	if err := validateOnlyRekorSignerChanged(
		generationPathFor(statePath, current.GenerationID),
		newPath,
	); err != nil {
		return bootstrapManifest{}, err
	}
	return bootstrapManifest{
		SchemaVersion:            4,
		CreatedAtUTC:             manifest.CreatedAtUTC,
		FulcioRootSHA256:         manifest.FulcioRootSHA256,
		CtLogPublicKeySHA256:     manifest.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:     manifest.RekorPublicKeySHA256,
		TsaRootSHA256:            manifest.TsaRootSHA256,
		TsaLeafSHA256:            manifest.TsaLeafSHA256,
		OIDCKeyID:                manifest.OIDCKeyID,
		TrustDomainID:            manifest.TrustDomainID,
		Generation:               manifest.Generation,
		GenerationID:             manifest.GenerationID,
		GenerationManifestSHA256: hashBytes(manifestData),
	}, nil
}

func validateOnlyRekorSignerChanged(currentPath, newPath string) error {
	current, err := collectGenerationFileHashes(currentPath)
	if err != nil {
		return err
	}
	next, err := collectGenerationFileHashes(newPath)
	if err != nil {
		return err
	}
	for path, hash := range current {
		if path == rekorSignerPrivateRelPath || path == rekorSignerPublicRelPath {
			if next[path] == hash {
				return fmt.Errorf("Rekor signer file %q did not change", path)
			}
			continue
		}
		if next[path] != hash {
			return fmt.Errorf("non-signer generation material %q changed", path)
		}
	}
	for path := range next {
		if _, ok := current[path]; !ok {
			return fmt.Errorf("unexpected generation material %q", path)
		}
	}
	return nil
}

func buildRekorRotationTargets(
	statePath string,
	newGenerationPath string,
	bootstrap bootstrapManifest,
	activeTargetsPath string,
) ([]tufTarget, int, int, error) {
	manifest, err := readOIDCGenerationManifest(
		statePath,
		filepath.Base(newGenerationPath),
	)
	if err != nil {
		return nil, 0, 0, err
	}
	priorPublicKey, priorDER, err := loadP256PublicKey(filepath.Join(
		statePath,
		"generations",
		manifest.RekorPriorGenerationID,
		filepath.FromSlash(rekorSignerPublicRelPath),
	))
	if err != nil {
		return nil, 0, 0, err
	}
	newPublicKey, newDER, err := loadP256PublicKey(filepath.Join(
		newGenerationPath,
		filepath.FromSlash(rekorSignerPublicRelPath),
	))
	if err != nil {
		return nil, 0, 0, err
	}
	if hashBytes(priorDER) != manifest.RekorPriorPublicKeySHA256 ||
		hashBytes(newDER) != manifest.RekorPublicKeySHA256 {
		return nil, 0, 0, errors.New("Rekor generation keys do not match rotation metadata")
	}
	for name, expected := range map[string][]byte{
		rekorPrimaryTargetName:   priorPublicKey,
		rekorSecondaryTargetName: newPublicKey,
	} {
		path := filepath.Join(activeTargetsPath, filepath.FromSlash(name))
		if existing, err := os.ReadFile(path); err == nil {
			if !bytes.Equal(existing, expected) {
				return nil, 0, 0, fmt.Errorf("immutable Rekor target %q conflicts with the rotation", name)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, 0, 0, err
		}
	}

	trustedRootData, err := os.ReadFile(filepath.Join(activeTargetsPath, "trusted_root.json"))
	if err != nil {
		return nil, 0, 0, err
	}
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(trustedRootData, trustedRoot); err != nil {
		return nil, 0, 0, err
	}
	priorCount := len(trustedRoot.Tlogs)
	foundPrior := false
	for _, entry := range trustedRoot.Tlogs {
		digest, err := transparencyLogDigest(entry)
		if err != nil {
			return nil, 0, 0, err
		}
		if digest == manifest.RekorPublicKeySHA256 {
			return nil, 0, 0, errors.New("committed TrustedRoot already contains the candidate Rekor shard")
		}
		if digest == manifest.RekorPriorPublicKeySHA256 && entry.GetBaseUrl() == manifest.RekorPriorBaseURL {
			foundPrior = true
		}
	}
	if !foundPrior {
		return nil, 0, 0, errors.New("committed TrustedRoot omits the prior active Rekor shard")
	}
	trustedRoot.Tlogs = append(
		trustedRoot.Tlogs,
		newTransparencyLog(rekorSecondaryURL, newDER, manifest.CreatedAtUTC),
	)

	signingConfigData, err := os.ReadFile(filepath.Join(activeTargetsPath, "signing_config.v0.2.json"))
	if err != nil {
		return nil, 0, 0, err
	}
	signingConfig := &trustrootv1.SigningConfig{}
	if err := protojson.Unmarshal(signingConfigData, signingConfig); err != nil {
		return nil, 0, 0, err
	}
	if len(signingConfig.RekorTlogUrls) != 1 ||
		signingConfig.RekorTlogUrls[0].GetUrl() != manifest.RekorPriorBaseURL ||
		signingConfig.RekorTlogUrls[0].GetMajorApiVersion() != 2 ||
		signingConfig.RekorTlogUrls[0].GetOperator() != operatorName ||
		signingConfig.GetRekorTlogConfig().GetSelector() != trustrootv1.ServiceSelector_ANY {
		return nil, 0, 0, errors.New("committed SigningConfig does not identify exactly the prior active Rekor shard")
	}
	signingConfig.RekorTlogUrls = []*trustrootv1.Service{
		newService(rekorSecondaryURL, 2, manifest.CreatedAtUTC),
	}

	trustedRootJSON, err := protoJSON.Marshal(trustedRoot)
	if err != nil {
		return nil, 0, 0, err
	}
	trustedRootBytes := append(trustedRootJSON, '\n')
	signingConfigJSON, err := protoJSON.Marshal(signingConfig)
	if err != nil {
		return nil, 0, 0, err
	}
	signingConfigBytes := append(signingConfigJSON, '\n')
	clientConfigJSON, err := protoJSON.Marshal(&trustrootv1.ClientTrustConfig{
		MediaType:     clientTrustConfigMediaType,
		TrustedRoot:   trustedRoot,
		SigningConfig: signingConfig,
	})
	if err != nil {
		return nil, 0, 0, err
	}
	clientConfigBytes := append(clientConfigJSON, '\n')
	statusJSON, err := json.MarshalIndent(trustStatusTarget{
		SchemaVersion:            trustStatusSchemaVersion,
		TrustDomainID:            bootstrap.TrustDomainID,
		Generation:               bootstrap.Generation,
		GenerationID:             bootstrap.GenerationID,
		GenerationManifestSHA256: bootstrap.GenerationManifestSHA256,
		TrustedRootSHA256:        hashBytes(trustedRootBytes),
		SigningConfigSHA256:      hashBytes(signingConfigBytes),
	}, "", "  ")
	if err != nil {
		return nil, 0, 0, err
	}
	return []tufTarget{
		{name: "rekor.pub", data: newPublicKey, custom: targetMetadata("Rekor", rekorSecondaryURL)},
		{name: rekorPrimaryTargetName, data: priorPublicKey, custom: targetMetadata("Rekor", rekorURL)},
		{name: rekorSecondaryTargetName, data: newPublicKey, custom: targetMetadata("Rekor", rekorSecondaryURL)},
		{name: "trusted_root.json", data: trustedRootBytes},
		{name: "signing_config.v0.2.json", data: signingConfigBytes},
		{name: "client_trust_config.json", data: clientConfigBytes},
		{name: trustStatusTargetName, data: append(statusJSON, '\n')},
	}, priorCount, len(trustedRoot.Tlogs), nil
}

func transparencyLogDigest(entry *trustrootv1.TransparencyLogInstance) (string, error) {
	if entry.GetHashAlgorithm() != commonv1.HashAlgorithm_SHA2_256 ||
		entry.GetPublicKey().GetKeyDetails() != commonv1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256 {
		return "", errors.New("TrustedRoot contains an unsupported Rekor transparency log")
	}
	parsed, err := x509.ParsePKIXPublicKey(entry.GetPublicKey().GetRawBytes())
	if err != nil {
		return "", err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return "", errors.New("TrustedRoot Rekor key must be ECDSA P-256")
	}
	sum := sha256.Sum256(entry.GetPublicKey().GetRawBytes())
	if !bytes.Equal(entry.GetLogId().GetKeyId(), sum[:]) {
		return "", errors.New("TrustedRoot Rekor log ID does not match its public key")
	}
	return hex.EncodeToString(sum[:]), nil
}

func publishRekorRotationUpdate(
	statePath string,
	oldBootstrap, newBootstrap bootstrapManifest,
	hooks publicationHooks,
) (int, int, error) {
	oldFingerprint, err := fingerprintSource(oldBootstrap)
	if err != nil {
		return 0, 0, err
	}
	newFingerprint, err := fingerprintSource(newBootstrap)
	if err != nil {
		return 0, 0, err
	}
	layout := newTUFLayout(statePath)
	if err := ensureTUFLayout(layout); err != nil {
		return 0, 0, err
	}
	state, err := loadPublicationState(layout)
	if err != nil {
		return 0, 0, err
	}
	if state.Status != publicationStatusCommitted || state.Active == nil {
		return 0, 0, errors.New("Rekor rotation requires a committed active TUF publication")
	}
	if err := cleanupPublicationTemps(layout); err != nil {
		return 0, 0, err
	}
	if err := cleanupUnjournaledCandidate(layout); err != nil {
		return 0, 0, err
	}
	activePath := committedPath(layout, state.Active.ID)
	if _, _, err := validateExistingRepository(activePath, oldFingerprint); err != nil {
		return 0, 0, err
	}
	if err := os.Mkdir(layout.candidate, 0o755); err != nil {
		return 0, 0, err
	}
	if err := copyDirectory(activePath, layout.candidate); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return 0, 0, err
	}
	targets, priorCount, newCount, err := buildRekorRotationTargets(
		statePath,
		generationPathFor(statePath, newBootstrap.GenerationID),
		newBootstrap,
		filepath.Join(activePath, "targets"),
	)
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return 0, 0, err
	}
	if err := replaceTargetsInRepository(layout.candidate, targets, newBootstrap); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return 0, 0, err
	}
	now := time.Now().UTC()
	if err := writeRepositoryManifest(layout.candidate, tufManifest{
		SchemaVersion:     tufSchemaVersion,
		CreatedAtUTC:      now,
		UpdatedAtUTC:      now,
		SourceFingerprint: newFingerprint,
	}); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return 0, 0, err
	}
	candidate, err := repositoryReference(layout.candidate, newFingerprint)
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return 0, 0, err
	}
	if candidate.ID == state.Active.ID || pathExists(committedPath(layout, candidate.ID)) {
		_ = os.RemoveAll(layout.candidate)
		return 0, 0, errors.New("Rekor rotation candidate publication is ambiguous")
	}
	preparing := state
	preparing.Status = publicationStatusPreparing
	preparing.UpdatedAtUTC = time.Now().UTC()
	preparing.Candidate = &candidate
	if err := writePublicationState(layout, preparing); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return 0, 0, err
	}
	if err := runCheckpoint(hooks, checkpointCandidatePrepared); err != nil {
		return 0, 0, rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}
	if state.Previous != nil {
		if err := os.Rename(layout.previous, layout.retiredPrevious); err != nil {
			return 0, 0, rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
		}
	}
	if err := runCheckpoint(hooks, checkpointHistoryParked); err != nil {
		return 0, 0, rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}
	if err := os.Rename(layout.candidate, committedPath(layout, candidate.ID)); err != nil {
		return 0, 0, rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}
	if err := runCheckpoint(hooks, checkpointCandidateCommitted); err != nil {
		return 0, 0, rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}
	if err := switchActivePublication(layout, candidate.ID, hooks); err != nil {
		return 0, 0, rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}
	if err := runCheckpoint(hooks, checkpointActiveSwitched); err != nil {
		return 0, 0, err
	}
	if err := finalizePublishPublication(layout, preparing, oldFingerprint, newFingerprint, hooks); err != nil {
		return 0, 0, err
	}
	return priorCount, newCount, nil
}

func switchRekorShardCatalog(
	statePath string,
	catalog *rekorShardCatalog,
	request rekorRotationRequest,
	bootstrap bootstrapManifest,
) (*rekorShardCatalog, error) {
	return switchRekorShardCatalogLocked(
		statePath,
		catalog,
		request,
		bootstrap,
		publicationHooks{},
	)
}

func switchRekorShardCatalogLocked(
	statePath string,
	catalog *rekorShardCatalog,
	request rekorRotationRequest,
	bootstrap bootstrapManifest,
	hooks publicationHooks,
) (*rekorShardCatalog, error) {
	if len(catalog.Shards) == 2 {
		if err := validateRekorShardCatalog(statePath, catalog, bootstrap); err != nil {
			return nil, err
		}
		return catalog, nil
	}
	if len(catalog.Shards) != 1 {
		return nil, errors.New("Rekor shard catalog is ambiguous")
	}
	if err := validateRekorCandidateState(statePath, request); err != nil {
		return nil, err
	}
	updated := *catalog
	updated.Shards = append([]rekorShard(nil), catalog.Shards...)
	updated.Shards[0].Status = "historical"
	activated, err := activateSecondaryRekorShardMetadata(statePath, request)
	if err != nil {
		return nil, err
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("rekor-shard-activated")); err != nil {
		return nil, err
	}
	updated.Shards = append(updated.Shards, rekorShard{
		ShardID:         request.CandidateShardID,
		Slot:            "secondary",
		BaseURL:         request.CandidateShardURL,
		Origin:          request.CandidateOrigin,
		PublicKeySHA256: request.CandidatePublicKeySHA256,
		LogIDSHA256:     request.CandidatePublicKeySHA256,
		StateID:         request.CandidateStateID,
		DataPath:        rekorSecondaryDataPath,
		ResourceName:    rekorSecondaryResourceName,
		CreatedAtUTC:    request.CandidateCreatedAtUTC,
		ActivatedAtUTC:  activated,
		Status:          "active",
	})
	updated.ActiveShardID = request.CandidateShardID
	updated.UpdatedAtUTC = activated
	if err := validateRekorShardCatalog(statePath, &updated, bootstrap); err != nil {
		return nil, err
	}
	if err := writeRekorShardCatalog(statePath, &updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

func activateSecondaryRekorShardMetadata(
	statePath string,
	request rekorRotationRequest,
) (time.Time, error) {
	path := filepath.Join(
		statePath,
		filepath.FromSlash(rekorSecondaryDataPath),
		rekorShardMetadataFileName,
	)
	if err := requireRegularFile(path); err != nil {
		return time.Time{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	var metadata rekorShardMetadata
	if err := decodeStrictJSON(data, &metadata); err != nil {
		return time.Time{}, fmt.Errorf("parse secondary Rekor shard metadata for activation: %w", err)
	}
	if metadata.OperationID != request.OperationID ||
		metadata.TrustDomainID != request.TrustDomainID ||
		metadata.ShardID != request.CandidateShardID ||
		metadata.PublicKeySHA256 != request.CandidatePublicKeySHA256 ||
		metadata.StateID != request.CandidateStateID ||
		!metadata.CreatedAtUTC.Equal(request.CandidateCreatedAtUTC) {
		return time.Time{}, errors.New("secondary Rekor shard metadata is not bound to its activation request")
	}
	if metadata.ActivatedAtUTC != nil || metadata.Status != "" {
		if metadata.ActivatedAtUTC == nil ||
			metadata.Status != "active" ||
			!isUTC(*metadata.ActivatedAtUTC) ||
			metadata.ActivatedAtUTC.Before(metadata.CreatedAtUTC) {
			return time.Time{}, errors.New("secondary Rekor shard metadata contains an invalid activation")
		}
		return *metadata.ActivatedAtUTC, nil
	}
	activated := time.Now().UTC()
	metadata.ActivatedAtUTC = &activated
	metadata.Status = "active"
	updated, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return time.Time{}, fmt.Errorf("marshal activated secondary Rekor shard metadata: %w", err)
	}
	if err := writeAtomicJSON(path, append(updated, '\n')); err != nil {
		return time.Time{}, fmt.Errorf("activate secondary Rekor shard metadata: %w", err)
	}
	return activated, nil
}

func loadRekorRotationCompletion(statePath string) (*rekorRotationCompletion, error) {
	data, err := os.ReadFile(filepath.Join(statePath, rekorRotationCompletionFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var completion rekorRotationCompletion
	if err := decodeStrictJSON(data, &completion); err != nil {
		return nil, err
	}
	if completion.SchemaVersion != rekorRotationCompletionSchema ||
		!rekorOperationIDPattern.MatchString(completion.OperationID) ||
		completion.TrustDomainID == "" ||
		completion.CompletedAtUTC.IsZero() ||
		!isUTC(completion.CompletedAtUTC) ||
		completion.NewGeneration != completion.PriorGeneration+1 ||
		completion.PriorGenerationID != fmt.Sprintf("generation-%08d", completion.PriorGeneration) ||
		completion.NewGenerationID != fmt.Sprintf("generation-%08d", completion.NewGeneration) ||
		validateSHA256(completion.PriorGenerationManifestSHA256) != nil ||
		validateSHA256(completion.GenerationManifestSHA256) != nil ||
		validateSHA256(completion.PriorPublicKeySHA256) != nil ||
		validateSHA256(completion.NewPublicKeySHA256) != nil ||
		completion.PriorShardID != rekorShardID(completion.PriorPublicKeySHA256) ||
		completion.NewShardID != rekorShardID(completion.NewPublicKeySHA256) ||
		completion.PriorBaseURL != rekorURL ||
		completion.NewBaseURL != rekorSecondaryURL ||
		completion.PriorStateID == "" ||
		!rekorStateIDPattern.MatchString(completion.NewStateID) ||
		completion.PublicationID == "" ||
		validateSHA256(completion.PublicationManifestSHA256) != nil ||
		validateSHA256(completion.TrustedRootSHA256) != nil ||
		validateSHA256(completion.SigningConfigSHA256) != nil ||
		completion.NewTrustedRootTlogCount != completion.PriorTrustedRootTlogCount+1 ||
		completion.ActiveSigningConfigURL != rekorSecondaryURL ||
		(completion.Action != string(repositoryActionPublished) &&
			completion.Action != string(repositoryActionRecovered)) {
		return nil, errors.New("Rekor rotation completion has malformed durable state")
	}
	return &completion, nil
}

func writeRekorRotationCompletion(
	statePath string,
	completion rekorRotationCompletion,
) error {
	data, err := json.MarshalIndent(completion, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicJSON(
		filepath.Join(statePath, rekorRotationCompletionFile),
		append(data, '\n'),
	)
}

func validateRekorCompletionAgainstState(
	statePath string,
	completion *rekorRotationCompletion,
) error {
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return err
	}
	if completion.TrustDomainID != bootstrap.TrustDomainID ||
		completion.NewGeneration != bootstrap.Generation ||
		completion.NewGenerationID != bootstrap.GenerationID ||
		completion.GenerationManifestSHA256 != bootstrap.GenerationManifestSHA256 ||
		completion.NewPublicKeySHA256 != bootstrap.RekorPublicKeySHA256 {
		return errors.New("Rekor rotation completion does not match the active generation")
	}
	manifest, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return err
	}
	if manifest.RekorRotationOperationID != completion.OperationID ||
		manifest.RekorPriorGeneration != completion.PriorGeneration ||
		manifest.RekorPriorGenerationID != completion.PriorGenerationID ||
		manifest.RekorPriorPublicKeySHA256 != completion.PriorPublicKeySHA256 ||
		manifest.RekorPriorShardID != completion.PriorShardID ||
		manifest.RekorPriorBaseURL != completion.PriorBaseURL ||
		manifest.RekorShardID != completion.NewShardID ||
		manifest.RekorBaseURL != completion.NewBaseURL {
		return errors.New("Rekor completion does not match generation rotation metadata")
	}
	priorManifestData, err := os.ReadFile(filepath.Join(
		generationPathFor(statePath, completion.PriorGenerationID),
		"manifest.json",
	))
	if err != nil || hashBytes(priorManifestData) != completion.PriorGenerationManifestSHA256 {
		return errors.New("Rekor completion prior generation reference is invalid")
	}
	catalog, err := loadRekorShardCatalog(statePath)
	if err != nil {
		return err
	}
	if err := validateRekorShardCatalog(statePath, catalog, bootstrap); err != nil {
		return err
	}
	if len(catalog.Shards) != 2 ||
		catalog.Shards[0].StateID != completion.PriorStateID ||
		catalog.Shards[1].StateID != completion.NewStateID {
		return errors.New("Rekor completion does not match the shard catalog")
	}
	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return err
	}
	if publication.Status != publicationStatusCommitted ||
		publication.Active == nil ||
		publication.Active.ID != completion.PublicationID ||
		publication.Active.ManifestSHA256 != completion.PublicationManifestSHA256 {
		return errors.New("Rekor completion does not match the active TUF publication")
	}
	targetsPath := filepath.Join(committedPath(layout, publication.Active.ID), "targets")
	trustedRootData, err := os.ReadFile(filepath.Join(targetsPath, "trusted_root.json"))
	if err != nil || hashBytes(trustedRootData) != completion.TrustedRootSHA256 {
		return errors.New("Rekor completion TrustedRoot hash is invalid")
	}
	signingConfigData, err := os.ReadFile(filepath.Join(targetsPath, "signing_config.v0.2.json"))
	if err != nil || hashBytes(signingConfigData) != completion.SigningConfigSHA256 {
		return errors.New("Rekor completion SigningConfig hash is invalid")
	}
	statusData, err := os.ReadFile(filepath.Join(targetsPath, trustStatusTargetName))
	if err != nil {
		return err
	}
	var status trustStatusTarget
	if err := decodeStrictJSON(statusData, &status); err != nil ||
		status.TrustDomainID != completion.TrustDomainID ||
		status.Generation != completion.NewGeneration ||
		status.GenerationID != completion.NewGenerationID ||
		status.GenerationManifestSHA256 != completion.GenerationManifestSHA256 ||
		status.TrustedRootSHA256 != completion.TrustedRootSHA256 ||
		status.SigningConfigSHA256 != completion.SigningConfigSHA256 {
		return errors.New("Rekor completion trust status is invalid")
	}
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(trustedRootData, trustedRoot); err != nil {
		return err
	}
	if len(trustedRoot.Tlogs) != completion.NewTrustedRootTlogCount {
		return errors.New("Rekor completion tlog count is invalid")
	}
	foundPrior, foundNew := false, false
	for _, entry := range trustedRoot.Tlogs {
		digest, err := transparencyLogDigest(entry)
		if err != nil {
			return err
		}
		if digest == completion.PriorPublicKeySHA256 && entry.GetBaseUrl() == completion.PriorBaseURL {
			foundPrior = true
		}
		if digest == completion.NewPublicKeySHA256 && entry.GetBaseUrl() == completion.NewBaseURL {
			foundNew = true
		}
	}
	if !foundPrior || !foundNew {
		return errors.New("Rekor completion shards are absent from TrustedRoot")
	}
	signingConfig := &trustrootv1.SigningConfig{}
	if err := protojson.Unmarshal(signingConfigData, signingConfig); err != nil {
		return err
	}
	if len(signingConfig.RekorTlogUrls) != 1 ||
		signingConfig.RekorTlogUrls[0].GetUrl() != completion.ActiveSigningConfigURL ||
		signingConfig.RekorTlogUrls[0].GetMajorApiVersion() != 2 ||
		signingConfig.RekorTlogUrls[0].GetOperator() != operatorName ||
		signingConfig.GetRekorTlogConfig().GetSelector() != trustrootv1.ServiceSelector_ANY {
		return errors.New("Rekor completion active SigningConfig URL is invalid")
	}
	for name, generationID := range map[string]string{
		rekorPrimaryTargetName:   completion.PriorGenerationID,
		rekorSecondaryTargetName: completion.NewGenerationID,
	} {
		target, err := os.ReadFile(filepath.Join(targetsPath, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		expected, err := os.ReadFile(filepath.Join(
			generationPathFor(statePath, generationID),
			filepath.FromSlash(rekorSignerPublicRelPath),
		))
		if err != nil || !bytes.Equal(target, expected) {
			return fmt.Errorf("Rekor completion target %q is invalid", name)
		}
	}
	rekorTarget, err := os.ReadFile(filepath.Join(targetsPath, "rekor.pub"))
	if err != nil {
		return err
	}
	activePublicKey, err := os.ReadFile(filepath.Join(
		generationPathFor(statePath, completion.NewGenerationID),
		filepath.FromSlash(rekorSignerPublicRelPath),
	))
	if err != nil || !bytes.Equal(rekorTarget, activePublicKey) {
		return errors.New("Rekor completion active rekor.pub target is invalid")
	}
	return nil
}

func finalizeRekorRotationCompletion(
	statePath string,
	request rekorRotationRequest,
	action repositoryAction,
	priorTlogCount int,
) error {
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return err
	}
	manifest, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return err
	}
	catalog, err := loadRekorShardCatalog(statePath)
	if err != nil {
		return err
	}
	if err := validateRekorShardCatalog(statePath, catalog, bootstrap); err != nil {
		return err
	}
	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return err
	}
	if publication.Status != publicationStatusCommitted || publication.Active == nil {
		return errors.New("Rekor rotation has no committed TUF publication")
	}
	targetsPath := filepath.Join(committedPath(layout, publication.Active.ID), "targets")
	trustedRootData, err := os.ReadFile(filepath.Join(targetsPath, "trusted_root.json"))
	if err != nil {
		return err
	}
	signingConfigData, err := os.ReadFile(filepath.Join(targetsPath, "signing_config.v0.2.json"))
	if err != nil {
		return err
	}
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(trustedRootData, trustedRoot); err != nil {
		return err
	}
	if priorTlogCount == 0 {
		priorTlogCount = len(trustedRoot.Tlogs) - 1
	}
	completion := rekorRotationCompletion{
		SchemaVersion:                 rekorRotationCompletionSchema,
		OperationID:                   request.OperationID,
		TrustDomainID:                 request.TrustDomainID,
		CompletedAtUTC:                time.Now().UTC(),
		PriorGeneration:               request.StartingGeneration,
		PriorGenerationID:             request.StartingGenerationID,
		PriorGenerationManifestSHA256: request.StartingGenerationManifestSHA256,
		PriorPublicKeySHA256:          request.StartingRekorPublicKeySHA256,
		PriorShardID:                  request.PriorShardID,
		PriorBaseURL:                  request.PriorShardURL,
		PriorStateID:                  catalog.Shards[0].StateID,
		NewGeneration:                 bootstrap.Generation,
		NewGenerationID:               bootstrap.GenerationID,
		GenerationManifestSHA256:      bootstrap.GenerationManifestSHA256,
		NewPublicKeySHA256:            bootstrap.RekorPublicKeySHA256,
		NewShardID:                    manifest.RekorShardID,
		NewBaseURL:                    manifest.RekorBaseURL,
		NewStateID:                    catalog.Shards[1].StateID,
		PublicationID:                 publication.Active.ID,
		PublicationManifestSHA256:     publication.Active.ManifestSHA256,
		TrustedRootSHA256:             hashBytes(trustedRootData),
		SigningConfigSHA256:           hashBytes(signingConfigData),
		PriorTrustedRootTlogCount:     priorTlogCount,
		NewTrustedRootTlogCount:       len(trustedRoot.Tlogs),
		ActiveSigningConfigURL:        rekorSecondaryURL,
		Action:                        string(action),
	}
	if err := writeRekorRotationCompletion(statePath, completion); err != nil {
		return err
	}
	return validateRekorCompletionAgainstState(statePath, &completion)
}

func dispatchRekorRotation(statePath string) (repositoryAction, error) {
	return dispatchRekorRotationWithHooks(statePath, publicationHooks{})
}

func dispatchRekorRotationWithHooks(
	statePath string,
	hooks publicationHooks,
) (repositoryAction, error) {
	requestPath := filepath.Join(statePath, rekorRotationRequestFile)
	requestData, err := os.ReadFile(requestPath)
	if err != nil {
		return "", fmt.Errorf("read Rekor shard rotation request: %w", err)
	}
	var request rekorRotationRequest
	if err := decodeStrictJSON(requestData, &request); err != nil {
		return "", fmt.Errorf("parse Rekor shard rotation request: %w", err)
	}
	if err := validateRekorRotationRequest(request); err != nil {
		return "", err
	}
	lock, err := acquireStateLock(statePath, 30*time.Second, "rekor-shard-rotation")
	if err != nil {
		return "", err
	}
	defer lock.release()

	domain, err := loadTrustDomain(statePath)
	if err != nil || domain.TrustDomainID != request.TrustDomainID {
		return "", errors.New("Rekor rotation request does not match the immutable trust domain")
	}
	catalog, err := loadRekorShardCatalog(statePath)
	if err != nil {
		return "", fmt.Errorf("load Rekor shard catalog: %w", err)
	}
	completion, err := loadRekorRotationCompletion(statePath)
	if err != nil {
		return "", fmt.Errorf("ambiguous Rekor rotation completion: %w", err)
	}
	if completion != nil && completion.OperationID != request.OperationID {
		return "", fmt.Errorf(
			"Rekor shard rotation is bounded to completed operation %q; operation %q is rejected",
			completion.OperationID,
			request.OperationID,
		)
	}
	if len(catalog.Shards) == 2 {
		active, loadErr := loadActiveTrustGeneration(statePath)
		if loadErr != nil {
			return "", loadErr
		}
		manifest, loadErr := readOIDCGenerationManifest(statePath, active.GenerationID)
		if loadErr != nil {
			return "", loadErr
		}
		if manifest.RekorRotationOperationID != request.OperationID {
			return "", fmt.Errorf(
				"Rekor shard rotation is bounded to operation %q; operation %q is rejected",
				manifest.RekorRotationOperationID,
				request.OperationID,
			)
		}
	}
	if err := validateRekorCandidateState(statePath, request); err != nil {
		return "", err
	}
	if completion != nil {
		if err := validateRekorCompletionAgainstState(statePath, completion); err != nil {
			return "", fmt.Errorf("Rekor rotation completion replay failed validation: %w", err)
		}
		if err := validateRequestMatchesRekorCompletion(request, completion); err != nil {
			return "", err
		}
		if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		return repositoryActionPublished, nil
	}

	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return "", err
	}
	if err := validateRekorRotationStartingState(statePath, request, active, catalog); err != nil {
		if active.Generation != request.StartingGeneration+1 {
			return "", err
		}
		manifest, manifestErr := readOIDCGenerationManifest(statePath, active.GenerationID)
		if manifestErr != nil || manifest.RekorRotationOperationID != request.OperationID {
			return "", err
		}
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("rekor-candidate-validated")); err != nil {
		return "", err
	}
	outcome, err := recoverTUFStateLocked(statePath, hooks)
	if err != nil {
		return "", fmt.Errorf("recover TUF state for Rekor rotation: %w", err)
	}
	active, err = loadActiveTrustGeneration(statePath)
	if err != nil {
		return "", err
	}
	catalog, err = loadRekorShardCatalog(statePath)
	if err != nil {
		return "", err
	}

	action := repositoryActionPublished
	priorTlogCount := 0
	if active.Generation == request.StartingGeneration {
		if err := validateRekorRotationStartingState(statePath, request, active, catalog); err != nil {
			return "", err
		}
		next, err := rotateRekorGeneration(statePath, active, request)
		if err != nil {
			return "", fmt.Errorf("create rotated Rekor generation: %w", err)
		}
		if err := runCheckpoint(hooks, publicationCheckpoint("rekor-generation-committed")); err != nil {
			return "", err
		}
		priorTlogCount, _, err = publishRekorRotationUpdate(statePath, active, next, hooks)
		if err != nil {
			return "", fmt.Errorf("publish Rekor shard rotation: %w", err)
		}
		if err := runCheckpoint(hooks, publicationCheckpoint("rekor-tuf-committed")); err != nil {
			return "", err
		}
		if err := switchActiveGeneration(
			statePath,
			active,
			next,
			next.GenerationManifestSHA256,
		); err != nil {
			return "", fmt.Errorf("switch active generation for Rekor rotation: %w", err)
		}
		if err := runCheckpoint(hooks, publicationCheckpoint("rekor-generation-switched")); err != nil {
			return "", err
		}
		active = next
	} else {
		if active.Generation != request.StartingGeneration+1 {
			return "", errors.New("Rekor rotation active generation is ambiguous")
		}
		action = repositoryActionRecovered
		if outcome == recoveryNoop && len(catalog.Shards) == 1 {
			action = repositoryActionRecovered
		}
	}
	manifest, err := readOIDCGenerationManifest(statePath, active.GenerationID)
	if err != nil {
		return "", err
	}
	if err := validateRekorRotatedGenerationAgainstRequest(manifest, request, active); err != nil {
		return "", err
	}
	if err := validateCommittedRekorPublication(statePath, active); err != nil {
		return "", err
	}
	catalog, err = switchRekorShardCatalogLocked(
		statePath,
		catalog,
		request,
		active,
		hooks,
	)
	if err != nil {
		return "", fmt.Errorf("switch Rekor shard catalog: %w", err)
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("rekor-catalog-switched")); err != nil {
		return "", err
	}
	if err := finalizeRekorRotationCompletion(
		statePath,
		request,
		action,
		priorTlogCount,
	); err != nil {
		return "", err
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("rekor-completion-written")); err != nil {
		return "", err
	}
	if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	_ = catalog
	return action, nil
}

func validateRekorRotationStartingState(
	statePath string,
	request rekorRotationRequest,
	active bootstrapManifest,
	catalog *rekorShardCatalog,
) error {
	if active.Generation != request.StartingGeneration ||
		active.GenerationID != request.StartingGenerationID ||
		active.GenerationManifestSHA256 != request.StartingGenerationManifestSHA256 ||
		active.RekorPublicKeySHA256 != request.StartingRekorPublicKeySHA256 ||
		len(catalog.Shards) != 1 ||
		catalog.ActiveShardID != request.PriorShardID ||
		catalog.Shards[0].ShardID != request.PriorShardID ||
		catalog.Shards[0].BaseURL != request.PriorShardURL ||
		catalog.Shards[0].PublicKeySHA256 != request.StartingRekorPublicKeySHA256 ||
		catalog.Shards[0].StateID == request.CandidateStateID {
		return errors.New("Rekor rotation request does not match the active starting state")
	}
	return validateRekorShardCatalog(statePath, catalog, active)
}

func validateRekorRotatedGenerationAgainstRequest(
	manifest generationManifest,
	request rekorRotationRequest,
	active bootstrapManifest,
) error {
	if active.Generation != request.StartingGeneration+1 ||
		active.GenerationID != fmt.Sprintf("generation-%08d", request.StartingGeneration+1) ||
		active.RekorPublicKeySHA256 != request.CandidatePublicKeySHA256 ||
		manifest.RekorRotationOperationID != request.OperationID ||
		manifest.RekorPriorGeneration != request.StartingGeneration ||
		manifest.RekorPriorGenerationID != request.StartingGenerationID ||
		manifest.RekorPriorPublicKeySHA256 != request.StartingRekorPublicKeySHA256 ||
		manifest.RekorPriorShardID != request.PriorShardID ||
		manifest.RekorPriorBaseURL != request.PriorShardURL ||
		manifest.RekorShardID != request.CandidateShardID ||
		manifest.RekorBaseURL != request.CandidateShardURL {
		return errors.New("rotated Rekor generation does not match its request")
	}
	return nil
}

func validateCommittedRekorPublication(
	statePath string,
	bootstrap bootstrapManifest,
) error {
	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return err
	}
	if publication.Status != publicationStatusCommitted || publication.Active == nil {
		return errors.New("rotated Rekor generation lacks a committed TUF publication")
	}
	fingerprint, err := fingerprintSource(bootstrap)
	if err != nil {
		return err
	}
	return validateReference(
		committedPath(layout, publication.Active.ID),
		*publication.Active,
		fingerprint,
	)
}

func validateRequestMatchesRekorCompletion(
	request rekorRotationRequest,
	completion *rekorRotationCompletion,
) error {
	if request.OperationID != completion.OperationID ||
		request.TrustDomainID != completion.TrustDomainID ||
		request.StartingGeneration != completion.PriorGeneration ||
		request.StartingGenerationID != completion.PriorGenerationID ||
		request.StartingGenerationManifestSHA256 != completion.PriorGenerationManifestSHA256 ||
		request.StartingRekorPublicKeySHA256 != completion.PriorPublicKeySHA256 ||
		request.PriorShardID != completion.PriorShardID ||
		request.PriorShardURL != completion.PriorBaseURL ||
		request.CandidateShardID != completion.NewShardID ||
		request.CandidateShardURL != completion.NewBaseURL ||
		request.CandidatePublicKeySHA256 != completion.NewPublicKeySHA256 ||
		request.CandidateStateID != completion.NewStateID {
		return errors.New("replayed Rekor rotation request does not match its completion")
	}
	return nil
}
