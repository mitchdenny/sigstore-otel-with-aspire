package main

// Certificate-transparency log shard rotation.
//
// A CT key change never mutates or restarts the historical primary
// Tesseract shard: that shard stays append-only, keeps its canonical URL,
// origin, signer, storage and checkpoint history forever. Instead exactly
// one bounded secondary logical shard is created with its own isolated
// signer, origin, canonical URL, storage and checkpoint, and the committed
// TrustedRoot gains a second `ctlogs` entry additively so both the old and
// the new shard remain verifiable. SigningConfig is deliberately untouched:
// certificate transparency is not a signing-service selector, and Fulcio's
// binding to a shard is a runtime configuration promotion performed by the
// hosting command after the additive trust has converged everywhere.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	trustrootv1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	ctRotationRequestFile      = "rotate-ct-log-shard.request"
	ctRotationCompletionFile   = "rotate-ct-log-shard.completed"
	ctRotationDirectory        = "ct-log-shard-rotation"
	ctRotationSchemaVersion    = 1
	ctRotationCompletionSchema = 1
	ctShardCatalogSchema       = 1
	ctShardMetadataSchema      = 1

	ctPrimaryOrigin          = "tesseract-sigstore.dev.localhost"
	ctSecondaryURL           = "http://tesseract-secondary-sigstore.dev.localhost:6963"
	ctSecondaryOrigin        = "tesseract-secondary-sigstore.dev.localhost"
	ctPrimaryDataPath        = "data/ctlog"
	ctSecondaryDataPath      = "data/ctlog-shards/secondary"
	ctPrimaryResourceName    = "tesseract"
	ctSecondaryResourceName  = "tesseract-secondary"
	ctShardCatalogPath       = "data/ctlog-shards/state.json"
	ctSecondaryRuntimeDir    = "runtime/tesseract-secondary"
	ctFulcioRuntimeDir       = "runtime/fulcio-ct"
	ctPrimaryTargetName      = "ctlog-shards/primary.pub"
	ctSecondaryTargetName    = "ctlog-shards/secondary.pub"
	ctCandidateStateFileName = "bootstrap-state"
	ctShardMetadataFileName  = "shard.json"

	// The Fulcio certificate-transparency projection is one stable,
	// bind-mounted directory holding immutable additive per-shard keys and
	// exactly one atomically replaced selection manifest, so a promotion
	// can never be observed as a mixed selector/origin/key configuration.
	ctRuntimeSelectionFileName = "selection"
	ctRuntimePrimaryKeyFile    = "primary.pub"
	ctRuntimeSecondaryKeyFile  = "secondary.pub"
	ctRuntimeSelectionHeader   = "sigstore-fulcio-ct-selection/1"
)

var (
	ctOperationIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	ctStateIDPattern     = regexp.MustCompile(
		`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`,
	)
)

// ctShardCatalog is the durable record of every logical CT shard in this
// trust domain. It is append-only in practice: the primary entry is
// created from the immutable trust domain and is never rewritten except to
// mark it historical when the bounded secondary shard is activated.
type ctShardCatalog struct {
	SchemaVersion int       `json:"schemaVersion"`
	TrustDomainID string    `json:"trustDomainId"`
	ActiveShardID string    `json:"activeShardId"`
	UpdatedAtUTC  time.Time `json:"updatedAtUtc"`
	Shards        []ctShard `json:"shards"`
}

type ctShard struct {
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
	// The complete Fulcio certificate-authority bundle this shard was
	// created accepting, recorded as both the SHA-256 of the exact bundle
	// bytes and its ordered per-root fingerprints, so the accepted trust of
	// every shard is durable and any added, removed or reordered root is
	// detectable.
	AcceptedRootsSHA256      string   `json:"acceptedRootsSha256"`
	AcceptedRootCount        int      `json:"acceptedRootCount"`
	AcceptedRootFingerprints []string `json:"acceptedRootFingerprints"`
}

type ctShardMetadata struct {
	SchemaVersion   int       `json:"schemaVersion"`
	OperationID     string    `json:"operationId"`
	TrustDomainID   string    `json:"trustDomainId"`
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

	AcceptedRootsSHA256      string   `json:"acceptedRootsSha256"`
	AcceptedRootCount        int      `json:"acceptedRootCount"`
	AcceptedRootFingerprints []string `json:"acceptedRootFingerprints"`

	ActivatedAtUTC *time.Time `json:"activatedAtUtc,omitempty"`
	Status         string     `json:"status,omitempty"`
}

type ctRotationRequest struct {
	SchemaVersion                    int       `json:"schemaVersion"`
	OperationID                      string    `json:"operationId"`
	TrustDomainID                    string    `json:"trustDomainId"`
	StartingGeneration               int       `json:"startingGeneration"`
	StartingGenerationID             string    `json:"startingGenerationId"`
	StartingGenerationManifestSHA256 string    `json:"startingGenerationManifestSha256"`
	StartingCtLogPublicKeySHA256     string    `json:"startingCtLogPublicKeySha256"`
	PriorShardID                     string    `json:"priorShardId"`
	PriorShardURL                    string    `json:"priorShardUrl"`
	CandidateShardID                 string    `json:"candidateShardId"`
	CandidateShardURL                string    `json:"candidateShardUrl"`
	CandidateOrigin                  string    `json:"candidateOrigin"`
	CandidatePublicKeySHA256         string    `json:"candidatePublicKeySha256"`
	CandidateStateID                 string    `json:"candidateStateId"`
	CandidateCreatedAtUTC            time.Time `json:"candidateCreatedAtUtc"`
}

type ctRotationCompletion struct {
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
	PriorOrigin                   string    `json:"priorOrigin"`
	PriorStateID                  string    `json:"priorStateId"`
	NewGeneration                 int       `json:"newGeneration"`
	NewGenerationID               string    `json:"newGenerationId"`
	GenerationManifestSHA256      string    `json:"generationManifestSha256"`
	NewPublicKeySHA256            string    `json:"newPublicKeySha256"`
	NewShardID                    string    `json:"newShardId"`
	NewBaseURL                    string    `json:"newBaseUrl"`
	NewOrigin                     string    `json:"newOrigin"`
	NewStateID                    string    `json:"newStateId"`
	PublicationID                 string    `json:"publicationId"`
	PublicationManifestSHA256     string    `json:"publicationManifestSha256"`
	TrustedRootSHA256             string    `json:"trustedRootSha256"`
	SigningConfigSHA256           string    `json:"signingConfigSha256"`
	PriorTrustedRootCtlogCount    int       `json:"priorTrustedRootCtlogCount"`
	NewTrustedRootCtlogCount      int       `json:"newTrustedRootCtlogCount"`
	Action                        string    `json:"action"`
}

func ctShardID(publicKeySHA256 string) string {
	return "sha256-" + publicKeySHA256
}

// acceptedRootsIdentity reads one certificate-transparency shard's accepted
// Fulcio root bundle and returns its durable identity: the SHA-256 of the
// exact bundle bytes plus the ordered fingerprint of every root it accepts.
func acceptedRootsIdentity(bundlePath string) ([]byte, string, []string, error) {
	if err := requireRegularFile(bundlePath); err != nil {
		return nil, "", nil, err
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, "", nil, fmt.Errorf("read accepted Fulcio roots: %w", err)
	}
	fingerprints := []string{}
	remaining := bundle
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, "", nil, errors.New("accepted Fulcio roots contain invalid PEM data")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, "", nil, fmt.Errorf(
				"unexpected PEM block %q in accepted Fulcio roots",
				block.Type,
			)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", nil, fmt.Errorf("parse accepted Fulcio root: %w", err)
		}
		fingerprints = append(fingerprints, hashDER(certificate.Raw))
		remaining = rest
	}
	if len(fingerprints) == 0 {
		return nil, "", nil, errors.New("accepted Fulcio roots contain no certificates")
	}
	return bundle, hashBytes(bundle), fingerprints, nil
}

// ctShardAcceptedRoots resolves one shard's runtime accepted-root bundle.
func ctShardAcceptedRootsPath(statePath, slot string) string {
	if slot == "secondary" {
		return filepath.Join(
			statePath,
			filepath.FromSlash(ctSecondaryRuntimeDir),
			runtimeAcceptedRootsFile,
		)
	}
	return filepath.Join(
		runtimeComponentPath(statePath, runtimeTesseractComponent),
		runtimeAcceptedRootsFile,
	)
}

// ensureCtShardCatalogLocked lazily materializes the single-shard catalog
// for a trust domain that has never rotated its CT log, deriving the
// primary entry entirely from immutable state so it can never disagree
// with the trust domain it describes.
func ensureCtShardCatalogLocked(
	statePath string,
	bootstrap bootstrapManifest,
) (*ctShardCatalog, error) {
	catalog, err := loadCtShardCatalog(statePath)
	if err == nil {
		if err := validateCtShardCatalog(statePath, catalog, bootstrap); err != nil {
			return nil, err
		}
		return catalog, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return nil, fmt.Errorf("read active generation for CT shard catalog: %w", err)
	}
	if generation.CtLogRotationOperationID != "" {
		return nil, errors.New("rotated CT log generation is missing its shard catalog")
	}
	generationPath := generationPathFor(statePath, bootstrap.GenerationID)
	_, _, digest, err := loadCtLogGenerationKeyPair(generationPath)
	if err != nil {
		return nil, err
	}
	if digest != bootstrap.CtLogPublicKeySHA256 {
		return nil, errors.New("active CT log public key does not match the generation manifest")
	}
	domain, err := loadTrustDomain(statePath)
	if err != nil {
		return nil, fmt.Errorf("load trust domain for CT shard catalog: %w", err)
	}
	primaryDataPath := filepath.Join(statePath, filepath.FromSlash(ctPrimaryDataPath))
	if err := requireRealDirectory(primaryDataPath); err != nil {
		return nil, err
	}
	stateID, err := readStateMarker(primaryDataPath)
	if err != nil {
		return nil, fmt.Errorf("read primary CT log state marker: %w", err)
	}
	if stateID != domain.CtLogStateID {
		return nil, errors.New("primary CT log state does not match the immutable trust domain")
	}
	_, acceptedSHA256, acceptedFingerprints, err := acceptedRootsIdentity(
		ctShardAcceptedRootsPath(statePath, "primary"),
	)
	if err != nil {
		return nil, fmt.Errorf("read primary CT shard accepted roots: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(statePath, filepath.FromSlash(ctShardCatalogPath))), 0o755); err != nil {
		return nil, fmt.Errorf("create CT shard catalog directory: %w", err)
	}
	catalog = &ctShardCatalog{
		SchemaVersion: ctShardCatalogSchema,
		TrustDomainID: domain.TrustDomainID,
		ActiveShardID: ctShardID(digest),
		UpdatedAtUTC:  time.Now().UTC(),
		Shards: []ctShard{{
			ShardID:         ctShardID(digest),
			Slot:            "primary",
			BaseURL:         ctLogURL,
			Origin:          ctPrimaryOrigin,
			PublicKeySHA256: digest,
			LogIDSHA256:     digest,
			StateID:         stateID,
			DataPath:        ctPrimaryDataPath,
			ResourceName:    ctPrimaryResourceName,
			CreatedAtUTC:    domain.CreatedAtUTC,
			ActivatedAtUTC:  domain.CreatedAtUTC,
			Status:          "active",

			AcceptedRootsSHA256:      acceptedSHA256,
			AcceptedRootCount:        len(acceptedFingerprints),
			AcceptedRootFingerprints: acceptedFingerprints,
		}},
	}
	if err := writeCtShardCatalog(statePath, catalog); err != nil {
		return nil, err
	}
	return catalog, nil
}

func loadCtShardCatalog(statePath string) (*ctShardCatalog, error) {
	path := filepath.Join(statePath, filepath.FromSlash(ctShardCatalogPath))
	if err := requireRegularFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var catalog ctShardCatalog
	if err := decodeStrictJSON(data, &catalog); err != nil {
		return nil, fmt.Errorf("parse CT shard catalog: %w", err)
	}
	return &catalog, nil
}

func writeCtShardCatalog(statePath string, catalog *ctShardCatalog) error {
	data, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal CT shard catalog: %w", err)
	}
	return writeAtomicJSON(
		filepath.Join(statePath, filepath.FromSlash(ctShardCatalogPath)),
		append(data, '\n'),
	)
}

// validateCtShardCatalog proves the catalog agrees with the immutable
// trust domain, the active generation and the on-disk shard storage. The
// historical primary entry must always describe the trust domain's
// original CT log identity, whether or not a rotation has happened.
func validateCtShardCatalog(
	statePath string,
	catalog *ctShardCatalog,
	bootstrap bootstrapManifest,
) error {
	if catalog.SchemaVersion != ctShardCatalogSchema ||
		catalog.TrustDomainID != bootstrap.TrustDomainID ||
		catalog.UpdatedAtUTC.IsZero() ||
		!isUTC(catalog.UpdatedAtUTC) ||
		(len(catalog.Shards) != 1 && len(catalog.Shards) != 2) {
		return errors.New("CT shard catalog has malformed durable state")
	}
	domain, err := loadTrustDomain(statePath)
	if err != nil {
		return err
	}
	generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return err
	}
	_, _, activeDigest, err := loadCtLogGenerationKeyPair(
		generationPathFor(statePath, bootstrap.GenerationID),
	)
	if err != nil {
		return err
	}
	if activeDigest != bootstrap.CtLogPublicKeySHA256 {
		return errors.New("active CT log generation fingerprint is inconsistent")
	}

	primary := catalog.Shards[0]
	if err := validateCtCatalogShard(primary); err != nil {
		return fmt.Errorf("validate primary CT shard: %w", err)
	}
	if primary.Slot != "primary" ||
		primary.BaseURL != ctLogURL ||
		primary.Origin != ctPrimaryOrigin ||
		primary.DataPath != ctPrimaryDataPath ||
		primary.ResourceName != ctPrimaryResourceName ||
		primary.StateID != domain.CtLogStateID ||
		!primary.CreatedAtUTC.Equal(domain.CreatedAtUTC) ||
		!primary.ActivatedAtUTC.Equal(domain.CreatedAtUTC) {
		return errors.New("primary CT shard catalog entry does not match the immutable trust domain")
	}
	primaryDataPath := filepath.Join(statePath, filepath.FromSlash(primary.DataPath))
	if err := requireRealDirectory(primaryDataPath); err != nil {
		return err
	}
	primaryState, err := readStateMarker(primaryDataPath)
	if err != nil || primaryState != primary.StateID {
		return errors.New("primary CT shard state marker does not match the catalog")
	}
	if err := validateCtShardAcceptedRoots(statePath, primary); err != nil {
		return fmt.Errorf("validate primary CT shard accepted roots: %w", err)
	}

	if len(catalog.Shards) == 1 {
		if catalog.ActiveShardID != primary.ShardID ||
			primary.Status != "active" ||
			generation.CtLogRotationOperationID != "" ||
			primary.PublicKeySHA256 != activeDigest {
			return errors.New("single-shard CT catalog does not match the active primary generation")
		}
		return nil
	}

	secondary := catalog.Shards[1]
	if err := validateCtCatalogShard(secondary); err != nil {
		return fmt.Errorf("validate secondary CT shard: %w", err)
	}
	if primary.Status != "historical" ||
		secondary.Status != "active" ||
		catalog.ActiveShardID != secondary.ShardID ||
		secondary.Slot != "secondary" ||
		secondary.BaseURL != ctSecondaryURL ||
		secondary.Origin != ctSecondaryOrigin ||
		secondary.DataPath != ctSecondaryDataPath ||
		secondary.ResourceName != ctSecondaryResourceName ||
		secondary.PublicKeySHA256 != activeDigest ||
		generation.CtLogRotationOperationID == "" ||
		generation.CtLogPriorPublicKeySHA256 != primary.PublicKeySHA256 ||
		generation.CtLogPriorShardID != primary.ShardID ||
		generation.CtLogPriorBaseURL != primary.BaseURL ||
		generation.CtLogShardID != secondary.ShardID ||
		generation.CtLogBaseURL != secondary.BaseURL ||
		secondary.AcceptedRootsSHA256 != primary.AcceptedRootsSHA256 ||
		secondary.AcceptedRootCount != primary.AcceptedRootCount ||
		!reflect.DeepEqual(
			secondary.AcceptedRootFingerprints,
			primary.AcceptedRootFingerprints,
		) {
		return errors.New("rotated CT shard catalog does not match the active generation")
	}
	if err := validateCtShardAcceptedRoots(statePath, secondary); err != nil {
		return fmt.Errorf("validate secondary CT shard accepted roots: %w", err)
	}
	return validateSecondaryCtShardState(
		statePath,
		generation.CtLogRotationOperationID,
		catalog.TrustDomainID,
		secondary,
		generationPathFor(statePath, bootstrap.GenerationID),
	)
}

func validateCtCatalogShard(shard ctShard) error {
	if validateAcceptedRootsIdentity(
		shard.AcceptedRootsSHA256,
		shard.AcceptedRootCount,
		shard.AcceptedRootFingerprints,
	) != nil {
		return errors.New("CT shard accepted-root identity is malformed")
	}
	if validateSHA256(shard.PublicKeySHA256) != nil ||
		shard.LogIDSHA256 != shard.PublicKeySHA256 ||
		shard.ShardID != ctShardID(shard.PublicKeySHA256) ||
		shard.StateID == "" ||
		shard.CreatedAtUTC.IsZero() ||
		shard.ActivatedAtUTC.IsZero() ||
		!isUTC(shard.CreatedAtUTC) ||
		!isUTC(shard.ActivatedAtUTC) ||
		shard.ActivatedAtUTC.Before(shard.CreatedAtUTC) ||
		(shard.Status != "active" && shard.Status != "historical") {
		return errors.New("CT shard entry is malformed")
	}
	return nil
}

// validateAcceptedRootsIdentity asserts a recorded accepted-root identity is
// internally consistent: a SHA-256 bundle digest plus a non-empty, ordered,
// duplicate-free list of SHA-256 root fingerprints whose length is the
// recorded count.
func validateAcceptedRootsIdentity(
	bundleSHA256 string,
	count int,
	fingerprints []string,
) error {
	if validateSHA256(bundleSHA256) != nil ||
		count < 1 ||
		len(fingerprints) != count {
		return errors.New("accepted-root identity is malformed")
	}
	seen := map[string]bool{}
	for _, fingerprint := range fingerprints {
		if validateSHA256(fingerprint) != nil || seen[fingerprint] {
			return errors.New("accepted-root fingerprints are malformed")
		}
		seen[fingerprint] = true
	}
	return nil
}

// validateCtShardAcceptedRoots binds one shard's recorded accepted-root
// identity to real bytes on disk. The historical primary shard's frozen
// runtime bundle must render exactly what the catalog records; the
// secondary shard was created accepting exactly that same complete bundle,
// so its recorded identity is identical and its live runtime bundle must
// still begin with it once later Fulcio CA rotations have extended it.
func validateCtShardAcceptedRoots(statePath string, shard ctShard) error {
	frozen, frozenSHA256, frozenFingerprints, err := acceptedRootsIdentity(
		ctShardAcceptedRootsPath(statePath, "primary"),
	)
	if err != nil {
		return err
	}
	if shard.AcceptedRootsSHA256 != frozenSHA256 ||
		shard.AcceptedRootCount != len(frozenFingerprints) ||
		!reflect.DeepEqual(shard.AcceptedRootFingerprints, frozenFingerprints) {
		return fmt.Errorf(
			"CT shard %q does not accept the Fulcio roots its catalog entry records",
			shard.ShardID,
		)
	}
	if shard.Slot != "secondary" {
		return nil
	}
	live, _, _, err := acceptedRootsIdentity(
		ctShardAcceptedRootsPath(statePath, "secondary"),
	)
	if err != nil {
		return err
	}
	if len(live) < len(frozen) || !bytes.Equal(live[:len(frozen)], frozen) {
		return errors.New(
			"the secondary CT shard no longer accepts the complete Fulcio root bundle it was created with",
		)
	}
	return nil
}

func validateCtRotationRequest(request ctRotationRequest) error {
	if request.SchemaVersion != ctRotationSchemaVersion ||
		!ctOperationIDPattern.MatchString(request.OperationID) ||
		request.TrustDomainID == "" ||
		request.StartingGeneration < initialGeneration ||
		request.StartingGenerationID != fmt.Sprintf("generation-%08d", request.StartingGeneration) ||
		validateSHA256(request.StartingGenerationManifestSHA256) != nil ||
		validateSHA256(request.StartingCtLogPublicKeySHA256) != nil ||
		validateSHA256(request.CandidatePublicKeySHA256) != nil ||
		request.PriorShardID != ctShardID(request.StartingCtLogPublicKeySHA256) ||
		request.PriorShardURL != ctLogURL ||
		request.CandidateShardID != ctShardID(request.CandidatePublicKeySHA256) ||
		request.CandidateShardURL != ctSecondaryURL ||
		request.CandidateOrigin != ctSecondaryOrigin ||
		request.CandidatePublicKeySHA256 == request.StartingCtLogPublicKeySHA256 ||
		!ctStateIDPattern.MatchString(request.CandidateStateID) ||
		request.CandidateCreatedAtUTC.IsZero() ||
		!isUTC(request.CandidateCreatedAtUTC) {
		return errors.New("CT log shard rotation request has malformed durable state")
	}
	return nil
}

// validateCtCandidateState proves the operation-bound candidate signer is
// exactly the two expected files, is a valid isolated ECDSA P-256 key pair
// bound to the request fingerprint, and that the secondary shard's
// storage, metadata and least-privilege runtime projections were staged
// from precisely that candidate.
func validateCtCandidateState(statePath string, request ctRotationRequest) error {
	candidatePath := filepath.Join(
		statePath,
		ctRotationDirectory,
		request.OperationID,
		"candidate",
	)
	expected := map[string]bool{
		ctLogPrivateKeyRelPath: true,
		ctLogPublicKeyRelPath:  true,
	}
	actual := map[string]bool{}
	err := filepath.WalkDir(candidatePath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("candidate CT log entry %q must not be a symbolic link", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("candidate CT log entry %q is not a regular file", path)
		}
		relative, err := filepath.Rel(candidatePath, path)
		if err != nil {
			return err
		}
		actual[filepath.ToSlash(relative)] = true
		return nil
	})
	if err != nil {
		return fmt.Errorf("inspect CT log rotation candidate: %w", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("CT log rotation candidate file set %v does not match %v", actual, expected)
	}
	privatePEM, publicPEM, digest, err := loadCtLogKeyPair(
		filepath.Join(candidatePath, filepath.FromSlash(ctLogPrivateKeyRelPath)),
		filepath.Join(candidatePath, filepath.FromSlash(ctLogPublicKeyRelPath)),
	)
	if err != nil {
		return fmt.Errorf("validate candidate CT log key pair: %w", err)
	}
	if digest != request.CandidatePublicKeySHA256 {
		return errors.New("candidate CT log key does not match the request fingerprint")
	}
	_, acceptedSHA256, acceptedFingerprints, err := acceptedRootsIdentity(
		ctShardAcceptedRootsPath(statePath, "primary"),
	)
	if err != nil {
		return fmt.Errorf("read primary CT shard accepted roots: %w", err)
	}
	secondary := ctShard{
		ShardID:         request.CandidateShardID,
		Slot:            "secondary",
		BaseURL:         request.CandidateShardURL,
		Origin:          request.CandidateOrigin,
		PublicKeySHA256: request.CandidatePublicKeySHA256,
		LogIDSHA256:     request.CandidatePublicKeySHA256,
		StateID:         request.CandidateStateID,
		DataPath:        ctSecondaryDataPath,
		ResourceName:    ctSecondaryResourceName,
		CreatedAtUTC:    request.CandidateCreatedAtUTC,

		AcceptedRootsSHA256:      acceptedSHA256,
		AcceptedRootCount:        len(acceptedFingerprints),
		AcceptedRootFingerprints: acceptedFingerprints,
	}
	return validateSecondaryCtShardFiles(
		statePath,
		request.OperationID,
		request.TrustDomainID,
		secondary,
		privatePEM,
		publicPEM,
	)
}

func validateSecondaryCtShardState(
	statePath, operationID, trustDomainID string,
	shard ctShard,
	activeGenerationPath string,
) error {
	privatePEM, err := os.ReadFile(filepath.Join(
		activeGenerationPath,
		filepath.FromSlash(ctLogPrivateKeyRelPath),
	))
	if err != nil {
		return err
	}
	publicPEM, err := os.ReadFile(filepath.Join(
		activeGenerationPath,
		filepath.FromSlash(ctLogPublicKeyRelPath),
	))
	if err != nil {
		return err
	}
	return validateSecondaryCtShardFiles(
		statePath,
		operationID,
		trustDomainID,
		shard,
		privatePEM,
		publicPEM,
	)
}

func validateSecondaryCtShardFiles(
	statePath, operationID, trustDomainID string,
	shard ctShard,
	expectedPrivatePEM, expectedPublicPEM []byte,
) error {
	dataPath := filepath.Join(statePath, filepath.FromSlash(ctSecondaryDataPath))
	if err := requireRealDirectory(dataPath); err != nil {
		return err
	}
	stateID, err := readStateMarker(dataPath)
	if err != nil {
		return fmt.Errorf("read secondary CT log state marker: %w", err)
	}
	if stateID != shard.StateID {
		return errors.New("secondary CT log state marker does not match its identity")
	}
	primaryStateID, err := readStateMarker(
		filepath.Join(statePath, filepath.FromSlash(ctPrimaryDataPath)),
	)
	if err != nil {
		return fmt.Errorf("read primary CT log state marker: %w", err)
	}
	if primaryStateID == stateID {
		return errors.New("secondary CT log storage is not isolated from the primary shard")
	}
	metadataPath := filepath.Join(dataPath, ctShardMetadataFileName)
	if err := requireRegularFile(metadataPath); err != nil {
		return err
	}
	metadataData, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("read secondary CT shard metadata: %w", err)
	}
	var metadata ctShardMetadata
	if err := decodeStrictJSON(metadataData, &metadata); err != nil {
		return fmt.Errorf("parse secondary CT shard metadata: %w", err)
	}
	if metadata.SchemaVersion != ctShardMetadataSchema ||
		metadata.OperationID != operationID ||
		metadata.TrustDomainID != trustDomainID ||
		metadata.ShardID != shard.ShardID ||
		metadata.Slot != "secondary" ||
		metadata.BaseURL != ctSecondaryURL ||
		metadata.Origin != ctSecondaryOrigin ||
		metadata.PublicKeySHA256 != shard.PublicKeySHA256 ||
		metadata.LogIDSHA256 != shard.PublicKeySHA256 ||
		metadata.StateID != shard.StateID ||
		metadata.DataPath != ctSecondaryDataPath ||
		metadata.ResourceName != ctSecondaryResourceName ||
		!isUTC(metadata.CreatedAtUTC) ||
		!metadata.CreatedAtUTC.Equal(shard.CreatedAtUTC) ||
		metadata.AcceptedRootsSHA256 != shard.AcceptedRootsSHA256 ||
		metadata.AcceptedRootCount != shard.AcceptedRootCount ||
		!reflect.DeepEqual(
			metadata.AcceptedRootFingerprints,
			shard.AcceptedRootFingerprints,
		) {
		return errors.New("secondary CT shard metadata does not match the rotation")
	}
	if err := validateAcceptedRootsIdentity(
		metadata.AcceptedRootsSHA256,
		metadata.AcceptedRootCount,
		metadata.AcceptedRootFingerprints,
	); err != nil {
		return fmt.Errorf("secondary CT shard metadata accepted roots: %w", err)
	}
	switch shard.Status {
	case "":
		if (metadata.ActivatedAtUTC == nil) != (metadata.Status == "") {
			return errors.New("secondary CT shard metadata contains a partial activation")
		}
		if metadata.ActivatedAtUTC != nil {
			if metadata.Status != "active" ||
				!isUTC(*metadata.ActivatedAtUTC) ||
				metadata.ActivatedAtUTC.Before(metadata.CreatedAtUTC) {
				return errors.New("secondary CT shard metadata has an invalid recovered activation")
			}
		}
	case "active":
		if metadata.ActivatedAtUTC == nil ||
			metadata.Status != "active" ||
			!isUTC(*metadata.ActivatedAtUTC) ||
			!metadata.ActivatedAtUTC.Equal(shard.ActivatedAtUTC) {
			return errors.New("secondary CT shard activation does not match the active catalog")
		}
	default:
		return errors.New("secondary CT shard catalog status is invalid")
	}
	return validateSecondaryCtRuntimeProjection(
		statePath,
		shard,
		expectedPrivatePEM,
		expectedPublicPEM,
	)
}

// validateSecondaryCtRuntimeProjection asserts the least-privilege
// runtime mounts the secondary Tesseract shard consumes: exactly its own
// isolated signer plus the accepted-root bundle the historical primary
// shard already enforces, and nothing else.
func validateSecondaryCtRuntimeProjection(
	statePath string,
	shard ctShard,
	expectedPrivatePEM, expectedPublicPEM []byte,
) error {
	runtimePath := filepath.Join(statePath, filepath.FromSlash(ctSecondaryRuntimeDir))
	if err := requireRealDirectory(runtimePath); err != nil {
		return err
	}
	if err := ensureOnlyEntries(runtimePath, map[string]bool{
		runtimeTesseractKeyFile:  true,
		runtimeAcceptedRootsFile: true,
	}); err != nil {
		return fmt.Errorf("secondary CT log runtime projection: %w", err)
	}
	keyPath := filepath.Join(runtimePath, runtimeTesseractKeyFile)
	if err := requireRegularFile(keyPath); err != nil {
		return err
	}
	runtimeKey, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read secondary CT log runtime key: %w", err)
	}
	if !bytes.Equal(runtimeKey, expectedPrivatePEM) {
		return errors.New("secondary CT log runtime key is not the candidate signer")
	}
	privateKey, err := parseCtLogPrivateKey(runtimeKey)
	if err != nil {
		return err
	}
	runtimeDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	if hashBytes(runtimeDER) != shard.PublicKeySHA256 {
		return errors.New("secondary CT log runtime signer identity is inconsistent")
	}
	expectedDER, err := publicKeyDERFromPEM(expectedPublicPEM)
	if err != nil {
		return err
	}
	if !bytes.Equal(runtimeDER, expectedDER) {
		return errors.New("secondary CT log runtime signer does not match its published public key")
	}
	if err := validateCtShardAcceptedRoots(statePath, shard); err != nil {
		return err
	}
	return validateFulcioCtRuntimeSelection(statePath, expectedPublicPEM)
}

// validateFulcioCtRuntimeSelection asserts the certificate-transparency
// configuration Fulcio is bound to is in one of exactly two recognized
// states — still primary with the secondary key additively staged for
// promotion, or already promoted to the secondary — and that the staged or
// promoted selection carries exactly the candidate shard's identity. The
// selection is a single atomically replaced manifest beside immutable
// per-shard keys, so it can never describe a mixed configuration.
func validateFulcioCtRuntimeSelection(
	statePath string,
	expectedPublicPEM []byte,
) error {
	component, err := readFulcioCtRuntimeComponent(
		filepath.Join(statePath, filepath.FromSlash(ctFulcioRuntimeDir)),
	)
	if err != nil {
		return err
	}
	if component.secondaryKey == nil {
		return errors.New(
			"the Fulcio certificate-transparency projection is missing its staged secondary shard key",
		)
	}
	if !bytes.Equal(component.secondaryKey, expectedPublicPEM) {
		return errors.New(
			"the staged Fulcio certificate-transparency key is not the rotation candidate",
		)
	}
	if bytes.Equal(component.primaryKey, component.secondaryKey) {
		return errors.New(
			"the staged Fulcio certificate-transparency key is not a distinct secondary shard",
		)
	}
	return nil
}

type fulcioCtRuntimeComponent struct {
	selector     string
	origin       string
	primaryKey   []byte
	secondaryKey []byte
}

// readFulcioCtRuntimeComponent strictly parses the projection: the
// immutable per-shard keys plus the four-line selection manifest, whose
// origin and key file name must both be the ones its selector implies.
func readFulcioCtRuntimeComponent(path string) (fulcioCtRuntimeComponent, error) {
	if err := requireRealDirectory(path); err != nil {
		return fulcioCtRuntimeComponent{}, err
	}
	allowed := map[string]bool{
		ctRuntimeSelectionFileName: true,
		ctRuntimePrimaryKeyFile:    true,
	}
	secondaryPath := filepath.Join(path, ctRuntimeSecondaryKeyFile)
	staged := pathExists(secondaryPath)
	if staged {
		allowed[ctRuntimeSecondaryKeyFile] = true
	}
	if err := ensureOnlyEntries(path, allowed); err != nil {
		return fulcioCtRuntimeComponent{}, fmt.Errorf(
			"Fulcio certificate-transparency projection: %w",
			err,
		)
	}
	selectionPath := filepath.Join(path, ctRuntimeSelectionFileName)
	if err := requireRegularFile(selectionPath); err != nil {
		return fulcioCtRuntimeComponent{}, err
	}
	selectionData, err := os.ReadFile(selectionPath)
	if err != nil {
		return fulcioCtRuntimeComponent{}, err
	}
	selection := string(selectionData)
	if len(selection) == 0 ||
		len(selection) > 4096 ||
		!strings.HasSuffix(selection, "\n") ||
		strings.Contains(selection, "\r") {
		return fulcioCtRuntimeComponent{}, fmt.Errorf(
			"Fulcio certificate-transparency selection %q is not a newline-terminated manifest",
			selectionPath,
		)
	}
	lines := strings.Split(strings.TrimSuffix(selection, "\n"), "\n")
	if len(lines) != 4 || lines[0] != ctRuntimeSelectionHeader {
		return fulcioCtRuntimeComponent{}, fmt.Errorf(
			"Fulcio certificate-transparency selection %q does not have the expected four-line shape",
			selectionPath,
		)
	}
	for _, line := range lines {
		if line == "" || strings.TrimSpace(line) != line {
			return fulcioCtRuntimeComponent{}, fmt.Errorf(
				"Fulcio certificate-transparency selection %q contains an untrimmed line",
				selectionPath,
			)
		}
	}
	expectedOrigin, expectedKey, err := ctSelectionExpectations(lines[1])
	if err != nil {
		return fulcioCtRuntimeComponent{}, err
	}
	if lines[2] != expectedOrigin || lines[3] != expectedKey {
		return fulcioCtRuntimeComponent{}, fmt.Errorf(
			"Fulcio certificate-transparency selection %q names an origin or key outside selector %q",
			selectionPath,
			lines[1],
		)
	}
	if lines[1] == "secondary" && !staged {
		return fulcioCtRuntimeComponent{}, errors.New(
			"the Fulcio certificate-transparency selection names a secondary shard key that does not exist",
		)
	}
	primaryKey, err := readFulcioCtShardKey(path, ctRuntimePrimaryKeyFile)
	if err != nil {
		return fulcioCtRuntimeComponent{}, err
	}
	var secondaryKey []byte
	if staged {
		secondaryKey, err = readFulcioCtShardKey(path, ctRuntimeSecondaryKeyFile)
		if err != nil {
			return fulcioCtRuntimeComponent{}, err
		}
	}
	return fulcioCtRuntimeComponent{
		selector:     lines[1],
		origin:       expectedOrigin,
		primaryKey:   primaryKey,
		secondaryKey: secondaryKey,
	}, nil
}

func ctSelectionExpectations(selector string) (string, string, error) {
	switch selector {
	case "primary":
		return ctPrimaryOrigin, ctRuntimePrimaryKeyFile, nil
	case "secondary":
		return ctSecondaryOrigin, ctRuntimeSecondaryKeyFile, nil
	default:
		return "", "", fmt.Errorf(
			"Fulcio certificate-transparency selector %q is invalid",
			selector,
		)
	}
}

func readFulcioCtShardKey(path, name string) ([]byte, error) {
	keyPath := filepath.Join(path, name)
	if err := requireRegularFile(keyPath); err != nil {
		return nil, err
	}
	publicKey, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	if _, err := publicKeyDERFromPEM(publicKey); err != nil {
		return nil, err
	}
	return publicKey, nil
}

func loadCtLogGenerationKeyPair(generationPath string) ([]byte, []byte, string, error) {
	return loadCtLogKeyPair(
		filepath.Join(generationPath, filepath.FromSlash(ctLogPrivateKeyRelPath)),
		filepath.Join(generationPath, filepath.FromSlash(ctLogPublicKeyRelPath)),
	)
}

func loadCtLogKeyPair(privatePath, publicPath string) ([]byte, []byte, string, error) {
	privatePEM, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("read CT log private key: %w", err)
	}
	privateKey, err := parseCtLogPrivateKey(privatePEM)
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
		return nil, nil, "", errors.New("CT log private and public keys do not match")
	}
	return privatePEM, publicPEM, hashBytes(publicDER), nil
}

func parseCtLogPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("CT log private key is not exactly one PEM block")
	}
	var parsed any
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unexpected CT log private key PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse CT log private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("CT log private key must be ECDSA P-256")
	}
	return key, nil
}

func publicKeyDERFromPEM(data []byte) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("CT log public key is not exactly one PEM public key block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CT log public key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("CT log public key must be ECDSA P-256")
	}
	return block.Bytes, nil
}

// validateCtLogGenerationMaterial enforces that every generation carries a
// consistent CT signer and that CT rotation provenance is either wholly
// absent or wholly present and internally consistent.
func validateCtLogGenerationMaterial(
	generationPath string,
	manifest generationManifest,
) error {
	_, _, digest, err := loadCtLogGenerationKeyPair(generationPath)
	if err != nil {
		return err
	}
	if digest != manifest.CtLogPublicKeySHA256 {
		return errors.New("CT log public key fingerprint does not match the generation manifest")
	}
	for path := range manifest.Files {
		if strings.HasPrefix(path, "private/ctlog/") && path != ctLogPrivateKeyRelPath {
			return fmt.Errorf("unexpected CT log private generation file %q", path)
		}
	}
	if _, ok := manifest.Files[ctLogPrivateKeyRelPath]; !ok {
		return errors.New("CT log generation is missing its private key")
	}
	if _, ok := manifest.Files[ctLogPublicKeyRelPath]; !ok {
		return errors.New("CT log generation is missing its public key")
	}
	if manifest.CtLogRotationOperationID == "" {
		if manifest.CtLogPriorGeneration != 0 ||
			manifest.CtLogPriorGenerationID != "" ||
			manifest.CtLogPriorPublicKeySHA256 != "" ||
			manifest.CtLogPriorShardID != "" ||
			manifest.CtLogPriorBaseURL != "" ||
			manifest.CtLogShardID != "" ||
			manifest.CtLogBaseURL != "" {
			return errors.New("generation contains partial CT log rotation metadata")
		}
		return nil
	}
	if !ctOperationIDPattern.MatchString(manifest.CtLogRotationOperationID) ||
		manifest.CtLogPriorGeneration < initialGeneration ||
		manifest.CtLogPriorGeneration >= manifest.Generation ||
		manifest.CtLogPriorGenerationID != fmt.Sprintf(
			"generation-%08d",
			manifest.CtLogPriorGeneration,
		) ||
		validateSHA256(manifest.CtLogPriorPublicKeySHA256) != nil ||
		manifest.CtLogPriorPublicKeySHA256 == manifest.CtLogPublicKeySHA256 ||
		manifest.CtLogPriorShardID != ctShardID(manifest.CtLogPriorPublicKeySHA256) ||
		manifest.CtLogPriorBaseURL != ctLogURL ||
		manifest.CtLogShardID != ctShardID(manifest.CtLogPublicKeySHA256) ||
		manifest.CtLogBaseURL != ctSecondaryURL {
		return errors.New("rotated generation has invalid CT log operation metadata")
	}
	return nil
}

// rotateCtLogGeneration produces the immutable generation N+1 whose only
// difference from its predecessor is the certificate-transparency signer:
// every Fulcio root, TSA certificate, Rekor shard signer and routing
// record, OIDC key and TUF material is copied byte-for-byte.
func rotateCtLogGeneration(
	statePath string,
	current bootstrapManifest,
	request ctRotationRequest,
) (bootstrapManifest, error) {
	newGeneration := current.Generation + 1
	newGenerationID := fmt.Sprintf("generation-%08d", newGeneration)
	currentPath := generationPathFor(statePath, current.GenerationID)
	newPath := generationPathFor(statePath, newGenerationID)
	if pathExists(newPath) {
		return validateAndReuseCtLogGeneration(
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
		ctRotationDirectory,
		request.OperationID,
		"candidate",
	)
	stagingPath := filepath.Join(
		statePath,
		ctRotationDirectory,
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
	for _, relative := range []string{ctLogPrivateKeyRelPath, ctLogPublicKeyRelPath} {
		data, err := os.ReadFile(filepath.Join(candidatePath, filepath.FromSlash(relative)))
		if err != nil {
			_ = os.RemoveAll(stagingPath)
			return bootstrapManifest{}, err
		}
		mode := os.FileMode(0o644)
		if relative == ctLogPrivateKeyRelPath {
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
		CtLogPublicKeySHA256:        request.CandidatePublicKeySHA256,
		RekorPublicKeySHA256:        current.RekorPublicKeySHA256,
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
		RekorRotationOperationID:    currentManifest.RekorRotationOperationID,
		RekorPriorGeneration:        currentManifest.RekorPriorGeneration,
		RekorPriorGenerationID:      currentManifest.RekorPriorGenerationID,
		RekorPriorPublicKeySHA256:   currentManifest.RekorPriorPublicKeySHA256,
		RekorPriorShardID:           currentManifest.RekorPriorShardID,
		RekorPriorBaseURL:           currentManifest.RekorPriorBaseURL,
		RekorShardID:                currentManifest.RekorShardID,
		RekorBaseURL:                currentManifest.RekorBaseURL,
		CtLogRotationOperationID:    request.OperationID,
		CtLogPriorGeneration:        current.Generation,
		CtLogPriorGenerationID:      current.GenerationID,
		CtLogPriorPublicKeySHA256:   current.CtLogPublicKeySHA256,
		CtLogPriorShardID:           request.PriorShardID,
		CtLogPriorBaseURL:           request.PriorShardURL,
		CtLogShardID:                request.CandidateShardID,
		CtLogBaseURL:                request.CandidateShardURL,
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
	if err := validateCtLogGenerationMaterial(stagingPath, manifest); err != nil {
		_ = os.RemoveAll(stagingPath)
		return bootstrapManifest{}, err
	}
	if err := validateOnlyCtLogSignerChanged(currentPath, stagingPath); err != nil {
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
		CtLogPublicKeySHA256:     request.CandidatePublicKeySHA256,
		RekorPublicKeySHA256:     current.RekorPublicKeySHA256,
		TsaRootSHA256:            current.TsaRootSHA256,
		TsaLeafSHA256:            current.TsaLeafSHA256,
		OIDCKeyID:                current.OIDCKeyID,
		TrustDomainID:            current.TrustDomainID,
		Generation:               newGeneration,
		GenerationID:             newGenerationID,
		GenerationManifestSHA256: hashBytes(manifestData),
	}, nil
}

func validateAndReuseCtLogGeneration(
	statePath string,
	current bootstrapManifest,
	request ctRotationRequest,
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
		manifest.CtLogRotationOperationID != request.OperationID ||
		manifest.CtLogPriorGeneration != request.StartingGeneration ||
		manifest.CtLogPriorGenerationID != request.StartingGenerationID ||
		manifest.CtLogPriorPublicKeySHA256 != request.StartingCtLogPublicKeySHA256 ||
		manifest.CtLogPriorShardID != request.PriorShardID ||
		manifest.CtLogPriorBaseURL != request.PriorShardURL ||
		manifest.CtLogPublicKeySHA256 != request.CandidatePublicKeySHA256 ||
		manifest.CtLogShardID != request.CandidateShardID ||
		manifest.CtLogBaseURL != request.CandidateShardURL {
		return bootstrapManifest{}, errors.New("pre-existing CT log generation is not bound to this request")
	}
	actual, err := collectGenerationFileHashes(newPath)
	if err != nil {
		return bootstrapManifest{}, err
	}
	if !reflect.DeepEqual(actual, manifest.Files) {
		return bootstrapManifest{}, errors.New("pre-existing CT log generation does not match its manifest")
	}
	if err := validateCtLogGenerationMaterial(newPath, manifest); err != nil {
		return bootstrapManifest{}, err
	}
	if err := validateOnlyCtLogSignerChanged(
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

// validateOnlyCtLogSignerChanged proves generation N+1 preserves every
// other trust artifact byte-for-byte.
func validateOnlyCtLogSignerChanged(currentPath, newPath string) error {
	current, err := collectGenerationFileHashes(currentPath)
	if err != nil {
		return err
	}
	next, err := collectGenerationFileHashes(newPath)
	if err != nil {
		return err
	}
	for path, hash := range current {
		if path == ctLogPrivateKeyRelPath || path == ctLogPublicKeyRelPath {
			if next[path] == hash {
				return fmt.Errorf("CT log signer file %q did not change", path)
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

// buildCtRotationTargets renders the additive TUF targets for the CT shard
// rotation. The TrustedRoot gains a second `ctlogs` entry for the new
// shard while the historical entry is preserved verbatim, every other
// TrustedRoot section is untouched, and SigningConfig is republished
// byte-for-byte unchanged.
func buildCtRotationTargets(
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
		manifest.CtLogPriorGenerationID,
		filepath.FromSlash(ctLogPublicKeyRelPath),
	))
	if err != nil {
		return nil, 0, 0, err
	}
	newPublicKey, newDER, err := loadP256PublicKey(filepath.Join(
		newGenerationPath,
		filepath.FromSlash(ctLogPublicKeyRelPath),
	))
	if err != nil {
		return nil, 0, 0, err
	}
	if hashBytes(priorDER) != manifest.CtLogPriorPublicKeySHA256 ||
		hashBytes(newDER) != manifest.CtLogPublicKeySHA256 {
		return nil, 0, 0, errors.New("CT log generation keys do not match rotation metadata")
	}
	for name, expected := range map[string][]byte{
		ctPrimaryTargetName:   priorPublicKey,
		ctSecondaryTargetName: newPublicKey,
	} {
		path := filepath.Join(activeTargetsPath, filepath.FromSlash(name))
		if existing, err := os.ReadFile(path); err == nil {
			if !bytes.Equal(existing, expected) {
				return nil, 0, 0, fmt.Errorf("immutable CT log target %q conflicts with the rotation", name)
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
	priorCount := len(trustedRoot.Ctlogs)
	foundPrior := false
	for _, entry := range trustedRoot.Ctlogs {
		digest, err := transparencyLogDigest(entry)
		if err != nil {
			return nil, 0, 0, err
		}
		if digest == manifest.CtLogPublicKeySHA256 {
			return nil, 0, 0, errors.New("committed TrustedRoot already contains the candidate CT log shard")
		}
		if digest == manifest.CtLogPriorPublicKeySHA256 && entry.GetBaseUrl() == manifest.CtLogPriorBaseURL {
			foundPrior = true
		}
	}
	if !foundPrior {
		return nil, 0, 0, errors.New("committed TrustedRoot omits the prior active CT log shard")
	}
	trustedRoot.Ctlogs = append(
		trustedRoot.Ctlogs,
		newTransparencyLog(ctSecondaryURL, newDER, manifest.CreatedAtUTC),
	)

	// SigningConfig is intentionally republished byte-for-byte: certificate
	// transparency has no SigningConfig selector, and the shard Fulcio uses
	// is a runtime binding rather than a client-visible signing service.
	signingConfigData, err := os.ReadFile(filepath.Join(activeTargetsPath, "signing_config.v0.2.json"))
	if err != nil {
		return nil, 0, 0, err
	}
	signingConfig := &trustrootv1.SigningConfig{}
	if err := protojson.Unmarshal(signingConfigData, signingConfig); err != nil {
		return nil, 0, 0, err
	}

	trustedRootJSON, err := protoJSON.Marshal(trustedRoot)
	if err != nil {
		return nil, 0, 0, err
	}
	trustedRootBytes := append(trustedRootJSON, '\n')
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
		SigningConfigSHA256:      hashBytes(signingConfigData),
	}, "", "  ")
	if err != nil {
		return nil, 0, 0, err
	}
	return []tufTarget{
		{name: "ctfe.pub", data: newPublicKey, custom: targetMetadata("CTFE", ctSecondaryURL)},
		{name: ctPrimaryTargetName, data: priorPublicKey, custom: targetMetadata("CTFE", ctLogURL)},
		{name: ctSecondaryTargetName, data: newPublicKey, custom: targetMetadata("CTFE", ctSecondaryURL)},
		{name: "trusted_root.json", data: trustedRootBytes},
		{name: "signing_config.v0.2.json", data: signingConfigData},
		{name: "client_trust_config.json", data: clientConfigBytes},
		{name: trustStatusTargetName, data: append(statusJSON, '\n')},
	}, priorCount, len(trustedRoot.Ctlogs), nil
}

func publishCtRotationUpdate(
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
		return 0, 0, errors.New("CT log rotation requires a committed active TUF publication")
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
	targets, priorCount, newCount, err := buildCtRotationTargets(
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
		return 0, 0, errors.New("CT log rotation candidate publication is ambiguous")
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

func switchCtShardCatalogLocked(
	statePath string,
	catalog *ctShardCatalog,
	request ctRotationRequest,
	bootstrap bootstrapManifest,
	hooks publicationHooks,
) (*ctShardCatalog, error) {
	if len(catalog.Shards) == 2 {
		if err := validateCtShardCatalog(statePath, catalog, bootstrap); err != nil {
			return nil, err
		}
		return catalog, nil
	}
	if len(catalog.Shards) != 1 {
		return nil, errors.New("CT shard catalog is ambiguous")
	}
	if err := validateCtCandidateState(statePath, request); err != nil {
		return nil, err
	}
	primary := catalog.Shards[0]
	updated := *catalog
	updated.Shards = append([]ctShard(nil), catalog.Shards...)
	updated.Shards[0].Status = "historical"
	activated, err := activateSecondaryCtShardMetadata(statePath, request)
	if err != nil {
		return nil, err
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("ct-shard-activated")); err != nil {
		return nil, err
	}
	updated.Shards = append(updated.Shards, ctShard{
		ShardID:         request.CandidateShardID,
		Slot:            "secondary",
		BaseURL:         request.CandidateShardURL,
		Origin:          request.CandidateOrigin,
		PublicKeySHA256: request.CandidatePublicKeySHA256,
		LogIDSHA256:     request.CandidatePublicKeySHA256,
		StateID:         request.CandidateStateID,
		DataPath:        ctSecondaryDataPath,
		ResourceName:    ctSecondaryResourceName,
		CreatedAtUTC:    request.CandidateCreatedAtUTC,
		ActivatedAtUTC:  activated,
		Status:          "active",

		// The bounded secondary shard is created accepting exactly the
		// complete Fulcio root bundle the primary shard already accepts,
		// including every root a prior Fulcio CA rotation added.
		AcceptedRootsSHA256:      primary.AcceptedRootsSHA256,
		AcceptedRootCount:        primary.AcceptedRootCount,
		AcceptedRootFingerprints: primary.AcceptedRootFingerprints,
	})
	updated.ActiveShardID = request.CandidateShardID
	updated.UpdatedAtUTC = activated
	if err := validateCtShardCatalog(statePath, &updated, bootstrap); err != nil {
		return nil, err
	}
	if err := writeCtShardCatalog(statePath, &updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

func activateSecondaryCtShardMetadata(
	statePath string,
	request ctRotationRequest,
) (time.Time, error) {
	path := filepath.Join(
		statePath,
		filepath.FromSlash(ctSecondaryDataPath),
		ctShardMetadataFileName,
	)
	if err := requireRegularFile(path); err != nil {
		return time.Time{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	var metadata ctShardMetadata
	if err := decodeStrictJSON(data, &metadata); err != nil {
		return time.Time{}, fmt.Errorf("parse secondary CT shard metadata for activation: %w", err)
	}
	if metadata.OperationID != request.OperationID ||
		metadata.TrustDomainID != request.TrustDomainID ||
		metadata.ShardID != request.CandidateShardID ||
		metadata.PublicKeySHA256 != request.CandidatePublicKeySHA256 ||
		metadata.StateID != request.CandidateStateID ||
		!metadata.CreatedAtUTC.Equal(request.CandidateCreatedAtUTC) {
		return time.Time{}, errors.New("secondary CT shard metadata is not bound to its activation request")
	}
	if metadata.ActivatedAtUTC != nil || metadata.Status != "" {
		if metadata.ActivatedAtUTC == nil ||
			metadata.Status != "active" ||
			!isUTC(*metadata.ActivatedAtUTC) ||
			metadata.ActivatedAtUTC.Before(metadata.CreatedAtUTC) {
			return time.Time{}, errors.New("secondary CT shard metadata contains an invalid activation")
		}
		return *metadata.ActivatedAtUTC, nil
	}
	activated := time.Now().UTC()
	metadata.ActivatedAtUTC = &activated
	metadata.Status = "active"
	updated, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return time.Time{}, fmt.Errorf("marshal activated secondary CT shard metadata: %w", err)
	}
	if err := writeAtomicJSON(path, append(updated, '\n')); err != nil {
		return time.Time{}, fmt.Errorf("activate secondary CT shard metadata: %w", err)
	}
	return activated, nil
}

func loadCtRotationCompletion(statePath string) (*ctRotationCompletion, error) {
	data, err := os.ReadFile(filepath.Join(statePath, ctRotationCompletionFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var completion ctRotationCompletion
	if err := decodeStrictJSON(data, &completion); err != nil {
		return nil, err
	}
	if completion.SchemaVersion != ctRotationCompletionSchema ||
		!ctOperationIDPattern.MatchString(completion.OperationID) ||
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
		completion.PriorShardID != ctShardID(completion.PriorPublicKeySHA256) ||
		completion.NewShardID != ctShardID(completion.NewPublicKeySHA256) ||
		completion.PriorBaseURL != ctLogURL ||
		completion.NewBaseURL != ctSecondaryURL ||
		completion.PriorOrigin != ctPrimaryOrigin ||
		completion.NewOrigin != ctSecondaryOrigin ||
		completion.PriorStateID == "" ||
		!ctStateIDPattern.MatchString(completion.NewStateID) ||
		completion.PublicationID == "" ||
		validateSHA256(completion.PublicationManifestSHA256) != nil ||
		validateSHA256(completion.TrustedRootSHA256) != nil ||
		validateSHA256(completion.SigningConfigSHA256) != nil ||
		completion.NewTrustedRootCtlogCount != completion.PriorTrustedRootCtlogCount+1 ||
		(completion.Action != string(repositoryActionPublished) &&
			completion.Action != string(repositoryActionRecovered)) {
		return nil, errors.New("CT log rotation completion has malformed durable state")
	}
	return &completion, nil
}

func writeCtRotationCompletion(
	statePath string,
	completion ctRotationCompletion,
) error {
	data, err := json.MarshalIndent(completion, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicJSON(
		filepath.Join(statePath, ctRotationCompletionFile),
		append(data, '\n'),
	)
}

// validateCtCompletionAgainstState re-derives every claim the completion
// record makes from committed state, so a replayed or tampered completion
// can never be accepted on trust.
func validateCtCompletionAgainstState(
	statePath string,
	completion *ctRotationCompletion,
) error {
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return err
	}
	if completion.TrustDomainID != bootstrap.TrustDomainID ||
		completion.NewGeneration != bootstrap.Generation ||
		completion.NewGenerationID != bootstrap.GenerationID ||
		completion.GenerationManifestSHA256 != bootstrap.GenerationManifestSHA256 ||
		completion.NewPublicKeySHA256 != bootstrap.CtLogPublicKeySHA256 {
		return errors.New("CT log rotation completion does not match the active generation")
	}
	manifest, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return err
	}
	if manifest.CtLogRotationOperationID != completion.OperationID ||
		manifest.CtLogPriorGeneration != completion.PriorGeneration ||
		manifest.CtLogPriorGenerationID != completion.PriorGenerationID ||
		manifest.CtLogPriorPublicKeySHA256 != completion.PriorPublicKeySHA256 ||
		manifest.CtLogPriorShardID != completion.PriorShardID ||
		manifest.CtLogPriorBaseURL != completion.PriorBaseURL ||
		manifest.CtLogShardID != completion.NewShardID ||
		manifest.CtLogBaseURL != completion.NewBaseURL {
		return errors.New("CT log completion does not match generation rotation metadata")
	}
	priorManifestData, err := os.ReadFile(filepath.Join(
		generationPathFor(statePath, completion.PriorGenerationID),
		"manifest.json",
	))
	if err != nil || hashBytes(priorManifestData) != completion.PriorGenerationManifestSHA256 {
		return errors.New("CT log completion prior generation reference is invalid")
	}
	catalog, err := loadCtShardCatalog(statePath)
	if err != nil {
		return err
	}
	if err := validateCtShardCatalog(statePath, catalog, bootstrap); err != nil {
		return err
	}
	if len(catalog.Shards) != 2 ||
		catalog.Shards[0].StateID != completion.PriorStateID ||
		catalog.Shards[1].StateID != completion.NewStateID {
		return errors.New("CT log completion does not match the shard catalog")
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
		return errors.New("CT log completion does not match the active TUF publication")
	}
	targetsPath := filepath.Join(committedPath(layout, publication.Active.ID), "targets")
	trustedRootData, err := os.ReadFile(filepath.Join(targetsPath, "trusted_root.json"))
	if err != nil || hashBytes(trustedRootData) != completion.TrustedRootSHA256 {
		return errors.New("CT log completion TrustedRoot hash is invalid")
	}
	signingConfigData, err := os.ReadFile(filepath.Join(targetsPath, "signing_config.v0.2.json"))
	if err != nil || hashBytes(signingConfigData) != completion.SigningConfigSHA256 {
		return errors.New("CT log completion SigningConfig hash is invalid")
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
		return errors.New("CT log completion trust status is invalid")
	}
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(trustedRootData, trustedRoot); err != nil {
		return err
	}
	if len(trustedRoot.Ctlogs) != completion.NewTrustedRootCtlogCount {
		return errors.New("CT log completion ctlog count is invalid")
	}
	foundPrior, foundNew := false, false
	for _, entry := range trustedRoot.Ctlogs {
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
		return errors.New("CT log completion shards are absent from TrustedRoot")
	}
	for name, generationID := range map[string]string{
		ctPrimaryTargetName:   completion.PriorGenerationID,
		ctSecondaryTargetName: completion.NewGenerationID,
	} {
		target, err := os.ReadFile(filepath.Join(targetsPath, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		expected, err := os.ReadFile(filepath.Join(
			generationPathFor(statePath, generationID),
			filepath.FromSlash(ctLogPublicKeyRelPath),
		))
		if err != nil || !bytes.Equal(target, expected) {
			return fmt.Errorf("CT log completion target %q is invalid", name)
		}
	}
	ctfeTarget, err := os.ReadFile(filepath.Join(targetsPath, "ctfe.pub"))
	if err != nil {
		return err
	}
	activePublicKey, err := os.ReadFile(filepath.Join(
		generationPathFor(statePath, completion.NewGenerationID),
		filepath.FromSlash(ctLogPublicKeyRelPath),
	))
	if err != nil || !bytes.Equal(ctfeTarget, activePublicKey) {
		return errors.New("CT log completion active ctfe.pub target is invalid")
	}
	return nil
}

func finalizeCtRotationCompletion(
	statePath string,
	request ctRotationRequest,
	action repositoryAction,
	priorCtlogCount int,
	priorSigningConfigSHA256 string,
) error {
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return err
	}
	manifest, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return err
	}
	catalog, err := loadCtShardCatalog(statePath)
	if err != nil {
		return err
	}
	if err := validateCtShardCatalog(statePath, catalog, bootstrap); err != nil {
		return err
	}
	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return err
	}
	if publication.Status != publicationStatusCommitted || publication.Active == nil {
		return errors.New("CT log rotation has no committed TUF publication")
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
	if priorSigningConfigSHA256 != "" &&
		hashBytes(signingConfigData) != priorSigningConfigSHA256 {
		return errors.New("CT log rotation must not change SigningConfig")
	}
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(trustedRootData, trustedRoot); err != nil {
		return err
	}
	if priorCtlogCount == 0 {
		priorCtlogCount = len(trustedRoot.Ctlogs) - 1
	}
	completion := ctRotationCompletion{
		SchemaVersion:                 ctRotationCompletionSchema,
		OperationID:                   request.OperationID,
		TrustDomainID:                 request.TrustDomainID,
		CompletedAtUTC:                time.Now().UTC(),
		PriorGeneration:               request.StartingGeneration,
		PriorGenerationID:             request.StartingGenerationID,
		PriorGenerationManifestSHA256: request.StartingGenerationManifestSHA256,
		PriorPublicKeySHA256:          request.StartingCtLogPublicKeySHA256,
		PriorShardID:                  request.PriorShardID,
		PriorBaseURL:                  request.PriorShardURL,
		PriorOrigin:                   ctPrimaryOrigin,
		PriorStateID:                  catalog.Shards[0].StateID,
		NewGeneration:                 bootstrap.Generation,
		NewGenerationID:               bootstrap.GenerationID,
		GenerationManifestSHA256:      bootstrap.GenerationManifestSHA256,
		NewPublicKeySHA256:            bootstrap.CtLogPublicKeySHA256,
		NewShardID:                    manifest.CtLogShardID,
		NewBaseURL:                    manifest.CtLogBaseURL,
		NewOrigin:                     ctSecondaryOrigin,
		NewStateID:                    catalog.Shards[1].StateID,
		PublicationID:                 publication.Active.ID,
		PublicationManifestSHA256:     publication.Active.ManifestSHA256,
		TrustedRootSHA256:             hashBytes(trustedRootData),
		SigningConfigSHA256:           hashBytes(signingConfigData),
		PriorTrustedRootCtlogCount:    priorCtlogCount,
		NewTrustedRootCtlogCount:      len(trustedRoot.Ctlogs),
		Action:                        string(action),
	}
	if err := writeCtRotationCompletion(statePath, completion); err != nil {
		return err
	}
	return validateCtCompletionAgainstState(statePath, &completion)
}

func dispatchCtRotation(statePath string) (repositoryAction, error) {
	return dispatchCtRotationWithHooks(statePath, publicationHooks{})
}

// dispatchCtRotationWithHooks is the single entry point for the bounded
// CT log shard rotation. It is total and idempotent: an interrupted run is
// resumed from committed state, a completed operation is replayed as a
// validated no-op, and any other operation ID is rejected without mutation.
func dispatchCtRotationWithHooks(
	statePath string,
	hooks publicationHooks,
) (repositoryAction, error) {
	requestPath := filepath.Join(statePath, ctRotationRequestFile)
	requestData, err := os.ReadFile(requestPath)
	if err != nil {
		return "", fmt.Errorf("read CT log shard rotation request: %w", err)
	}
	var request ctRotationRequest
	if err := decodeStrictJSON(requestData, &request); err != nil {
		return "", fmt.Errorf("parse CT log shard rotation request: %w", err)
	}
	if err := validateCtRotationRequest(request); err != nil {
		return "", err
	}
	lock, err := acquireStateLock(statePath, 30*time.Second, "ct-log-shard-rotation")
	if err != nil {
		return "", err
	}
	defer lock.release()

	domain, err := loadTrustDomain(statePath)
	if err != nil || domain.TrustDomainID != request.TrustDomainID {
		return "", errors.New("CT log rotation request does not match the immutable trust domain")
	}
	active, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return "", err
	}
	// The single-shard catalog is materialized once, before any mutation,
	// while the active generation is still the starting one. After the
	// generation switch the catalog already exists and is only loaded, so
	// a resumed run never re-derives it from a rotated generation.
	var catalog *ctShardCatalog
	if active.Generation == request.StartingGeneration {
		catalog, err = ensureCtShardCatalogLocked(statePath, active)
	} else {
		catalog, err = loadCtShardCatalog(statePath)
	}
	if err != nil {
		return "", fmt.Errorf("load CT shard catalog: %w", err)
	}
	completion, err := loadCtRotationCompletion(statePath)
	if err != nil {
		return "", fmt.Errorf("ambiguous CT log rotation completion: %w", err)
	}
	if completion != nil && completion.OperationID != request.OperationID {
		return "", fmt.Errorf(
			"CT log shard rotation is bounded to completed operation %q; operation %q is rejected",
			completion.OperationID,
			request.OperationID,
		)
	}
	if len(catalog.Shards) == 2 {
		manifest, loadErr := readOIDCGenerationManifest(statePath, active.GenerationID)
		if loadErr != nil {
			return "", loadErr
		}
		if manifest.CtLogRotationOperationID != request.OperationID {
			return "", fmt.Errorf(
				"CT log shard rotation is bounded to operation %q; operation %q is rejected",
				manifest.CtLogRotationOperationID,
				request.OperationID,
			)
		}
	}
	if err := validateCtCandidateState(statePath, request); err != nil {
		return "", err
	}
	if completion != nil {
		if err := validateCtCompletionAgainstState(statePath, completion); err != nil {
			return "", fmt.Errorf("CT log rotation completion replay failed validation: %w", err)
		}
		if err := validateRequestMatchesCtCompletion(request, completion); err != nil {
			return "", err
		}
		if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		return repositoryActionPublished, nil
	}

	if err := validateCtRotationStartingState(statePath, request, active, catalog); err != nil {
		if active.Generation != request.StartingGeneration+1 {
			return "", err
		}
		manifest, manifestErr := readOIDCGenerationManifest(statePath, active.GenerationID)
		if manifestErr != nil || manifest.CtLogRotationOperationID != request.OperationID {
			return "", err
		}
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("ct-candidate-validated")); err != nil {
		return "", err
	}
	if _, err := recoverTUFStateLocked(statePath, hooks); err != nil {
		return "", fmt.Errorf("recover TUF state for CT log rotation: %w", err)
	}
	// The SigningConfig digest is captured from the recovered committed
	// publication so the "SigningConfig never changes" postcondition is
	// anchored to real committed state on both a fresh run and a replay.
	priorSigningConfigSHA256, err := readActiveSigningConfigDigest(statePath)
	if err != nil {
		return "", err
	}
	active, err = loadActiveTrustGeneration(statePath)
	if err != nil {
		return "", err
	}
	catalog, err = loadCtShardCatalog(statePath)
	if err != nil {
		return "", err
	}

	action := repositoryActionPublished
	priorCtlogCount := 0
	if active.Generation == request.StartingGeneration {
		if err := validateCtRotationStartingState(statePath, request, active, catalog); err != nil {
			return "", err
		}
		next, err := rotateCtLogGeneration(statePath, active, request)
		if err != nil {
			return "", fmt.Errorf("create rotated CT log generation: %w", err)
		}
		if err := runCheckpoint(hooks, publicationCheckpoint("ct-generation-committed")); err != nil {
			return "", err
		}
		priorCtlogCount, _, err = publishCtRotationUpdate(statePath, active, next, hooks)
		if err != nil {
			return "", fmt.Errorf("publish CT log shard rotation: %w", err)
		}
		if err := runCheckpoint(hooks, publicationCheckpoint("ct-tuf-committed")); err != nil {
			return "", err
		}
		if err := switchActiveGeneration(
			statePath,
			active,
			next,
			next.GenerationManifestSHA256,
		); err != nil {
			return "", fmt.Errorf("switch active generation for CT log rotation: %w", err)
		}
		if err := runCheckpoint(hooks, publicationCheckpoint("ct-generation-switched")); err != nil {
			return "", err
		}
		active = next
	} else if active.Generation != request.StartingGeneration+1 {
		return "", errors.New("CT log rotation active generation is ambiguous")
	} else {
		action = repositoryActionRecovered
	}
	manifest, err := readOIDCGenerationManifest(statePath, active.GenerationID)
	if err != nil {
		return "", err
	}
	if err := validateCtRotatedGenerationAgainstRequest(manifest, request, active); err != nil {
		return "", err
	}
	if err := validateCommittedCtPublication(statePath, active); err != nil {
		return "", err
	}
	if _, err := switchCtShardCatalogLocked(
		statePath,
		catalog,
		request,
		active,
		hooks,
	); err != nil {
		return "", fmt.Errorf("switch CT shard catalog: %w", err)
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("ct-catalog-switched")); err != nil {
		return "", err
	}
	if err := finalizeCtRotationCompletion(
		statePath,
		request,
		action,
		priorCtlogCount,
		priorSigningConfigSHA256,
	); err != nil {
		return "", err
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("ct-completion-written")); err != nil {
		return "", err
	}
	if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return action, nil
}

func readActiveSigningConfigDigest(statePath string) (string, error) {
	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return "", err
	}
	if publication.Status != publicationStatusCommitted || publication.Active == nil {
		return "", errors.New("CT log rotation requires a committed active TUF publication")
	}
	data, err := os.ReadFile(filepath.Join(
		committedPath(layout, publication.Active.ID),
		"targets",
		"signing_config.v0.2.json",
	))
	if err != nil {
		return "", err
	}
	return hashBytes(data), nil
}

func validateCtRotationStartingState(
	statePath string,
	request ctRotationRequest,
	active bootstrapManifest,
	catalog *ctShardCatalog,
) error {
	if active.Generation != request.StartingGeneration ||
		active.GenerationID != request.StartingGenerationID ||
		active.GenerationManifestSHA256 != request.StartingGenerationManifestSHA256 ||
		active.CtLogPublicKeySHA256 != request.StartingCtLogPublicKeySHA256 ||
		len(catalog.Shards) != 1 ||
		catalog.ActiveShardID != request.PriorShardID ||
		catalog.Shards[0].ShardID != request.PriorShardID ||
		catalog.Shards[0].BaseURL != request.PriorShardURL ||
		catalog.Shards[0].PublicKeySHA256 != request.StartingCtLogPublicKeySHA256 ||
		catalog.Shards[0].StateID == request.CandidateStateID {
		return errors.New("CT log rotation request does not match the active starting state")
	}
	return validateCtShardCatalog(statePath, catalog, active)
}

func validateCtRotatedGenerationAgainstRequest(
	manifest generationManifest,
	request ctRotationRequest,
	active bootstrapManifest,
) error {
	if active.Generation != request.StartingGeneration+1 ||
		active.GenerationID != fmt.Sprintf("generation-%08d", request.StartingGeneration+1) ||
		active.CtLogPublicKeySHA256 != request.CandidatePublicKeySHA256 ||
		manifest.CtLogRotationOperationID != request.OperationID ||
		manifest.CtLogPriorGeneration != request.StartingGeneration ||
		manifest.CtLogPriorGenerationID != request.StartingGenerationID ||
		manifest.CtLogPriorPublicKeySHA256 != request.StartingCtLogPublicKeySHA256 ||
		manifest.CtLogPriorShardID != request.PriorShardID ||
		manifest.CtLogPriorBaseURL != request.PriorShardURL ||
		manifest.CtLogShardID != request.CandidateShardID ||
		manifest.CtLogBaseURL != request.CandidateShardURL {
		return errors.New("rotated CT log generation does not match its request")
	}
	return nil
}

func validateCommittedCtPublication(
	statePath string,
	bootstrap bootstrapManifest,
) error {
	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return err
	}
	if publication.Status != publicationStatusCommitted || publication.Active == nil {
		return errors.New("rotated CT log generation lacks a committed TUF publication")
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

func validateRequestMatchesCtCompletion(
	request ctRotationRequest,
	completion *ctRotationCompletion,
) error {
	if request.OperationID != completion.OperationID ||
		request.TrustDomainID != completion.TrustDomainID ||
		request.StartingGeneration != completion.PriorGeneration ||
		request.StartingGenerationID != completion.PriorGenerationID ||
		request.StartingGenerationManifestSHA256 != completion.PriorGenerationManifestSHA256 ||
		request.StartingCtLogPublicKeySHA256 != completion.PriorPublicKeySHA256 ||
		request.PriorShardID != completion.PriorShardID ||
		request.PriorShardURL != completion.PriorBaseURL ||
		request.CandidateShardID != completion.NewShardID ||
		request.CandidateShardURL != completion.NewBaseURL ||
		request.CandidatePublicKeySHA256 != completion.NewPublicKeySHA256 ||
		request.CandidateStateID != completion.NewStateID {
		return errors.New("replayed CT log rotation request does not match its completion")
	}
	return nil
}
