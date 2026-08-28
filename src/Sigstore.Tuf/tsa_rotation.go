package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	trustrootv1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/youmark/pkcs8"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	tsaRotationRequestFile      = "rotate-timestamp-authority.request"
	tsaRotationCompletionFile   = "rotate-timestamp-authority.completed"
	tsaRotationDirectory        = "tsa-rotation"
	tsaRotationSchemaVersion    = 1
	tsaRotationCompletionSchema = 1

	tsaRootKeyRelPath   = "private/tsa/root.key"
	tsaSignerKeyRelPath = "private/tsa/signer.key"
	tsaPasswordRelPath  = "private/tsa/password"
	tsaRootCertRelPath  = "public/tsa/root.pem"
	tsaLeafCertRelPath  = "public/tsa/leaf.pem"
	tsaChainRelPath     = "public/tsa/cert-chain.pem"
)

// tsaOperationIDPattern matches the 32-character lowercase hexadecimal
// operation identifier used to bind a TSA rotation request, its staged
// candidate generation, and its completion record together.
var tsaOperationIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// tsaExtKeyUsageOID is the id-ce-extKeyUsage extension OID (2.5.29.37), used
// to confirm the TSA leaf certificate's extended key usage extension is
// marked critical, which crypto/x509 does not expose directly.
var tsaExtKeyUsageOID = asn1.ObjectIdentifier{2, 5, 29, 37}

var tsaBasicConstraintsOID = asn1.ObjectIdentifier{2, 5, 29, 19}

var tsaKeyUsageOID = asn1.ObjectIdentifier{2, 5, 29, 15}

// tsaRotationRequest is the strict, operation-bound request written by the
// C# host to ask the Go worker to promote already-generated, already
// validated candidate timestamp-authority material into a new trust
// generation. All fields are mandatory; the candidate material itself lives
// on disk under tsa-rotation/<operationId>/candidate/ and is independently
// validated before it is trusted.
type tsaRotationRequest struct {
	SchemaVersion          int    `json:"schemaVersion"`
	OperationID            string `json:"operationId"`
	TrustDomainID          string `json:"trustDomainId"`
	StartingGeneration     int    `json:"startingGeneration"`
	StartingGenerationID   string `json:"startingGenerationId"`
	StartingTsaRootSHA256  string `json:"startingTsaRootSha256"`
	StartingTsaLeafSHA256  string `json:"startingTsaLeafSha256"`
	CandidateTsaRootSHA256 string `json:"candidateTsaRootSha256"`
	CandidateTsaLeafSHA256 string `json:"candidateTsaLeafSha256"`
}

// tsaRotationCompletion is the durable, schema-versioned record written once
// a TSA rotation has been fully committed: the new generation is active, the
// TUF repository additively carries both the prior and the new timestamp
// authority, and the operation is bound end-to-end. It intentionally
// captures enough live-state fingerprints (generation manifest hash, active
// TUF publication ID and manifest hash, trusted_root/signing_config hashes,
// and the resulting TSA authority count) that a replayed request can be
// strictly validated against current disk state instead of trusted blindly.
type tsaRotationCompletion struct {
	SchemaVersion             int       `json:"schemaVersion"`
	OperationID               string    `json:"operationId"`
	TrustDomainID             string    `json:"trustDomainId"`
	CompletedAtUTC            time.Time `json:"completedAtUtc"`
	PriorGeneration           int       `json:"priorGeneration"`
	PriorGenerationID         string    `json:"priorGenerationId"`
	PriorTsaRootSHA256        string    `json:"priorTsaRootSha256"`
	PriorTsaLeafSHA256        string    `json:"priorTsaLeafSha256"`
	NewGeneration             int       `json:"newGeneration"`
	NewGenerationID           string    `json:"newGenerationId"`
	NewTsaRootSHA256          string    `json:"newTsaRootSha256"`
	NewTsaLeafSHA256          string    `json:"newTsaLeafSha256"`
	ManifestSHA256            string    `json:"manifestSha256"`
	PublicationID             string    `json:"publicationId"`
	PublicationManifestSHA256 string    `json:"publicationManifestSha256"`
	TrustedRootSHA256         string    `json:"trustedRootSha256"`
	SigningConfigSHA256       string    `json:"signingConfigSha256"`
	TsaTrustEntryCount        int       `json:"tsaTrustEntryCount"`
}

// dispatchTsaRotation is the entry point invoked from main() when a
// rotate-timestamp-authority.request file is present.
func dispatchTsaRotation(statePath string) (repositoryAction, error) {
	return dispatchTsaRotationWithHooks(statePath, publicationHooks{})
}

func dispatchTsaRotationWithHooks(
	statePath string,
	hooks publicationHooks,
) (repositoryAction, error) {
	requestPath := filepath.Join(statePath, tsaRotationRequestFile)
	requestData, err := os.ReadFile(requestPath)
	if err != nil {
		return "", fmt.Errorf("read TSA rotation request: %w", err)
	}
	var request tsaRotationRequest
	if err := json.Unmarshal(requestData, &request); err != nil {
		return "", fmt.Errorf("parse TSA rotation request: %w", err)
	}
	if err := validateTsaRotationRequest(request); err != nil {
		return "", fmt.Errorf("invalid TSA rotation request: %w", err)
	}

	lock, err := acquireStateLock(statePath, 30*time.Second, "tsa-rotation-dispatch")
	if err != nil {
		return "", err
	}
	defer lock.release()

	domain, err := loadTrustDomain(statePath)
	if err != nil {
		return "", fmt.Errorf("load trust domain for TSA rotation: %w", err)
	}
	if request.TrustDomainID != domain.TrustDomainID {
		return "", fmt.Errorf(
			"TSA rotation request trust domain %q does not match the immutable domain %q",
			request.TrustDomainID,
			domain.TrustDomainID,
		)
	}

	completion, err := loadTsaRotationCompletion(statePath)
	if err != nil {
		return "", fmt.Errorf("ambiguous TSA rotation completion state: %w", err)
	}
	if completion != nil && completion.OperationID == request.OperationID {
		if err := validateTsaCompletionAgainstState(statePath, completion); err != nil {
			return "", fmt.Errorf("TSA rotation completion replay failed validation: %w", err)
		}
		if err := removeTsaOperationPrivateCandidate(statePath, request.OperationID); err != nil {
			return "", err
		}
		if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("remove replayed TSA rotation request: %w", err)
		}
		return repositoryActionPublished, nil
	}

	if err := recoverCommittedTSARotation(statePath, request); err != nil {
		return "", fmt.Errorf("recover committed TSA rotation: %w", err)
	}
	if _, err := recoverTUFStateLocked(statePath, hooks); err != nil {
		return "", fmt.Errorf("recover TUF publication state for TSA rotation: %w", err)
	}

	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return "", fmt.Errorf("load active generation for TSA rotation: %w", err)
	}

	if bootstrap.Generation == request.StartingGeneration+1 {
		generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
		if err != nil {
			return "", fmt.Errorf("read active generation manifest: %w", err)
		}
		if generation.TSARotationOperationID != request.OperationID {
			return "", fmt.Errorf(
				"active generation %s belongs to TSA rotation %q, not %q",
				bootstrap.GenerationID,
				generation.TSARotationOperationID,
				request.OperationID,
			)
		}
		if err := validateTsaRequestStartingState(request, generation); err != nil {
			return "", err
		}
		if err := finalizeTsaRotationCompletion(statePath, request, bootstrap); err != nil {
			return "", err
		}
		if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("remove recovered TSA rotation request: %w", err)
		}
		return repositoryActionRecovered, nil
	}

	if bootstrap.Generation != request.StartingGeneration ||
		bootstrap.GenerationID != request.StartingGenerationID ||
		bootstrap.TsaRootSHA256 != request.StartingTsaRootSHA256 ||
		bootstrap.TsaLeafSHA256 != request.StartingTsaLeafSHA256 {
		return "", errors.New(
			"TSA rotation request does not match the currently active generation",
		)
	}

	newBootstrap, err := rotateTsaGeneration(statePath, bootstrap, request)
	if err != nil {
		return "", fmt.Errorf("rotate TSA generation: %w", err)
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("tsa-generation-committed")); err != nil {
		return "", err
	}

	if err := publishTsaRotationUpdate(statePath, bootstrap, newBootstrap, hooks); err != nil {
		return "", fmt.Errorf("publish TSA rotation TUF update: %w", err)
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("tsa-tuf-committed")); err != nil {
		return "", err
	}

	if err := switchActiveGeneration(
		statePath,
		bootstrap,
		newBootstrap,
		newBootstrap.GenerationManifestSHA256,
	); err != nil {
		return "", fmt.Errorf("switch active generation for TSA rotation: %w", err)
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("tsa-generation-switched")); err != nil {
		return "", err
	}

	if err := finalizeTsaRotationCompletion(statePath, request, newBootstrap); err != nil {
		return "", err
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("tsa-completion-written")); err != nil {
		return "", err
	}

	if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("remove TSA rotation request file: %w", err)
	}

	return repositoryActionPublished, nil
}

func validateTsaRotationRequest(request tsaRotationRequest) error {
	if request.SchemaVersion != tsaRotationSchemaVersion {
		return fmt.Errorf(
			"TSA rotation request schema %d is unsupported; expected %d",
			request.SchemaVersion,
			tsaRotationSchemaVersion,
		)
	}
	if !tsaOperationIDPattern.MatchString(request.OperationID) {
		return errors.New("TSA rotation operationId must be 32 lowercase hexadecimal characters")
	}
	if request.TrustDomainID == "" {
		return errors.New("TSA rotation request is missing trustDomainId")
	}
	if request.StartingGeneration < initialGeneration ||
		request.StartingGenerationID != fmt.Sprintf("generation-%08d", request.StartingGeneration) {
		return errors.New("TSA rotation request has an invalid starting generation")
	}
	if validateSHA256(request.StartingTsaRootSHA256) != nil ||
		validateSHA256(request.StartingTsaLeafSHA256) != nil ||
		validateSHA256(request.CandidateTsaRootSHA256) != nil ||
		validateSHA256(request.CandidateTsaLeafSHA256) != nil {
		return errors.New("TSA rotation request has malformed certificate fingerprints")
	}
	if request.StartingTsaRootSHA256 == request.CandidateTsaRootSHA256 ||
		request.StartingTsaLeafSHA256 == request.CandidateTsaLeafSHA256 {
		return errors.New("TSA rotation request candidate does not change the timestamp authority")
	}
	return nil
}

func validateTsaRequestStartingState(
	request tsaRotationRequest,
	generation generationManifest,
) error {
	if generation.TrustDomainID != request.TrustDomainID ||
		generation.TSAPriorGeneration != request.StartingGeneration ||
		generation.TSAPriorGenerationID != request.StartingGenerationID ||
		generation.TSAPriorRootSHA256 != request.StartingTsaRootSHA256 ||
		generation.TSAPriorLeafSHA256 != request.StartingTsaLeafSHA256 {
		return errors.New(
			"active TSA generation does not match the starting state of the rotation request",
		)
	}
	return nil
}

// rotateTsaGeneration produces (or reuses) the immutable generation N+1 whose
// only difference from generation N is a wholesale replacement of the
// private/tsa and public/tsa subtrees with the pre-validated candidate
// material that C# already generated and placed under
// tsa-rotation/<operationId>/candidate/.
func rotateTsaGeneration(
	statePath string,
	current bootstrapManifest,
	request tsaRotationRequest,
) (bootstrapManifest, error) {
	newGeneration := current.Generation + 1
	newGenerationID := fmt.Sprintf("generation-%08d", newGeneration)
	currentGenerationPath := filepath.Join(statePath, "generations", current.GenerationID)
	newGenerationPath := filepath.Join(statePath, "generations", newGenerationID)
	currentManifest, err := readOIDCGenerationManifest(
		statePath,
		current.GenerationID,
	)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf(
			"read current generation manifest for TSA rotation: %w",
			err,
		)
	}

	if pathExists(newGenerationPath) {
		return validateAndReuseTsaGeneration(
			statePath,
			current,
			newGenerationPath,
			newGenerationID,
			newGeneration,
			request,
		)
	}

	candidatePath := filepath.Join(statePath, tsaRotationDirectory, request.OperationID, "candidate")
	if err := validateTimestampAuthorityCandidateFileSet(candidatePath); err != nil {
		return bootstrapManifest{}, fmt.Errorf("validate TSA rotation candidate: %w", err)
	}
	candidateRootCert, candidateLeafCert, err := loadTsaCertificatePair(candidatePath)
	if err != nil {
		return bootstrapManifest{}, err
	}
	if err := validateTimestampAuthorityCertificates(candidateRootCert, candidateLeafCert); err != nil {
		return bootstrapManifest{}, fmt.Errorf("validate candidate TSA certificates: %w", err)
	}
	if err := validateTsaChainMatches(
		candidateRootCert,
		candidateLeafCert,
		filepath.Join(candidatePath, filepath.FromSlash(tsaChainRelPath)),
	); err != nil {
		return bootstrapManifest{}, fmt.Errorf("validate candidate TSA chain: %w", err)
	}
	candidateRootHash := hashDER(candidateRootCert.Raw)
	candidateLeafHash := hashDER(candidateLeafCert.Raw)
	if candidateRootHash != request.CandidateTsaRootSHA256 ||
		candidateLeafHash != request.CandidateTsaLeafSHA256 {
		return bootstrapManifest{}, errors.New(
			"candidate TSA material does not match the rotation request fingerprints",
		)
	}
	if candidateRootHash == current.TsaRootSHA256 || candidateLeafHash == current.TsaLeafSHA256 {
		return bootstrapManifest{}, errors.New(
			"candidate TSA material does not change the currently active timestamp authority",
		)
	}
	candidatePassword, err := os.ReadFile(
		filepath.Join(candidatePath, filepath.FromSlash(tsaPasswordRelPath)),
	)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("read candidate TSA password: %w", err)
	}
	candidateSigner, err := loadEncryptedTSAKey(
		filepath.Join(candidatePath, filepath.FromSlash(tsaSignerKeyRelPath)),
		candidatePassword,
	)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("load candidate TSA signer key: %w", err)
	}
	if err := ensureECDSAPublicKeyMatches(
		"candidate TSA signer key",
		&candidateSigner.PublicKey,
		candidateLeafCert,
	); err != nil {
		return bootstrapManifest{}, err
	}

	stagingGenerationPath := filepath.Join(
		statePath,
		tsaRotationDirectory,
		request.OperationID,
		newGenerationID+".staging",
	)
	if err := os.RemoveAll(stagingGenerationPath); err != nil {
		return bootstrapManifest{}, fmt.Errorf("clean TSA generation staging directory: %w", err)
	}
	if err := os.MkdirAll(stagingGenerationPath, 0o755); err != nil {
		return bootstrapManifest{}, fmt.Errorf("create TSA rotation staging directory: %w", err)
	}
	if err := copyDirectory(currentGenerationPath, stagingGenerationPath); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("copy prior generation material: %w", err)
	}
	if err := os.Remove(filepath.Join(stagingGenerationPath, "manifest.json")); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("remove copied generation manifest: %w", err)
	}
	if err := os.RemoveAll(filepath.Join(stagingGenerationPath, "private", "tsa")); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("remove prior private TSA material: %w", err)
	}
	if err := os.RemoveAll(filepath.Join(stagingGenerationPath, "public", "tsa")); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("remove prior public TSA material: %w", err)
	}
	if err := copyTsaCandidateFiles(candidatePath, stagingGenerationPath); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, err
	}

	newFiles, err := collectGenerationFileHashes(stagingGenerationPath)
	if err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, err
	}

	now := time.Now().UTC()
	genManifest := generationManifest{
		SchemaVersion:        trustStateSchemaVersion,
		Generation:           newGeneration,
		GenerationID:         newGenerationID,
		TrustDomainID:        current.TrustDomainID,
		CreatedAtUTC:         now,
		SourceSchemaVersion:  trustStateSchemaVersion,
		FulcioRootSHA256:     current.FulcioRootSHA256,
		CtLogPublicKeySHA256: current.CtLogPublicKeySHA256,
		RekorPublicKeySHA256: current.RekorPublicKeySHA256,
		TsaRootSHA256:        candidateRootHash,
		TsaLeafSHA256:        candidateLeafHash,
		OIDCKeyID:            current.OIDCKeyID,
		OIDCRetainedPrivateKeyPaths: append(
			[]string(nil),
			currentManifest.OIDCRetainedPrivateKeyPaths...,
		),
		TSARotationOperationID: request.OperationID,
		TSAPriorGeneration:     current.Generation,
		TSAPriorGenerationID:   current.GenerationID,
		TSAPriorRootSHA256:     current.TsaRootSHA256,
		TSAPriorLeafSHA256:     current.TsaLeafSHA256,
		Files:                  newFiles,
	}
	manifestBytes, err := json.MarshalIndent(genManifest, "", "  ")
	if err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("marshal TSA generation manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(
		filepath.Join(stagingGenerationPath, "manifest.json"),
		manifestBytes,
		0o644,
	); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("write TSA generation manifest: %w", err)
	}
	manifestHash := hashBytes(manifestBytes)

	if err := validateTSAGenerationMaterial(stagingGenerationPath, genManifest); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("validate new TSA generation: %w", err)
	}
	if err := validateUnchangedNonTSAMaterial(currentGenerationPath, stagingGenerationPath); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, err
	}

	if err := os.Rename(stagingGenerationPath, newGenerationPath); err != nil {
		return bootstrapManifest{}, fmt.Errorf("commit new TSA generation: %w", err)
	}
	if err := syncDirectory(filepath.Dir(newGenerationPath)); err != nil {
		return bootstrapManifest{}, fmt.Errorf("sync committed TSA generation: %w", err)
	}

	return bootstrapManifest{
		SchemaVersion:            4,
		CreatedAtUTC:             now,
		FulcioRootSHA256:         current.FulcioRootSHA256,
		CtLogPublicKeySHA256:     current.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:     current.RekorPublicKeySHA256,
		TsaRootSHA256:            candidateRootHash,
		TsaLeafSHA256:            candidateLeafHash,
		OIDCKeyID:                current.OIDCKeyID,
		TrustDomainID:            current.TrustDomainID,
		Generation:               newGeneration,
		GenerationID:             newGenerationID,
		GenerationManifestSHA256: manifestHash,
	}, nil
}

// validateAndReuseTsaGeneration validates a pre-existing generation N+1
// directory (left over from a prior crashed attempt) and reuses it only if
// it is bound to exactly this rotation request and cryptographically valid.
func validateAndReuseTsaGeneration(
	statePath string,
	current bootstrapManifest,
	newGenerationPath string,
	newGenerationID string,
	newGeneration int,
	request tsaRotationRequest,
) (bootstrapManifest, error) {
	manifestPath := filepath.Join(newGenerationPath, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("read pre-existing TSA generation manifest: %w", err)
	}
	var genManifest generationManifest
	if err := json.Unmarshal(manifestBytes, &genManifest); err != nil {
		return bootstrapManifest{}, fmt.Errorf("parse pre-existing TSA generation manifest: %w", err)
	}
	if genManifest.SchemaVersion != trustStateSchemaVersion ||
		genManifest.Generation != newGeneration ||
		genManifest.GenerationID != newGenerationID ||
		genManifest.TrustDomainID != current.TrustDomainID {
		return bootstrapManifest{}, errors.New(
			"pre-existing TSA generation does not match the expected identity",
		)
	}
	if genManifest.TSARotationOperationID != request.OperationID ||
		genManifest.TSAPriorGeneration != request.StartingGeneration ||
		genManifest.TSAPriorGenerationID != request.StartingGenerationID ||
		genManifest.TSAPriorRootSHA256 != request.StartingTsaRootSHA256 ||
		genManifest.TSAPriorLeafSHA256 != request.StartingTsaLeafSHA256 ||
		genManifest.TsaRootSHA256 != request.CandidateTsaRootSHA256 ||
		genManifest.TsaLeafSHA256 != request.CandidateTsaLeafSHA256 {
		return bootstrapManifest{}, errors.New(
			"pre-existing TSA generation is not bound to this rotation request",
		)
	}

	actualFiles, err := collectGenerationFileHashes(newGenerationPath)
	if err != nil {
		return bootstrapManifest{}, err
	}
	if len(actualFiles) != len(genManifest.Files) {
		return bootstrapManifest{}, errors.New(
			"pre-existing TSA generation files do not match its manifest",
		)
	}
	for path, hash := range genManifest.Files {
		if actualFiles[path] != hash {
			return bootstrapManifest{}, fmt.Errorf(
				"pre-existing TSA generation file %q does not match its manifest",
				path,
			)
		}
	}

	if err := validateTSAGenerationMaterial(newGenerationPath, genManifest); err != nil {
		return bootstrapManifest{}, fmt.Errorf("validate pre-existing TSA generation: %w", err)
	}
	currentGenerationPath := filepath.Join(statePath, "generations", current.GenerationID)
	if err := validateUnchangedNonTSAMaterial(currentGenerationPath, newGenerationPath); err != nil {
		return bootstrapManifest{}, err
	}

	return bootstrapManifest{
		SchemaVersion:            4,
		CreatedAtUTC:             genManifest.CreatedAtUTC,
		FulcioRootSHA256:         genManifest.FulcioRootSHA256,
		CtLogPublicKeySHA256:     genManifest.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:     genManifest.RekorPublicKeySHA256,
		TsaRootSHA256:            genManifest.TsaRootSHA256,
		TsaLeafSHA256:            genManifest.TsaLeafSHA256,
		OIDCKeyID:                genManifest.OIDCKeyID,
		TrustDomainID:            genManifest.TrustDomainID,
		Generation:               genManifest.Generation,
		GenerationID:             genManifest.GenerationID,
		GenerationManifestSHA256: hashBytes(manifestBytes),
	}, nil
}

func copyTsaCandidateFiles(candidatePath, destGenerationPath string) error {
	for _, relative := range []string{
		tsaSignerKeyRelPath,
		tsaPasswordRelPath,
		tsaRootCertRelPath,
		tsaLeafCertRelPath,
		tsaChainRelPath,
	} {
		relPath := filepath.FromSlash(relative)
		data, err := os.ReadFile(filepath.Join(candidatePath, relPath))
		if err != nil {
			return fmt.Errorf("read candidate TSA file %q: %w", relative, err)
		}
		destPath := filepath.Join(destGenerationPath, relPath)
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("create TSA directory for %q: %w", relative, err)
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(relative, "private/") {
			mode = 0o600
		}
		if err := os.WriteFile(destPath, data, mode); err != nil {
			return fmt.Errorf("write TSA file %q: %w", relative, err)
		}
	}
	return nil
}

func loadTsaCertificatePair(directory string) (rootCert, leafCert *x509.Certificate, err error) {
	rootCert, err = loadSingleCertificate(
		filepath.Join(directory, filepath.FromSlash(tsaRootCertRelPath)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("load TSA root certificate: %w", err)
	}
	leafCert, err = loadSingleCertificate(
		filepath.Join(directory, filepath.FromSlash(tsaLeafCertRelPath)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("load TSA leaf certificate: %w", err)
	}
	return rootCert, leafCert, nil
}

func loadSingleCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("%s must contain exactly one PEM certificate", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// validateTimestampAuthorityCandidateFileSet asserts that a TSA rotation
// candidate directory contains exactly the five files C# is contracted to
// produce: an encrypted signer key, its shared password, and the
// leaf/root/chain public certificates. Critically, there must be no
// root.key: candidate material never carries a new root private key.
func validateTimestampAuthorityCandidateFileSet(candidatePath string) error {
	actual, err := collectGenerationFileHashes(candidatePath)
	if err != nil {
		return fmt.Errorf("hash candidate TSA material: %w", err)
	}
	expected := []string{
		tsaSignerKeyRelPath,
		tsaPasswordRelPath,
		tsaRootCertRelPath,
		tsaLeafCertRelPath,
		tsaChainRelPath,
	}
	if len(actual) != len(expected) {
		return fmt.Errorf(
			"candidate TSA material has %d files; expected exactly %d",
			len(actual),
			len(expected),
		)
	}
	for _, path := range expected {
		if _, ok := actual[path]; !ok {
			return fmt.Errorf("candidate TSA material is missing %q", path)
		}
	}
	return nil
}

// validateTimestampAuthorityCertificates re-implements, in Go, the same
// cryptographic checks the C# host applies when it first generates TSA
// material: the root is a self-signed CA permitted to sign certificates, the
// leaf is a non-CA end-entity certificate carrying exactly one critical
// timestamping-only extended key usage and is signed by the root, and both
// certificates use ECDSA P-256 with SHA-256 signatures.
func validateTimestampAuthorityCertificates(rootCert, leafCert *x509.Certificate) error {
	if !rootCert.IsCA || !rootCert.BasicConstraintsValid {
		return errors.New("TSA root certificate must be a CA with basic constraints")
	}
	if rootCert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return errors.New(
			"TSA root certificate must carry exactly certificate-signing and CRL-signing key usages",
		)
	}
	if leafCert.IsCA {
		return errors.New("TSA leaf certificate must not be a CA")
	}
	if !leafCert.BasicConstraintsValid {
		return errors.New("TSA leaf certificate must carry basic constraints")
	}
	if leafCert.KeyUsage != x509.KeyUsageDigitalSignature {
		return errors.New(
			"TSA leaf certificate must carry exactly the digital-signature key usage",
		)
	}
	if len(leafCert.ExtKeyUsage) != 1 ||
		leafCert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping ||
		len(leafCert.UnknownExtKeyUsage) != 0 {
		return errors.New(
			"TSA leaf certificate must carry exactly the timestamping extended key usage",
		)
	}
	if !extensionIsCritical(leafCert, tsaExtKeyUsageOID) {
		return errors.New(
			"TSA leaf certificate extended key usage extension must be critical",
		)
	}
	if !extensionIsCritical(rootCert, tsaBasicConstraintsOID) ||
		!extensionIsCritical(rootCert, tsaKeyUsageOID) ||
		!extensionIsCritical(leafCert, tsaBasicConstraintsOID) ||
		!extensionIsCritical(leafCert, tsaKeyUsageOID) {
		return errors.New(
			"TSA basic-constraints and key-usage extensions must be critical",
		)
	}
	rootPublicKey, ok := rootCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || rootPublicKey.Curve.Params().Name != "P-256" {
		return errors.New("TSA root certificate must use an ECDSA P-256 public key")
	}
	leafPublicKey, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || leafPublicKey.Curve.Params().Name != "P-256" {
		return errors.New("TSA leaf certificate must use an ECDSA P-256 public key")
	}
	if rootCert.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
		leafCert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return errors.New("TSA certificates must be signed with ECDSA-SHA256")
	}
	if !rootCert.NotBefore.Before(rootCert.NotAfter) ||
		!leafCert.NotBefore.Before(leafCert.NotAfter) {
		return errors.New("TSA certificate validity window is invalid")
	}
	now := time.Now().UTC()
	if now.Before(rootCert.NotBefore) || !now.Before(rootCert.NotAfter) ||
		now.Before(leafCert.NotBefore) || !now.Before(leafCert.NotAfter) {
		return errors.New("TSA certificate chain is not currently valid")
	}
	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		return fmt.Errorf("TSA root certificate is not validly self-signed: %w", err)
	}
	if err := leafCert.CheckSignatureFrom(rootCert); err != nil {
		return fmt.Errorf("TSA leaf certificate is not validly signed by its root: %w", err)
	}
	return nil
}

func extensionIsCritical(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oid) {
			return extension.Critical
		}
	}
	return false
}

// validateTsaChainMatches asserts that a cert-chain.pem file contains
// exactly [leaf, root], byte-identical to the standalone certificates.
func validateTsaChainMatches(rootCert, leafCert *x509.Certificate, chainPath string) error {
	_, chainCertificates, err := loadCertificateChain(chainPath)
	if err != nil {
		return fmt.Errorf("load TSA certificate chain: %w", err)
	}
	if len(chainCertificates) != 2 {
		return fmt.Errorf(
			"TSA certificate chain must contain exactly a leaf and a root certificate, found %d",
			len(chainCertificates),
		)
	}
	if !bytes.Equal(chainCertificates[0].Raw, leafCert.Raw) {
		return errors.New(
			"TSA certificate chain leaf does not match the standalone leaf certificate",
		)
	}
	if !bytes.Equal(chainCertificates[1].Raw, rootCert.Raw) {
		return errors.New(
			"TSA certificate chain root does not match the standalone root certificate",
		)
	}
	return nil
}

func hashDER(der []byte) string {
	sum := sha256Bytes(der)
	return hex.EncodeToString(sum[:])
}

func loadEncryptedTSAKey(keyPath string, password []byte) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil ||
		block.Type != "ENCRYPTED PRIVATE KEY" ||
		len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("%s is not exactly one encrypted PKCS#8 PEM block", keyPath)
	}
	key, err := pkcs8.ParsePKCS8PrivateKeyECDSA(block.Bytes, password)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", keyPath, err)
	}
	return key, nil
}

func ensureECDSAPublicKeyMatches(
	description string,
	key *ecdsa.PublicKey,
	cert *x509.Certificate,
) error {
	certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%s: certificate does not carry an ECDSA public key", description)
	}
	keySPKI, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	certSPKI, err := x509.MarshalPKIXPublicKey(certKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(keySPKI, certSPKI) {
		return fmt.Errorf("%s does not match its certificate", description)
	}
	return nil
}

// validateTSAGenerationMaterial validates the private/tsa and public/tsa
// trees of an active or candidate generation directory: the file set is
// exactly what is expected (with or without a root private key, matching the
// rotation-operation invariant), the certificates satisfy every structural
// and cryptographic constraint, the chain file matches the standalone
// certificates, private keys match their certificates, and TSA rotation
// metadata on the manifest is internally consistent.
func validateTSAGenerationMaterial(generationPath string, manifest generationManifest) error {
	rootCertPath := filepath.Join(generationPath, filepath.FromSlash(tsaRootCertRelPath))
	leafCertPath := filepath.Join(generationPath, filepath.FromSlash(tsaLeafCertRelPath))
	chainPath := filepath.Join(generationPath, filepath.FromSlash(tsaChainRelPath))
	signerKeyPath := filepath.Join(generationPath, filepath.FromSlash(tsaSignerKeyRelPath))
	passwordPath := filepath.Join(generationPath, filepath.FromSlash(tsaPasswordRelPath))
	rootKeyPath := filepath.Join(generationPath, filepath.FromSlash(tsaRootKeyRelPath))

	rootCert, err := loadSingleCertificate(rootCertPath)
	if err != nil {
		return fmt.Errorf("load TSA root certificate: %w", err)
	}
	leafCert, err := loadSingleCertificate(leafCertPath)
	if err != nil {
		return fmt.Errorf("load TSA leaf certificate: %w", err)
	}
	if err := validateTsaChainMatches(rootCert, leafCert, chainPath); err != nil {
		return err
	}
	if err := validateTimestampAuthorityCertificates(rootCert, leafCert); err != nil {
		return err
	}

	rootHash := hashDER(rootCert.Raw)
	leafHash := hashDER(leafCert.Raw)
	if rootHash != manifest.TsaRootSHA256 {
		return errors.New("TSA root certificate hash does not match the generation manifest")
	}
	if leafHash != manifest.TsaLeafSHA256 {
		return errors.New("TSA leaf certificate hash does not match the generation manifest")
	}

	password, err := os.ReadFile(passwordPath)
	if err != nil {
		return fmt.Errorf("read TSA password: %w", err)
	}
	signerKey, err := loadEncryptedTSAKey(signerKeyPath, password)
	if err != nil {
		return fmt.Errorf("load TSA signer key: %w", err)
	}
	if err := ensureECDSAPublicKeyMatches("active TSA signer key", &signerKey.PublicKey, leafCert); err != nil {
		return err
	}

	rootKeyExists := pathExists(rootKeyPath)
	isRotated := manifest.TSARotationOperationID != ""
	if rootKeyExists && isRotated {
		return errors.New("rotated TSA generation must not retain its root private key")
	}
	if !rootKeyExists && !isRotated {
		return errors.New("non-rotated TSA generation is missing its root private key")
	}
	if rootKeyExists {
		rootKey, err := loadEncryptedTSAKey(rootKeyPath, password)
		if err != nil {
			return fmt.Errorf("load TSA root key: %w", err)
		}
		if err := ensureECDSAPublicKeyMatches("active TSA root key", &rootKey.PublicKey, rootCert); err != nil {
			return err
		}
	}

	expected := map[string]bool{
		tsaSignerKeyRelPath: true,
		tsaPasswordRelPath:  true,
		tsaRootCertRelPath:  true,
		tsaLeafCertRelPath:  true,
		tsaChainRelPath:     true,
	}
	if rootKeyExists {
		expected[tsaRootKeyRelPath] = true
	}
	for path := range manifest.Files {
		if strings.HasPrefix(path, "private/tsa/") || strings.HasPrefix(path, "public/tsa/") {
			if !expected[path] {
				return fmt.Errorf("unexpected TSA generation file %q", path)
			}
		}
	}
	for path := range expected {
		if _, ok := manifest.Files[path]; !ok {
			return fmt.Errorf("TSA generation is missing required file %q", path)
		}
	}

	if manifest.TSARotationOperationID == "" {
		if manifest.TSAPriorGeneration != 0 ||
			manifest.TSAPriorGenerationID != "" ||
			manifest.TSAPriorRootSHA256 != "" ||
			manifest.TSAPriorLeafSHA256 != "" {
			return errors.New("generation contains partial TSA rotation metadata")
		}
	} else {
		if !tsaOperationIDPattern.MatchString(manifest.TSARotationOperationID) ||
			manifest.TSAPriorGeneration < initialGeneration ||
			manifest.TSAPriorGeneration >= manifest.Generation ||
			manifest.TSAPriorGenerationID != fmt.Sprintf("generation-%08d", manifest.TSAPriorGeneration) ||
			validateSHA256(manifest.TSAPriorRootSHA256) != nil ||
			validateSHA256(manifest.TSAPriorLeafSHA256) != nil ||
			manifest.TSAPriorRootSHA256 == manifest.TsaRootSHA256 ||
			manifest.TSAPriorLeafSHA256 == manifest.TsaLeafSHA256 {
			return errors.New("rotated generation has invalid TSA operation metadata")
		}
	}
	return nil
}

// validateUnchangedNonTSAMaterial asserts that everything outside
// private/tsa/ and public/tsa/ is preserved byte-for-byte across a rotation,
// mirroring validateUnchangedNonOIDCMaterial.
func validateUnchangedNonTSAMaterial(currentPath, nextPath string) error {
	current, err := collectGenerationFileHashes(currentPath)
	if err != nil {
		return err
	}
	next, err := collectGenerationFileHashes(nextPath)
	if err != nil {
		return err
	}
	for path, hash := range current {
		if strings.HasPrefix(path, "private/tsa/") || strings.HasPrefix(path, "public/tsa/") {
			continue
		}
		if next[path] != hash {
			return fmt.Errorf("non-TSA generation material %q changed", path)
		}
	}
	for path := range next {
		if strings.HasPrefix(path, "private/tsa/") || strings.HasPrefix(path, "public/tsa/") {
			continue
		}
		if _, ok := current[path]; !ok {
			return fmt.Errorf("unexpected non-TSA generation material %q", path)
		}
	}
	return nil
}

// buildTsaRotationTargets computes the minimal set of TUF targets that must
// change to additively introduce the new timestamp authority: the three TSA
// certificate targets, the TrustedRoot (existing entries preserved, new
// authority appended), the rebuilt ClientTrustConfig, and trust_status.
// signing_config.v0.2.json and every non-TSA target are deliberately left
// out of this list so they remain byte-identical to the active publication.
func buildTsaRotationTargets(
	newGenerationPath string,
	bootstrap bootstrapManifest,
	activeTargetsPath string,
) ([]tufTarget, error) {
	newChainPEM, newCertificates, err := loadCertificateChain(
		filepath.Join(newGenerationPath, filepath.FromSlash(tsaChainRelPath)),
	)
	if err != nil {
		return nil, fmt.Errorf("load new TSA certificate chain: %w", err)
	}
	if len(newCertificates) != 2 {
		return nil, fmt.Errorf(
			"new TSA certificate chain must contain exactly a leaf and a root certificate, found %d",
			len(newCertificates),
		)
	}

	existingTrustedRootBytes, err := os.ReadFile(filepath.Join(activeTargetsPath, "trusted_root.json"))
	if err != nil {
		return nil, fmt.Errorf("read committed trusted_root.json: %w", err)
	}
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(existingTrustedRootBytes, trustedRoot); err != nil {
		return nil, fmt.Errorf("parse committed TrustedRoot: %w", err)
	}
	generation, err := readOIDCGenerationManifest(
		filepath.Dir(filepath.Dir(newGenerationPath)),
		filepath.Base(newGenerationPath),
	)
	if err != nil {
		return nil, fmt.Errorf("read TSA generation manifest for trust update: %w", err)
	}
	seenAuthorities := map[string]bool{}
	foundPrior := false
	for _, authority := range trustedRoot.TimestampAuthorities {
		if authority.GetUri() != tsaURL {
			return nil, fmt.Errorf(
				"committed TrustedRoot timestamp-authority URI %q does not match %q",
				authority.GetUri(),
				tsaURL,
			)
		}
		rootHash, leafHash, err := timestampAuthorityFingerprints(authority)
		if err != nil {
			return nil, fmt.Errorf("validate existing timestamp authority: %w", err)
		}
		identity := rootHash + "/" + leafHash
		if seenAuthorities[identity] {
			return nil, errors.New("committed TrustedRoot contains duplicate timestamp authorities")
		}
		seenAuthorities[identity] = true
		if rootHash == generation.TSAPriorRootSHA256 &&
			leafHash == generation.TSAPriorLeafSHA256 {
			foundPrior = true
		}
		if rootHash == bootstrap.TsaRootSHA256 &&
			leafHash == bootstrap.TsaLeafSHA256 {
			return nil, errors.New("committed TrustedRoot already contains the candidate timestamp authority")
		}
	}
	if !foundPrior {
		return nil, errors.New("committed TrustedRoot omits the active prior timestamp authority")
	}
	trustedRoot.TimestampAuthorities = append(
		trustedRoot.TimestampAuthorities,
		newTimestampAuthority(tsaURL, newCertificates),
	)

	signingConfigBytes, err := os.ReadFile(filepath.Join(activeTargetsPath, "signing_config.v0.2.json"))
	if err != nil {
		return nil, fmt.Errorf("read committed signing_config.v0.2.json: %w", err)
	}
	signingConfig := &trustrootv1.SigningConfig{}
	if err := protojson.Unmarshal(signingConfigBytes, signingConfig); err != nil {
		return nil, fmt.Errorf("parse committed SigningConfig: %w", err)
	}

	trustedRootJSON, err := protojson.Marshal(trustedRoot)
	if err != nil {
		return nil, fmt.Errorf("marshal TrustedRoot: %w", err)
	}
	trustedRootBytes := append(trustedRootJSON, '\n')

	clientTrustConfig := &trustrootv1.ClientTrustConfig{
		MediaType:     clientTrustConfigMediaType,
		TrustedRoot:   trustedRoot,
		SigningConfig: signingConfig,
	}
	clientTrustConfigJSON, err := protojson.Marshal(clientTrustConfig)
	if err != nil {
		return nil, fmt.Errorf("marshal ClientTrustConfig: %w", err)
	}
	clientTrustConfigBytes := append(clientTrustConfigJSON, '\n')

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
		return nil, fmt.Errorf("marshal trust status: %w", err)
	}
	statusBytes := append(statusJSON, '\n')

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCertificates[0].Raw})
	rootPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCertificates[len(newCertificates)-1].Raw,
	})

	return []tufTarget{
		{name: "tsa.certchain.pem", data: newChainPEM, custom: targetMetadata("TSA", tsaURL)},
		{name: "tsa_leaf.crt.pem", data: leafPEM, custom: targetMetadata("TSA", tsaURL)},
		{name: "tsa_root.crt.pem", data: rootPEM, custom: targetMetadata("TSA", tsaURL)},
		{name: "trusted_root.json", data: trustedRootBytes},
		{name: "client_trust_config.json", data: clientTrustConfigBytes},
		{name: trustStatusTargetName, data: statusBytes},
	}, nil
}

// publishTsaRotationUpdate publishes the additive TUF update that introduces
// the new timestamp authority while preserving every other target byte for
// byte, using the same preparing -> candidate-committed -> active-switched
// -> history transaction the rest of the repository publication code uses.
func publishTsaRotationUpdate(
	statePath string,
	oldBootstrap, newBootstrap bootstrapManifest,
	hooks publicationHooks,
) error {
	oldFingerprint, err := fingerprintSource(oldBootstrap)
	if err != nil {
		return fmt.Errorf("compute old source fingerprint: %w", err)
	}
	newFingerprint, err := fingerprintSource(newBootstrap)
	if err != nil {
		return fmt.Errorf("compute new source fingerprint: %w", err)
	}

	layout := newTUFLayout(statePath)
	if err := ensureTUFLayout(layout); err != nil {
		return err
	}
	state, err := loadPublicationState(layout)
	if err != nil {
		return fmt.Errorf("load TUF publication state: %w", err)
	}
	if state.Status != publicationStatusCommitted {
		return fmt.Errorf(
			"TSA rotation requires a committed TUF publication, found status %q",
			state.Status,
		)
	}
	if state.Active == nil {
		return errors.New("no active TUF publication exists for TSA rotation")
	}
	if err := cleanupPublicationTemps(layout); err != nil {
		return err
	}
	if err := cleanupUnjournaledCandidate(layout); err != nil {
		return err
	}

	activePath := committedPath(layout, state.Active.ID)
	if _, _, err := validateExistingRepository(activePath, oldFingerprint); err != nil {
		return fmt.Errorf("validate active publication before TSA rotation: %w", err)
	}

	if err := os.Mkdir(layout.candidate, 0o755); err != nil {
		return fmt.Errorf("create TSA rotation candidate directory: %w", err)
	}
	if err := copyDirectory(activePath, layout.candidate); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("copy active publication into TSA rotation candidate: %w", err)
	}

	newGenerationPath := filepath.Join(statePath, "generations", newBootstrap.GenerationID)
	targets, err := buildTsaRotationTargets(
		newGenerationPath,
		newBootstrap,
		filepath.Join(activePath, "targets"),
	)
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return err
	}
	if err := replaceTargetsInRepository(layout.candidate, targets, newBootstrap); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("replace TSA rotation targets: %w", err)
	}

	manifest := tufManifest{
		SchemaVersion:     tufSchemaVersion,
		CreatedAtUTC:      time.Now().UTC(),
		UpdatedAtUTC:      time.Now().UTC(),
		SourceFingerprint: newFingerprint,
	}
	if err := writeRepositoryManifest(layout.candidate, manifest); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("write TSA rotation candidate manifest: %w", err)
	}

	candidate, err := repositoryReference(layout.candidate, newFingerprint)
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("compute TSA rotation candidate reference: %w", err)
	}
	if candidate.ID == state.Active.ID {
		_ = os.RemoveAll(layout.candidate)
		return errors.New("TSA rotation candidate is identical to the active publication")
	}
	if pathExists(committedPath(layout, candidate.ID)) {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("TSA rotation candidate %s is already committed", candidate.ID)
	}

	preparing := state
	preparing.Status = publicationStatusPreparing
	preparing.UpdatedAtUTC = time.Now().UTC()
	preparing.Candidate = &candidate
	if err := writePublicationState(layout, preparing); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return err
	}
	if err := runCheckpoint(hooks, checkpointCandidatePrepared); err != nil {
		return rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}

	if state.Previous != nil {
		if err := os.Rename(layout.previous, layout.retiredPrevious); err != nil {
			return rollbackPreparingPublication(
				layout,
				preparing,
				oldFingerprint,
				fmt.Errorf("park previous publication: %w", err),
			)
		}
	}
	if err := runCheckpoint(hooks, checkpointHistoryParked); err != nil {
		return rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}

	candidatePath := committedPath(layout, candidate.ID)
	if err := os.Rename(layout.candidate, candidatePath); err != nil {
		return rollbackPreparingPublication(
			layout,
			preparing,
			oldFingerprint,
			fmt.Errorf("commit TSA rotation candidate: %w", err),
		)
	}
	if err := runCheckpoint(hooks, checkpointCandidateCommitted); err != nil {
		return rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}

	if err := switchActivePublication(layout, candidate.ID, hooks); err != nil {
		return rollbackPreparingPublication(layout, preparing, oldFingerprint, err)
	}
	if err := runCheckpoint(hooks, checkpointActiveSwitched); err != nil {
		return err
	}

	return finalizePublishPublication(layout, preparing, oldFingerprint, newFingerprint, hooks)
}

func loadTsaRotationCompletion(statePath string) (*tsaRotationCompletion, error) {
	completionPath := filepath.Join(statePath, tsaRotationCompletionFile)
	data, err := os.ReadFile(completionPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read TSA rotation completion: %w", err)
	}
	var completion tsaRotationCompletion
	if err := json.Unmarshal(data, &completion); err != nil {
		return nil, fmt.Errorf("parse TSA rotation completion: %w", err)
	}
	if completion.SchemaVersion != tsaRotationCompletionSchema {
		return nil, fmt.Errorf(
			"TSA rotation completion schema %d is unsupported; expected %d",
			completion.SchemaVersion,
			tsaRotationCompletionSchema,
		)
	}
	if !tsaOperationIDPattern.MatchString(completion.OperationID) ||
		completion.TrustDomainID == "" ||
		completion.NewGeneration != completion.PriorGeneration+1 ||
		completion.PriorGenerationID != fmt.Sprintf("generation-%08d", completion.PriorGeneration) ||
		completion.NewGenerationID != fmt.Sprintf("generation-%08d", completion.NewGeneration) ||
		validateSHA256(completion.PriorTsaRootSHA256) != nil ||
		validateSHA256(completion.PriorTsaLeafSHA256) != nil ||
		validateSHA256(completion.NewTsaRootSHA256) != nil ||
		validateSHA256(completion.NewTsaLeafSHA256) != nil ||
		completion.PriorTsaRootSHA256 == completion.NewTsaRootSHA256 ||
		completion.PriorTsaLeafSHA256 == completion.NewTsaLeafSHA256 ||
		validateSHA256(completion.ManifestSHA256) != nil ||
		validateSHA256(completion.TrustedRootSHA256) != nil ||
		validateSHA256(completion.SigningConfigSHA256) != nil ||
		validateSHA256(completion.PublicationManifestSHA256) != nil ||
		completion.PublicationID == "" ||
		completion.TsaTrustEntryCount < 2 ||
		completion.CompletedAtUTC.IsZero() {
		return nil, errors.New("TSA rotation completion has malformed durable state")
	}
	return &completion, nil
}

func writeTsaRotationCompletion(statePath string, completion tsaRotationCompletion) error {
	data, err := json.MarshalIndent(completion, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal TSA rotation completion: %w", err)
	}
	data = append(data, '\n')
	return writeAtomicJSON(filepath.Join(statePath, tsaRotationCompletionFile), data)
}

// timestampAuthorityFingerprints returns the DER-hash of a TrustedRoot
// CertificateAuthority entry's leaf (first) and root (last) certificate,
// matching the [leaf, root] convention used throughout this file.
func timestampAuthorityFingerprints(
	authority *trustrootv1.CertificateAuthority,
) (rootHash, leafHash string, err error) {
	certificates := authority.GetCertChain().GetCertificates()
	if len(certificates) == 0 {
		return "", "", errors.New("TSA authority entry has no certificates")
	}
	leafHash = hashDER(certificates[0].GetRawBytes())
	rootHash = hashDER(certificates[len(certificates)-1].GetRawBytes())
	return rootHash, leafHash, nil
}

// validateTsaCompletionAgainstState strictly re-derives every field of a
// completion record from live disk state (trust domain, active generation,
// its manifest, the committed TUF publication, and its trusted_root.json)
// and rejects the completion if any binding does not hold exactly. This is
// what makes replaying a rotate-timestamp-authority.request against an
// already-completed operation safe and idempotent.
func validateTsaCompletionAgainstState(statePath string, completion *tsaRotationCompletion) error {
	domain, err := loadTrustDomain(statePath)
	if err != nil {
		return fmt.Errorf("load trust domain: %w", err)
	}
	if completion.TrustDomainID != domain.TrustDomainID {
		return fmt.Errorf(
			"completion trust domain %q does not match the active domain %q",
			completion.TrustDomainID,
			domain.TrustDomainID,
		)
	}

	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return fmt.Errorf("load active generation: %w", err)
	}
	if completion.NewGeneration != bootstrap.Generation ||
		completion.NewGenerationID != bootstrap.GenerationID {
		return errors.New("completion generation does not match the active generation")
	}
	if completion.ManifestSHA256 != bootstrap.GenerationManifestSHA256 {
		return errors.New("completion manifestSha256 does not match the active generation")
	}
	if completion.NewTsaRootSHA256 != bootstrap.TsaRootSHA256 ||
		completion.NewTsaLeafSHA256 != bootstrap.TsaLeafSHA256 {
		return errors.New("completion TSA chain does not match the active generation")
	}

	generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return fmt.Errorf("read active generation manifest: %w", err)
	}
	if generation.TSARotationOperationID != completion.OperationID ||
		generation.TSAPriorGeneration != completion.PriorGeneration ||
		generation.TSAPriorGenerationID != completion.PriorGenerationID ||
		generation.TSAPriorRootSHA256 != completion.PriorTsaRootSHA256 ||
		generation.TSAPriorLeafSHA256 != completion.PriorTsaLeafSHA256 {
		return errors.New("completion does not match the active generation's TSA rotation metadata")
	}

	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return fmt.Errorf("load TUF publication state: %w", err)
	}
	if publication.Status != publicationStatusCommitted ||
		publication.Active == nil ||
		publication.Active.ID != completion.PublicationID ||
		publication.Active.ManifestSHA256 != completion.PublicationManifestSHA256 {
		return errors.New("completion does not match the active TUF publication")
	}

	activeTargetsPath := filepath.Join(committedPath(layout, publication.Active.ID), "targets")
	statusData, err := os.ReadFile(filepath.Join(activeTargetsPath, trustStatusTargetName))
	if err != nil {
		return fmt.Errorf("read active trust status: %w", err)
	}
	var status trustStatusTarget
	if err := json.Unmarshal(statusData, &status); err != nil {
		return fmt.Errorf("parse active trust status: %w", err)
	}
	if status.TrustedRootSHA256 != completion.TrustedRootSHA256 ||
		status.SigningConfigSHA256 != completion.SigningConfigSHA256 {
		return errors.New("completion trust-status hashes do not match the active publication")
	}
	if status.TrustDomainID != completion.TrustDomainID ||
		status.Generation != completion.NewGeneration ||
		status.GenerationID != completion.NewGenerationID ||
		status.GenerationManifestSHA256 != completion.ManifestSHA256 {
		return errors.New("completion trust status does not match the active generation")
	}

	trustedRootData, err := os.ReadFile(filepath.Join(activeTargetsPath, "trusted_root.json"))
	if err != nil {
		return fmt.Errorf("read active trusted_root.json: %w", err)
	}
	if hashBytes(trustedRootData) != completion.TrustedRootSHA256 {
		return errors.New("completion trustedRootSha256 does not match the active trusted_root.json")
	}
	signingConfigData, err := os.ReadFile(
		filepath.Join(activeTargetsPath, "signing_config.v0.2.json"),
	)
	if err != nil {
		return fmt.Errorf("read active signing_config.v0.2.json: %w", err)
	}
	if hashBytes(signingConfigData) != completion.SigningConfigSHA256 {
		return errors.New(
			"completion signingConfigSha256 does not match the active signing_config.v0.2.json",
		)
	}
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(trustedRootData, trustedRoot); err != nil {
		return fmt.Errorf("parse active trusted_root.json: %w", err)
	}
	if len(trustedRoot.TimestampAuthorities) != completion.TsaTrustEntryCount {
		return fmt.Errorf(
			"completion tsaTrustEntryCount %d does not match the active trusted_root.json (%d entries)",
			completion.TsaTrustEntryCount,
			len(trustedRoot.TimestampAuthorities),
		)
	}
	foundOld, foundNew := false, false
	for _, authority := range trustedRoot.TimestampAuthorities {
		rootHash, leafHash, err := timestampAuthorityFingerprints(authority)
		if err != nil {
			return err
		}
		if rootHash == completion.PriorTsaRootSHA256 && leafHash == completion.PriorTsaLeafSHA256 {
			foundOld = true
		}
		if rootHash == completion.NewTsaRootSHA256 && leafHash == completion.NewTsaLeafSHA256 {
			foundNew = true
		}
	}
	if !foundOld {
		return errors.New(
			"completion prior TSA authority is missing from the active trusted_root.json",
		)
	}
	if !foundNew {
		return errors.New(
			"completion new TSA authority is missing from the active trusted_root.json",
		)
	}
	return nil
}

// finalizeTsaRotationCompletion writes the durable completion record for a
// TSA rotation that has just switched its generation and TUF publication,
// then removes the operation's private candidate material (the encrypted
// signer key and its password) since it has now been fully consumed into
// the new generation. The rest of the operation directory (including the
// candidate's public certificates) is left in place as the operation
// journal.
func finalizeTsaRotationCompletion(
	statePath string,
	request tsaRotationRequest,
	bootstrap bootstrapManifest,
) error {
	generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return fmt.Errorf("read rotated generation for completion: %w", err)
	}
	if generation.TSARotationOperationID != request.OperationID {
		return errors.New("rotated generation operation ID does not match the completion request")
	}

	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return fmt.Errorf("load final TUF publication for completion: %w", err)
	}
	if publication.Status != publicationStatusCommitted || publication.Active == nil {
		return errors.New("TSA rotation has no committed active TUF publication")
	}

	activeTargetsPath := filepath.Join(committedPath(layout, publication.Active.ID), "targets")
	statusData, err := os.ReadFile(filepath.Join(activeTargetsPath, trustStatusTargetName))
	if err != nil {
		return fmt.Errorf("read active trust status for completion: %w", err)
	}
	var status trustStatusTarget
	if err := json.Unmarshal(statusData, &status); err != nil {
		return fmt.Errorf("parse active trust status for completion: %w", err)
	}

	trustedRootData, err := os.ReadFile(filepath.Join(activeTargetsPath, "trusted_root.json"))
	if err != nil {
		return fmt.Errorf("read active trusted_root.json for completion: %w", err)
	}
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(trustedRootData, trustedRoot); err != nil {
		return fmt.Errorf("parse active trusted_root.json for completion: %w", err)
	}

	completion := tsaRotationCompletion{
		SchemaVersion:             tsaRotationCompletionSchema,
		OperationID:               request.OperationID,
		TrustDomainID:             request.TrustDomainID,
		PriorGeneration:           request.StartingGeneration,
		PriorGenerationID:         request.StartingGenerationID,
		PriorTsaRootSHA256:        generation.TSAPriorRootSHA256,
		PriorTsaLeafSHA256:        generation.TSAPriorLeafSHA256,
		NewGeneration:             bootstrap.Generation,
		NewGenerationID:           bootstrap.GenerationID,
		NewTsaRootSHA256:          bootstrap.TsaRootSHA256,
		NewTsaLeafSHA256:          bootstrap.TsaLeafSHA256,
		ManifestSHA256:            bootstrap.GenerationManifestSHA256,
		PublicationID:             publication.Active.ID,
		PublicationManifestSHA256: publication.Active.ManifestSHA256,
		TrustedRootSHA256:         status.TrustedRootSHA256,
		SigningConfigSHA256:       status.SigningConfigSHA256,
		TsaTrustEntryCount:        len(trustedRoot.TimestampAuthorities),
		CompletedAtUTC:            time.Now().UTC(),
	}
	if err := writeTsaRotationCompletion(statePath, completion); err != nil {
		return err
	}

	return removeTsaOperationPrivateCandidate(statePath, request.OperationID)
}

func removeTsaOperationPrivateCandidate(statePath, operationID string) error {
	candidatePrivatePath := filepath.Join(
		statePath,
		tsaRotationDirectory,
		operationID,
		"candidate",
		"private",
	)
	if err := os.RemoveAll(candidatePrivatePath); err != nil {
		return fmt.Errorf("remove completed TSA operation private candidate material: %w", err)
	}
	return nil
}

// recoverCommittedTSARotation forward-completes a TSA rotation whose
// generation and TUF publication both committed but whose active-generation
// symlink switch had not yet happened when the process previously crashed,
// mirroring recoverCommittedOIDCRotation for OIDC rotations.
func recoverCommittedTSARotation(statePath string, request tsaRotationRequest) error {
	journalPath := filepath.Join(statePath, "transition", "state.json")
	journalData, err := os.ReadFile(journalPath)
	if err != nil {
		return fmt.Errorf("read trust transition journal: %w", err)
	}
	var journal trustTransitionJournal
	if err := json.Unmarshal(journalData, &journal); err != nil {
		return fmt.Errorf("parse trust transition journal: %w", err)
	}
	if journal.Operation != "tsa-rotation" ||
		journal.TransitionID != request.OperationID ||
		journal.Status != "staged" {
		return nil
	}
	expectedGenerationID := fmt.Sprintf("generation-%08d", request.StartingGeneration+1)
	if journal.Candidate.Generation != request.StartingGeneration+1 ||
		journal.Candidate.GenerationID != expectedGenerationID ||
		journal.PriorGeneration == nil ||
		journal.PriorGeneration.Generation != request.StartingGeneration ||
		journal.PriorGeneration.GenerationID != request.StartingGenerationID ||
		journal.CandidateManifest.TSARotationOperationID != request.OperationID {
		return errors.New("staged TSA transition does not match its rotation request")
	}

	generationPath := filepath.Join(statePath, "generations", journal.Candidate.GenerationID)
	manifestData, err := os.ReadFile(filepath.Join(generationPath, "manifest.json"))
	if err != nil {
		return fmt.Errorf("read staged TSA generation manifest: %w", err)
	}
	if hashBytes(manifestData) != journal.Candidate.ManifestSHA256 {
		return errors.New("staged TSA transition manifest hash does not match its generation")
	}
	if err := validateTSAGenerationMaterial(generationPath, journal.CandidateManifest); err != nil {
		return fmt.Errorf("validate staged TSA generation: %w", err)
	}

	nextBootstrap := bootstrapManifest{
		SchemaVersion:            4,
		CreatedAtUTC:             journal.CandidateManifest.CreatedAtUTC,
		FulcioRootSHA256:         journal.CandidateManifest.FulcioRootSHA256,
		CtLogPublicKeySHA256:     journal.CandidateManifest.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:     journal.CandidateManifest.RekorPublicKeySHA256,
		TsaRootSHA256:            journal.CandidateManifest.TsaRootSHA256,
		TsaLeafSHA256:            journal.CandidateManifest.TsaLeafSHA256,
		OIDCKeyID:                journal.CandidateManifest.OIDCKeyID,
		TrustDomainID:            journal.CandidateManifest.TrustDomainID,
		Generation:               journal.Candidate.Generation,
		GenerationID:             journal.Candidate.GenerationID,
		GenerationManifestSHA256: journal.Candidate.ManifestSHA256,
	}
	fingerprint, err := fingerprintSource(nextBootstrap)
	if err != nil {
		return fmt.Errorf("compute staged TSA generation fingerprint: %w", err)
	}

	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return fmt.Errorf("load TUF publication state: %w", err)
	}
	if publication.Status != publicationStatusCommitted || publication.Active == nil {
		return errors.New("staged TSA transition lacks a committed TUF publication")
	}
	if err := validateReference(
		committedPath(layout, publication.Active.ID),
		*publication.Active,
		fingerprint,
	); err != nil {
		return fmt.Errorf("validate staged TSA TUF publication: %w", err)
	}

	activeID, err := readActiveGeneration(filepath.Join(statePath, "active-generation"))
	if err != nil {
		return err
	}
	switch activeID {
	case request.StartingGenerationID:
		activeLink := filepath.Join(statePath, "active-generation")
		nextLink := filepath.Join(statePath, "active-generation.next")
		if pathExists(nextLink) {
			if err := os.Remove(nextLink); err != nil {
				return err
			}
		}
		target := filepath.Join("generations", journal.Candidate.GenerationID)
		if err := os.Symlink(target, nextLink); err != nil {
			return err
		}
		if err := os.Rename(nextLink, activeLink); err != nil {
			return err
		}
	case journal.Candidate.GenerationID:
	default:
		return fmt.Errorf("staged TSA transition has unexpected active generation %q", activeID)
	}

	journal.Status = "recovered"
	journal.LastCheckpoint = "transition-finalized"
	journal.UpdatedAtUTC = time.Now().UTC()
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicJSON(journalPath, append(data, '\n'))
}
