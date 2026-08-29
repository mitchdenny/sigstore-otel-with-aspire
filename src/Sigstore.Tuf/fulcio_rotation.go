package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
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
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	fulcioRotationRequestFile      = "rotate-fulcio-ca.request"
	fulcioRotationCompletionFile   = "rotate-fulcio-ca.completed"
	fulcioRotationDirectory        = "fulcio-rotation"
	fulcioRotationSchemaVersion    = 1
	fulcioRotationCompletionSchema = 1

	fulcioRootKeyRelPath  = "private/fulcio/root.key"
	fulcioPasswordRelPath = "private/fulcio/password"
	fulcioRootCertRelPath = "public/fulcio/root.pem"

	fulcioTargetName = "fulcio_v1.crt.pem"
)

// fulcioOperationIDPattern matches the 32-character lowercase hexadecimal
// operation identifier that binds a Fulcio CA rotation request, its staged
// candidate material, the resulting generation, and its completion record.
var fulcioOperationIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// fulcioSubjectKeyIDOID is the id-ce-subjectKeyIdentifier extension OID
// (2.5.29.14), used to confirm the certificate authority carries a subject
// key identifier exactly as the C# host's Fulcio profile emits it.
var fulcioSubjectKeyIDOID = asn1.ObjectIdentifier{2, 5, 29, 14}

// fulcioRotationRequest is the strict, operation-bound request written by the
// C# host asking the Go worker to promote already-generated, already
// validated candidate Fulcio certificate-authority material into a new trust
// generation. All fields are mandatory; the candidate material itself lives
// under fulcio-rotation/<operationId>/candidate/ and is independently
// re-validated in Go before it is trusted.
type fulcioRotationRequest struct {
	SchemaVersion             int    `json:"schemaVersion"`
	OperationID               string `json:"operationId"`
	TrustDomainID             string `json:"trustDomainId"`
	StartingGeneration        int    `json:"startingGeneration"`
	StartingGenerationID      string `json:"startingGenerationId"`
	StartingFulcioRootSHA256  string `json:"startingFulcioRootSha256"`
	CandidateFulcioRootSHA256 string `json:"candidateFulcioRootSha256"`
}

// fulcioRotationCompletion is the durable, schema-versioned record written
// once a Fulcio CA rotation has fully committed: the new generation is
// active, the TUF repository additively carries both the prior and the new
// certificate authority, the Tesseract accepted-root bundle spans both, and
// the new CA is staged — but deliberately NOT activated — for Fulcio. It
// captures enough live-state fingerprints that a replayed request is strictly
// re-derived from disk rather than trusted blindly, including the
// pre-activation runtime condition: the active Fulcio projection must still
// serve the prior root while the staged projection carries the new one.
type fulcioRotationCompletion struct {
	SchemaVersion                 int       `json:"schemaVersion"`
	OperationID                   string    `json:"operationId"`
	TrustDomainID                 string    `json:"trustDomainId"`
	CompletedAtUTC                time.Time `json:"completedAtUtc"`
	PriorGeneration               int       `json:"priorGeneration"`
	PriorGenerationID             string    `json:"priorGenerationId"`
	PriorFulcioRootSHA256         string    `json:"priorFulcioRootSha256"`
	NewGeneration                 int       `json:"newGeneration"`
	NewGenerationID               string    `json:"newGenerationId"`
	NewFulcioRootSHA256           string    `json:"newFulcioRootSha256"`
	ManifestSHA256                string    `json:"manifestSha256"`
	PublicationID                 string    `json:"publicationId"`
	PublicationManifestSHA256     string    `json:"publicationManifestSha256"`
	TrustedRootSHA256             string    `json:"trustedRootSha256"`
	SigningConfigSHA256           string    `json:"signingConfigSha256"`
	FulcioTrustEntryCount         int       `json:"fulcioTrustEntryCount"`
	AcceptedRootsSHA256           string    `json:"acceptedRootsSha256"`
	AcceptedRootFingerprints      []string  `json:"acceptedRootFingerprints"`
	ActiveFulcioRuntimeRootSHA256 string    `json:"activeFulcioRuntimeRootSha256"`
	StagedFulcioRuntimeRootSHA256 string    `json:"stagedFulcioRuntimeRootSha256"`
}

// dispatchFulcioRotation is the entry point invoked from main() when a
// rotate-fulcio-ca.request file is present.
func dispatchFulcioRotation(statePath string) (repositoryAction, error) {
	return dispatchFulcioRotationWithHooks(statePath, publicationHooks{})
}

func dispatchFulcioRotationWithHooks(
	statePath string,
	hooks publicationHooks,
) (repositoryAction, error) {
	requestPath := filepath.Join(statePath, fulcioRotationRequestFile)
	requestData, err := os.ReadFile(requestPath)
	if err != nil {
		return "", fmt.Errorf("read Fulcio rotation request: %w", err)
	}
	var request fulcioRotationRequest
	if err := json.Unmarshal(requestData, &request); err != nil {
		return "", fmt.Errorf("parse Fulcio rotation request: %w", err)
	}
	if err := validateFulcioRotationRequest(request); err != nil {
		return "", fmt.Errorf("invalid Fulcio rotation request: %w", err)
	}

	lock, err := acquireStateLock(statePath, 30*time.Second, "fulcio-rotation-dispatch")
	if err != nil {
		return "", err
	}
	defer lock.release()

	domain, err := loadTrustDomain(statePath)
	if err != nil {
		return "", fmt.Errorf("load trust domain for Fulcio rotation: %w", err)
	}
	if request.TrustDomainID != domain.TrustDomainID {
		return "", fmt.Errorf(
			"Fulcio rotation request trust domain %q does not match the immutable domain %q",
			request.TrustDomainID,
			domain.TrustDomainID,
		)
	}

	completion, err := loadFulcioRotationCompletion(statePath)
	if err != nil {
		return "", fmt.Errorf("ambiguous Fulcio rotation completion state: %w", err)
	}
	if completion != nil && completion.OperationID == request.OperationID {
		if err := validateFulcioCompletionAgainstState(statePath, completion); err != nil {
			return "", fmt.Errorf("Fulcio rotation completion replay failed validation: %w", err)
		}
		if err := removeFulcioOperationPrivateCandidate(statePath, request.OperationID); err != nil {
			return "", err
		}
		if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("remove replayed Fulcio rotation request: %w", err)
		}
		return repositoryActionPublished, nil
	}

	if err := recoverCommittedFulcioRotation(statePath, request); err != nil {
		return "", fmt.Errorf("recover committed Fulcio rotation: %w", err)
	}
	if _, err := recoverTUFStateLocked(statePath, hooks); err != nil {
		return "", fmt.Errorf("recover TUF publication state for Fulcio rotation: %w", err)
	}

	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return "", fmt.Errorf("load active generation for Fulcio rotation: %w", err)
	}

	if bootstrap.Generation == request.StartingGeneration+1 {
		generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
		if err != nil {
			return "", fmt.Errorf("read active generation manifest: %w", err)
		}
		if generation.FulcioRotationOperationID != request.OperationID {
			return "", fmt.Errorf(
				"active generation %s belongs to Fulcio rotation %q, not %q",
				bootstrap.GenerationID,
				generation.FulcioRotationOperationID,
				request.OperationID,
			)
		}
		if err := validateFulcioRequestStartingState(request, generation); err != nil {
			return "", err
		}
		if err := finalizeFulcioRotationCompletion(statePath, request, bootstrap); err != nil {
			return "", err
		}
		if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("remove recovered Fulcio rotation request: %w", err)
		}
		return repositoryActionRecovered, nil
	}

	if bootstrap.Generation != request.StartingGeneration ||
		bootstrap.GenerationID != request.StartingGenerationID ||
		bootstrap.FulcioRootSHA256 != request.StartingFulcioRootSHA256 {
		return "", errors.New(
			"Fulcio rotation request does not match the currently active generation",
		)
	}
	if err := ensureFulcioRotationPreconditions(statePath, bootstrap); err != nil {
		return "", err
	}

	newBootstrap, err := rotateFulcioGeneration(statePath, bootstrap, request)
	if err != nil {
		return "", fmt.Errorf("rotate Fulcio generation: %w", err)
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("fulcio-generation-committed")); err != nil {
		return "", err
	}

	if err := publishFulcioRotationUpdate(statePath, bootstrap, newBootstrap, hooks); err != nil {
		return "", fmt.Errorf("publish Fulcio rotation TUF update: %w", err)
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("fulcio-tuf-committed")); err != nil {
		return "", err
	}

	if err := switchActiveGeneration(
		statePath,
		bootstrap,
		newBootstrap,
		newBootstrap.GenerationManifestSHA256,
	); err != nil {
		return "", fmt.Errorf("switch active generation for Fulcio rotation: %w", err)
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("fulcio-generation-switched")); err != nil {
		return "", err
	}

	if _, _, err := ensureFulcioRotationRuntimeProjection(
		statePath,
		request.StartingGenerationID,
	); err != nil {
		return "", fmt.Errorf("project Fulcio rotation runtime state: %w", err)
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("fulcio-runtime-projected")); err != nil {
		return "", err
	}

	if err := finalizeFulcioRotationCompletion(statePath, request, newBootstrap); err != nil {
		return "", err
	}
	if err := runCheckpoint(hooks, publicationCheckpoint("fulcio-completion-written")); err != nil {
		return "", err
	}

	if err := os.Remove(requestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("remove Fulcio rotation request file: %w", err)
	}

	return repositoryActionPublished, nil
}

func validateFulcioRotationRequest(request fulcioRotationRequest) error {
	if request.SchemaVersion != fulcioRotationSchemaVersion {
		return fmt.Errorf(
			"Fulcio rotation request schema %d is unsupported; expected %d",
			request.SchemaVersion,
			fulcioRotationSchemaVersion,
		)
	}
	if !fulcioOperationIDPattern.MatchString(request.OperationID) {
		return errors.New("Fulcio rotation operationId must be 32 lowercase hexadecimal characters")
	}
	if request.TrustDomainID == "" {
		return errors.New("Fulcio rotation request is missing trustDomainId")
	}
	if request.StartingGeneration < initialGeneration ||
		request.StartingGenerationID != fmt.Sprintf("generation-%08d", request.StartingGeneration) {
		return errors.New("Fulcio rotation request has an invalid starting generation")
	}
	if validateSHA256(request.StartingFulcioRootSHA256) != nil ||
		validateSHA256(request.CandidateFulcioRootSHA256) != nil {
		return errors.New("Fulcio rotation request has malformed certificate fingerprints")
	}
	if request.StartingFulcioRootSHA256 == request.CandidateFulcioRootSHA256 {
		return errors.New("Fulcio rotation request candidate does not change the certificate authority")
	}
	return nil
}

// ensureFulcioRotationPreconditions refuses to begin a new rotation unless the
// component-scoped runtime projection is in its steady state: Fulcio is
// serving exactly the active generation's CA and no earlier rotation is still
// awaiting Hosting promotion. Starting a second rotation on top of a pending
// promotion would strand the un-promoted candidate and make the "which CA is
// live?" question ambiguous.
func ensureFulcioRotationPreconditions(
	statePath string,
	bootstrap bootstrapManifest,
) error {
	fulcioPath := runtimeComponentPath(statePath, runtimeFulcioComponent)
	if !pathExists(fulcioPath) {
		return fmt.Errorf(
			"Fulcio rotation requires an existing runtime projection at %q",
			fulcioPath,
		)
	}
	if pathExists(runtimeComponentPath(statePath, runtimeFulcioNextComponent)) {
		return errors.New(
			"a previous Fulcio rotation is still awaiting runtime promotion",
		)
	}
	matches, err := runtimeComponentMatches(
		fulcioPath,
		fulcioRuntimeSources(generationPathFor(statePath, bootstrap.GenerationID)),
	)
	if err != nil {
		return err
	}
	if !matches {
		return errors.New(
			"the Fulcio runtime projection does not serve the active generation",
		)
	}
	return nil
}

func validateFulcioRequestStartingState(
	request fulcioRotationRequest,
	generation generationManifest,
) error {
	if generation.TrustDomainID != request.TrustDomainID ||
		generation.FulcioPriorGeneration != request.StartingGeneration ||
		generation.FulcioPriorGenerationID != request.StartingGenerationID ||
		generation.FulcioPriorRootSHA256 != request.StartingFulcioRootSHA256 ||
		generation.FulcioRootSHA256 != request.CandidateFulcioRootSHA256 {
		return errors.New(
			"active Fulcio generation does not match the starting state of the rotation request",
		)
	}
	return nil
}

// rotateFulcioGeneration produces (or reuses) the immutable generation N+1
// whose only difference from generation N is a wholesale replacement of the
// private/fulcio and public/fulcio subtrees with the pre-validated candidate
// material the C# host placed under fulcio-rotation/<operationId>/candidate/.
// All other rotation provenance (OIDC, TSA) is carried forward verbatim so a
// later generation never appears to un-rotate an earlier component.
func rotateFulcioGeneration(
	statePath string,
	current bootstrapManifest,
	request fulcioRotationRequest,
) (bootstrapManifest, error) {
	newGeneration := current.Generation + 1
	newGenerationID := fmt.Sprintf("generation-%08d", newGeneration)
	currentGenerationPath := filepath.Join(statePath, "generations", current.GenerationID)
	newGenerationPath := filepath.Join(statePath, "generations", newGenerationID)
	currentManifest, err := readOIDCGenerationManifest(statePath, current.GenerationID)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf(
			"read current generation manifest for Fulcio rotation: %w",
			err,
		)
	}

	if pathExists(newGenerationPath) {
		return validateAndReuseFulcioGeneration(
			statePath,
			current,
			newGenerationPath,
			newGenerationID,
			newGeneration,
			request,
		)
	}

	candidatePath := filepath.Join(
		statePath,
		fulcioRotationDirectory,
		request.OperationID,
		"candidate",
	)
	if err := validateFulcioCandidateFileSet(candidatePath); err != nil {
		return bootstrapManifest{}, fmt.Errorf("validate Fulcio rotation candidate: %w", err)
	}
	candidateCert, err := loadSingleCertificate(
		filepath.Join(candidatePath, filepath.FromSlash(fulcioRootCertRelPath)),
	)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("load candidate Fulcio root certificate: %w", err)
	}
	if err := validateFulcioCertificateAuthority(candidateCert); err != nil {
		return bootstrapManifest{}, fmt.Errorf("validate candidate Fulcio root: %w", err)
	}
	candidateRootHash := hashDER(candidateCert.Raw)
	if candidateRootHash != request.CandidateFulcioRootSHA256 {
		return bootstrapManifest{}, errors.New(
			"candidate Fulcio material does not match the rotation request fingerprint",
		)
	}
	if candidateRootHash == current.FulcioRootSHA256 {
		return bootstrapManifest{}, errors.New(
			"candidate Fulcio material does not change the currently active certificate authority",
		)
	}
	candidatePassword, err := os.ReadFile(
		filepath.Join(candidatePath, filepath.FromSlash(fulcioPasswordRelPath)),
	)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("read candidate Fulcio password: %w", err)
	}
	candidateKey, err := loadEncryptedTSAKey(
		filepath.Join(candidatePath, filepath.FromSlash(fulcioRootKeyRelPath)),
		candidatePassword,
	)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("load candidate Fulcio root key: %w", err)
	}
	if err := ensureECDSAPublicKeyMatches(
		"candidate Fulcio root key",
		&candidateKey.PublicKey,
		candidateCert,
	); err != nil {
		return bootstrapManifest{}, err
	}

	stagingGenerationPath := filepath.Join(
		statePath,
		fulcioRotationDirectory,
		request.OperationID,
		newGenerationID+".staging",
	)
	if err := os.RemoveAll(stagingGenerationPath); err != nil {
		return bootstrapManifest{}, fmt.Errorf("clean Fulcio generation staging directory: %w", err)
	}
	if err := os.MkdirAll(stagingGenerationPath, 0o755); err != nil {
		return bootstrapManifest{}, fmt.Errorf("create Fulcio rotation staging directory: %w", err)
	}
	if err := copyDirectory(currentGenerationPath, stagingGenerationPath); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("copy prior generation material: %w", err)
	}
	if err := os.Remove(filepath.Join(stagingGenerationPath, "manifest.json")); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("remove copied generation manifest: %w", err)
	}
	if err := os.RemoveAll(filepath.Join(stagingGenerationPath, "private", "fulcio")); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("remove prior private Fulcio material: %w", err)
	}
	if err := os.RemoveAll(filepath.Join(stagingGenerationPath, "public", "fulcio")); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("remove prior public Fulcio material: %w", err)
	}
	if err := copyFulcioCandidateFiles(candidatePath, stagingGenerationPath); err != nil {
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
		FulcioRootSHA256:     candidateRootHash,
		CtLogPublicKeySHA256: current.CtLogPublicKeySHA256,
		RekorPublicKeySHA256: current.RekorPublicKeySHA256,
		TsaRootSHA256:        current.TsaRootSHA256,
		TsaLeafSHA256:        current.TsaLeafSHA256,
		OIDCKeyID:            current.OIDCKeyID,
		OIDCRetainedPrivateKeyPaths: append(
			[]string(nil),
			currentManifest.OIDCRetainedPrivateKeyPaths...,
		),
		TSARotationOperationID:    currentManifest.TSARotationOperationID,
		TSAPriorGeneration:        currentManifest.TSAPriorGeneration,
		TSAPriorGenerationID:      currentManifest.TSAPriorGenerationID,
		TSAPriorRootSHA256:        currentManifest.TSAPriorRootSHA256,
		TSAPriorLeafSHA256:        currentManifest.TSAPriorLeafSHA256,
		FulcioRotationOperationID: request.OperationID,
		FulcioPriorGeneration:     current.Generation,
		FulcioPriorGenerationID:   current.GenerationID,
		FulcioPriorRootSHA256:     current.FulcioRootSHA256,
		RekorRotationOperationID:  currentManifest.RekorRotationOperationID,
		RekorPriorGeneration:      currentManifest.RekorPriorGeneration,
		RekorPriorGenerationID:    currentManifest.RekorPriorGenerationID,
		RekorPriorPublicKeySHA256: currentManifest.RekorPriorPublicKeySHA256,
		RekorPriorShardID:         currentManifest.RekorPriorShardID,
		RekorPriorBaseURL:         currentManifest.RekorPriorBaseURL,
		RekorShardID:              currentManifest.RekorShardID,
		RekorBaseURL:              currentManifest.RekorBaseURL,
		Files:                     newFiles,
	}
	manifestBytes, err := json.MarshalIndent(genManifest, "", "  ")
	if err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("marshal Fulcio generation manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := writeGenerationManifest(
		filepath.Join(stagingGenerationPath, "manifest.json"),
		manifestBytes,
	); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("write Fulcio generation manifest: %w", err)
	}
	manifestHash := hashBytes(manifestBytes)

	if err := validateFulcioGenerationMaterial(stagingGenerationPath, genManifest); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, fmt.Errorf("validate new Fulcio generation: %w", err)
	}
	if err := validateUnchangedNonFulcioMaterial(
		currentGenerationPath,
		stagingGenerationPath,
	); err != nil {
		_ = os.RemoveAll(stagingGenerationPath)
		return bootstrapManifest{}, err
	}

	if err := os.Rename(stagingGenerationPath, newGenerationPath); err != nil {
		return bootstrapManifest{}, fmt.Errorf("commit new Fulcio generation: %w", err)
	}
	if err := syncDirectory(filepath.Dir(newGenerationPath)); err != nil {
		return bootstrapManifest{}, fmt.Errorf("sync committed Fulcio generation: %w", err)
	}

	return bootstrapManifest{
		SchemaVersion:            4,
		CreatedAtUTC:             now,
		FulcioRootSHA256:         candidateRootHash,
		CtLogPublicKeySHA256:     current.CtLogPublicKeySHA256,
		RekorPublicKeySHA256:     current.RekorPublicKeySHA256,
		TsaRootSHA256:            current.TsaRootSHA256,
		TsaLeafSHA256:            current.TsaLeafSHA256,
		OIDCKeyID:                current.OIDCKeyID,
		TrustDomainID:            current.TrustDomainID,
		Generation:               newGeneration,
		GenerationID:             newGenerationID,
		GenerationManifestSHA256: manifestHash,
	}, nil
}

// validateAndReuseFulcioGeneration validates a pre-existing generation N+1
// directory left behind by a crashed attempt and reuses it only when it is
// bound to exactly this rotation request and cryptographically valid.
func validateAndReuseFulcioGeneration(
	statePath string,
	current bootstrapManifest,
	newGenerationPath string,
	newGenerationID string,
	newGeneration int,
	request fulcioRotationRequest,
) (bootstrapManifest, error) {
	manifestPath := filepath.Join(newGenerationPath, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("read pre-existing Fulcio generation manifest: %w", err)
	}
	var genManifest generationManifest
	if err := json.Unmarshal(manifestBytes, &genManifest); err != nil {
		return bootstrapManifest{}, fmt.Errorf("parse pre-existing Fulcio generation manifest: %w", err)
	}
	if genManifest.SchemaVersion != trustStateSchemaVersion ||
		genManifest.Generation != newGeneration ||
		genManifest.GenerationID != newGenerationID ||
		genManifest.TrustDomainID != current.TrustDomainID {
		return bootstrapManifest{}, errors.New(
			"pre-existing Fulcio generation does not match the expected identity",
		)
	}
	if genManifest.FulcioRotationOperationID != request.OperationID ||
		genManifest.FulcioPriorGeneration != request.StartingGeneration ||
		genManifest.FulcioPriorGenerationID != request.StartingGenerationID ||
		genManifest.FulcioPriorRootSHA256 != request.StartingFulcioRootSHA256 ||
		genManifest.FulcioRootSHA256 != request.CandidateFulcioRootSHA256 {
		return bootstrapManifest{}, errors.New(
			"pre-existing Fulcio generation is not bound to this rotation request",
		)
	}

	actualFiles, err := collectGenerationFileHashes(newGenerationPath)
	if err != nil {
		return bootstrapManifest{}, err
	}
	if len(actualFiles) != len(genManifest.Files) {
		return bootstrapManifest{}, errors.New(
			"pre-existing Fulcio generation files do not match its manifest",
		)
	}
	for path, hash := range genManifest.Files {
		if actualFiles[path] != hash {
			return bootstrapManifest{}, fmt.Errorf(
				"pre-existing Fulcio generation file %q does not match its manifest",
				path,
			)
		}
	}

	if err := validateFulcioGenerationMaterial(newGenerationPath, genManifest); err != nil {
		return bootstrapManifest{}, fmt.Errorf("validate pre-existing Fulcio generation: %w", err)
	}
	currentGenerationPath := filepath.Join(statePath, "generations", current.GenerationID)
	if err := validateUnchangedNonFulcioMaterial(currentGenerationPath, newGenerationPath); err != nil {
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

func copyFulcioCandidateFiles(candidatePath, destGenerationPath string) error {
	for _, relative := range []string{
		fulcioRootKeyRelPath,
		fulcioPasswordRelPath,
		fulcioRootCertRelPath,
	} {
		relPath := filepath.FromSlash(relative)
		data, err := os.ReadFile(filepath.Join(candidatePath, relPath))
		if err != nil {
			return fmt.Errorf("read candidate Fulcio file %q: %w", relative, err)
		}
		destPath := filepath.Join(destGenerationPath, relPath)
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("create Fulcio directory for %q: %w", relative, err)
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(relative, "private/") {
			mode = 0o600
		}
		if err := os.WriteFile(destPath, data, mode); err != nil {
			return fmt.Errorf("write Fulcio file %q: %w", relative, err)
		}
	}
	return nil
}

// validateFulcioCandidateFileSet asserts that a Fulcio rotation candidate
// directory contains exactly the three files C# is contracted to produce: the
// encrypted root key, its password, and the root certificate. Anything extra
// is ambiguous material and is rejected rather than silently ignored.
func validateFulcioCandidateFileSet(candidatePath string) error {
	actual, err := collectGenerationFileHashes(candidatePath)
	if err != nil {
		return fmt.Errorf("hash candidate Fulcio material: %w", err)
	}
	expected := []string{
		fulcioRootKeyRelPath,
		fulcioPasswordRelPath,
		fulcioRootCertRelPath,
	}
	if len(actual) != len(expected) {
		return fmt.Errorf(
			"candidate Fulcio material has %d files; expected exactly %d",
			len(actual),
			len(expected),
		)
	}
	for _, path := range expected {
		if _, ok := actual[path]; !ok {
			return fmt.Errorf("candidate Fulcio material is missing %q", path)
		}
	}
	return nil
}

// validateFulcioCertificateAuthority re-implements, in Go, the same profile
// the C# host applies when it generates Fulcio material: a self-signed ECDSA
// P-256 / SHA-256 CA with critical basic constraints (no path-length
// constraint), exactly the critical
// digitalSignature|keyCertSign|cRLSign key usage, and a subject key
// identifier.
func validateFulcioCertificateAuthority(cert *x509.Certificate) error {
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return errors.New("Fulcio root certificate must be a CA with basic constraints")
	}
	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		return errors.New("Fulcio root certificate must not carry a path-length constraint")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature|
		x509.KeyUsageCertSign|
		x509.KeyUsageCRLSign {
		return errors.New(
			"Fulcio root certificate must carry exactly digital-signature, " +
				"certificate-signing, and CRL-signing key usages",
		)
	}
	if len(cert.ExtKeyUsage) != 0 || len(cert.UnknownExtKeyUsage) != 0 {
		return errors.New("Fulcio root certificate must not carry extended key usages")
	}
	if !extensionIsCritical(cert, tsaBasicConstraintsOID) ||
		!extensionIsCritical(cert, tsaKeyUsageOID) {
		return errors.New(
			"Fulcio basic-constraints and key-usage extensions must be critical",
		)
	}
	if len(cert.SubjectKeyId) == 0 || !certificateHasExtension(cert, fulcioSubjectKeyIDOID) {
		return errors.New("Fulcio root certificate must carry a subject key identifier")
	}
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve.Params().Name != "P-256" {
		return errors.New("Fulcio root certificate must use an ECDSA P-256 public key")
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return errors.New("Fulcio root certificate must be signed with ECDSA-SHA256")
	}
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return errors.New("Fulcio root certificate must be self-issued")
	}
	if !cert.NotBefore.Before(cert.NotAfter) {
		return errors.New("Fulcio root certificate validity window is invalid")
	}
	now := time.Now().UTC()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return errors.New("Fulcio root certificate is not currently valid")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("Fulcio root certificate is not validly self-signed: %w", err)
	}
	return nil
}

func certificateHasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// validateFulcioGenerationMaterial validates the private/fulcio and
// public/fulcio trees of an active or candidate generation directory: the
// file set is exactly the three contracted files, the certificate satisfies
// the full profile, the encrypted private key decrypts with the stored
// password and matches the certificate, and the manifest's Fulcio rotation
// metadata is internally consistent.
func validateFulcioGenerationMaterial(
	generationPath string,
	manifest generationManifest,
) error {
	rootCertPath := filepath.Join(generationPath, filepath.FromSlash(fulcioRootCertRelPath))
	rootKeyPath := filepath.Join(generationPath, filepath.FromSlash(fulcioRootKeyRelPath))
	passwordPath := filepath.Join(generationPath, filepath.FromSlash(fulcioPasswordRelPath))

	cert, err := loadSingleCertificate(rootCertPath)
	if err != nil {
		return fmt.Errorf("load Fulcio root certificate: %w", err)
	}
	if err := validateFulcioCertificateAuthority(cert); err != nil {
		return err
	}
	if hashDER(cert.Raw) != manifest.FulcioRootSHA256 {
		return errors.New("Fulcio root certificate hash does not match the generation manifest")
	}

	password, err := os.ReadFile(passwordPath)
	if err != nil {
		return fmt.Errorf("read Fulcio password: %w", err)
	}
	rootKey, err := loadEncryptedTSAKey(rootKeyPath, password)
	if err != nil {
		return fmt.Errorf("load Fulcio root key: %w", err)
	}
	if err := ensureECDSAPublicKeyMatches("active Fulcio root key", &rootKey.PublicKey, cert); err != nil {
		return err
	}

	expected := map[string]bool{
		fulcioRootKeyRelPath:  true,
		fulcioPasswordRelPath: true,
		fulcioRootCertRelPath: true,
	}
	for path := range manifest.Files {
		if strings.HasPrefix(path, "private/fulcio/") || strings.HasPrefix(path, "public/fulcio/") {
			if !expected[path] {
				return fmt.Errorf("unexpected Fulcio generation file %q", path)
			}
		}
	}
	for path := range expected {
		if _, ok := manifest.Files[path]; !ok {
			return fmt.Errorf("Fulcio generation is missing required file %q", path)
		}
	}

	if manifest.FulcioRotationOperationID == "" {
		if manifest.FulcioPriorGeneration != 0 ||
			manifest.FulcioPriorGenerationID != "" ||
			manifest.FulcioPriorRootSHA256 != "" {
			return errors.New("generation contains partial Fulcio rotation metadata")
		}
		return nil
	}
	if !fulcioOperationIDPattern.MatchString(manifest.FulcioRotationOperationID) ||
		manifest.FulcioPriorGeneration < initialGeneration ||
		manifest.FulcioPriorGeneration >= manifest.Generation ||
		manifest.FulcioPriorGenerationID != fmt.Sprintf("generation-%08d", manifest.FulcioPriorGeneration) ||
		validateSHA256(manifest.FulcioPriorRootSHA256) != nil ||
		manifest.FulcioPriorRootSHA256 == manifest.FulcioRootSHA256 {
		return errors.New("rotated generation has invalid Fulcio operation metadata")
	}
	return nil
}

// validateUnchangedNonFulcioMaterial asserts that everything outside
// private/fulcio/ and public/fulcio/ is preserved byte-for-byte across a
// rotation, mirroring validateUnchangedNonTSAMaterial.
func validateUnchangedNonFulcioMaterial(currentPath, nextPath string) error {
	current, err := collectGenerationFileHashes(currentPath)
	if err != nil {
		return err
	}
	next, err := collectGenerationFileHashes(nextPath)
	if err != nil {
		return err
	}
	for path, hash := range current {
		if strings.HasPrefix(path, "private/fulcio/") || strings.HasPrefix(path, "public/fulcio/") {
			continue
		}
		if next[path] != hash {
			return fmt.Errorf("non-Fulcio generation material %q changed", path)
		}
	}
	for path := range next {
		if strings.HasPrefix(path, "private/fulcio/") || strings.HasPrefix(path, "public/fulcio/") {
			continue
		}
		if _, ok := current[path]; !ok {
			return fmt.Errorf("unexpected non-Fulcio generation material %q", path)
		}
	}
	return nil
}

// fulcioTrustEntry describes one validated Fulcio CertificateAuthority entry
// read back from a committed TrustedRoot, in entry order.
type fulcioTrustEntry struct {
	certificate *x509.Certificate
	fingerprint string
}

// readFulcioTrustEntries validates and returns, in entry order, every Fulcio
// certificate authority carried by a TrustedRoot. Each entry must use the
// canonical Fulcio URL, carry exactly one parseable root certificate that
// satisfies the Fulcio CA profile, and have a fingerprint no other entry
// already claimed.
func readFulcioTrustEntries(trustedRoot *trustrootv1.TrustedRoot) ([]fulcioTrustEntry, error) {
	entries := make([]fulcioTrustEntry, 0, len(trustedRoot.CertificateAuthorities))
	seen := map[string]bool{}
	for _, authority := range trustedRoot.CertificateAuthorities {
		if authority.GetUri() != fulcioURL {
			return nil, fmt.Errorf(
				"committed TrustedRoot certificate-authority URI %q does not match %q",
				authority.GetUri(),
				fulcioURL,
			)
		}
		certificates := authority.GetCertChain().GetCertificates()
		if len(certificates) != 1 {
			return nil, fmt.Errorf(
				"Fulcio certificate-authority entry must contain exactly one root certificate, found %d",
				len(certificates),
			)
		}
		certificate, err := x509.ParseCertificate(certificates[0].GetRawBytes())
		if err != nil {
			return nil, fmt.Errorf("parse Fulcio certificate-authority entry: %w", err)
		}
		if err := validateFulcioCertificateAuthority(certificate); err != nil {
			return nil, fmt.Errorf("validate Fulcio certificate-authority entry: %w", err)
		}
		fingerprint := hashDER(certificate.Raw)
		if seen[fingerprint] {
			return nil, errors.New(
				"committed TrustedRoot contains duplicate Fulcio certificate authorities",
			)
		}
		seen[fingerprint] = true
		entries = append(entries, fulcioTrustEntry{
			certificate: certificate,
			fingerprint: fingerprint,
		})
	}
	if len(entries) == 0 {
		return nil, errors.New("committed TrustedRoot contains no Fulcio certificate authority")
	}
	return entries, nil
}

// buildFulcioRotationTargets computes the minimal set of TUF targets that
// must change to additively introduce the new Fulcio certificate authority:
// the active fulcio_v1.crt.pem target, the TrustedRoot (all existing entries
// preserved, the candidate appended), the rebuilt ClientTrustConfig, and
// trust_status. signing_config.v0.2.json and every non-Fulcio target are
// deliberately excluded so they stay byte-identical to the active
// publication.
func buildFulcioRotationTargets(
	newGenerationPath string,
	bootstrap bootstrapManifest,
	activeTargetsPath string,
) ([]tufTarget, error) {
	newRootPEM, err := os.ReadFile(
		filepath.Join(newGenerationPath, filepath.FromSlash(fulcioRootCertRelPath)),
	)
	if err != nil {
		return nil, fmt.Errorf("read new Fulcio root certificate: %w", err)
	}
	newCertificate, err := loadSingleCertificate(
		filepath.Join(newGenerationPath, filepath.FromSlash(fulcioRootCertRelPath)),
	)
	if err != nil {
		return nil, fmt.Errorf("load new Fulcio root certificate: %w", err)
	}
	if err := validateFulcioCertificateAuthority(newCertificate); err != nil {
		return nil, fmt.Errorf("validate new Fulcio root certificate: %w", err)
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
		return nil, fmt.Errorf("read Fulcio generation manifest for trust update: %w", err)
	}
	entries, err := readFulcioTrustEntries(trustedRoot)
	if err != nil {
		return nil, err
	}
	newFingerprint := hashDER(newCertificate.Raw)
	foundPrior := false
	for _, entry := range entries {
		if entry.fingerprint == generation.FulcioPriorRootSHA256 {
			foundPrior = true
		}
		if entry.fingerprint == newFingerprint {
			return nil, errors.New(
				"committed TrustedRoot already contains the candidate Fulcio certificate authority",
			)
		}
	}
	if !foundPrior {
		return nil, errors.New(
			"committed TrustedRoot omits the active prior Fulcio certificate authority",
		)
	}
	trustedRoot.CertificateAuthorities = append(
		trustedRoot.CertificateAuthorities,
		newCertificateAuthority(fulcioURL, newCertificate),
	)

	signingConfigBytes, err := os.ReadFile(filepath.Join(activeTargetsPath, "signing_config.v0.2.json"))
	if err != nil {
		return nil, fmt.Errorf("read committed signing_config.v0.2.json: %w", err)
	}
	signingConfig := &trustrootv1.SigningConfig{}
	if err := protojson.Unmarshal(signingConfigBytes, signingConfig); err != nil {
		return nil, fmt.Errorf("parse committed SigningConfig: %w", err)
	}

	trustedRootJSON, err := protoJSON.Marshal(trustedRoot)
	if err != nil {
		return nil, fmt.Errorf("marshal TrustedRoot: %w", err)
	}
	trustedRootBytes := append(trustedRootJSON, '\n')

	clientTrustConfig := &trustrootv1.ClientTrustConfig{
		MediaType:     clientTrustConfigMediaType,
		TrustedRoot:   trustedRoot,
		SigningConfig: signingConfig,
	}
	clientTrustConfigJSON, err := protoJSON.Marshal(clientTrustConfig)
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

	return []tufTarget{
		{name: fulcioTargetName, data: newRootPEM, custom: targetMetadata("Fulcio", fulcioURL)},
		{name: "trusted_root.json", data: trustedRootBytes},
		{name: "client_trust_config.json", data: clientTrustConfigBytes},
		{name: trustStatusTargetName, data: statusBytes},
	}, nil
}

// publishFulcioRotationUpdate publishes the additive TUF update that
// introduces the new certificate authority while preserving every other
// target byte for byte, using the same preparing -> candidate-committed ->
// active-switched -> history transaction the rest of the publication code
// uses.
func publishFulcioRotationUpdate(
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
			"Fulcio rotation requires a committed TUF publication, found status %q",
			state.Status,
		)
	}
	if state.Active == nil {
		return errors.New("no active TUF publication exists for Fulcio rotation")
	}
	if err := cleanupPublicationTemps(layout); err != nil {
		return err
	}
	if err := cleanupUnjournaledCandidate(layout); err != nil {
		return err
	}

	activePath := committedPath(layout, state.Active.ID)
	if _, _, err := validateExistingRepository(activePath, oldFingerprint); err != nil {
		return fmt.Errorf("validate active publication before Fulcio rotation: %w", err)
	}

	if err := os.Mkdir(layout.candidate, 0o755); err != nil {
		return fmt.Errorf("create Fulcio rotation candidate directory: %w", err)
	}
	if err := copyDirectory(activePath, layout.candidate); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("copy active publication into Fulcio rotation candidate: %w", err)
	}

	newGenerationPath := filepath.Join(statePath, "generations", newBootstrap.GenerationID)
	targets, err := buildFulcioRotationTargets(
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
		return fmt.Errorf("replace Fulcio rotation targets: %w", err)
	}

	manifest := tufManifest{
		SchemaVersion:     tufSchemaVersion,
		CreatedAtUTC:      time.Now().UTC(),
		UpdatedAtUTC:      time.Now().UTC(),
		SourceFingerprint: newFingerprint,
	}
	if err := writeRepositoryManifest(layout.candidate, manifest); err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("write Fulcio rotation candidate manifest: %w", err)
	}

	candidate, err := repositoryReference(layout.candidate, newFingerprint)
	if err != nil {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("compute Fulcio rotation candidate reference: %w", err)
	}
	if candidate.ID == state.Active.ID {
		_ = os.RemoveAll(layout.candidate)
		return errors.New("Fulcio rotation candidate is identical to the active publication")
	}
	if pathExists(committedPath(layout, candidate.ID)) {
		_ = os.RemoveAll(layout.candidate)
		return fmt.Errorf("Fulcio rotation candidate %s is already committed", candidate.ID)
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
			fmt.Errorf("commit Fulcio rotation candidate: %w", err),
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

func loadFulcioRotationCompletion(statePath string) (*fulcioRotationCompletion, error) {
	completionPath := filepath.Join(statePath, fulcioRotationCompletionFile)
	data, err := os.ReadFile(completionPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Fulcio rotation completion: %w", err)
	}
	var completion fulcioRotationCompletion
	if err := json.Unmarshal(data, &completion); err != nil {
		return nil, fmt.Errorf("parse Fulcio rotation completion: %w", err)
	}
	if completion.SchemaVersion != fulcioRotationCompletionSchema {
		return nil, fmt.Errorf(
			"Fulcio rotation completion schema %d is unsupported; expected %d",
			completion.SchemaVersion,
			fulcioRotationCompletionSchema,
		)
	}
	if !fulcioOperationIDPattern.MatchString(completion.OperationID) ||
		completion.TrustDomainID == "" ||
		completion.NewGeneration != completion.PriorGeneration+1 ||
		completion.PriorGenerationID != fmt.Sprintf("generation-%08d", completion.PriorGeneration) ||
		completion.NewGenerationID != fmt.Sprintf("generation-%08d", completion.NewGeneration) ||
		validateSHA256(completion.PriorFulcioRootSHA256) != nil ||
		validateSHA256(completion.NewFulcioRootSHA256) != nil ||
		completion.PriorFulcioRootSHA256 == completion.NewFulcioRootSHA256 ||
		validateSHA256(completion.ManifestSHA256) != nil ||
		validateSHA256(completion.TrustedRootSHA256) != nil ||
		validateSHA256(completion.SigningConfigSHA256) != nil ||
		validateSHA256(completion.PublicationManifestSHA256) != nil ||
		validateSHA256(completion.AcceptedRootsSHA256) != nil ||
		completion.ActiveFulcioRuntimeRootSHA256 != completion.PriorFulcioRootSHA256 ||
		completion.StagedFulcioRuntimeRootSHA256 != completion.NewFulcioRootSHA256 ||
		completion.PublicationID == "" ||
		completion.FulcioTrustEntryCount < 2 ||
		len(completion.AcceptedRootFingerprints) != completion.FulcioTrustEntryCount ||
		completion.CompletedAtUTC.IsZero() {
		return nil, errors.New("Fulcio rotation completion has malformed durable state")
	}
	for _, fingerprint := range completion.AcceptedRootFingerprints {
		if validateSHA256(fingerprint) != nil {
			return nil, errors.New("Fulcio rotation completion has malformed accepted-root fingerprints")
		}
	}
	return &completion, nil
}

func writeFulcioRotationCompletion(statePath string, completion fulcioRotationCompletion) error {
	data, err := json.MarshalIndent(completion, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal Fulcio rotation completion: %w", err)
	}
	data = append(data, '\n')
	return writeAtomicJSON(filepath.Join(statePath, fulcioRotationCompletionFile), data)
}

// validateFulcioCompletionAgainstState strictly re-derives every field of a
// completion record from live disk state (trust domain, active generation and
// its manifest, the committed TUF publication, its trusted_root.json, and the
// component-scoped runtime projection) and rejects the completion if any
// binding does not hold exactly. This is what makes replaying a
// rotate-fulcio-ca.request against an already-completed operation safe.
func validateFulcioCompletionAgainstState(
	statePath string,
	completion *fulcioRotationCompletion,
) error {
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
	if completion.NewFulcioRootSHA256 != bootstrap.FulcioRootSHA256 {
		return errors.New("completion Fulcio root does not match the active generation")
	}

	generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return fmt.Errorf("read active generation manifest: %w", err)
	}
	if generation.FulcioRotationOperationID != completion.OperationID ||
		generation.FulcioPriorGeneration != completion.PriorGeneration ||
		generation.FulcioPriorGenerationID != completion.PriorGenerationID ||
		generation.FulcioPriorRootSHA256 != completion.PriorFulcioRootSHA256 {
		return errors.New(
			"completion does not match the active generation's Fulcio rotation metadata",
		)
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
	fulcioTargetData, err := os.ReadFile(filepath.Join(activeTargetsPath, fulcioTargetName))
	if err != nil {
		return fmt.Errorf("read active %s: %w", fulcioTargetName, err)
	}
	activeTargetCert, err := parseSingleCertificatePEM(fulcioTargetData)
	if err != nil {
		return fmt.Errorf("parse active %s: %w", fulcioTargetName, err)
	}
	if hashDER(activeTargetCert.Raw) != completion.NewFulcioRootSHA256 {
		return fmt.Errorf(
			"active %s does not carry the rotated Fulcio root",
			fulcioTargetName,
		)
	}

	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(trustedRootData, trustedRoot); err != nil {
		return fmt.Errorf("parse active trusted_root.json: %w", err)
	}
	entries, err := readFulcioTrustEntries(trustedRoot)
	if err != nil {
		return err
	}
	if len(entries) != completion.FulcioTrustEntryCount {
		return fmt.Errorf(
			"completion fulcioTrustEntryCount %d does not match the active trusted_root.json (%d entries)",
			completion.FulcioTrustEntryCount,
			len(entries),
		)
	}
	bundle, fingerprints := buildAcceptedRootsBundle(entries)
	if len(fingerprints) != len(completion.AcceptedRootFingerprints) {
		return errors.New("completion accepted-root fingerprints do not match the active trusted_root.json")
	}
	for index, fingerprint := range fingerprints {
		if completion.AcceptedRootFingerprints[index] != fingerprint {
			return errors.New(
				"completion accepted-root fingerprint order does not match the active trusted_root.json",
			)
		}
	}
	if hashBytes(bundle) != completion.AcceptedRootsSHA256 {
		return errors.New("completion acceptedRootsSha256 does not match the active trusted_root.json")
	}
	if entries[len(entries)-1].fingerprint != completion.NewFulcioRootSHA256 {
		return errors.New("the rotated Fulcio root is not the last accepted root")
	}
	foundPrior := false
	for _, entry := range entries {
		if entry.fingerprint == completion.PriorFulcioRootSHA256 {
			foundPrior = true
		}
	}
	if !foundPrior {
		return errors.New(
			"completion prior Fulcio certificate authority is missing from the active trusted_root.json",
		)
	}

	return validateFulcioRotationRuntimeProjection(
		statePath,
		bootstrap,
		completion.PriorGenerationID,
		bundle,
	)
}

// finalizeFulcioRotationCompletion refreshes the Tesseract accepted-root
// projection and re-stages the new Fulcio CA (both idempotent, so this also
// repairs a partially written projection from an interrupted attempt),
// writes the durable completion record, and then removes the operation's
// private candidate material now that it has been fully consumed into the
// new immutable generation. The active runtime/fulcio projection is left
// untouched: promoting it is the Hosting command's job, after clients and
// Tesseract have restarted and the old CA has been proven.
func finalizeFulcioRotationCompletion(
	statePath string,
	request fulcioRotationRequest,
	bootstrap bootstrapManifest,
) error {
	generation, err := readOIDCGenerationManifest(statePath, bootstrap.GenerationID)
	if err != nil {
		return fmt.Errorf("read rotated generation for completion: %w", err)
	}
	if generation.FulcioRotationOperationID != request.OperationID {
		return errors.New("rotated generation operation ID does not match the completion request")
	}

	acceptedRootsBundle, acceptedRootFingerprints, err := ensureFulcioRotationRuntimeProjection(
		statePath,
		request.StartingGenerationID,
	)
	if err != nil {
		return err
	}

	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return fmt.Errorf("load final TUF publication for completion: %w", err)
	}
	if publication.Status != publicationStatusCommitted || publication.Active == nil {
		return errors.New("Fulcio rotation has no committed active TUF publication")
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

	completion := fulcioRotationCompletion{
		SchemaVersion:                 fulcioRotationCompletionSchema,
		OperationID:                   request.OperationID,
		TrustDomainID:                 request.TrustDomainID,
		PriorGeneration:               request.StartingGeneration,
		PriorGenerationID:             request.StartingGenerationID,
		PriorFulcioRootSHA256:         generation.FulcioPriorRootSHA256,
		NewGeneration:                 bootstrap.Generation,
		NewGenerationID:               bootstrap.GenerationID,
		NewFulcioRootSHA256:           bootstrap.FulcioRootSHA256,
		ManifestSHA256:                bootstrap.GenerationManifestSHA256,
		PublicationID:                 publication.Active.ID,
		PublicationManifestSHA256:     publication.Active.ManifestSHA256,
		TrustedRootSHA256:             status.TrustedRootSHA256,
		SigningConfigSHA256:           status.SigningConfigSHA256,
		FulcioTrustEntryCount:         len(acceptedRootFingerprints),
		AcceptedRootsSHA256:           hashBytes(acceptedRootsBundle),
		AcceptedRootFingerprints:      acceptedRootFingerprints,
		ActiveFulcioRuntimeRootSHA256: generation.FulcioPriorRootSHA256,
		StagedFulcioRuntimeRootSHA256: bootstrap.FulcioRootSHA256,
		CompletedAtUTC:                time.Now().UTC(),
	}
	if err := writeFulcioRotationCompletion(statePath, completion); err != nil {
		return err
	}

	return removeFulcioOperationPrivateCandidate(statePath, request.OperationID)
}

func removeFulcioOperationPrivateCandidate(statePath, operationID string) error {
	candidatePrivatePath := filepath.Join(
		statePath,
		fulcioRotationDirectory,
		operationID,
		"candidate",
		"private",
	)
	if err := os.RemoveAll(candidatePrivatePath); err != nil {
		return fmt.Errorf("remove completed Fulcio operation private candidate material: %w", err)
	}
	return nil
}

// recoverCommittedFulcioRotation forward-completes a Fulcio rotation whose
// generation and TUF publication both committed but whose active-generation
// symlink switch had not yet happened when the process previously crashed,
// mirroring recoverCommittedTSARotation.
func recoverCommittedFulcioRotation(statePath string, request fulcioRotationRequest) error {
	journalPath := filepath.Join(statePath, "transition", "state.json")
	journalData, err := os.ReadFile(journalPath)
	if err != nil {
		return fmt.Errorf("read trust transition journal: %w", err)
	}
	var journal trustTransitionJournal
	if err := json.Unmarshal(journalData, &journal); err != nil {
		return fmt.Errorf("parse trust transition journal: %w", err)
	}
	if journal.Operation != "fulcio-rotation" ||
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
		journal.CandidateManifest.FulcioRotationOperationID != request.OperationID {
		return errors.New("staged Fulcio transition does not match its rotation request")
	}

	generationPath := filepath.Join(statePath, "generations", journal.Candidate.GenerationID)
	manifestData, err := os.ReadFile(filepath.Join(generationPath, "manifest.json"))
	if err != nil {
		return fmt.Errorf("read staged Fulcio generation manifest: %w", err)
	}
	if hashBytes(manifestData) != journal.Candidate.ManifestSHA256 {
		return errors.New("staged Fulcio transition manifest hash does not match its generation")
	}
	if err := validateFulcioGenerationMaterial(generationPath, journal.CandidateManifest); err != nil {
		return fmt.Errorf("validate staged Fulcio generation: %w", err)
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
		return fmt.Errorf("compute staged Fulcio generation fingerprint: %w", err)
	}

	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return fmt.Errorf("load TUF publication state: %w", err)
	}
	if publication.Status != publicationStatusCommitted || publication.Active == nil {
		return errors.New("staged Fulcio transition lacks a committed TUF publication")
	}
	if err := validateReference(
		committedPath(layout, publication.Active.ID),
		*publication.Active,
		fingerprint,
	); err != nil {
		return fmt.Errorf("validate staged Fulcio TUF publication: %w", err)
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
		return fmt.Errorf("staged Fulcio transition has unexpected active generation %q", activeID)
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

func parseSingleCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("expected exactly one PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
