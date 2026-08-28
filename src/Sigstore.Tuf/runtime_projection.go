package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	trustrootv1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	runtimeDirectory            = "runtime"
	runtimeFulcioComponent      = "fulcio"
	runtimeFulcioNextComponent  = "fulcio.next"
	runtimeTesseractComponent   = "tesseract"
	runtimeFulcioRootCertFile   = "root.pem"
	runtimeFulcioRootKeyFile    = "root.key"
	runtimeFulcioPasswordFile   = "password"
	runtimeFulcioCtLogKeyFile   = "ctlog.pub"
	runtimeTesseractKeyFile     = "privkey.pem"
	runtimeAcceptedRootsFile    = "accepted-roots.pem"
	ctLogPrivateKeyRelPath      = "private/ctlog/privkey.pem"
	ctLogPublicKeyRelPath       = "public/ctlog/pubkey.pem"
	runtimeProjectionFilePrefix = ".runtime-"
)

// runtimeSource binds one fixed runtime projection file name to the
// generation file whose bytes it mirrors and the mode it must carry.
type runtimeSource struct {
	name   string
	source string
	mode   os.FileMode
}

// fulcioRuntimeSources describes the component-scoped Fulcio projection.
// Fulcio needs its own CA material plus the CT log public key, because it
// verifies SCTs against that key; exposing a public key here is safe and it
// keeps the container's bind mount to a single stable directory.
func fulcioRuntimeSources(generationPath string) []runtimeSource {
	return []runtimeSource{
		{
			name:   runtimeFulcioRootCertFile,
			source: filepath.Join(generationPath, filepath.FromSlash(fulcioRootCertRelPath)),
			mode:   0o644,
		},
		{
			name:   runtimeFulcioRootKeyFile,
			source: filepath.Join(generationPath, filepath.FromSlash(fulcioRootKeyRelPath)),
			mode:   0o600,
		},
		{
			name:   runtimeFulcioPasswordFile,
			source: filepath.Join(generationPath, filepath.FromSlash(fulcioPasswordRelPath)),
			mode:   0o600,
		},
		{
			name:   runtimeFulcioCtLogKeyFile,
			source: filepath.Join(generationPath, filepath.FromSlash(ctLogPublicKeyRelPath)),
			mode:   0o644,
		},
	}
}

// tesseractRuntimeSources describes the fixed Tesseract projection files that
// are copied verbatim from a generation. The accepted-root bundle is derived
// from the committed TrustedRoot instead and is handled separately.
func tesseractRuntimeSources(generationPath string) []runtimeSource {
	return []runtimeSource{
		{
			name:   runtimeTesseractKeyFile,
			source: filepath.Join(generationPath, filepath.FromSlash(ctLogPrivateKeyRelPath)),
			mode:   0o600,
		},
	}
}

func runtimeComponentPath(statePath, component string) string {
	return filepath.Join(statePath, runtimeDirectory, component)
}

func generationPathFor(statePath, generationID string) string {
	return filepath.Join(statePath, "generations", generationID)
}

// buildAcceptedRootsBundle renders the deterministic accepted-root PEM bundle
// for a validated, ordered list of Fulcio trust entries: one normalized PEM
// block per unique root, in TrustedRoot entry order, so the newest root is
// always last. It returns the bundle bytes and the matching ordered
// fingerprints.
func buildAcceptedRootsBundle(entries []fulcioTrustEntry) ([]byte, []string) {
	var bundle bytes.Buffer
	fingerprints := make([]string, 0, len(entries))
	for _, entry := range entries {
		bundle.Write(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: entry.certificate.Raw,
		}))
		fingerprints = append(fingerprints, entry.fingerprint)
	}
	return bundle.Bytes(), fingerprints
}

// readActiveFulcioTrustEntries reads the committed TUF publication's
// TrustedRoot and returns its validated, ordered Fulcio certificate
// authorities.
func readActiveFulcioTrustEntries(statePath string) ([]fulcioTrustEntry, error) {
	layout := newTUFLayout(statePath)
	publication, err := loadPublicationState(layout)
	if err != nil {
		return nil, fmt.Errorf("load TUF publication state for runtime projection: %w", err)
	}
	if publication.Status != publicationStatusCommitted || publication.Active == nil {
		return nil, errors.New("runtime projection requires a committed active TUF publication")
	}
	trustedRootData, err := os.ReadFile(filepath.Join(
		committedPath(layout, publication.Active.ID),
		"targets",
		"trusted_root.json",
	))
	if err != nil {
		return nil, fmt.Errorf("read active trusted_root.json for runtime projection: %w", err)
	}
	trustedRoot := &trustrootv1.TrustedRoot{}
	if err := protojson.Unmarshal(trustedRootData, trustedRoot); err != nil {
		return nil, fmt.Errorf("parse active trusted_root.json for runtime projection: %w", err)
	}
	return readFulcioTrustEntries(trustedRoot)
}

// ensureRuntimeBaselineProjection materializes the complete component-scoped
// projection for a trust state that has no rotation awaiting promotion: the
// Fulcio component tracks the active generation and the Tesseract component
// carries the active CT signing key plus the accepted-root bundle derived
// from the committed TrustedRoot. This mirrors what the C# bootstrapper
// creates and is only safe when the active generation is already the one
// Fulcio is expected to serve.
func ensureRuntimeBaselineProjection(statePath string) ([]byte, []string, error) {
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return nil, nil, fmt.Errorf("load active generation for runtime projection: %w", err)
	}
	generationPath := generationPathFor(statePath, bootstrap.GenerationID)
	bundle, fingerprints, err := deriveAcceptedRootsBundle(statePath, bootstrap)
	if err != nil {
		return nil, nil, err
	}
	if err := ensureRuntimeDirectories(
		statePath,
		runtimeFulcioComponent,
		runtimeTesseractComponent,
	); err != nil {
		return nil, nil, err
	}
	if err := writeRuntimeComponent(
		runtimeComponentPath(statePath, runtimeFulcioComponent),
		fulcioRuntimeSources(generationPath),
	); err != nil {
		return nil, nil, err
	}
	if err := writeTesseractRuntimeComponent(statePath, generationPath, bundle); err != nil {
		return nil, nil, err
	}
	return bundle, fingerprints, nil
}

// ensureFulcioRotationRuntimeProjection is the projection step of a Fulcio CA
// rotation. It deliberately does NOT replace the active runtime/fulcio
// projection: the running Fulcio must keep serving the old CA until the
// Hosting command has restarted clients and Tesseract and proven the old CA
// still issues, so an unexpected Fulcio recreation can never activate the
// candidate early. Instead it (a) additively refreshes the Tesseract
// accepted-root bundle so the log accepts both roots and (b) stages the new
// CA under runtime/fulcio.next, leaving promotion to the Hosting helper. It
// is idempotent and total, so replaying it repairs a partial projection.
func ensureFulcioRotationRuntimeProjection(
	statePath string,
	priorGenerationID string,
) ([]byte, []string, error) {
	bootstrap, err := loadActiveTrustGeneration(statePath)
	if err != nil {
		return nil, nil, fmt.Errorf("load active generation for runtime projection: %w", err)
	}
	generationPath := generationPathFor(statePath, bootstrap.GenerationID)
	bundle, fingerprints, err := deriveAcceptedRootsBundle(statePath, bootstrap)
	if err != nil {
		return nil, nil, err
	}

	promoted, err := runtimeComponentMatches(
		runtimeComponentPath(statePath, runtimeFulcioComponent),
		fulcioRuntimeSources(generationPath),
	)
	if err != nil {
		return nil, nil, err
	}

	components := []string{runtimeFulcioComponent, runtimeTesseractComponent}
	if !promoted {
		components = append(components, runtimeFulcioNextComponent)
	}
	if err := ensureRuntimeDirectories(statePath, components...); err != nil {
		return nil, nil, err
	}
	if !promoted {
		if err := writeRuntimeComponent(
			runtimeComponentPath(statePath, runtimeFulcioNextComponent),
			fulcioRuntimeSources(generationPath),
		); err != nil {
			return nil, nil, err
		}
	}
	if err := writeTesseractRuntimeComponent(statePath, generationPath, bundle); err != nil {
		return nil, nil, err
	}

	if err := validateFulcioRotationRuntimeProjection(
		statePath,
		bootstrap,
		priorGenerationID,
		bundle,
	); err != nil {
		return nil, nil, err
	}
	return bundle, fingerprints, nil
}

func deriveAcceptedRootsBundle(
	statePath string,
	bootstrap bootstrapManifest,
) ([]byte, []string, error) {
	entries, err := readActiveFulcioTrustEntries(statePath)
	if err != nil {
		return nil, nil, err
	}
	if entries[len(entries)-1].fingerprint != bootstrap.FulcioRootSHA256 {
		return nil, nil, errors.New(
			"the active Fulcio root is not the last accepted root in the committed TrustedRoot",
		)
	}
	bundle, fingerprints := buildAcceptedRootsBundle(entries)
	return bundle, fingerprints, nil
}

func writeTesseractRuntimeComponent(
	statePath string,
	generationPath string,
	bundle []byte,
) error {
	tesseractPath := runtimeComponentPath(statePath, runtimeTesseractComponent)
	if err := writeRuntimeComponent(
		tesseractPath,
		tesseractRuntimeSources(generationPath),
	); err != nil {
		return err
	}
	return writeRuntimeProjectionFile(
		filepath.Join(tesseractPath, runtimeAcceptedRootsFile),
		bundle,
		0o644,
	)
}

// validateFulcioRotationRuntimeProjection asserts the runtime projection is in
// one of exactly two recognized states for a completed rotation: pending
// promotion (runtime/fulcio still serves the prior CA and runtime/fulcio.next
// carries the new one) or already promoted by the Hosting command
// (runtime/fulcio serves the new CA). Everything else — extra entries, stale
// secrets, a missing stage, or an accepted-root bundle that does not exactly
// render the committed TrustedRoot — is rejected.
func validateFulcioRotationRuntimeProjection(
	statePath string,
	bootstrap bootstrapManifest,
	priorGenerationID string,
	expectedBundle []byte,
) error {
	activeGenerationPath := generationPathFor(statePath, bootstrap.GenerationID)
	priorGenerationPath := generationPathFor(statePath, priorGenerationID)
	fulcioPath := runtimeComponentPath(statePath, runtimeFulcioComponent)
	stagePath := runtimeComponentPath(statePath, runtimeFulcioNextComponent)

	promoted, err := runtimeComponentMatches(
		fulcioPath,
		fulcioRuntimeSources(activeGenerationPath),
	)
	if err != nil {
		return err
	}
	if !promoted {
		pending, err := runtimeComponentMatches(
			fulcioPath,
			fulcioRuntimeSources(priorGenerationPath),
		)
		if err != nil {
			return err
		}
		if !pending {
			return errors.New(
				"the active Fulcio runtime projection matches neither the prior nor the rotated generation",
			)
		}
	}

	expectedRuntimeEntries := []string{runtimeFulcioComponent, runtimeTesseractComponent}
	if pathExists(stagePath) {
		expectedRuntimeEntries = append(expectedRuntimeEntries, runtimeFulcioNextComponent)
		staged, err := runtimeComponentMatches(
			stagePath,
			fulcioRuntimeSources(activeGenerationPath),
		)
		if err != nil {
			return err
		}
		if !staged {
			return errors.New(
				"the staged Fulcio runtime projection does not match the rotated generation",
			)
		}
	} else if !promoted {
		return errors.New(
			"the rotated Fulcio runtime projection is pending promotion but was never staged",
		)
	}

	if err := ensureRuntimeEntries(
		filepath.Join(statePath, runtimeDirectory),
		expectedRuntimeEntries,
	); err != nil {
		return err
	}
	if err := runtimeComponentIsExact(
		runtimeComponentPath(statePath, runtimeTesseractComponent),
		tesseractRuntimeSources(activeGenerationPath),
		[]string{runtimeAcceptedRootsFile},
	); err != nil {
		return err
	}

	acceptedRootsPath := filepath.Join(
		runtimeComponentPath(statePath, runtimeTesseractComponent),
		runtimeAcceptedRootsFile,
	)
	acceptedRoots, err := os.ReadFile(acceptedRootsPath)
	if err != nil {
		return fmt.Errorf("read accepted Fulcio roots: %w", err)
	}
	if !bytes.Equal(acceptedRoots, expectedBundle) {
		return errors.New(
			"the projected accepted Fulcio roots do not match the committed TrustedRoot",
		)
	}
	return validateAcceptedRootsBundleBytes(acceptedRoots, bootstrap.FulcioRootSHA256)
}

// validateAcceptedRootsBundleBytes independently re-parses an accepted-root
// bundle and asserts it is a normalized, duplicate-free PEM concatenation
// whose final entry is the active Fulcio root.
func validateAcceptedRootsBundleBytes(bundle []byte, activeRootSHA256 string) error {
	remaining := bundle
	var certificates []*x509.Certificate
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return errors.New("accepted Fulcio roots contain invalid PEM data")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("unexpected PEM block %q in accepted Fulcio roots", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse accepted Fulcio root: %w", err)
		}
		certificates = append(certificates, certificate)
		remaining = rest
	}
	if len(certificates) == 0 {
		return errors.New("accepted Fulcio roots contain no certificates")
	}

	seen := map[string]bool{}
	var normalized bytes.Buffer
	for _, certificate := range certificates {
		fingerprint := hashDER(certificate.Raw)
		if seen[fingerprint] {
			return errors.New("accepted Fulcio roots contain duplicate certificates")
		}
		seen[fingerprint] = true
		normalized.Write(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		}))
	}
	if !bytes.Equal(normalized.Bytes(), bundle) {
		return errors.New("accepted Fulcio roots are not a normalized certificate bundle")
	}
	if hashDER(certificates[len(certificates)-1].Raw) != activeRootSHA256 {
		return errors.New("accepted Fulcio roots do not end with the active Fulcio root")
	}
	return nil
}

func ensureRuntimeDirectories(statePath string, components ...string) error {
	runtimePath := filepath.Join(statePath, runtimeDirectory)
	if err := ensureRealDirectory(runtimePath); err != nil {
		return fmt.Errorf("prepare runtime projection directory: %w", err)
	}
	for _, component := range components {
		if err := ensureRealDirectory(filepath.Join(runtimePath, component)); err != nil {
			return fmt.Errorf("prepare runtime projection directory: %w", err)
		}
	}
	return nil
}

func writeRuntimeComponent(componentPath string, sources []runtimeSource) error {
	for _, source := range sources {
		data, err := os.ReadFile(source.source)
		if err != nil {
			return fmt.Errorf("read runtime projection source %q: %w", source.source, err)
		}
		if err := writeRuntimeProjectionFile(
			filepath.Join(componentPath, source.name),
			data,
			source.mode,
		); err != nil {
			return err
		}
	}
	return nil
}

// runtimeComponentMatches reports whether a projected component is exactly the
// given generation's material: the file set is exact and every file is byte
// identical. A component that carries a different generation's bytes reports
// false rather than an error, because promotion resolves that state; an
// unexpected file set is always an error.
func runtimeComponentMatches(componentPath string, sources []runtimeSource) (bool, error) {
	if !pathExists(componentPath) {
		return false, fmt.Errorf("runtime projection directory %q is missing", componentPath)
	}
	expected := make([]string, 0, len(sources))
	for _, source := range sources {
		expected = append(expected, source.name)
	}
	if err := ensureRuntimeEntries(componentPath, expected); err != nil {
		return false, err
	}
	for _, source := range sources {
		projected, err := os.ReadFile(filepath.Join(componentPath, source.name))
		if err != nil {
			return false, fmt.Errorf("read runtime projection %q: %w", source.name, err)
		}
		want, err := os.ReadFile(source.source)
		if err != nil {
			return false, fmt.Errorf("read runtime projection source %q: %w", source.source, err)
		}
		if !bytes.Equal(projected, want) {
			return false, nil
		}
	}
	return true, nil
}

// runtimeComponentIsExact asserts a component matches its generation sources
// exactly, allowing the named derived files (such as the accepted-root
// bundle) to be present without a generation counterpart.
func runtimeComponentIsExact(
	componentPath string,
	sources []runtimeSource,
	derived []string,
) error {
	expected := append([]string(nil), derived...)
	for _, source := range sources {
		expected = append(expected, source.name)
	}
	if err := ensureRuntimeEntries(componentPath, expected); err != nil {
		return err
	}
	for _, source := range sources {
		projected, err := os.ReadFile(filepath.Join(componentPath, source.name))
		if err != nil {
			return fmt.Errorf("read runtime projection %q: %w", source.name, err)
		}
		want, err := os.ReadFile(source.source)
		if err != nil {
			return fmt.Errorf("read runtime projection source %q: %w", source.source, err)
		}
		if !bytes.Equal(projected, want) {
			return fmt.Errorf(
				"runtime projection %q does not match the active generation",
				filepath.Join(componentPath, source.name),
			)
		}
	}
	return nil
}

func ensureRuntimeEntries(path string, expected []string) error {
	if err := ensureRealDirectory(path); err != nil {
		return fmt.Errorf("runtime projection directory %q: %w", path, err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("read runtime projection directory %q: %w", path, err)
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf(
				"runtime projection entry %q must not be a symbolic link",
				filepath.Join(path, entry.Name()),
			)
		}
		actual = append(actual, entry.Name())
	}
	sort.Strings(actual)
	want := append([]string(nil), expected...)
	sort.Strings(want)
	if strings.Join(actual, "\x00") != strings.Join(want, "\x00") {
		return fmt.Errorf(
			"runtime projection directory %q has an unexpected entry set %v; expected %v",
			path,
			actual,
			want,
		)
	}
	return nil
}

// writeRuntimeProjectionFile replaces one fixed runtime file atomically. The
// temporary file is created inside the destination directory so the rename is
// always same-filesystem, and the directory is fsynced so a crash can never
// leave the projection referencing a half-written file.
func writeRuntimeProjectionFile(path string, data []byte, mode os.FileMode) error {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return os.Chmod(path, mode)
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, runtimeProjectionFilePrefix+"*")
	if err != nil {
		return fmt.Errorf("create temporary runtime projection file: %w", err)
	}
	temporaryPath := temporary.Name()
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		os.Remove(temporaryPath)
		return fmt.Errorf("write runtime projection file: %w", err)
	}
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		os.Remove(temporaryPath)
		return fmt.Errorf("set runtime projection file mode: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		os.Remove(temporaryPath)
		return fmt.Errorf("fsync runtime projection file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("close runtime projection file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("commit runtime projection file: %w", err)
	}
	return syncDirectory(directory)
}
