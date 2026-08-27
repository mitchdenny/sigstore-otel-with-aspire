package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	commonv1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	trustrootv1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	tuf "github.com/theupdateframework/go-tuf"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	tufSchemaVersion           = 3
	trustedRootMediaType       = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
	signingConfigMediaType     = "application/vnd.dev.sigstore.signingconfig.v0.2+json"
	clientTrustConfigMediaType = "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json"
	operatorName               = "sigstore.local"
	fulcioURL                  = "http://fulcio-sigstore.dev.localhost:5555"
	oidcURL                    = "https://oidc-sigstore.dev.localhost:7443"
	rekorURL                   = "http://rekor-sigstore.dev.localhost:3000"
	ctLogURL                   = "http://tesseract-sigstore.dev.localhost:6962"
	tsaURL                     = "http://timestamp-sigstore.dev.localhost:3004/api/v1/timestamp"
)

var protoJSON = protojson.MarshalOptions{
	Indent: "  ",
}

type bootstrapManifest struct {
	SchemaVersion        int       `json:"schemaVersion"`
	CreatedAtUTC         time.Time `json:"createdAtUtc"`
	FulcioRootSHA256     string    `json:"fulcioRootSha256"`
	CtLogPublicKeySHA256 string    `json:"ctLogPublicKeySha256"`
	RekorPublicKeySHA256 string    `json:"rekorPublicKeySha256"`
	TsaRootSHA256        string    `json:"tsaRootSha256"`
	TsaLeafSHA256        string    `json:"tsaLeafSha256"`
	OIDCKeyID            string    `json:"oidcKeyId"`
}

type tufManifest struct {
	SchemaVersion     int               `json:"schemaVersion"`
	CreatedAtUTC      time.Time         `json:"createdAtUtc"`
	UpdatedAtUTC      time.Time         `json:"updatedAtUtc"`
	SourceFingerprint string            `json:"sourceFingerprint"`
	Files             map[string]string `json:"files"`
}

type sourceDefinition struct {
	Bootstrap         bootstrapManifest `json:"bootstrap"`
	TrustedRootType   string            `json:"trustedRootType"`
	SigningConfigType string            `json:"signingConfigType"`
	ClientConfigType  string            `json:"clientConfigType"`
	Operator          string            `json:"operator"`
	FulcioURL         string            `json:"fulcioUrl"`
	OIDCURL           string            `json:"oidcUrl"`
	RekorURL          string            `json:"rekorUrl"`
	CTLogURL          string            `json:"ctLogUrl"`
	TSAURL            string            `json:"tsaUrl"`
}

type tufTarget struct {
	name   string
	data   []byte
	custom []byte
}

func main() {
	statePath := os.Getenv("SIGSTORE_STATE_PATH")
	if statePath == "" {
		fatalf("SIGSTORE_STATE_PATH must identify the Sigstore state directory")
	}

	action, err := ensureTUFRepository(filepath.Clean(statePath))
	if err != nil {
		fatalf("%v", err)
	}

	fmt.Printf("%s Sigstore TUF repository at %s.\n", action, filepath.Join(statePath, "tuf"))
}

func buildSigstoreTargets(statePath string, bootstrap bootstrapManifest) ([]tufTarget, error) {
	fulcioPEM, err := os.ReadFile(filepath.Join(statePath, "public", "fulcio", "root.pem"))
	if err != nil {
		return nil, fmt.Errorf("read Fulcio root: %w", err)
	}
	fulcioBlock, _ := pem.Decode(fulcioPEM)
	if fulcioBlock == nil || fulcioBlock.Type != "CERTIFICATE" {
		return nil, errors.New("Fulcio root is not a PEM certificate")
	}
	fulcioCert, err := x509.ParseCertificate(fulcioBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Fulcio root: %w", err)
	}

	ctPEM, ctDER, err := loadP256PublicKey(filepath.Join(statePath, "public", "ctlog", "pubkey.pem"))
	if err != nil {
		return nil, fmt.Errorf("load CT log key: %w", err)
	}
	rekorPEM, rekorDER, err := loadP256PublicKey(filepath.Join(statePath, "public", "rekor", "signer.pub"))
	if err != nil {
		return nil, fmt.Errorf("load Rekor key: %w", err)
	}
	tsaChainPEM, tsaCertificates, err := loadCertificateChain(
		filepath.Join(statePath, "public", "tsa", "cert-chain.pem"))
	if err != nil {
		return nil, fmt.Errorf("load TSA certificate chain: %w", err)
	}

	trustedRoot := &trustrootv1.TrustedRoot{
		MediaType: trustedRootMediaType,
		Tlogs: []*trustrootv1.TransparencyLogInstance{
			newTransparencyLog(rekorURL, rekorDER, bootstrap.CreatedAtUTC),
		},
		CertificateAuthorities: []*trustrootv1.CertificateAuthority{
			newCertificateAuthority(fulcioURL, fulcioCert),
		},
		Ctlogs: []*trustrootv1.TransparencyLogInstance{
			newTransparencyLog(ctLogURL, ctDER, bootstrap.CreatedAtUTC),
		},
		TimestampAuthorities: []*trustrootv1.CertificateAuthority{
			newTimestampAuthority(tsaURL, tsaCertificates),
		},
	}
	signingConfig := &trustrootv1.SigningConfig{
		MediaType: signingConfigMediaType,
		CaUrls: []*trustrootv1.Service{
			newService(fulcioURL, 1, bootstrap.CreatedAtUTC),
		},
		OidcUrls: []*trustrootv1.Service{
			newService(oidcURL, 1, bootstrap.CreatedAtUTC),
		},
		RekorTlogUrls: []*trustrootv1.Service{
			newService(rekorURL, 2, bootstrap.CreatedAtUTC),
		},
		RekorTlogConfig: &trustrootv1.ServiceConfiguration{
			Selector: trustrootv1.ServiceSelector_ANY,
		},
		TsaUrls: []*trustrootv1.Service{
			newService(tsaURL, 1, bootstrap.CreatedAtUTC),
		},
		TsaConfig: &trustrootv1.ServiceConfiguration{
			Selector: trustrootv1.ServiceSelector_ANY,
		},
	}
	clientConfig := &trustrootv1.ClientTrustConfig{
		MediaType:     clientTrustConfigMediaType,
		TrustedRoot:   trustedRoot,
		SigningConfig: signingConfig,
	}

	trustedRootJSON, err := protoJSON.Marshal(trustedRoot)
	if err != nil {
		return nil, fmt.Errorf("marshal TrustedRoot: %w", err)
	}
	signingConfigJSON, err := protoJSON.Marshal(signingConfig)
	if err != nil {
		return nil, fmt.Errorf("marshal SigningConfig: %w", err)
	}
	clientConfigJSON, err := protoJSON.Marshal(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("marshal ClientTrustConfig: %w", err)
	}

	return []tufTarget{
		{
			name:   "fulcio_v1.crt.pem",
			data:   fulcioPEM,
			custom: targetMetadata("Fulcio", fulcioURL),
		},
		{
			name:   "ctfe.pub",
			data:   ctPEM,
			custom: targetMetadata("CTFE", ctLogURL),
		},
		{
			name:   "rekor.pub",
			data:   rekorPEM,
			custom: targetMetadata("Rekor", rekorURL),
		},
		{
			name:   "tsa.certchain.pem",
			data:   tsaChainPEM,
			custom: targetMetadata("TSA", tsaURL),
		},
		{
			name: "tsa_leaf.crt.pem",
			data: pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: tsaCertificates[0].Raw,
				}),
			custom: targetMetadata("TSA", tsaURL),
		},
		{
			name: "tsa_root.crt.pem",
			data: pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: tsaCertificates[len(tsaCertificates)-1].Raw,
				}),
			custom: targetMetadata("TSA", tsaURL),
		},
		{name: "trusted_root.json", data: append(trustedRootJSON, '\n')},
		{name: "signing_config.v0.2.json", data: append(signingConfigJSON, '\n')},
		{name: "client_trust_config.json", data: append(clientConfigJSON, '\n')},
	}, nil
}

func newTransparencyLog(baseURL string, publicKeyDER []byte, start time.Time) *trustrootv1.TransparencyLogInstance {
	logID := sha256.Sum256(publicKeyDER)
	return &trustrootv1.TransparencyLogInstance{
		BaseUrl:       baseURL,
		HashAlgorithm: commonv1.HashAlgorithm_SHA2_256,
		PublicKey: &commonv1.PublicKey{
			RawBytes:   publicKeyDER,
			KeyDetails: commonv1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			ValidFor: &commonv1.TimeRange{
				Start: timestamppb.New(start),
			},
		},
		LogId: &commonv1.LogId{
			KeyId: append([]byte(nil), logID[:]...),
		},
	}
}

func newCertificateAuthority(uri string, cert *x509.Certificate) *trustrootv1.CertificateAuthority {
	organization := ""
	if len(cert.Subject.Organization) != 0 {
		organization = cert.Subject.Organization[0]
	}
	return &trustrootv1.CertificateAuthority{
		Subject: &commonv1.DistinguishedName{
			Organization: organization,
			CommonName:   cert.Subject.CommonName,
		},
		Uri: uri,
		CertChain: &commonv1.X509CertificateChain{
			Certificates: []*commonv1.X509Certificate{
				{RawBytes: cert.Raw},
			},
		},
		ValidFor: &commonv1.TimeRange{
			Start: timestamppb.New(cert.NotBefore),
			End:   timestamppb.New(cert.NotAfter),
		},
	}
}

func newTimestampAuthority(uri string, certificates []*x509.Certificate) *trustrootv1.CertificateAuthority {
	root := certificates[len(certificates)-1]
	organization := ""
	if len(root.Subject.Organization) != 0 {
		organization = root.Subject.Organization[0]
	}
	start := certificates[0].NotBefore
	end := certificates[0].NotAfter
	protobufCertificates := make([]*commonv1.X509Certificate, 0, len(certificates))
	for _, certificate := range certificates {
		protobufCertificates = append(
			protobufCertificates,
			&commonv1.X509Certificate{RawBytes: certificate.Raw})
		if certificate.NotBefore.After(start) {
			start = certificate.NotBefore
		}
		if certificate.NotAfter.Before(end) {
			end = certificate.NotAfter
		}
	}
	return &trustrootv1.CertificateAuthority{
		Subject: &commonv1.DistinguishedName{
			Organization: organization,
			CommonName:   root.Subject.CommonName,
		},
		Uri: uri,
		CertChain: &commonv1.X509CertificateChain{
			Certificates: protobufCertificates,
		},
		ValidFor: &commonv1.TimeRange{
			Start: timestamppb.New(start),
			End:   timestamppb.New(end),
		},
	}
}

func newService(url string, majorVersion uint32, start time.Time) *trustrootv1.Service {
	return &trustrootv1.Service{
		Url:             url,
		MajorApiVersion: majorVersion,
		ValidFor: &commonv1.TimeRange{
			Start: timestamppb.New(start),
		},
		Operator: operatorName,
	}
}

func createTUFRepository(basePath string, targets []tufTarget) error {
	store := tuf.FileSystemStore(basePath, nil)
	repository, err := tuf.NewRepoIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("create TUF repository: %w", err)
	}
	if err := repository.Init(true); err != nil {
		return fmt.Errorf("initialize TUF repository: %w", err)
	}

	rootAndTargetsExpires := time.Now().UTC().AddDate(1, 0, 0)
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if _, err := repository.GenKeyWithExpires(role, rootAndTargetsExpires); err != nil {
			return fmt.Errorf("generate %s key: %w", role, err)
		}
	}

	for _, target := range targets {
		stagedPath := filepath.Join(basePath, "staged", "targets", target.name)
		if err := os.MkdirAll(filepath.Dir(stagedPath), 0o755); err != nil {
			return fmt.Errorf("create staged target directory: %w", err)
		}
		if err := os.WriteFile(stagedPath, target.data, 0o644); err != nil {
			return fmt.Errorf("write staged target %s: %w", target.name, err)
		}
		if err := repository.AddTargetWithExpires(target.name, target.custom, rootAndTargetsExpires); err != nil {
			return fmt.Errorf("add TUF target %s: %w", target.name, err)
		}
	}

	if err := repository.SnapshotWithExpires(time.Now().UTC().Add(30 * 24 * time.Hour)); err != nil {
		return fmt.Errorf("create TUF snapshot: %w", err)
	}
	if err := repository.TimestampWithExpires(time.Now().UTC().Add(24 * time.Hour)); err != nil {
		return fmt.Errorf("create TUF timestamp: %w", err)
	}
	if err := repository.Commit(); err != nil {
		return fmt.Errorf("commit TUF repository: %w", err)
	}
	return nil
}

func writePublicTargets(basePath string, targets []tufTarget) error {
	targetPath := filepath.Join(basePath, "targets")
	if err := os.MkdirAll(targetPath, 0o755); err != nil {
		return fmt.Errorf("create public target directory: %w", err)
	}
	for _, target := range targets {
		if err := os.WriteFile(filepath.Join(targetPath, target.name), target.data, 0o644); err != nil {
			return fmt.Errorf("write public target %s: %w", target.name, err)
		}
	}
	return nil
}

func refreshTUFRepository(tufPath string) error {
	store := tuf.FileSystemStore(tufPath, nil)
	repository, err := tuf.NewRepoIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("open TUF repository for refresh: %w", err)
	}
	if err := repository.SnapshotWithExpires(time.Now().UTC().Add(30 * 24 * time.Hour)); err != nil {
		return fmt.Errorf("refresh TUF snapshot: %w", err)
	}
	if err := repository.TimestampWithExpires(time.Now().UTC().Add(24 * time.Hour)); err != nil {
		return fmt.Errorf("refresh TUF timestamp: %w", err)
	}
	if err := repository.Commit(); err != nil {
		return fmt.Errorf("commit refreshed TUF metadata: %w", err)
	}
	return nil
}

func loadBootstrapManifest(path string) (bootstrapManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return bootstrapManifest{}, fmt.Errorf("read bootstrap manifest: %w", err)
	}
	var manifest bootstrapManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return bootstrapManifest{}, fmt.Errorf("parse bootstrap manifest: %w", err)
	}
	if manifest.SchemaVersion < 4 {
		return bootstrapManifest{}, fmt.Errorf("bootstrap schema %d does not include the required Sigstore state", manifest.SchemaVersion)
	}
	return manifest, nil
}

func fingerprintSource(bootstrap bootstrapManifest) (string, error) {
	source := sourceDefinition{
		Bootstrap:         bootstrap,
		TrustedRootType:   trustedRootMediaType,
		SigningConfigType: signingConfigMediaType,
		ClientConfigType:  clientTrustConfigMediaType,
		Operator:          operatorName,
		FulcioURL:         fulcioURL,
		OIDCURL:           oidcURL,
		RekorURL:          rekorURL,
		CTLogURL:          ctLogURL,
		TSAURL:            tsaURL,
	}
	data, err := json.Marshal(source)
	if err != nil {
		return "", fmt.Errorf("marshal TUF source definition: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func loadP256PublicKey(path string) ([]byte, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, nil, errors.New("expected a PKIX PEM public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok || ecKey.Curve != elliptic.P256() {
		return nil, nil, errors.New("expected a P-256 public key")
	}
	der, err := x509.MarshalPKIXPublicKey(ecKey)
	if err != nil {
		return nil, nil, err
	}
	return data, der, nil
}

func loadCertificateChain(path string) ([]byte, []*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	remaining := data
	var certificates []*x509.Certificate
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			if len(strings.TrimSpace(string(remaining))) != 0 {
				return nil, nil, errors.New("certificate chain contains invalid PEM data")
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("unexpected PEM block %q in certificate chain", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certificates = append(certificates, certificate)
		remaining = rest
	}
	if len(certificates) < 2 {
		return nil, nil, fmt.Errorf("certificate chain requires leaf and root, found %d certificates", len(certificates))
	}
	return data, certificates, nil
}

func targetMetadata(usage, uri string) []byte {
	data, err := json.Marshal(map[string]any{
		"sigstore": map[string]string{
			"usage":  usage,
			"status": "Active",
			"uri":    uri,
		},
	})
	if err != nil {
		panic(err)
	}
	return data
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func writeJSON(path string, value any, mode fs.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", filepath.Base(path), err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "tuf-bootstrap: "+format+"\n", args...)
	os.Exit(1)
}
