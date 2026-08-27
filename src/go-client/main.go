package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	maximumPendingAttempts = 5
	pollInterval           = 2 * time.Second
	produceInterval        = 10 * time.Second
	requestTimeout         = 30 * time.Second
	trustStatusSchema      = 1
	trustStatusTargetName  = "trust_status.v1.json"
	tufCachePath           = "/tmp/sigstore-go-tuf-cache"
)

var tracer = otel.Tracer("sigstore.demo.go-client")

type config struct {
	artifactStoreURL *url.URL
	expectedIdentity string
	expectedIssuer   string
	oidcURL          *url.URL
	port             string
	tufRootPath      string
	tufURL           string
}

type artifactStore struct {
	baseURL *url.URL
	client  *http.Client
}

type artifactReservation struct {
	ID           uint64 `json:"id"`
	URL          string `json:"url"`
	SignatureURL string `json:"signatureUrl"`
	SealToken    string `json:"sealToken"`
}

type artifactHead struct {
	ID uint64 `json:"id"`
}

type publishedTrustStatus struct {
	SchemaVersion            int    `json:"schemaVersion"`
	TrustDomainID            string `json:"trustDomainId"`
	Generation               int    `json:"generation"`
	GenerationID             string `json:"generationId"`
	GenerationManifestSHA256 string `json:"generationManifestSha256"`
	TUFRootVersion           int    `json:"tufRootVersion"`
	TUFTargetsVersion        int    `json:"tufTargetsVersion"`
	TrustedRootSHA256        string `json:"trustedRootSha256"`
	SigningConfigSHA256      string `json:"signingConfigSha256"`
}

type clientTrustStatus struct {
	SchemaVersion            int       `json:"schemaVersion"`
	Resource                 string    `json:"resource"`
	Language                 string    `json:"language"`
	Ready                    bool      `json:"ready"`
	LastError                *string   `json:"lastError"`
	TrustDomainID            string    `json:"trustDomainId"`
	Generation               int       `json:"generation"`
	GenerationID             string    `json:"generationId"`
	GenerationManifestSHA256 string    `json:"generationManifestSha256"`
	TUFRootVersion           int       `json:"tufRootVersion"`
	TUFTargetsVersion        int       `json:"tufTargetsVersion"`
	TrustedRootSHA256        string    `json:"trustedRootSha256"`
	SigningConfigSHA256      string    `json:"signingConfigSha256"`
	InitializedAtUTC         time.Time `json:"initializedAtUtc"`
}

type tufMetadataEnvelope struct {
	Signed struct {
		Version int `json:"version"`
	} `json:"signed"`
}

type fetchState int

const (
	fetchFound fetchState = iota
	fetchMissing
	fetchPending
)

type fetchResult struct {
	state      fetchState
	content    []byte
	retryAfter time.Duration
}

type httpStatusError struct {
	status int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("HTTP status %d", e.status)
}

type tracedTransparency struct {
	inner sign.Transparency
	url   string
}

func (t *tracedTransparency) GetTransparencyLogEntry(
	ctx context.Context,
	keyOrCertPEM []byte,
	b *protobundle.Bundle,
) error {
	ctx, span := tracer.Start(
		ctx,
		"POST",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("http.request.method", http.MethodPost),
			attribute.String("url.full", strings.TrimRight(t.url, "/")+"/api/v2/log/entries"),
		),
	)
	defer span.End()

	err := t.inner.GetTransparencyLogEntry(ctx, keyOrCertPEM, b)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	return err
}

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer cancel()

	shutdownTelemetry, err := initTelemetry(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := shutdownTelemetry(context.Background()); err != nil {
			log.Printf("warning: failed to flush OpenTelemetry: %v", err)
		}
	}()

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	store := newArtifactStore(cfg.artifactStoreURL)
	trustedRoot, signingConfig, trustStatus, err := initializeTrust(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	signerOptions, err := createSignerOptions(signingConfig, trustedRoot)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := verify.NewVerifier(
		trustedRoot,
		verify.WithTransparencyLog(1),
		verify.WithSignedCertificateTimestamps(1),
		verify.WithSignedTimestamps(1),
	)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", healthHandler(ctx))
	mux.Handle("/trust/status", trustStatusHandler(ctx, trustStatus))
	server := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           otelhttp.NewHandler(mux, "client.status"),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("health server failed: %v", err)
			cancel()
		}
	}()

	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		producerLoop(ctx, cfg, store, signerOptions)
	}()
	go func() {
		defer workers.Done()
		validatorLoop(ctx, cfg, store, trustedRoot, verifier)
	}()

	log.Print("Go producer and validator started.")
	<-ctx.Done()
	shutdownContext, shutdownCancel := context.WithTimeout(
		context.Background(),
		requestTimeout,
	)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownContext)
	workers.Wait()
}

func loadConfig() (config, error) {
	artifactStoreURL, err := requiredURL("SHADY_BLOB_STORE_URL")
	if err != nil {
		return config{}, err
	}
	oidcURL, err := requiredURL("SIGSTORE_OIDC_URL")
	if err != nil {
		return config{}, err
	}
	return config{
		artifactStoreURL: artifactStoreURL,
		expectedIdentity: required("SIGSTORE_EXPECTED_IDENTITY"),
		expectedIssuer:   required("SIGSTORE_EXPECTED_ISSUER"),
		oidcURL:          oidcURL,
		port:             valueOrDefault("GO_CLIENT_PORT", "8080"),
		tufRootPath:      required("SIGSTORE_TUF_ROOT_PATH"),
		tufURL:           required("SIGSTORE_TUF_URL"),
	}, nil
}

func initTelemetry(ctx context.Context) (
	func(context.Context) error,
	error,
) {
	exporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, err
	}
	serviceName := valueOrDefault("OTEL_SERVICE_NAME", "go-client")
	res, err := resource.New(
		ctx,
		resource.WithAttributes(
			attribute.String("service.name", serviceName),
		),
	)
	if err != nil {
		return nil, err
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(provider)
	tracer = provider.Tracer("sigstore.demo.go-client")
	return provider.Shutdown, nil
}

func initializeTrust(
	ctx context.Context,
	cfg config,
) (*root.TrustedRoot, *root.SigningConfig, clientTrustStatus, error) {
	ctx, span := tracer.Start(
		ctx,
		"sigstore.trust.initialize",
		trace.WithAttributes(
			attribute.String("client.language", "go"),
			attribute.String("client.resource.name", "go-client"),
		),
	)
	defer span.End()

	rootBytes, err := os.ReadFile(cfg.tufRootPath)
	if err != nil {
		return nil, nil, clientTrustStatus{}, recordError(span, err)
	}
	httpTransport := otelhttp.NewTransport(http.DefaultTransport)
	defaultFetcher := fetcher.NewDefaultFetcher()
	defaultFetcher.SetHTTPUserAgent(util.ConstructUserAgent())
	defaultFetcher.SetTransport(httpTransport)
	client, err := tuf.New(&tuf.Options{
		CachePath:         tufCachePath,
		Context:           ctx,
		Fetcher:           defaultFetcher,
		RepositoryBaseURL: cfg.tufURL,
		Root:              rootBytes,
	})
	if err != nil {
		return nil, nil, clientTrustStatus{}, recordError(span, err)
	}
	trustedRoot, err := root.GetTrustedRoot(client)
	if err != nil {
		return nil, nil, clientTrustStatus{}, recordError(span, err)
	}
	signingConfig, err := root.GetSigningConfig(client)
	if err != nil {
		return nil, nil, clientTrustStatus{}, recordError(span, err)
	}
	trustedRootBytes, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return nil, nil, clientTrustStatus{}, recordError(span, err)
	}
	signingConfigBytes, err := client.GetTarget("signing_config.v0.2.json")
	if err != nil {
		return nil, nil, clientTrustStatus{}, recordError(span, err)
	}
	publishedBytes, err := client.GetTarget(trustStatusTargetName)
	if err != nil {
		return nil, nil, clientTrustStatus{}, recordError(span, err)
	}
	metadataPath := filepath.Join(
		tufCachePath,
		tuf.URLToPath(cfg.tufURL),
	)
	rootVersion, err := readTUFMetadataVersion(
		filepath.Join(metadataPath, "root.json"),
	)
	if err != nil {
		return nil, nil, clientTrustStatus{}, recordError(span, err)
	}
	targetsVersion, err := readTUFMetadataVersion(
		filepath.Join(metadataPath, "targets.json"),
	)
	if err != nil {
		return nil, nil, clientTrustStatus{}, recordError(span, err)
	}
	status, err := newClientTrustStatus(
		"go-client",
		"go",
		publishedBytes,
		trustedRootBytes,
		signingConfigBytes,
		rootVersion,
		targetsVersion,
		time.Now().UTC(),
	)
	if err != nil {
		return nil, nil, clientTrustStatus{}, recordError(span, err)
	}
	setTrustSpanAttributes(span, status)
	span.SetStatus(codes.Ok, "")
	return trustedRoot, signingConfig, status, nil
}

func createSignerOptions(
	signingConfig *root.SigningConfig,
	trustedRoot *root.TrustedRoot,
) (sign.BundleOptions, error) {
	transport := otelhttp.NewTransport(http.DefaultTransport)
	fulcioService, err := root.SelectService(
		signingConfig.FulcioCertificateAuthorityURLs(),
		sign.FulcioAPIVersions,
		time.Now(),
	)
	if err != nil {
		return sign.BundleOptions{}, err
	}
	rekorService, err := root.SelectService(
		signingConfig.RekorLogURLs(),
		[]uint32{2},
		time.Now(),
	)
	if err != nil {
		return sign.BundleOptions{}, err
	}
	tsaServices, err := root.SelectServices(
		signingConfig.TimestampAuthorityURLs(),
		signingConfig.TimestampAuthorityURLsConfig(),
		sign.TimestampAuthorityAPIVersions,
		time.Now(),
	)
	if err != nil {
		return sign.BundleOptions{}, err
	}
	if len(tsaServices) == 0 {
		return sign.BundleOptions{}, errors.New("no timestamp authority configured")
	}

	options := sign.BundleOptions{
		CertificateProvider: sign.NewFulcio(&sign.FulcioOptions{
			BaseURL:   fulcioService.URL,
			Retries:   1,
			Timeout:   requestTimeout,
			Transport: transport,
		}),
		TimestampAuthorities: []*sign.TimestampAuthority{
			sign.NewTimestampAuthority(&sign.TimestampAuthorityOptions{
				URL:       tsaServices[0].URL,
				Retries:   1,
				Timeout:   requestTimeout,
				Transport: transport,
			}),
		},
		TransparencyLogs: []sign.Transparency{
			&tracedTransparency{
				inner: sign.NewRekor(&sign.RekorOptions{
					BaseURL: rekorService.URL,
					Retries: 1,
					Timeout: 90 * time.Second,
					Version: 2,
				}),
				url: rekorService.URL,
			},
		},
		TrustedRoot: trustedRoot,
	}
	return options, nil
}

func producerLoop(
	ctx context.Context,
	cfg config,
	store *artifactStore,
	baseOptions sign.BundleOptions,
) {
	for ctx.Err() == nil {
		if err := produceOnce(ctx, cfg, store, baseOptions); err != nil {
			log.Printf("Failed to produce an artifact: %v", err)
		}
		if wait(ctx, produceInterval) {
			return
		}
	}
}

func produceOnce(
	ctx context.Context,
	cfg config,
	store *artifactStore,
	baseOptions sign.BundleOptions,
) error {
	randomSize, err := rand.Int(
		rand.Reader,
		big.NewInt(4097-256),
	)
	if err != nil {
		return err
	}
	size := 256 + int(randomSize.Int64())
	artifact := make([]byte, size)
	if _, err := rand.Read(artifact); err != nil {
		return err
	}

	ctx, span := tracer.Start(
		ctx,
		"artifact.produce",
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			attribute.Int("artifact.size", len(artifact)),
			attribute.String("client.language", "go"),
		),
	)
	defer span.End()

	token, err := getIdentityToken(ctx, cfg)
	if err != nil {
		return recordError(span, err)
	}
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return recordError(span, err)
	}
	options := baseOptions
	options.Context = ctx
	options.CertificateProviderOptions = &sign.CertificateProviderOptions{
		IDToken: token,
	}
	protoBundle, err := sign.Bundle(
		&sign.PlainData{Data: artifact},
		keypair,
		options,
	)
	if err != nil {
		return recordError(span, err)
	}
	bundleJSON, err := protojson.Marshal(protoBundle)
	if err != nil {
		return recordError(span, err)
	}
	reservation, err := store.uploadArtifact(ctx, artifact)
	if err != nil {
		return recordError(span, err)
	}
	span.SetAttributes(attribute.Int64("artifact.id", int64(reservation.ID)))

	for ctx.Err() == nil {
		err = store.uploadSignature(ctx, reservation, bundleJSON)
		if err == nil {
			break
		}
		var statusError *httpStatusError
		if errors.As(err, &statusError) && statusError.status < 500 {
			return recordError(span, err)
		}
		log.Printf(
			"Signature upload for artifact %d failed; retrying: %v",
			reservation.ID,
			err,
		)
		if wait(ctx, pollInterval) {
			return ctx.Err()
		}
	}

	log.Printf(
		"Produced and signed artifact %d (%d bytes).",
		reservation.ID,
		len(artifact),
	)
	return nil
}

func getIdentityToken(ctx context.Context, cfg config) (string, error) {
	tokenURL := cfg.oidcURL.ResolveReference(&url.URL{Path: "token"})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return "", err
	}
	response, err := newHTTPClient().Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if !isSuccess(response.StatusCode) {
		return "", &httpStatusError{status: response.StatusCode}
	}
	tokenBytes, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(tokenBytes))
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("OIDC endpoint did not return a JWT")
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return "", err
	}
	if claims.Subject != cfg.expectedIdentity {
		return "", errors.New("OIDC identity did not match expected identity")
	}
	if claims.Issuer != cfg.expectedIssuer {
		return "", errors.New("OIDC issuer did not match expected issuer")
	}
	return token, nil
}

func validatorLoop(
	ctx context.Context,
	cfg config,
	store *artifactStore,
	trustedRoot *root.TrustedRoot,
	verifier *verify.SignedEntityVerifier,
) {
	nextID := uint64(1)
	highWatermark := uint64(0)
	pendingAttempts := 0

	for ctx.Err() == nil {
		retryAfter := pollInterval
		if nextID > highWatermark {
			head, err := store.head(ctx)
			if err != nil {
				log.Printf("Failed to read artifact head: %v", err)
				if wait(ctx, retryAfter) {
					return
				}
				continue
			}
			if head < highWatermark {
				log.Printf(
					"Artifact head moved backward from %d to %d.",
					highWatermark,
					head,
				)
				if wait(ctx, retryAfter) {
					return
				}
				continue
			}
			highWatermark = head
			if nextID > highWatermark {
				if wait(ctx, retryAfter) {
					return
				}
				continue
			}
		}

		action, delay, err := validateOnce(
			ctx,
			nextID,
			store,
			trustedRoot,
			verifier,
			cfg,
		)
		if err != nil {
			log.Printf("Failed to validate artifact %d: %v", nextID, err)
		} else {
			switch action {
			case "validated":
				nextID++
				pendingAttempts = 0
				continue
			case "pending":
				pendingAttempts++
				if pendingAttempts >= maximumPendingAttempts {
					skipArtifact(
						ctx,
						nextID,
						fmt.Sprintf(
							"The artifact remained unsealed after %d attempts.",
							pendingAttempts,
						),
						pendingAttempts,
					)
					nextID++
					pendingAttempts = 0
					continue
				}
				retryAfter = delay
			case "missing":
				skipArtifact(
					ctx,
					nextID,
					"The artifact is below the sealed head but is missing.",
					pendingAttempts,
				)
				nextID++
				pendingAttempts = 0
				continue
			}
		}
		if wait(ctx, retryAfter) {
			return
		}
	}
}

func validateOnce(
	ctx context.Context,
	id uint64,
	store *artifactStore,
	trustedRoot *root.TrustedRoot,
	verifier *verify.SignedEntityVerifier,
	cfg config,
) (string, time.Duration, error) {
	artifactResult, err := store.artifact(ctx, id)
	if err != nil {
		return "", 0, err
	}
	if artifactResult.state == fetchMissing {
		return "missing", 0, nil
	}
	if artifactResult.state == fetchPending {
		return "pending", artifactResult.retryAfter, nil
	}
	signatureResult, err := store.signature(ctx, id)
	if err != nil {
		return "", 0, err
	}
	if signatureResult.state == fetchMissing {
		return "missing", 0, nil
	}
	if signatureResult.state == fetchPending {
		return "pending", signatureResult.retryAfter, nil
	}

	protoBundle := &protobundle.Bundle{}
	if err := protojson.Unmarshal(signatureResult.content, protoBundle); err != nil {
		return "", 0, err
	}
	parsedBundle, err := bundle.NewBundle(protoBundle)
	if err != nil {
		return "", 0, err
	}
	certificateIdentity, err := verify.NewShortCertificateIdentity(
		cfg.expectedIssuer,
		"",
		cfg.expectedIdentity,
		"",
	)
	if err != nil {
		return "", 0, err
	}
	policy := verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(artifactResult.content)),
		verify.WithCertificateIdentity(certificateIdentity),
	)
	ctx, span := tracer.Start(
		ctx,
		"artifact.validate",
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.Int64("artifact.id", int64(id)),
			attribute.Int("artifact.size", len(artifactResult.content)),
			attribute.String("client.language", "go"),
		),
	)
	defer span.End()
	_, err = verifier.Verify(parsedBundle, policy)
	if err != nil {
		return "", 0, recordError(span, err)
	}
	log.Printf("Validated artifact %d (%d bytes).", id, len(artifactResult.content))
	return "validated", 0, nil
}

func skipArtifact(
	ctx context.Context,
	id uint64,
	reason string,
	attempts int,
) {
	_, span := tracer.Start(
		ctx,
		"artifact.skip",
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.Int64("artifact.id", int64(id)),
			attribute.Int("artifact.retry_count", attempts),
			attribute.String("artifact.warning", reason),
			attribute.String("client.language", "go"),
		),
	)
	span.AddEvent("artifact.skipped")
	log.Printf("Skipping artifact %d: %s", id, reason)
	span.End()
}

func newArtifactStore(baseURL *url.URL) *artifactStore {
	return &artifactStore{
		baseURL: baseURL,
		client:  newHTTPClient(),
	}
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
}

func (s *artifactStore) uploadArtifact(
	ctx context.Context,
	artifact []byte,
) (artifactReservation, error) {
	endpoint := s.baseURL.ResolveReference(&url.URL{Path: "artifacts"})
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint.String(),
		bytes.NewReader(artifact),
	)
	if err != nil {
		return artifactReservation{}, err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := s.client.Do(request)
	if err != nil {
		return artifactReservation{}, err
	}
	defer response.Body.Close()
	if !isSuccess(response.StatusCode) {
		return artifactReservation{}, &httpStatusError{status: response.StatusCode}
	}
	var reservation artifactReservation
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&reservation); err != nil {
		return artifactReservation{}, err
	}
	if reservation.ID == 0 || reservation.SealToken == "" {
		return artifactReservation{}, errors.New("artifact store returned invalid reservation")
	}
	artifactURL, err := url.Parse(reservation.URL)
	if err != nil {
		return artifactReservation{}, err
	}
	signatureURL, err := url.Parse(reservation.SignatureURL)
	if err != nil {
		return artifactReservation{}, err
	}
	expected := s.baseURL.ResolveReference(
		&url.URL{Path: fmt.Sprintf("artifacts/%d", reservation.ID)},
	)
	if artifactURL.String() != expected.String() ||
		signatureURL.String() != expected.String()+"/signature" ||
		artifactURL.Scheme != s.baseURL.Scheme ||
		artifactURL.Host != s.baseURL.Host ||
		signatureURL.Scheme != s.baseURL.Scheme ||
		signatureURL.Host != s.baseURL.Host {
		return artifactReservation{}, errors.New("artifact store returned unexpected URL")
	}
	return reservation, nil
}

func (s *artifactStore) uploadSignature(
	ctx context.Context,
	reservation artifactReservation,
	bundleJSON []byte,
) error {
	endpoint, err := url.Parse(reservation.SignatureURL)
	if err != nil {
		return err
	}
	if endpoint.Scheme != s.baseURL.Scheme || endpoint.Host != s.baseURL.Host {
		return errors.New("refusing signature upload outside artifact store")
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint.String(),
		bytes.NewReader(bundleJSON),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/vnd.dev.sigstore.bundle+json")
	request.Header.Set("X-Artifact-Seal-Token", reservation.SealToken)
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if !isSuccess(response.StatusCode) {
		return &httpStatusError{status: response.StatusCode}
	}
	return nil
}

func (s *artifactStore) head(ctx context.Context) (uint64, error) {
	result, err := s.get(ctx, "artifacts/head")
	if err != nil {
		return 0, err
	}
	defer result.Body.Close()
	if !isSuccess(result.StatusCode) {
		return 0, &httpStatusError{status: result.StatusCode}
	}
	var head artifactHead
	err = json.NewDecoder(io.LimitReader(result.Body, 1<<20)).Decode(&head)
	return head.ID, err
}

func (s *artifactStore) artifact(
	ctx context.Context,
	id uint64,
) (fetchResult, error) {
	return s.fetch(ctx, fmt.Sprintf("artifacts/%d", id))
}

func (s *artifactStore) signature(
	ctx context.Context,
	id uint64,
) (fetchResult, error) {
	return s.fetch(ctx, fmt.Sprintf("artifacts/%d/signature", id))
}

func (s *artifactStore) fetch(
	ctx context.Context,
	path string,
) (fetchResult, error) {
	response, err := s.get(ctx, path)
	if err != nil {
		return fetchResult{}, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNotFound:
		return fetchResult{state: fetchMissing}, nil
	case 425:
		return fetchResult{
			state:      fetchPending,
			retryAfter: parseRetryAfter(response),
		}, nil
	default:
		if !isSuccess(response.StatusCode) {
			return fetchResult{}, &httpStatusError{status: response.StatusCode}
		}
		content, err := io.ReadAll(io.LimitReader(response.Body, 17<<20))
		return fetchResult{state: fetchFound, content: content}, err
	}
}

func (s *artifactStore) get(
	ctx context.Context,
	path string,
) (*http.Response, error) {
	endpoint := s.baseURL.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		endpoint.String(),
		nil,
	)
	if err != nil {
		return nil, err
	}
	return s.client.Do(request)
}

func healthHandler(ctx context.Context) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" || ctx.Err() != nil {
			http.Error(response, `{"status":"NOT_SERVING"}`, http.StatusServiceUnavailable)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte(`{"status":"SERVING"}`))
	})
}

func trustStatusHandler(
	ctx context.Context,
	status clientTrustStatus,
) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		current := status
		if ctx.Err() != nil {
			message := "client is stopping"
			current.Ready = false
			current.LastError = &message
		}
		response.Header().Set("Content-Type", "application/json")
		if !current.Ready {
			response.WriteHeader(http.StatusServiceUnavailable)
		} else {
			response.WriteHeader(http.StatusOK)
		}
		if err := json.NewEncoder(response).Encode(current); err != nil {
			log.Printf("write trust status: %v", err)
		}
	})
}

func newClientTrustStatus(
	resourceName string,
	language string,
	publishedBytes []byte,
	trustedRootBytes []byte,
	signingConfigBytes []byte,
	rootVersion int,
	targetsVersion int,
	initializedAt time.Time,
) (clientTrustStatus, error) {
	var published publishedTrustStatus
	if err := json.Unmarshal(publishedBytes, &published); err != nil {
		return clientTrustStatus{}, fmt.Errorf("parse published trust status: %w", err)
	}
	trustedRootHash := sha256Hex(trustedRootBytes)
	signingConfigHash := sha256Hex(signingConfigBytes)
	if published.SchemaVersion != trustStatusSchema ||
		published.TrustDomainID == "" ||
		published.Generation <= 0 ||
		published.GenerationID == "" ||
		published.TUFRootVersion != rootVersion ||
		published.TUFTargetsVersion != targetsVersion ||
		published.TrustedRootSHA256 != trustedRootHash ||
		published.SigningConfigSHA256 != signingConfigHash ||
		!isLowerHexSHA256(published.GenerationManifestSHA256) {
		return clientTrustStatus{}, errors.New(
			"published trust status does not match verified TUF material",
		)
	}
	return clientTrustStatus{
		SchemaVersion:            trustStatusSchema,
		Resource:                 resourceName,
		Language:                 language,
		Ready:                    true,
		TrustDomainID:            published.TrustDomainID,
		Generation:               published.Generation,
		GenerationID:             published.GenerationID,
		GenerationManifestSHA256: published.GenerationManifestSHA256,
		TUFRootVersion:           rootVersion,
		TUFTargetsVersion:        targetsVersion,
		TrustedRootSHA256:        trustedRootHash,
		SigningConfigSHA256:      signingConfigHash,
		InitializedAtUTC:         initializedAt,
	}, nil
}

func readTUFMetadataVersion(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read TUF metadata %s: %w", filepath.Base(path), err)
	}
	var envelope tufMetadataEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return 0, fmt.Errorf("parse TUF metadata %s: %w", filepath.Base(path), err)
	}
	if envelope.Signed.Version <= 0 {
		return 0, fmt.Errorf(
			"TUF metadata %s has invalid version %d",
			filepath.Base(path),
			envelope.Signed.Version,
		)
	}
	return envelope.Signed.Version, nil
}

func setTrustSpanAttributes(span trace.Span, status clientTrustStatus) {
	span.SetAttributes(
		attribute.String("sigstore.trust.domain.id", status.TrustDomainID),
		attribute.Int("sigstore.trust.generation", status.Generation),
		attribute.String("sigstore.trust.generation.id", status.GenerationID),
		attribute.String(
			"sigstore.trust.generation.manifest.sha256",
			status.GenerationManifestSHA256,
		),
		attribute.Int("sigstore.trust.tuf.root.version", status.TUFRootVersion),
		attribute.Int("sigstore.trust.tuf.targets.version", status.TUFTargetsVersion),
		attribute.String(
			"sigstore.trust.trusted_root.sha256",
			status.TrustedRootSHA256,
		),
		attribute.String(
			"sigstore.trust.signing_config.sha256",
			status.SigningConfigSHA256,
		),
		attribute.String(
			"sigstore.trust.initialized_at",
			status.InitializedAtUTC.Format(time.RFC3339Nano),
		),
	)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func isLowerHexSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func recordError(span trace.Span, err error) error {
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
	return err
}

func parseRetryAfter(response *http.Response) time.Duration {
	seconds, err := strconv.ParseFloat(response.Header.Get("Retry-After"), 64)
	if err != nil {
		return pollInterval
	}
	if seconds < 0.1 {
		seconds = 0.1
	}
	if seconds > 30 {
		seconds = 30
	}
	return time.Duration(seconds * float64(time.Second))
}

func isSuccess(status int) bool {
	return status >= 200 && status < 300
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-timer.C:
		return false
	}
}

func required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s must be configured", name)
	}
	return value
}

func valueOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func requiredURL(name string) (*url.URL, error) {
	value := required(name)
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%s must be an absolute HTTP(S) URL", name)
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}
	return parsed, nil
}
