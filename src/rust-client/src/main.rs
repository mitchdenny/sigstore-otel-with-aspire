use std::error::Error;
use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithTonicConfig;
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use rand::RngCore;
use reqwest::{Client, RequestBuilder, Response, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigstore_oidc::IdentityToken;
use sigstore_sign::{SigningConfig as RuntimeSigningConfig, SigningContext};
use sigstore_trust_root::{SigningConfig as TufSigningConfig, TrustedRoot};
use sigstore_tuf::transport::FetchFuture;
use sigstore_tuf::{FileStore, HttpRepository, Repository, Updater};
use sigstore_types::Bundle;
use sigstore_verify::{verify, VerificationPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tonic::transport::{Certificate, ClientTlsConfig};
use tracing::{field, Instrument, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const CACHE_PATH: &str = "/tmp/sigstore-rust-tuf-cache";
const TRUST_STATUS_SCHEMA_VERSION: u32 = 1;
const TRUST_STATUS_TARGET_NAME: &str = "trust_status.v1.json";
const MAXIMUM_PENDING_ATTEMPTS: usize = 5;
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const PRODUCE_INTERVAL: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Debug)]
struct HttpStatusError(u16);

impl fmt::Display for HttpStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "HTTP status {}", self.0)
    }
}

impl Error for HttpStatusError {}

struct TelemetryGuard {
    provider: SdkTracerProvider,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Err(error) = self.provider.shutdown() {
            eprintln!("warning: failed to flush OpenTelemetry spans: {error}");
        }
    }
}

#[derive(Clone)]
struct TracedRepository {
    inner: HttpRepository,
    metadata_base: String,
    targets_base: String,
}

impl TracedRepository {
    fn new(base_url: &str) -> Result<Self, sigstore_tuf::Error> {
        let normalized = base_url.trim_end_matches('/');
        Ok(Self {
            inner: HttpRepository::new(normalized)?,
            metadata_base: normalized.to_string(),
            targets_base: format!("{normalized}/targets"),
        })
    }
}

impl Repository for TracedRepository {
    fn fetch_metadata<'a>(&'a self, name: &'a str, max_length: u64) -> FetchFuture<'a> {
        let url = format!("{}/{}", self.metadata_base, name);
        let span = http_span(&url, "metadata", name);
        let fetch = self.inner.fetch_metadata(name, max_length);

        Box::pin(
            async move {
                let result = fetch.await;
                record_tuf_result(&result);
                result
            }
            .instrument(span),
        )
    }

    fn fetch_target<'a>(&'a self, path: &'a str, max_length: u64) -> FetchFuture<'a> {
        let url = format!("{}/{}", self.targets_base, path);
        let span = http_span(&url, "target", path);
        let fetch = self.inner.fetch_target(path, max_length);

        Box::pin(
            async move {
                let result = fetch.await;
                record_tuf_result(&result);
                result
            }
            .instrument(span),
        )
    }
}

#[derive(Clone)]
struct Config {
    artifact_store_url: Url,
    expected_identity: String,
    expected_issuer: String,
    oidc_url: Url,
    port: u16,
    tuf_root_path: String,
    tuf_url: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublishedTrustStatus {
    schema_version: u32,
    trust_domain_id: String,
    generation: u64,
    generation_id: String,
    generation_manifest_sha256: String,
    tuf_root_version: u64,
    tuf_targets_version: u64,
    trusted_root_sha256: String,
    signing_config_sha256: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientTrustStatus {
    schema_version: u32,
    resource: String,
    language: String,
    ready: bool,
    last_error: Option<String>,
    trust_domain_id: String,
    generation: u64,
    generation_id: String,
    generation_manifest_sha256: String,
    tuf_root_version: u64,
    tuf_targets_version: u64,
    trusted_root_sha256: String,
    signing_config_sha256: String,
    initialized_at_utc: String,
}

impl Config {
    fn from_environment() -> Result<Self> {
        Ok(Self {
            artifact_store_url: required_url("SHADY_BLOB_STORE_URL")?,
            expected_identity: required("SIGSTORE_EXPECTED_IDENTITY")?,
            expected_issuer: required("SIGSTORE_EXPECTED_ISSUER")?,
            oidc_url: required_url("SIGSTORE_OIDC_URL")?,
            port: std::env::var("RUST_CLIENT_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .context("RUST_CLIENT_PORT must be an integer")?,
            tuf_root_path: required("SIGSTORE_TUF_ROOT_PATH")?,
            tuf_url: required("SIGSTORE_TUF_URL")?,
        })
    }
}

#[derive(Clone)]
struct ArtifactStore {
    base_url: Url,
    client: Client,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactReservation {
    id: u64,
    url: String,
    signature_url: String,
    seal_token: String,
}

#[derive(Deserialize)]
struct ArtifactHead {
    id: u64,
}

enum ArtifactFetch<T> {
    Found(T),
    Missing,
    Pending(Duration),
}

impl ArtifactStore {
    fn new(base_url: Url) -> Result<Self> {
        Ok(Self {
            base_url,
            client: Client::builder().timeout(REQUEST_TIMEOUT).build()?,
        })
    }

    async fn upload_artifact(&self, artifact: &[u8]) -> Result<ArtifactReservation> {
        let url = self.base_url.join("artifacts")?;
        let response = self
            .send(
                "POST",
                &url,
                self.client
                    .post(url.clone())
                    .header("Content-Type", "application/octet-stream")
                    .body(artifact.to_vec()),
            )
            .await?;
        ensure_success(&response)?;
        let reservation: ArtifactReservation = response.json().await?;
        if reservation.id == 0 || reservation.seal_token.is_empty() {
            bail!("artifact store returned an invalid reservation");
        }

        let expected_url = self
            .base_url
            .join(&format!("artifacts/{}", reservation.id))?;
        let returned_url = Url::parse(&reservation.url)?;
        let signature_url = Url::parse(&reservation.signature_url)?;
        if returned_url != expected_url
            || signature_url.as_str() != format!("{}/signature", expected_url).as_str()
            || returned_url.origin() != self.base_url.origin()
            || signature_url.origin() != self.base_url.origin()
        {
            bail!("artifact store returned an unexpected artifact URL");
        }
        Ok(reservation)
    }

    async fn upload_signature(
        &self,
        reservation: &ArtifactReservation,
        bundle: &str,
    ) -> Result<()> {
        let url = Url::parse(&reservation.signature_url)?;
        if url.origin() != self.base_url.origin() {
            bail!("refusing to upload a signature outside the artifact store");
        }
        let response = self
            .send(
                "POST",
                &url,
                self.client
                    .post(url.clone())
                    .header("Content-Type", "application/vnd.dev.sigstore.bundle+json")
                    .header("X-Artifact-Seal-Token", &reservation.seal_token)
                    .body(bundle.to_string()),
            )
            .await?;
        ensure_success(&response)?;
        Ok(())
    }

    async fn head(&self) -> Result<u64> {
        let url = self.base_url.join("artifacts/head")?;
        let response = self.send("GET", &url, self.client.get(url.clone())).await?;
        ensure_success(&response)?;
        Ok(response.json::<ArtifactHead>().await?.id)
    }

    async fn artifact(&self, id: u64) -> Result<ArtifactFetch<Vec<u8>>> {
        let url = self.base_url.join(&format!("artifacts/{id}"))?;
        let response = self.send("GET", &url, self.client.get(url.clone())).await?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(ArtifactFetch::Missing),
            status if status.as_u16() == 425 => Ok(ArtifactFetch::Pending(retry_after(&response))),
            _ => {
                ensure_success(&response)?;
                Ok(ArtifactFetch::Found(response.bytes().await?.to_vec()))
            }
        }
    }

    async fn signature(&self, id: u64) -> Result<ArtifactFetch<String>> {
        let url = self.base_url.join(&format!("artifacts/{id}/signature"))?;
        let response = self.send("GET", &url, self.client.get(url.clone())).await?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(ArtifactFetch::Missing),
            status if status.as_u16() == 425 => Ok(ArtifactFetch::Pending(retry_after(&response))),
            _ => {
                ensure_success(&response)?;
                Ok(ArtifactFetch::Found(response.text().await?))
            }
        }
    }

    async fn send(
        &self,
        method: &'static str,
        url: &Url,
        request: RequestBuilder,
    ) -> Result<Response> {
        let span = tracing::info_span!(
            "http.client",
            otel.name = method,
            otel.kind = "client",
            otel.status_code = field::Empty,
            http.request.method = method,
            http.response.status_code = field::Empty,
            url.full = %url,
            error.type = field::Empty,
        );
        let response = request.send().instrument(span.clone()).await;
        match &response {
            Ok(response) => {
                span.record(
                    "http.response.status_code",
                    response.status().as_u16() as i64,
                );
                if response.status().is_server_error() {
                    span.record("otel.status_code", "ERROR");
                }
            }
            Err(error) => {
                span.record("otel.status_code", "ERROR");
                span.record("error.type", field::display(error));
            }
        }
        Ok(response?)
    }
}

fn init_telemetry() -> Result<TelemetryGuard, BoxError> {
    let mut exporter_builder = opentelemetry_otlp::SpanExporter::builder().with_tonic();
    if let Ok(certificate_path) = std::env::var("OTEL_EXPORTER_OTLP_CERTIFICATE") {
        let certificate = Certificate::from_pem(fs::read(certificate_path)?);
        exporter_builder =
            exporter_builder.with_tls_config(ClientTlsConfig::new().ca_certificate(certificate));
    }
    let exporter = exporter_builder.build()?;
    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "rust-client".to_string());
    let provider = SdkTracerProvider::builder()
        .with_resource(Resource::builder().with_service_name(service_name).build())
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer("sigstore.demo.rust-client");

    tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init()?;

    Ok(TelemetryGuard { provider })
}

async fn initialize_trust(
    config: &Config,
) -> Result<(TrustedRoot, SigningContext, ClientTrustStatus)> {
    let span = tracing::info_span!(
        "sigstore.trust.initialize",
        otel.status_code = field::Empty,
        client.language = "rust",
        client.resource.name = "rust-client",
        sigstore.trust.domain.id = field::Empty,
        sigstore.trust.generation = field::Empty,
        sigstore.trust.generation.id = field::Empty,
        sigstore.trust.generation.manifest.sha256 = field::Empty,
        sigstore.trust.tuf.root.version = field::Empty,
        sigstore.trust.tuf.targets.version = field::Empty,
        sigstore.trust.trusted_root.sha256 = field::Empty,
        sigstore.trust.signing_config.sha256 = field::Empty,
        sigstore.trust.initialized_at = field::Empty,
        error.type = field::Empty,
    );
    let result = async {
        let repository = TracedRepository::new(&config.tuf_url)?;
        let bootstrap_root = fs::read(&config.tuf_root_path)?;
        let mut updater =
            Updater::new(repository, &bootstrap_root)?.with_store(FileStore::new(CACHE_PATH));
        let now = jiff::Timestamp::now();
        updater.refresh(now).await?;
        let root_version = updater.trusted().root().version;
        let targets_version = updater
            .trusted()
            .targets()
            .context("TUF targets metadata was not initialized")?
            .version;
        let trusted_root_bytes = updater.get_target("trusted_root.json", now).await?;
        let signing_config_bytes = updater.get_target("signing_config.v0.2.json", now).await?;
        let published_status_bytes = updater.get_target(TRUST_STATUS_TARGET_NAME, now).await?;
        let trusted_root_json = String::from_utf8(trusted_root_bytes.clone())?;
        let signing_config_json = String::from_utf8(signing_config_bytes.clone())?;
        let trusted_root = TrustedRoot::from_json(&trusted_root_json)?;
        let tuf_signing_config = TufSigningConfig::from_json(&signing_config_json)?;
        let runtime_signing_config =
            RuntimeSigningConfig::from_tuf_config_with_rekor_version(&tuf_signing_config, Some(2))?;
        let status = build_client_trust_status(
            &published_status_bytes,
            &trusted_root_bytes,
            &signing_config_bytes,
            root_version,
            targets_version,
            jiff::Timestamp::now().to_string(),
        )?;
        Ok::<_, anyhow::Error>((
            trusted_root,
            SigningContext::with_config(runtime_signing_config),
            status,
        ))
    }
    .instrument(span.clone())
    .await;
    if let Ok((_, _, status)) = &result {
        record_trust_span_attributes(&span, status);
    }
    record_result(&span, &result);
    result
}

async fn producer_loop(
    config: Config,
    artifact_store: ArtifactStore,
    signing_context: Arc<SigningContext>,
    mut shutdown: watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        if let Err(error) = produce_once(&config, &artifact_store, &signing_context).await {
            tracing::error!(error = %error, "Failed to produce an artifact.");
        }
        if wait_or_shutdown(&mut shutdown, PRODUCE_INTERVAL).await {
            break;
        }
    }
}

async fn produce_once(
    config: &Config,
    artifact_store: &ArtifactStore,
    signing_context: &SigningContext,
) -> Result<()> {
    let size = rand::random_range(256..4097);
    let mut artifact = vec![0_u8; size];
    rand::rng().fill_bytes(&mut artifact);
    let span = tracing::info_span!(
        "artifact.produce",
        otel.kind = "producer",
        otel.status_code = field::Empty,
        artifact.id = field::Empty,
        artifact.size = size as i64,
        client.language = "rust",
        error.type = field::Empty,
    );
    let result = async {
        let token = fetch_identity_token(config).await?;
        let signer = signing_context.signer(token);
        let sign_span = tracing::info_span!(
            "sigstore.sign",
            fulcio.url = %signing_context.config().fulcio_url,
            rekor.url = %signing_context.config().rekor_url,
            tsa.url = ?signing_context.config().tsa_url,
        );
        let bundle = signer
            .sign(artifact.as_slice())
            .instrument(sign_span)
            .await?;
        let bundle_json = bundle.to_json()?;
        let reservation = artifact_store.upload_artifact(&artifact).await?;
        Span::current().record("artifact.id", reservation.id as i64);

        loop {
            match artifact_store
                .upload_signature(&reservation, &bundle_json)
                .await
            {
                Ok(()) => break,
                Err(error) => {
                    if error
                        .downcast_ref::<HttpStatusError>()
                        .is_some_and(|status| status.0 < 500)
                    {
                        return Err(error);
                    }
                    tracing::warn!(
                        artifact.id = reservation.id,
                        error = %error,
                        "Signature upload failed; retrying."
                    );
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }
        }
        tracing::info!(
            artifact.id = reservation.id,
            artifact.size = artifact.len(),
            "Produced and signed artifact."
        );
        Ok::<_, anyhow::Error>(())
    }
    .instrument(span.clone())
    .await;
    record_result(&span, &result);
    result
}

async fn fetch_identity_token(config: &Config) -> Result<IdentityToken> {
    let client = Client::builder().timeout(REQUEST_TIMEOUT).build()?;
    let url = config.oidc_url.join("token")?;
    let span = http_span(url.as_str(), "oidc", "token");
    let response = client.get(url).send().instrument(span.clone()).await?;
    span.record(
        "http.response.status_code",
        response.status().as_u16() as i64,
    );
    ensure_success(&response)?;
    let token = IdentityToken::from_jwt(response.text().await?.trim())?;
    if token.identity() != config.expected_identity {
        bail!("OIDC identity did not match the expected identity");
    }
    if token.issuer() != config.expected_issuer {
        bail!("OIDC issuer did not match the expected issuer");
    }
    Ok(token)
}

async fn validator_loop(
    config: Config,
    artifact_store: ArtifactStore,
    trusted_root: Arc<TrustedRoot>,
    mut shutdown: watch::Receiver<bool>,
) {
    let policy = VerificationPolicy::default()
        .require_identity(config.expected_identity)
        .require_issuer(config.expected_issuer);
    let mut artifact_id = 1_u64;
    let mut high_watermark = 0_u64;
    let mut pending_attempts = 0_usize;

    while !*shutdown.borrow() {
        let mut retry_after = POLL_INTERVAL;
        let result = async {
            if artifact_id > high_watermark {
                let observed_head = artifact_store.head().await?;
                if observed_head < high_watermark {
                    bail!("artifact head moved backward from {high_watermark} to {observed_head}");
                }
                high_watermark = observed_head;
                if artifact_id > high_watermark {
                    return Ok(ValidationAction::Wait);
                }
            }

            match validate_once(artifact_id, &artifact_store, &trusted_root, &policy).await? {
                ValidationAction::Validated => {
                    artifact_id += 1;
                    pending_attempts = 0;
                    Ok(ValidationAction::Validated)
                }
                ValidationAction::Pending(delay) => {
                    pending_attempts += 1;
                    if pending_attempts >= MAXIMUM_PENDING_ATTEMPTS {
                        skip_artifact(
                            artifact_id,
                            &format!(
                                "The artifact remained unsealed after {pending_attempts} attempts."
                            ),
                            pending_attempts,
                        );
                        artifact_id += 1;
                        pending_attempts = 0;
                        Ok(ValidationAction::Validated)
                    } else {
                        Ok(ValidationAction::Pending(delay))
                    }
                }
                ValidationAction::Missing(reason) => {
                    skip_artifact(artifact_id, &reason, pending_attempts);
                    artifact_id += 1;
                    pending_attempts = 0;
                    Ok(ValidationAction::Validated)
                }
                ValidationAction::Wait => Ok(ValidationAction::Wait),
            }
        }
        .await;

        match result {
            Ok(ValidationAction::Validated) => continue,
            Ok(ValidationAction::Pending(delay)) => retry_after = delay,
            Ok(ValidationAction::Wait) => {}
            Ok(ValidationAction::Missing(_)) => unreachable!(),
            Err(error) => {
                tracing::error!(artifact.id = artifact_id, error = %error, "Validation failed.");
            }
        }

        if wait_or_shutdown(&mut shutdown, retry_after).await {
            break;
        }
    }
}

enum ValidationAction {
    Validated,
    Pending(Duration),
    Missing(String),
    Wait,
}

async fn validate_once(
    id: u64,
    artifact_store: &ArtifactStore,
    trusted_root: &TrustedRoot,
    policy: &VerificationPolicy,
) -> Result<ValidationAction> {
    let artifact = match artifact_store.artifact(id).await? {
        ArtifactFetch::Found(artifact) => artifact,
        ArtifactFetch::Missing => {
            return Ok(ValidationAction::Missing(format!(
                "Artifact {id} is below the sealed head but its content is missing."
            )))
        }
        ArtifactFetch::Pending(delay) => return Ok(ValidationAction::Pending(delay)),
    };
    let bundle_json = match artifact_store.signature(id).await? {
        ArtifactFetch::Found(bundle) => bundle,
        ArtifactFetch::Missing => {
            return Ok(ValidationAction::Missing(format!(
                "Artifact {id} is below the sealed head but its signature is missing."
            )))
        }
        ArtifactFetch::Pending(delay) => return Ok(ValidationAction::Pending(delay)),
    };
    let bundle = Bundle::from_json(&bundle_json)?;
    let span = tracing::info_span!(
        "artifact.validate",
        otel.kind = "consumer",
        otel.status_code = field::Empty,
        artifact.id = id as i64,
        artifact.size = artifact.len() as i64,
        client.language = "rust",
        error.type = field::Empty,
    );
    let result = span.in_scope(|| verify(artifact.as_slice(), &bundle, policy, trusted_root));
    record_result(&span, &result);
    result?;
    tracing::info!(
        artifact.id = id,
        artifact.size = artifact.len(),
        "Validated artifact."
    );
    Ok(ValidationAction::Validated)
}

fn skip_artifact(id: u64, reason: &str, attempts: usize) {
    let span = tracing::warn_span!(
        "artifact.skip",
        otel.kind = "consumer",
        artifact.id = id as i64,
        artifact.retry_count = attempts as i64,
        artifact.warning = reason,
        client.language = "rust",
    );
    let _entered = span.enter();
    tracing::warn!(artifact.id = id, reason, "Skipping artifact.");
}

async fn health_server(
    port: u16,
    healthy: Arc<AtomicBool>,
    trust_status: Arc<ClientTrustStatus>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (mut stream, _) = accepted?;
                let is_healthy = healthy.load(Ordering::Relaxed) && !*shutdown.borrow();
                let trust_status = trust_status.clone();
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    let read = stream.read(&mut buffer).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let path_is_health = request.starts_with("GET /healthz ");
                    let path_is_status = request.starts_with("GET /trust/status ");
                    let (body, serialized) = if path_is_status {
                        let mut status = (*trust_status).clone();
                        status.ready = is_healthy;
                        if !is_healthy {
                            status.last_error = Some("client is stopping".to_string());
                        }
                        match serde_json::to_string(&status) {
                            Ok(body) => (body, true),
                            Err(error) => (
                                serde_json::json!({
                                    "error": format!("status serialization failed: {error}")
                                })
                                .to_string(),
                                false,
                            ),
                        }
                    } else if is_healthy && path_is_health {
                        (r#"{"status":"SERVING"}"#.to_string(), true)
                    } else {
                        (r#"{"status":"NOT_SERVING"}"#.to_string(), true)
                    };
                    let ok =
                        is_healthy && (path_is_health || path_is_status) && serialized;
                    let status = if ok { "200 OK" } else { "503 Service Unavailable" };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        }
    }
    Ok(())
}

fn build_client_trust_status(
    published_status_bytes: &[u8],
    trusted_root_bytes: &[u8],
    signing_config_bytes: &[u8],
    root_version: u64,
    targets_version: u64,
    initialized_at_utc: String,
) -> Result<ClientTrustStatus> {
    let published: PublishedTrustStatus = serde_json::from_slice(published_status_bytes)?;
    let trusted_root_sha256 = sha256_hex(trusted_root_bytes);
    let signing_config_sha256 = sha256_hex(signing_config_bytes);
    if published.schema_version != TRUST_STATUS_SCHEMA_VERSION
        || published.trust_domain_id.is_empty()
        || published.generation == 0
        || published.generation_id.is_empty()
        || !is_lower_hex_sha256(&published.generation_manifest_sha256)
        || published.tuf_root_version != root_version
        || published.tuf_targets_version != targets_version
        || published.trusted_root_sha256 != trusted_root_sha256
        || published.signing_config_sha256 != signing_config_sha256
    {
        bail!("published trust status does not match verified TUF material");
    }

    Ok(ClientTrustStatus {
        schema_version: TRUST_STATUS_SCHEMA_VERSION,
        resource: "rust-client".to_string(),
        language: "rust".to_string(),
        ready: true,
        last_error: None,
        trust_domain_id: published.trust_domain_id,
        generation: published.generation,
        generation_id: published.generation_id,
        generation_manifest_sha256: published.generation_manifest_sha256,
        tuf_root_version: root_version,
        tuf_targets_version: targets_version,
        trusted_root_sha256,
        signing_config_sha256,
        initialized_at_utc,
    })
}

fn record_trust_span_attributes(span: &Span, status: &ClientTrustStatus) {
    span.record("sigstore.trust.domain.id", status.trust_domain_id.as_str());
    span.record("sigstore.trust.generation", status.generation as i64);
    span.record(
        "sigstore.trust.generation.id",
        status.generation_id.as_str(),
    );
    span.record(
        "sigstore.trust.generation.manifest.sha256",
        status.generation_manifest_sha256.as_str(),
    );
    span.record(
        "sigstore.trust.tuf.root.version",
        status.tuf_root_version as i64,
    );
    span.record(
        "sigstore.trust.tuf.targets.version",
        status.tuf_targets_version as i64,
    );
    span.record(
        "sigstore.trust.trusted_root.sha256",
        status.trusted_root_sha256.as_str(),
    );
    span.record(
        "sigstore.trust.signing_config.sha256",
        status.signing_config_sha256.as_str(),
    );
    span.record(
        "sigstore.trust.initialized_at",
        status.initialized_at_utc.as_str(),
    );
}

fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn wait_or_shutdown(shutdown: &mut watch::Receiver<bool>, duration: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
    }
}

fn http_span(url: &str, resource_type: &'static str, resource_name: &str) -> Span {
    tracing::info_span!(
        "http.client",
        otel.name = "GET",
        otel.kind = "client",
        otel.status_code = field::Empty,
        http.request.method = "GET",
        http.response.status_code = field::Empty,
        url.full = %url,
        resource.type = resource_type,
        resource.name = resource_name,
        error.type = field::Empty,
    )
}

fn record_tuf_result(result: &sigstore_tuf::Result<Option<Vec<u8>>>) {
    let span = Span::current();
    match result {
        Ok(Some(_)) => {
            span.record("http.response.status_code", 200_i64);
        }
        Ok(None) => {
            span.record("http.response.status_code", 404_i64);
            span.record("otel.status_code", "ERROR");
        }
        Err(error) => {
            span.record("otel.status_code", "ERROR");
            span.record("error.type", field::display(error));
        }
    }
}

fn record_result<T, E: std::fmt::Display>(span: &Span, result: &std::result::Result<T, E>) {
    match result {
        Ok(_) => {
            span.record("otel.status_code", "OK");
        }
        Err(error) => {
            span.record("otel.status_code", "ERROR");
            span.record("error.type", field::display(error));
        }
    }
}

fn ensure_success(response: &Response) -> Result<()> {
    if !response.status().is_success() {
        return Err(HttpStatusError(response.status().as_u16()).into());
    }
    Ok(())
}

fn retry_after(response: &Response) -> Duration {
    let seconds = response
        .headers()
        .get("Retry-After")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(2.0)
        .clamp(0.1, 30.0);
    Duration::from_secs_f64(seconds)
}

fn required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} must be configured"))
}

fn required_url(name: &str) -> Result<Url> {
    let value = required(name)?;
    let url = Url::parse(&value)?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("{name} must be an absolute HTTP(S) URL");
    }
    Ok(url)
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut terminate = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let _telemetry = init_telemetry()?;
    let config = Config::from_environment()?;
    let artifact_store = ArtifactStore::new(config.artifact_store_url.clone())?;
    let (trusted_root, signing_context, trust_status) = initialize_trust(&config).await?;
    let trusted_root = Arc::new(trusted_root);
    let signing_context = Arc::new(signing_context);
    let healthy = Arc::new(AtomicBool::new(true));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let health = tokio::spawn(health_server(
        config.port,
        healthy.clone(),
        Arc::new(trust_status),
        shutdown_rx.clone(),
    ));
    let producer = tokio::spawn(producer_loop(
        config.clone(),
        artifact_store.clone(),
        signing_context,
        shutdown_rx.clone(),
    ));
    let validator = tokio::spawn(validator_loop(
        config,
        artifact_store,
        trusted_root,
        shutdown_rx,
    ));

    println!("Rust producer and validator started.");
    shutdown_signal().await;
    healthy.store(false, Ordering::Relaxed);
    let _ = shutdown_tx.send(true);
    let _ = tokio::join!(health, producer, validator);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_hashes_exact_verified_target_bytes() {
        let trusted_root = b"{\"trusted\":true}\n";
        let signing_config = b"{\"signing\":true}\n";
        let published = serde_json::json!({
            "schemaVersion": 1,
            "trustDomainId": format!("sha256-{}", "a".repeat(64)),
            "generation": 1,
            "generationId": "generation-00000001",
            "generationManifestSha256": "b".repeat(64),
            "tufRootVersion": 2,
            "tufTargetsVersion": 3,
            "trustedRootSha256": sha256_hex(trusted_root),
            "signingConfigSha256": sha256_hex(signing_config),
        });
        let published = serde_json::to_vec(&published).unwrap();

        let status = build_client_trust_status(
            &published,
            trusted_root,
            signing_config,
            2,
            3,
            "2026-08-27T00:00:00Z".to_string(),
        )
        .unwrap();
        assert!(status.ready);

        let mut changed_root = trusted_root.to_vec();
        changed_root[0] ^= 0xff;
        assert!(build_client_trust_status(
            &published,
            &changed_root,
            signing_config,
            2,
            3,
            "2026-08-27T00:00:00Z".to_string(),
        )
        .is_err());
    }
}
