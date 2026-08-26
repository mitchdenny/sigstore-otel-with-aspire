use std::error::Error;
use std::fs;
use std::time::Duration;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithTonicConfig;
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use sigstore_trust_root::{TrustedRoot, PRODUCTION_TUF_ROOT};
use sigstore_tuf::transport::FetchFuture;
use sigstore_tuf::{FileStore, HttpRepository, Repository, Updater};
use sigstore_types::Bundle;
use sigstore_verify::{verify, VerificationPolicy};
use tonic::transport::{Certificate, ClientTlsConfig};
use tracing::{field, Instrument, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const ARTIFACT_PATH: &str = "/opt/sigstore-rust-fixture/artifact.txt";
const BUNDLE_PATH: &str = "/opt/sigstore-rust-fixture/bundle.sigstore.json";
const CACHE_PATH: &str = "/tmp/sigstore-rust-tuf-cache";
const PRODUCTION_TUF_URL: &str = "https://tuf-repo-cdn.sigstore.dev";
const PROBE_INTERVAL: Duration = Duration::from_secs(15);

type BoxError = Box<dyn Error + Send + Sync>;

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
                record_http_result(&result);
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
                record_http_result(&result);
                result
            }
            .instrument(span),
        )
    }
}

fn http_span(url: &str, resource_type: &'static str, resource_name: &str) -> Span {
    tracing::info_span!(
        "tuf.http.fetch",
        otel.name = "GET",
        otel.kind = "client",
        otel.status_code = field::Empty,
        http.request.method = "GET",
        http.response.status_code = field::Empty,
        url.full = %url,
        tuf.resource.type = resource_type,
        tuf.resource.name = resource_name,
        error.type = field::Empty,
    )
}

fn record_http_result(result: &sigstore_tuf::Result<Option<Vec<u8>>>) {
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

fn init_telemetry() -> Result<TelemetryGuard, BoxError> {
    let mut exporter_builder = opentelemetry_otlp::SpanExporter::builder().with_tonic();
    if let Ok(certificate_path) = std::env::var("OTEL_EXPORTER_OTLP_CERTIFICATE") {
        let certificate = Certificate::from_pem(fs::read(certificate_path)?);
        exporter_builder =
            exporter_builder.with_tls_config(ClientTlsConfig::new().ca_certificate(certificate));
    }
    let exporter = exporter_builder.build()?;
    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "rust-test".to_string());
    let provider = SdkTracerProvider::builder()
        .with_resource(Resource::builder().with_service_name(service_name).build())
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer("sigstore-rust-test");

    tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init()?;

    Ok(TelemetryGuard { provider })
}

async fn initialize_trusted_root() -> Result<TrustedRoot, BoxError> {
    let span = tracing::info_span!(
        "sigstore.verifier.initialize",
        otel.status_code = field::Empty,
        sigstore.client.language = "rust",
        error.type = field::Empty,
    );

    let result = async {
        let repository = TracedRepository::new(PRODUCTION_TUF_URL)?;
        let mut updater =
            Updater::new(repository, PRODUCTION_TUF_ROOT)?.with_store(FileStore::new(CACHE_PATH));
        let now = jiff::Timestamp::now();
        updater.refresh(now).await?;
        let trusted_root_bytes = updater.get_target("trusted_root.json", now).await?;
        let trusted_root_json = String::from_utf8(trusted_root_bytes)?;
        Ok::<_, BoxError>(TrustedRoot::from_json(&trusted_root_json)?)
    }
    .instrument(span.clone())
    .await;

    match &result {
        Ok(_) => {
            span.record("otel.status_code", "OK");
        }
        Err(error) => {
            span.record("otel.status_code", "ERROR");
            span.record("error.type", field::display(error));
        }
    }

    result
}

fn verify_once(
    trusted_root: &TrustedRoot,
    artifact: &[u8],
    bundle: &Bundle,
    policy: &VerificationPolicy,
) -> sigstore_verify::Result<()> {
    let span = tracing::info_span!(
        "sigstore.verify",
        otel.status_code = field::Empty,
        sigstore.client.language = "rust",
        sigstore.bundle.media_type = %bundle.media_type,
        error.type = field::Empty,
    );

    let result = span.in_scope(|| verify(artifact, bundle, policy, trusted_root).map(|_| ()));
    match &result {
        Ok(_) => {
            span.record("otel.status_code", "OK");
        }
        Err(error) => {
            span.record("otel.status_code", "ERROR");
            span.record("error.type", field::display(error));
        }
    }

    result
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
    let artifact = fs::read(ARTIFACT_PATH)?;
    let bundle = Bundle::from_json(&fs::read_to_string(BUNDLE_PATH)?)?;
    let policy = VerificationPolicy::default();
    let trusted_root = initialize_trusted_root().await?;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    println!("Starting sigstore-rust telemetry probe.");

    loop {
        verify_once(&trusted_root, &artifact, &bundle, &policy)?;
        println!("sigstore-rust verification emitted an OpenTelemetry trace.");

        tokio::select! {
            _ = &mut shutdown => break,
            _ = tokio::time::sleep(PROBE_INTERVAL) => {}
        }
    }

    Ok(())
}
