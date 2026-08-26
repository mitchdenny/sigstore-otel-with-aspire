from __future__ import annotations

import logging
import os
import random
import secrets
import signal
import sys
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import FrameType
from urllib.parse import urljoin, urlparse

import requests
from opentelemetry import _logs as otel_logs
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
    OTLPMetricExporter,
)
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.urllib3 import URLLib3Instrumentor
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import SpanKind
from sigstore._internal.fulcio.client import FulcioClientError
from sigstore._internal.rekor import RekorClientError
from sigstore._internal.timestamp import TimestampError
from sigstore.errors import Error as SigstoreError
from sigstore.models import Bundle, ClientTrustConfig
from sigstore.oidc import IdentityToken
from sigstore.sign import SigningContext
from sigstore.verify import Verifier
from sigstore.verify.policy import Identity

REQUEST_TIMEOUT_SECONDS = 30


class ArtifactProtocolError(RuntimeError):
    pass


class ArtifactNotReady(RuntimeError):
    def __init__(self, retry_after_seconds: float) -> None:
        super().__init__("The artifact is reserved but not sealed.")
        self.retry_after_seconds = retry_after_seconds


class ArtifactMissing(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    artifact_store_url: str
    tuf_url: str
    tuf_root_path: Path
    oidc_url: str
    expected_identity: str
    expected_issuer: str
    produce_interval_seconds: float
    poll_interval_seconds: float
    port: int

    @classmethod
    def from_environment(cls) -> Config:
        return cls(
            artifact_store_url=_required_url("SHADY_BLOB_STORE_URL"),
            tuf_url=_required_url("SIGSTORE_TUF_URL"),
            tuf_root_path=Path(_required_value("SIGSTORE_TUF_ROOT_PATH")),
            oidc_url=_required_url("SIGSTORE_OIDC_URL"),
            expected_identity=_required_value("SIGSTORE_EXPECTED_IDENTITY"),
            expected_issuer=_required_url("SIGSTORE_EXPECTED_ISSUER"),
            produce_interval_seconds=10,
            poll_interval_seconds=2,
            port=int(os.environ.get("PYTHON_CLIENT_PORT", "8080")),
        )


@dataclass(frozen=True)
class ArtifactLocation:
    artifact_id: int
    artifact_url: str
    signature_url: str
    seal_token: str


class Telemetry:
    def __init__(self) -> None:
        resource = Resource.create(
            {
                "service.name": os.environ.get(
                    "OTEL_SERVICE_NAME",
                    "python-client",
                )
            }
        )

        self.trace_provider = TracerProvider(resource=resource)
        self.trace_provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter())
        )
        trace.set_tracer_provider(self.trace_provider)

        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(),
            export_interval_millis=5_000,
        )
        self.meter_provider = MeterProvider(
            resource=resource,
            metric_readers=[metric_reader],
        )
        metrics.set_meter_provider(self.meter_provider)

        self.logger_provider = LoggerProvider(resource=resource)
        self.logger_provider.add_log_record_processor(
            BatchLogRecordProcessor(OTLPLogExporter())
        )
        otel_logs.set_logger_provider(self.logger_provider)

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        logging.getLogger().addHandler(
            LoggingHandler(
                level=logging.NOTSET,
                logger_provider=self.logger_provider,
            )
        )
        logging.getLogger("urllib3").setLevel(logging.WARNING)

        RequestsInstrumentor().instrument()
        URLLib3Instrumentor().instrument()

        self.tracer = trace.get_tracer("sigstore.demo.python-client")
        meter = metrics.get_meter("sigstore.demo.python-client")
        self.artifacts_produced = meter.create_counter(
            "sigstore.demo.artifacts.produced"
        )
        self.artifacts_verified = meter.create_counter(
            "sigstore.demo.artifacts.verified"
        )
        self.artifacts_skipped = meter.create_counter(
            "sigstore.demo.artifacts.skipped"
        )
        self.operation_failures = meter.create_counter(
            "sigstore.demo.operation.failures"
        )

    def shutdown(self) -> None:
        URLLib3Instrumentor().uninstrument()
        RequestsInstrumentor().uninstrument()
        self.logger_provider.shutdown()
        self.meter_provider.shutdown()
        self.trace_provider.shutdown()


class ArtifactStoreClient:
    def __init__(self, base_url: str) -> None:
        self._base_url = _normalize_url(base_url)
        self._origin = _origin(self._base_url)
        self._local = threading.local()
        self._sessions: list[requests.Session] = []
        self._sessions_lock = threading.Lock()

    @property
    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            self._local.session = session
            with self._sessions_lock:
                self._sessions.append(session)
        return session

    def upload_artifact(self, artifact: bytes) -> ArtifactLocation:
        response = self._session.post(
            urljoin(self._base_url, "artifacts"),
            data=artifact,
            headers={"Content-Type": "application/octet-stream"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()

        try:
            payload = response.json()
            artifact_id = int(payload["id"])
            artifact_url = str(payload["url"])
            signature_url = str(payload["signatureUrl"])
            seal_token_value = payload["sealToken"]
            if not isinstance(seal_token_value, str):
                raise TypeError("sealToken must be a string")
            seal_token = seal_token_value
        except (KeyError, TypeError, ValueError) as exception:
            raise ArtifactProtocolError(
                "The artifact store returned an invalid creation response."
            ) from exception

        if artifact_id <= 0:
            raise ArtifactProtocolError(
                "The artifact store returned an invalid artifact ID."
            )
        if not seal_token:
            raise ArtifactProtocolError(
                "The artifact store returned an empty seal token."
            )

        expected_artifact_url = urljoin(
            self._base_url,
            f"artifacts/{artifact_id}",
        )
        expected_signature_url = f"{expected_artifact_url}/signature"
        if (
            artifact_url != expected_artifact_url
            or signature_url != expected_signature_url
            or _origin(artifact_url) != self._origin
            or _origin(signature_url) != self._origin
        ):
            raise ArtifactProtocolError(
                "The artifact store returned an unexpected artifact URL."
            )

        return ArtifactLocation(
            artifact_id,
            artifact_url,
            signature_url,
            seal_token,
        )

    def upload_signature(
        self,
        signature_url: str,
        seal_token: str,
        bundle_json: str,
    ) -> None:
        if _origin(signature_url) != self._origin:
            raise ArtifactProtocolError(
                "Refusing to upload a signature outside the artifact store."
            )

        response = self._session.post(
            signature_url,
            data=bundle_json.encode(),
            headers={
                "Content-Type": "application/vnd.dev.sigstore.bundle+json",
                "X-Artifact-Seal-Token": seal_token,
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code == HTTPStatus.CONFLICT:
            raise ArtifactProtocolError(
                "The artifact already has a different signature."
            )
        response.raise_for_status()

    def get_head(self) -> int:
        response = self._session.get(
            urljoin(self._base_url, "artifacts/head"),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        try:
            artifact_id = int(response.json()["id"])
        except (KeyError, TypeError, ValueError) as exception:
            raise ArtifactProtocolError(
                "The artifact store returned an invalid head response."
            ) from exception
        if artifact_id < 0:
            raise ArtifactProtocolError(
                "The artifact store returned an invalid head ID."
            )
        return artifact_id

    def download_artifact(self, artifact_id: int) -> bytes | None:
        response = self._session.get(
            urljoin(self._base_url, f"artifacts/{artifact_id}"),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None
        if response.status_code == HTTPStatus.TOO_EARLY:
            raise ArtifactNotReady(_retry_after_seconds(response))
        response.raise_for_status()
        return response.content

    def download_signature(self, artifact_id: int) -> str | None:
        response = self._session.get(
            urljoin(
                self._base_url,
                f"artifacts/{artifact_id}/signature",
            ),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None
        if response.status_code == HTTPStatus.TOO_EARLY:
            raise ArtifactNotReady(_retry_after_seconds(response))
        response.raise_for_status()
        return response.text

    def close(self) -> None:
        with self._sessions_lock:
            for session in self._sessions:
                session.close()
            self._sessions.clear()


class OidcTokenProvider:
    def __init__(
        self,
        base_url: str,
        expected_identity: str,
        expected_issuer: str,
    ) -> None:
        self._token_url = urljoin(_normalize_url(base_url), "token")
        self._expected_identity = expected_identity
        self._expected_issuer = expected_issuer
        self._session = requests.Session()

    def get_token(self) -> IdentityToken:
        response = self._session.get(
            self._token_url,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        token = IdentityToken(response.text.strip())

        if token.identity != self._expected_identity:
            raise ArtifactProtocolError(
                f"OIDC identity {token.identity!r} did not match "
                f"{self._expected_identity!r}."
            )
        if token.issuer != self._expected_issuer:
            raise ArtifactProtocolError(
                f"OIDC issuer {token.issuer!r} did not match "
                f"{self._expected_issuer!r}."
            )

        return token

    def close(self) -> None:
        self._session.close()


class ArtifactProducer:
    def __init__(
        self,
        config: Config,
        stop_event: threading.Event,
        artifact_store: ArtifactStoreClient,
        token_provider: OidcTokenProvider,
        signing_context: SigningContext,
        telemetry: Telemetry,
    ) -> None:
        self._config = config
        self._stop_event = stop_event
        self._artifact_store = artifact_store
        self._token_provider = token_provider
        self._signing_context = signing_context
        self._telemetry = telemetry
        self._logger = logging.getLogger("python-client.producer")

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._produce()
            except (
                ArtifactProtocolError,
                OSError,
                requests.RequestException,
                FulcioClientError,
                RekorClientError,
                SigstoreError,
                TimestampError,
                ValueError,
            ):
                self._telemetry.operation_failures.add(
                    1,
                    {"client.language": "python", "operation": "produce"},
                )
                self._logger.exception("Failed to produce an artifact.")

            self._stop_event.wait(
                self._config.produce_interval_seconds
            )

    def _produce(self) -> None:
        artifact = secrets.token_bytes(random.randint(256, 4096))

        with self._telemetry.tracer.start_as_current_span(
            "artifact.produce",
            kind=SpanKind.PRODUCER,
            attributes={
                "artifact.size": len(artifact),
                "client.language": "python",
            },
        ) as span:
            identity_token = self._token_provider.get_token()
            with self._signing_context.signer(identity_token) as signer:
                bundle = signer.sign_artifact(artifact)

            uploaded = self._artifact_store.upload_artifact(artifact)
            span.set_attribute("artifact.id", uploaded.artifact_id)

            bundle_json = bundle.to_json()
            while not self._stop_event.is_set():
                try:
                    self._artifact_store.upload_signature(
                        uploaded.signature_url,
                        uploaded.seal_token,
                        bundle_json,
                    )
                    break
                except requests.RequestException:
                    self._logger.warning(
                        "Signature upload for artifact %s failed; retrying.",
                        uploaded.artifact_id,
                        exc_info=True,
                    )
                    self._stop_event.wait(
                        self._config.poll_interval_seconds
                    )

            if self._stop_event.is_set():
                return

            self._telemetry.artifacts_produced.add(
                1,
                {"client.language": "python"},
            )
            self._logger.info(
                "Produced and signed artifact %s (%s bytes).",
                uploaded.artifact_id,
                len(artifact),
            )


class ArtifactValidator:
    MAXIMUM_PENDING_ATTEMPTS = 5

    def __init__(
        self,
        config: Config,
        stop_event: threading.Event,
        artifact_store: ArtifactStoreClient,
        verifier: Verifier,
        telemetry: Telemetry,
    ) -> None:
        self._config = config
        self._stop_event = stop_event
        self._artifact_store = artifact_store
        self._verifier = verifier
        self._policy = Identity(
            identity=config.expected_identity,
            issuer=config.expected_issuer,
        )
        self._telemetry = telemetry
        self._logger = logging.getLogger("python-client.validator")

    def run(self) -> None:
        artifact_id = 1
        high_watermark = 0
        pending_attempts = 0
        while not self._stop_event.is_set():
            retry_after_seconds = self._config.poll_interval_seconds
            try:
                if artifact_id > high_watermark:
                    observed_head = self._artifact_store.get_head()
                    if observed_head < high_watermark:
                        raise ArtifactProtocolError(
                            "The artifact head moved backward from "
                            f"{high_watermark} to {observed_head}."
                        )
                    high_watermark = observed_head
                    if artifact_id > high_watermark:
                        self._stop_event.wait(retry_after_seconds)
                        continue

                if self._try_validate(artifact_id):
                    artifact_id += 1
                    pending_attempts = 0
                    continue
            except ArtifactNotReady as exception:
                pending_attempts += 1
                if pending_attempts >= self.MAXIMUM_PENDING_ATTEMPTS:
                    self._skip_artifact(
                        artifact_id,
                        "The artifact remained unsealed after "
                        f"{pending_attempts} attempts.",
                        pending_attempts,
                    )
                    artifact_id += 1
                    pending_attempts = 0
                    continue
                retry_after_seconds = exception.retry_after_seconds
            except ArtifactMissing as exception:
                self._skip_artifact(
                    artifact_id,
                    str(exception),
                    pending_attempts,
                )
                artifact_id += 1
                pending_attempts = 0
                continue
            except (
                ArtifactProtocolError,
                OSError,
                requests.RequestException,
                FulcioClientError,
                RekorClientError,
                SigstoreError,
                TimestampError,
                ValueError,
            ):
                self._telemetry.operation_failures.add(
                    1,
                    {"client.language": "python", "operation": "validate"},
                )
                self._logger.exception(
                    "Failed to validate artifact %s.",
                    artifact_id,
                )

            self._stop_event.wait(retry_after_seconds)

    def _try_validate(self, artifact_id: int) -> bool:
        artifact = self._artifact_store.download_artifact(artifact_id)
        if artifact is None:
            raise ArtifactMissing(
                f"Artifact {artifact_id} is below the sealed head but "
                "its content is missing."
            )

        bundle_json = self._artifact_store.download_signature(artifact_id)
        if bundle_json is None:
            raise ArtifactMissing(
                f"Artifact {artifact_id} is below the sealed head but "
                "its signature is missing."
            )

        with self._telemetry.tracer.start_as_current_span(
            "artifact.validate",
            kind=SpanKind.CONSUMER,
            attributes={
                "artifact.id": artifact_id,
                "artifact.size": len(artifact),
                "client.language": "python",
            },
        ):
            bundle = Bundle.from_json(bundle_json)
            self._verifier.verify_artifact(
                artifact,
                bundle,
                self._policy,
            )

        self._telemetry.artifacts_verified.add(
            1,
            {"client.language": "python"},
        )
        self._logger.info(
            "Validated artifact %s (%s bytes).",
            artifact_id,
            len(artifact),
        )
        return True

    def _skip_artifact(
        self,
        artifact_id: int,
        reason: str,
        attempts: int,
    ) -> None:
        with self._telemetry.tracer.start_as_current_span(
            "artifact.skip",
            kind=SpanKind.CONSUMER,
            attributes={
                "artifact.id": artifact_id,
                "artifact.retry_count": attempts,
                "artifact.warning": reason,
                "client.language": "python",
            },
        ) as span:
            span.add_event("artifact.skipped")
            self._logger.warning(
                "Skipping artifact %s: %s",
                artifact_id,
                reason,
            )

        self._telemetry.artifacts_skipped.add(
            1,
            {"client.language": "python"},
        )


class HealthHandler(BaseHTTPRequestHandler):
    stop_event: threading.Event
    workers: list[threading.Thread]

    def do_GET(self) -> None:
        healthy = (
            self.path == "/healthz"
            and not self.stop_event.is_set()
            and all(worker.is_alive() for worker in self.workers)
        )
        status = HTTPStatus.OK if healthy else HTTPStatus.SERVICE_UNAVAILABLE
        body = (
            b'{"status":"SERVING"}'
            if healthy
            else b'{"status":"NOT_SERVING"}'
        )

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def _required_value(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} must be configured.")
    return value


def _required_url(name: str) -> str:
    value = _required_value(name)
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RuntimeError(f"{name} must be an absolute HTTP(S) URL.")
    return value


def _normalize_url(value: str) -> str:
    return value.rstrip("/") + "/"


def _origin(value: str) -> tuple[str, str, int | None]:
    parsed = urlparse(value)
    return (parsed.scheme.lower(), parsed.hostname or "", parsed.port)


def _retry_after_seconds(response: requests.Response) -> float:
    value = response.headers.get("Retry-After", "2")
    try:
        delay = float(value)
    except ValueError:
        delay = 2
    return min(max(delay, 0.1), 30)


def main() -> int:
    config = Config.from_environment()
    telemetry = Telemetry()
    logger = logging.getLogger("python-client")
    stop_event = threading.Event()

    artifact_store = ArtifactStoreClient(config.artifact_store_url)
    token_provider = OidcTokenProvider(
        config.oidc_url,
        config.expected_identity,
        config.expected_issuer,
    )

    try:
        with telemetry.tracer.start_as_current_span(
            "sigstore.trust.initialize"
        ):
            trust_config = ClientTrustConfig.from_tuf(
                config.tuf_url,
                bootstrap_root=config.tuf_root_path,
            )
            trust_config.force_tlog_version = 2
            signing_context = SigningContext.from_trust_config(
                trust_config
            )
            verifier = Verifier(
                trusted_root=trust_config.trusted_root
            )

        producer = ArtifactProducer(
            config,
            stop_event,
            artifact_store,
            token_provider,
            signing_context,
            telemetry,
        )
        validator = ArtifactValidator(
            config,
            stop_event,
            artifact_store,
            verifier,
            telemetry,
        )
        workers = [
            threading.Thread(
                target=producer.run,
                name="artifact-producer",
            ),
            threading.Thread(
                target=validator.run,
                name="artifact-validator",
            ),
        ]

        HealthHandler.stop_event = stop_event
        HealthHandler.workers = workers
        health_server = ThreadingHTTPServer(
            ("0.0.0.0", config.port),
            HealthHandler,
        )
        health_thread = threading.Thread(
            target=health_server.serve_forever,
            name="health-server",
            daemon=True,
        )

        def stop(
            signal_number: int,
            frame: FrameType | None,
        ) -> None:
            del signal_number, frame
            stop_event.set()

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)

        for worker in workers:
            worker.start()
        health_thread.start()
        logger.info("Python producer and validator started.")

        exit_code = 0
        while not stop_event.wait(1):
            if not all(worker.is_alive() for worker in workers):
                logger.critical("A background worker stopped unexpectedly.")
                exit_code = 1
                stop_event.set()

        health_server.shutdown()
        health_server.server_close()
        for worker in workers:
            worker.join(timeout=REQUEST_TIMEOUT_SECONDS)

        return exit_code
    finally:
        token_provider.close()
        artifact_store.close()
        telemetry.shutdown()


if __name__ == "__main__":
    sys.exit(main())
