from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import secrets
import signal
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
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
from sigstore._internal.tuf import TrustUpdater
from sigstore.errors import Error as SigstoreError
from sigstore.models import Bundle, ClientTrustConfig
from sigstore.oidc import IdentityToken
from sigstore.sign import SigningContext
from sigstore.verify import Verifier
from sigstore.verify.policy import Identity

REQUEST_TIMEOUT_SECONDS = 30
TRUST_STATUS_SCHEMA_VERSION = 1
TRUST_STATUS_TARGET_NAME = "trust_status.v1.json"


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
        trust_status: dict[str, object],
        telemetry: Telemetry,
    ) -> None:
        self._config = config
        self._stop_event = stop_event
        self._artifact_store = artifact_store
        self._verifier = verifier
        self._trust_status = trust_status
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
        evidence = self.verify_artifact(artifact_id)

        self._telemetry.artifacts_verified.add(
            1,
            {"client.language": "python"},
        )
        self._logger.info(
            "Validated artifact %s (%s).",
            artifact_id,
            evidence["artifactSha256"],
        )
        return True

    def verify_artifact(self, artifact_id: int) -> dict[str, object]:
        if artifact_id <= 0:
            raise ArtifactProtocolError("Artifact ID must be positive.")
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

        return {
            "schemaVersion": 1,
            "resource": "python-client",
            "language": "python",
            "verified": True,
            "artifactId": artifact_id,
            "artifactSha256": hashlib.sha256(artifact).hexdigest(),
            "bundleSha256": hashlib.sha256(
                bundle_json.encode("utf-8")
            ).hexdigest(),
            "generation": self._trust_status["generation"],
            "generationId": self._trust_status["generationId"],
            "trustedRootSha256": self._trust_status[
                "trustedRootSha256"
            ],
        }

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
    trust_status: dict[str, object]
    artifact_validator: ArtifactValidator
    last_error: str | None = None

    def do_GET(self) -> None:
        verification_match = re.fullmatch(
            r"/artifacts/([1-9][0-9]*)/verify",
            self.path,
        )
        if verification_match is not None:
            try:
                payload = self.artifact_validator.verify_artifact(
                    int(verification_match.group(1))
                )
                body = json.dumps(
                    payload,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                status = HTTPStatus.OK
            except ArtifactMissing as exception:
                body = json.dumps(
                    {"error": str(exception)},
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                status = HTTPStatus.NOT_FOUND
            except (
                ArtifactNotReady,
                ArtifactProtocolError,
                OSError,
                requests.RequestException,
                SigstoreError,
                ValueError,
            ) as exception:
                body = json.dumps(
                    {"error": str(exception)},
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                status = HTTPStatus.UNPROCESSABLE_ENTITY
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/trust/status":
            ready = (
                not self.stop_event.is_set()
                and all(worker.is_alive() for worker in self.workers)
            )
            status_payload = dict(self.trust_status)
            status_payload["ready"] = ready
            status_payload["lastError"] = (
                None
                if ready
                else self.last_error or "client is stopping"
            )
            body = json.dumps(
                status_payload,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            self.send_response(
                HTTPStatus.OK
                if ready
                else HTTPStatus.SERVICE_UNAVAILABLE
            )
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

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


def _initialize_trust(
    config: Config,
) -> tuple[ClientTrustConfig, dict[str, object]]:
    updater = TrustUpdater(
        config.tuf_url,
        bootstrap_root=config.tuf_root_path,
    )
    trusted_root_path = Path(updater.get_trusted_root_path())
    signing_config_path = Path(updater.get_signing_config_path())
    status_path = _get_verified_target_path(
        updater,
        TRUST_STATUS_TARGET_NAME,
    )
    trusted_root_bytes = trusted_root_path.read_bytes()
    signing_config_bytes = signing_config_path.read_bytes()
    root_version = _metadata_version(
        updater._metadata_dir / "root.json",
    )
    targets_version = _metadata_version(
        updater._metadata_dir / "targets.json",
    )
    initialized_at_utc = (
        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    status = _new_client_trust_status(
        json.loads(status_path.read_text(encoding="utf-8")),
        trusted_root_bytes,
        signing_config_bytes,
        root_version,
        targets_version,
        initialized_at_utc,
    )
    combined = {
        "mediaType": (
            "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json"
        ),
        "trustedRoot": json.loads(trusted_root_bytes),
        "signingConfig": json.loads(signing_config_bytes),
    }
    return (
        ClientTrustConfig.from_json(
            json.dumps(combined, separators=(",", ":"))
        ),
        status,
    )


def _get_verified_target_path(
    updater: TrustUpdater,
    target_name: str,
) -> Path:
    tuf_updater = updater._updater
    if tuf_updater is None:
        raise RuntimeError("TUF updater is unavailable in online mode.")
    target_info = tuf_updater.get_targetinfo(target_name)
    if target_info is None:
        raise RuntimeError(f"TUF target {target_name} is missing.")
    cached = tuf_updater.find_cached_target(target_info)
    if cached is not None:
        return Path(cached)
    return Path(tuf_updater.download_target(target_info))


def _metadata_version(path: Path) -> int:
    try:
        version = json.loads(path.read_bytes())["signed"]["version"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError(f"TUF metadata {path.name} is malformed.") from error
    if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
        raise RuntimeError(
            f"TUF metadata {path.name} has invalid version {version!r}."
        )
    return version


def _new_client_trust_status(
    published: dict[str, object],
    trusted_root_bytes: bytes,
    signing_config_bytes: bytes,
    root_version: int,
    targets_version: int,
    initialized_at_utc: str,
) -> dict[str, object]:
    trusted_root_sha256 = hashlib.sha256(trusted_root_bytes).hexdigest()
    signing_config_sha256 = hashlib.sha256(
        signing_config_bytes
    ).hexdigest()
    if (
        published.get("schemaVersion") != TRUST_STATUS_SCHEMA_VERSION
        or not isinstance(published.get("trustDomainId"), str)
        or not published["trustDomainId"]
        or not isinstance(published.get("generation"), int)
        or isinstance(published.get("generation"), bool)
        or published["generation"] <= 0
        or not isinstance(published.get("generationId"), str)
        or not published["generationId"]
        or not _is_lower_hex_sha256(
            published.get("generationManifestSha256")
        )
        or published.get("tufRootVersion") != root_version
        or published.get("tufTargetsVersion") != targets_version
        or published.get("trustedRootSha256") != trusted_root_sha256
        or published.get("signingConfigSha256")
        != signing_config_sha256
    ):
        raise RuntimeError(
            "Published trust status does not match verified TUF material."
        )

    return {
        "schemaVersion": TRUST_STATUS_SCHEMA_VERSION,
        "resource": "python-client",
        "language": "python",
        "ready": True,
        "lastError": None,
        "trustDomainId": published["trustDomainId"],
        "generation": published["generation"],
        "generationId": published["generationId"],
        "generationManifestSha256": published[
            "generationManifestSha256"
        ],
        "tufRootVersion": root_version,
        "tufTargetsVersion": targets_version,
        "trustedRootSha256": trusted_root_sha256,
        "signingConfigSha256": signing_config_sha256,
        "initializedAtUtc": initialized_at_utc,
    }


def _is_lower_hex_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _set_trust_span_attributes(
    span: trace.Span,
    status: dict[str, object],
) -> None:
    attributes = {
        "client.language": status["language"],
        "client.resource.name": status["resource"],
        "sigstore.trust.domain.id": status["trustDomainId"],
        "sigstore.trust.generation": status["generation"],
        "sigstore.trust.generation.id": status["generationId"],
        "sigstore.trust.generation.manifest.sha256": status[
            "generationManifestSha256"
        ],
        "sigstore.trust.tuf.root.version": status["tufRootVersion"],
        "sigstore.trust.tuf.targets.version": status[
            "tufTargetsVersion"
        ],
        "sigstore.trust.trusted_root.sha256": status[
            "trustedRootSha256"
        ],
        "sigstore.trust.signing_config.sha256": status[
            "signingConfigSha256"
        ],
        "sigstore.trust.initialized_at": status["initializedAtUtc"],
    }
    for name, value in attributes.items():
        span.set_attribute(name, value)


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
        ) as span:
            span.set_attribute("client.language", "python")
            span.set_attribute(
                "client.resource.name",
                "python-client",
            )
            trust_config, trust_status = _initialize_trust(config)
            trust_config.force_tlog_version = 2
            signing_context = SigningContext.from_trust_config(
                trust_config
            )
            verifier = Verifier(
                trusted_root=trust_config.trusted_root
            )
            _set_trust_span_attributes(span, trust_status)

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
            trust_status,
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
        HealthHandler.trust_status = trust_status
        HealthHandler.artifact_validator = validator
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
                HealthHandler.last_error = (
                    "a background worker stopped unexpectedly"
                )
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
