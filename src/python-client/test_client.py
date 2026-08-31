import hashlib
import threading
import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from typing import Callable

import client
from sigstore._internal.fulcio.client import ExpiredCertificate
from sigstore.oidc import ExpiredIdentity


class TrustStatusTests(unittest.TestCase):
    def test_hashes_exact_verified_target_bytes(self) -> None:
        trusted_root = b'{"trusted":true}\n'
        signing_config = b'{"signing":true}\n'
        published = {
            "schemaVersion": 1,
            "trustDomainId": f"sha256-{'a' * 64}",
            "generation": 1,
            "generationId": "generation-00000001",
            "generationManifestSha256": "b" * 64,
            "tufRootVersion": 2,
            "tufTargetsVersion": 3,
            "trustedRootSha256": hashlib.sha256(
                trusted_root
            ).hexdigest(),
            "signingConfigSha256": hashlib.sha256(
                signing_config
            ).hexdigest(),
        }

        status = client._new_client_trust_status(
            published,
            trusted_root,
            signing_config,
            2,
            3,
            "2026-08-27T00:00:00Z",
        )

        self.assertTrue(status["ready"])
        with self.assertRaisesRegex(
            RuntimeError,
            "does not match verified TUF material",
        ):
            client._new_client_trust_status(
                published,
                b"x" + trusted_root[1:],
                signing_config,
                2,
                3,
                "2026-08-27T00:00:00Z",
            )


class ArtifactProducerTests(unittest.TestCase):
    def test_expired_certificate_is_retried_with_fresh_signer(self) -> None:
        self._assert_expiry_is_retried(ExpiredCertificate())

    def test_expired_identity_is_retried_with_fresh_token(self) -> None:
        self._assert_expiry_is_retried(ExpiredIdentity())

    def _assert_expiry_is_retried(self, failure: Exception) -> None:
        stop_event = threading.Event()
        token_provider = _FakeTokenProvider()
        signing_context = _FakeSigningContext(failure)
        artifact_store = _FakeArtifactStore(stop_event)
        telemetry = _FakeTelemetry(stop_event)
        config = SimpleNamespace(
            produce_interval_seconds=0,
            poll_interval_seconds=0,
        )
        producer = client.ArtifactProducer(
            config,
            stop_event,
            artifact_store,
            token_provider,
            signing_context,
            telemetry,
        )

        producer.run()

        self.assertEqual(2, token_provider.calls)
        self.assertEqual(2, signing_context.signer_calls)
        self.assertEqual(2, signing_context.sign_calls)
        self.assertEqual(1, artifact_store.artifact_uploads)
        self.assertEqual(1, artifact_store.signature_uploads)
        self.assertEqual(1, telemetry.operation_failures.value)
        self.assertEqual(1, telemetry.artifacts_produced.value)


class _FakeCounter:
    def __init__(
        self,
        on_add: Callable[[], None] | None = None,
    ) -> None:
        self.value = 0
        self._on_add = on_add

    def add(
        self,
        value: int,
        attributes: dict[str, str] | None = None,
    ) -> None:
        del attributes
        self.value += value
        if self._on_add is not None:
            self._on_add()


class _FakeSpan:
    def set_attribute(self, name: str, value: object) -> None:
        del name, value


class _FakeTracer:
    def start_as_current_span(
        self,
        name: str,
        **kwargs: object,
    ) -> nullcontext[_FakeSpan]:
        del name, kwargs
        return nullcontext(_FakeSpan())


class _FakeTelemetry:
    def __init__(self, stop_event: threading.Event) -> None:
        self.tracer = _FakeTracer()
        self.operation_failures = _FakeCounter()
        self.artifacts_produced = _FakeCounter(stop_event.set)


class _FakeTokenProvider:
    def __init__(self) -> None:
        self.calls = 0

    def get_token(self) -> object:
        self.calls += 1
        return object()


class _FakeBundle:
    def to_json(self) -> str:
        return '{"bundle":true}'


class _FakeSigner:
    def __init__(self, owner: "_FakeSigningContext") -> None:
        self._owner = owner

    def sign_artifact(self, artifact: bytes) -> _FakeBundle:
        del artifact
        self._owner.sign_calls += 1
        if self._owner.failure is not None:
            failure = self._owner.failure
            self._owner.failure = None
            raise failure
        return _FakeBundle()


class _FakeSigningContext:
    def __init__(self, failure: Exception) -> None:
        self.failure: Exception | None = failure
        self.signer_calls = 0
        self.sign_calls = 0

    def signer(self, token: object) -> nullcontext[_FakeSigner]:
        del token
        self.signer_calls += 1
        return nullcontext(_FakeSigner(self))


class _FakeArtifactStore:
    def __init__(self, stop_event: threading.Event) -> None:
        del stop_event
        self.artifact_uploads = 0
        self.signature_uploads = 0

    def upload_artifact(self, artifact: bytes) -> SimpleNamespace:
        del artifact
        self.artifact_uploads += 1
        return SimpleNamespace(
            artifact_id=1,
            signature_url="http://artifact.test/signature",
            seal_token="test-token",
        )

    def upload_signature(
        self,
        signature_url: str,
        seal_token: str,
        bundle_json: str,
    ) -> None:
        del signature_url, seal_token, bundle_json
        self.signature_uploads += 1


if __name__ == "__main__":
    unittest.main()
