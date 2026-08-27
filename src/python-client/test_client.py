import hashlib
import unittest

import client


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


if __name__ == "__main__":
    unittest.main()
