package example;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

final class SigstoreClientTest {
  private static final Gson GSON = new Gson();

  @Test
  void statusHashesExactVerifiedTargetBytes() throws Exception {
    byte[] trustedRoot =
        "{\"trusted\":true}\n".getBytes(StandardCharsets.UTF_8);
    byte[] signingConfig =
        "{\"signing\":true}\n".getBytes(StandardCharsets.UTF_8);
    byte[] published =
        GSON.toJson(
                new SigstoreClient.PublishedTrustStatus(
                    1,
                    "sha256-" + "a".repeat(64),
                    1,
                    "generation-00000001",
                    "b".repeat(64),
                    2,
                    3,
                    sha256(trustedRoot),
                    sha256(signingConfig)))
            .getBytes(StandardCharsets.UTF_8);

    SigstoreClient.ClientTrustStatus status =
        SigstoreClient.createClientTrustStatus(
            published,
            trustedRoot,
            signingConfig,
            2,
            3,
            "2026-08-27T00:00:00Z");

    assertTrue(status.ready());
    byte[] changedRoot = trustedRoot.clone();
    changedRoot[0] ^= (byte) 0xff;
    assertThrows(
        IllegalStateException.class,
        () ->
            SigstoreClient.createClientTrustStatus(
                published,
                changedRoot,
                signingConfig,
                2,
                3,
                "2026-08-27T00:00:00Z"));
  }

  private static String sha256(byte[] value) throws Exception {
    return HexFormat.of()
        .formatHex(
            MessageDigest.getInstance("SHA-256").digest(value));
  }
}
