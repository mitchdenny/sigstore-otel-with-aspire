package example;

import dev.sigstore.KeylessVerifier;
import dev.sigstore.VerificationOptions;
import dev.sigstore.bundle.Bundle;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;

public final class TelemetryProbe {
  private static final Path ARTIFACT_PATH = Path.of("/opt/sigstore-java-fixture/artifact.txt");
  private static final Path BUNDLE_PATH =
      Path.of("/opt/sigstore-java-fixture/bundle.sigstore.json");
  private static final Duration PROBE_INTERVAL = Duration.ofSeconds(15);

  private TelemetryProbe() {}

  public static void main(String[] args) throws Exception {
    var tracer = GlobalOpenTelemetry.getTracer("sigstore-java-test", "1.0.0");
    var bundle = Bundle.from(BUNDLE_PATH, StandardCharsets.UTF_8);
    var verifier = initializeVerifier(tracer);

    System.out.println("Starting sigstore-java telemetry probe.");

    while (!Thread.currentThread().isInterrupted()) {
      verify(tracer, verifier, bundle);

      try {
        Thread.sleep(PROBE_INTERVAL);
      } catch (InterruptedException exception) {
        Thread.currentThread().interrupt();
      }
    }
  }

  private static KeylessVerifier initializeVerifier(Tracer tracer) throws Exception {
    Span span = tracer.spanBuilder("sigstore.verifier.initialize").startSpan();
    try (Scope ignored = span.makeCurrent()) {
      var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
      span.setAttribute("sigstore.client.language", "java");
      span.setStatus(StatusCode.OK);
      return verifier;
    } catch (Exception exception) {
      span.recordException(exception);
      span.setStatus(StatusCode.ERROR, exception.getMessage());
      throw exception;
    } finally {
      span.end();
    }
  }

  private static void verify(Tracer tracer, KeylessVerifier verifier, Bundle bundle)
      throws Exception {
    Span span = tracer.spanBuilder("sigstore.verify").startSpan();
    try (Scope ignored = span.makeCurrent()) {
      verifier.verify(ARTIFACT_PATH, bundle, VerificationOptions.empty());
      span.setAttribute("sigstore.client.language", "java");
      span.setStatus(StatusCode.OK);
      System.out.println("sigstore-java verification emitted an OpenTelemetry trace.");
    } catch (Exception exception) {
      span.recordException(exception);
      span.setStatus(StatusCode.ERROR, exception.getMessage());
      throw exception;
    } finally {
      span.end();
    }
  }
}
