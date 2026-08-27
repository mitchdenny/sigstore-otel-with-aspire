package example;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.protobuf.ByteString;
import com.sun.net.httpserver.HttpServer;
import dev.sigstore.AlgorithmRegistry;
import dev.sigstore.KeylessVerifier;
import dev.sigstore.VerificationOptions;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.bundle.ImmutableBundle;
import dev.sigstore.bundle.ImmutableTimestamp;
import dev.sigstore.encryption.Hashers;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.fulcio.client.CertificateRequest;
import dev.sigstore.fulcio.client.FulcioClientHttp;
import dev.sigstore.fulcio.client.FulcioVerifier;
import dev.sigstore.http.HttpParams;
import dev.sigstore.oidc.client.TokenStringOidcClient;
import dev.sigstore.proto.ProtoMutators;
import dev.sigstore.proto.common.v1.X509Certificate;
import dev.sigstore.proto.rekor.v2.HashedRekordRequestV002;
import dev.sigstore.proto.rekor.v2.Signature;
import dev.sigstore.proto.rekor.v2.Verifier;
import dev.sigstore.rekor.client.RekorVerifier;
import dev.sigstore.rekor.v2.client.RekorV2ClientHttp;
import dev.sigstore.strings.StringMatcher;
import dev.sigstore.timestamp.client.ImmutableTimestampRequest;
import dev.sigstore.timestamp.client.TimestampClientHttp;
import dev.sigstore.timestamp.client.TimestampVerifier;
import dev.sigstore.trustroot.Service;
import dev.sigstore.trustroot.SigstoreSigningConfig;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import dev.sigstore.tuf.RootProvider;
import dev.sigstore.tuf.SigstoreTufClient;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import java.io.IOException;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class SigstoreClient {
  private static final int MAXIMUM_PENDING_ATTEMPTS = 5;
  private static final Duration POLL_INTERVAL = Duration.ofSeconds(2);
  private static final Duration PRODUCE_INTERVAL = Duration.ofSeconds(10);
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
  private static final int TRUST_STATUS_SCHEMA_VERSION = 1;
  private static final String TRUST_STATUS_TARGET_NAME = "trust_status.v1.json";

  private static final Gson GSON = new Gson();
  private static final Gson STATUS_GSON =
      new GsonBuilder().serializeNulls().create();
  private static final Logger LOGGER = Logger.getLogger(SigstoreClient.class.getName());
  private static final SecureRandom RANDOM = new SecureRandom();

  private SigstoreClient() {}

  public static void main(String[] args) throws Exception {
    Config config = Config.fromEnvironment();
    Tracer tracer = GlobalOpenTelemetry.getTracer("sigstore.demo.java-client", "1.0.0");
    TrustMaterial trust = initializeTrust(config, tracer);
    var artifactStore = new ArtifactStore(config.artifactStoreUrl());
    var signer = new LocalKeylessSigner(trust.trustedRoot(), trust.signingConfig());
    var verifier =
        KeylessVerifier.builder()
            .trustedRootProvider(() -> trust.trustedRoot())
            .build();
    var verificationOptions =
        VerificationOptions.builder()
            .addCertificateMatchers(
                VerificationOptions.CertificateMatcher.fulcio()
                    .issuer(StringMatcher.string(config.expectedIssuer()))
                    .subjectAlternativeName(
                        StringMatcher.string(config.expectedIdentity()))
                    .build())
            .build();

    var running = new AtomicBoolean(true);
    var workersHealthy = new AtomicBoolean(true);
    var stopped = new CountDownLatch(1);
    var workerPool = Executors.newFixedThreadPool(2);
    var healthServer =
        startHealthServer(
            config.port(), running, workersHealthy, trust.status());

    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  running.set(false);
                  healthServer.stop(0);
                  workerPool.shutdownNow();
                  stopped.countDown();
                }));

    workerPool.submit(
        () -> producerLoop(config, tracer, artifactStore, signer, running));
    workerPool.submit(
        () ->
            validatorLoop(
                config,
                tracer,
                artifactStore,
                verifier,
                verificationOptions,
                running));

    LOGGER.info("Java producer and validator started.");
    stopped.await();
    workersHealthy.set(false);
  }

  private static TrustMaterial initializeTrust(Config config, Tracer tracer)
      throws Exception {
    Span span =
        tracer
            .spanBuilder("sigstore.trust.initialize")
            .setAttribute("client.language", "java")
            .setAttribute("client.resource.name", "java-client")
            .startSpan();
    try (Scope ignored = span.makeCurrent()) {
      Path cachePath = Path.of("/tmp/sigstore-java-tuf-cache");
      SigstoreTufClient tufClient =
          SigstoreTufClient.builder()
              .tufMirror(
                  config.tufUrl(),
                  RootProvider.fromFile(config.tufRootPath()))
              .tufCacheLocation(cachePath)
              .build();
      tufClient.update();
      SigstoreTrustedRoot trustedRoot = tufClient.getSigstoreTrustedRoot();
      SigstoreSigningConfig signingConfig =
          tufClient.getSigstoreSigningConfig();
      byte[] trustedRootBytes =
          readVerifiedCachedTarget(
              cachePath, "trusted_root.json");
      byte[] signingConfigBytes =
          readVerifiedCachedTarget(
              cachePath, "signing_config.v0.2.json");
      byte[] publishedStatusBytes =
          readVerifiedMountedTarget(
              cachePath,
              config.tufTrustStatusPath(),
              TRUST_STATUS_TARGET_NAME);
      ClientTrustStatus status =
          createClientTrustStatus(
              publishedStatusBytes,
              trustedRootBytes,
              signingConfigBytes,
              readMetadataVersion(cachePath.resolve("root.json")),
              readMetadataVersion(cachePath.resolve("targets.json")),
              Instant.now().toString());
      setTrustSpanAttributes(span, status);
      span.setStatus(StatusCode.OK);
      return new TrustMaterial(trustedRoot, signingConfig, status);
    } catch (Exception exception) {
      recordError(span, exception);
      throw exception;
    } finally {
      span.end();
    }
  }

  private static void producerLoop(
      Config config,
      Tracer tracer,
      ArtifactStore artifactStore,
      LocalKeylessSigner signer,
      AtomicBoolean running) {
    while (running.get() && !Thread.currentThread().isInterrupted()) {
      try {
        produceOnce(config, tracer, artifactStore, signer, running);
      } catch (Exception exception) {
        LOGGER.log(Level.SEVERE, "Failed to produce an artifact.", exception);
      }
      sleep(PRODUCE_INTERVAL);
    }
  }

  private static void produceOnce(
      Config config,
      Tracer tracer,
      ArtifactStore artifactStore,
      LocalKeylessSigner signer,
      AtomicBoolean running)
      throws Exception {
    byte[] artifact = new byte[RANDOM.nextInt(256, 4097)];
    RANDOM.nextBytes(artifact);
    Span span =
        tracer
            .spanBuilder("artifact.produce")
            .setSpanKind(SpanKind.PRODUCER)
            .startSpan();
    span.setAttribute("artifact.size", artifact.length);
    span.setAttribute("client.language", "java");

    try (Scope ignored = span.makeCurrent()) {
      String token = fetchIdentityToken(config);
      Bundle bundle = signer.sign(artifact, token);
      ArtifactReservation reservation =
          artifactStore.uploadArtifact(artifact);
      span.setAttribute("artifact.id", reservation.id());

      while (running.get()) {
        try {
          artifactStore.uploadSignature(
              reservation,
              bundle.toJson());
          break;
        } catch (HttpStatusException exception) {
          if (exception.status() < 500) {
            throw exception;
          }
          LOGGER.log(
              Level.WARNING,
              "Signature upload failed; retrying.",
              exception);
          sleep(POLL_INTERVAL);
        } catch (IOException exception) {
          LOGGER.log(
              Level.WARNING,
              "Signature upload failed; retrying.",
              exception);
          sleep(POLL_INTERVAL);
        } catch (InterruptedException exception) {
          Thread.currentThread().interrupt();
          throw exception;
        }
      }

      span.setStatus(StatusCode.OK);
      LOGGER.info(
          "Produced and signed artifact "
              + reservation.id()
              + " ("
              + artifact.length
              + " bytes).");
    } catch (Exception exception) {
      recordError(span, exception);
      throw exception;
    } finally {
      span.end();
    }
  }

  private static String fetchIdentityToken(Config config)
      throws Exception {
    URI tokenUrl = config.oidcUrl().resolve("token");
    HttpResponse<String> response =
        HttpClient.newBuilder()
            .connectTimeout(REQUEST_TIMEOUT)
            .build()
            .send(
                HttpRequest.newBuilder(tokenUrl)
                    .timeout(REQUEST_TIMEOUT)
                    .GET()
                    .build(),
                HttpResponse.BodyHandlers.ofString());
    ensureSuccess(response.statusCode());
    var tokenClient = TokenStringOidcClient.from(response.body().trim());
    var token = tokenClient.getIDToken(Map.of());
    if (!token.getSubjectAlternativeName().equals(config.expectedIdentity())) {
      throw new IllegalStateException("OIDC identity did not match");
    }
    if (!token.getIssuer().equals(config.expectedIssuer())) {
      throw new IllegalStateException("OIDC issuer did not match");
    }
    return token.getIdToken();
  }

  private static void validatorLoop(
      Config config,
      Tracer tracer,
      ArtifactStore artifactStore,
      KeylessVerifier verifier,
      VerificationOptions verificationOptions,
      AtomicBoolean running) {
    long nextId = 1;
    long highWatermark = 0;
    int pendingAttempts = 0;

    while (running.get() && !Thread.currentThread().isInterrupted()) {
      Duration retryAfter = POLL_INTERVAL;
      try {
        if (nextId > highWatermark) {
          long observedHead = artifactStore.head();
          if (observedHead < highWatermark) {
            throw new IllegalStateException(
                "Artifact head moved backward from "
                    + highWatermark
                    + " to "
                    + observedHead);
          }
          highWatermark = observedHead;
          if (nextId > highWatermark) {
            sleep(retryAfter);
            continue;
          }
        }

        FetchResult artifactResult = artifactStore.artifact(nextId);
        if (artifactResult.state() == FetchState.PENDING) {
          pendingAttempts++;
          if (pendingAttempts >= MAXIMUM_PENDING_ATTEMPTS) {
            skipArtifact(
                tracer,
                nextId,
                "The artifact remained unsealed after "
                    + pendingAttempts
                    + " attempts.",
                pendingAttempts);
            nextId++;
            pendingAttempts = 0;
            continue;
          }
          retryAfter = artifactResult.retryAfter();
          sleep(retryAfter);
          continue;
        }
        if (artifactResult.state() == FetchState.MISSING) {
          skipArtifact(
              tracer,
              nextId,
              "The artifact is below the sealed head but its content is missing.",
              pendingAttempts);
          nextId++;
          pendingAttempts = 0;
          continue;
        }

        FetchResult signatureResult = artifactStore.signature(nextId);
        if (signatureResult.state() == FetchState.PENDING) {
          pendingAttempts++;
          if (pendingAttempts >= MAXIMUM_PENDING_ATTEMPTS) {
            skipArtifact(
                tracer,
                nextId,
                "The artifact remained unsealed after "
                    + pendingAttempts
                    + " attempts.",
                pendingAttempts);
            nextId++;
            pendingAttempts = 0;
            continue;
          }
          retryAfter = signatureResult.retryAfter();
          sleep(retryAfter);
          continue;
        }
        if (signatureResult.state() == FetchState.MISSING) {
          skipArtifact(
              tracer,
              nextId,
              "The artifact is below the sealed head but its signature is missing.",
              pendingAttempts);
          nextId++;
          pendingAttempts = 0;
          continue;
        }

        validateOnce(
            tracer,
            verifier,
            verificationOptions,
            nextId,
            artifactResult.content(),
            signatureResult.content());
        nextId++;
        pendingAttempts = 0;
        continue;
      } catch (Exception exception) {
        LOGGER.log(
            Level.SEVERE,
            "Failed to validate artifact " + nextId + ".",
            exception);
      }
      sleep(retryAfter);
    }
  }

  private static void validateOnce(
      Tracer tracer,
      KeylessVerifier verifier,
      VerificationOptions verificationOptions,
      long id,
      byte[] artifact,
      byte[] bundleJson)
      throws Exception {
    Span span =
        tracer
            .spanBuilder("artifact.validate")
            .setSpanKind(SpanKind.CONSUMER)
            .startSpan();
    span.setAttribute("artifact.id", id);
    span.setAttribute("artifact.size", artifact.length);
    span.setAttribute("client.language", "java");
    try (Scope ignored = span.makeCurrent()) {
      Bundle bundle =
          Bundle.from(
              new StringReader(
                  new String(bundleJson, StandardCharsets.UTF_8)));
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(artifact);
      verifier.verify(digest, bundle, verificationOptions);
      span.setStatus(StatusCode.OK);
      LOGGER.info(
          "Validated artifact "
              + id
              + " ("
              + artifact.length
              + " bytes).");
    } catch (Exception exception) {
      recordError(span, exception);
      throw exception;
    } finally {
      span.end();
    }
  }

  private static void skipArtifact(
      Tracer tracer,
      long id,
      String reason,
      int attempts) {
    Span span =
        tracer
            .spanBuilder("artifact.skip")
            .setSpanKind(SpanKind.CONSUMER)
            .startSpan();
    span.setAttribute("artifact.id", id);
    span.setAttribute("artifact.retry_count", attempts);
    span.setAttribute("artifact.warning", reason);
    span.setAttribute("client.language", "java");
    try (Scope ignored = span.makeCurrent()) {
      span.addEvent("artifact.skipped");
      LOGGER.warning("Skipping artifact " + id + ": " + reason);
    } finally {
      span.end();
    }
  }

  private static HttpServer startHealthServer(
      int port,
      AtomicBoolean running,
      AtomicBoolean workersHealthy,
      ClientTrustStatus trustStatus)
      throws Exception {
    HttpServer server =
        HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
    server.createContext(
        "/healthz",
        exchange -> {
          boolean healthy = running.get() && workersHealthy.get();
          byte[] body =
              (healthy
                      ? "{\"status\":\"SERVING\"}"
                      : "{\"status\":\"NOT_SERVING\"}")
                  .getBytes(StandardCharsets.UTF_8);
          exchange
              .getResponseHeaders()
              .set("Content-Type", "application/json");
          exchange.sendResponseHeaders(healthy ? 200 : 503, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    server.createContext(
        "/trust/status",
        exchange -> {
          boolean healthy = running.get() && workersHealthy.get();
          ClientTrustStatus current =
              trustStatus.withAvailability(
                  healthy,
                  healthy ? null : "client is stopping");
          byte[] body =
              STATUS_GSON.toJson(current).getBytes(StandardCharsets.UTF_8);
          exchange
              .getResponseHeaders()
              .set("Content-Type", "application/json");
          exchange.sendResponseHeaders(healthy ? 200 : 503, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    server.start();
    return server;
  }

  private static void sleep(Duration duration) {
    try {
      Thread.sleep(duration);
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
    }
  }

  private static void recordError(Span span, Exception exception) {
    span.recordException(exception);
    span.setStatus(StatusCode.ERROR, exception.getMessage());
  }

  private static void ensureSuccess(int status) throws HttpStatusException {
    if (status < 200 || status >= 300) {
      throw new HttpStatusException(status);
    }
  }

  private record Config(
      URI artifactStoreUrl,
      URI tufUrl,
      Path tufRootPath,
      Path tufTrustStatusPath,
      URI oidcUrl,
      String expectedIdentity,
      String expectedIssuer,
      int port) {
    static Config fromEnvironment() {
      return new Config(
          requiredUri("SHADY_BLOB_STORE_URL"),
          requiredUri("SIGSTORE_TUF_URL"),
          Path.of(required("SIGSTORE_TUF_ROOT_PATH")),
          Path.of(required("SIGSTORE_TUF_TRUST_STATUS_PATH")),
          requiredUri("SIGSTORE_OIDC_URL"),
          required("SIGSTORE_EXPECTED_IDENTITY"),
          required("SIGSTORE_EXPECTED_ISSUER"),
          Integer.parseInt(
              System.getenv().getOrDefault("JAVA_CLIENT_PORT", "8080")));
    }
  }

  private record TrustMaterial(
      SigstoreTrustedRoot trustedRoot,
      SigstoreSigningConfig signingConfig,
      ClientTrustStatus status) {}

  record PublishedTrustStatus(
      int schemaVersion,
      String trustDomainId,
      long generation,
      String generationId,
      String generationManifestSha256,
      long tufRootVersion,
      long tufTargetsVersion,
      String trustedRootSha256,
      String signingConfigSha256) {}

  record ClientTrustStatus(
      int schemaVersion,
      String resource,
      String language,
      boolean ready,
      String lastError,
      String trustDomainId,
      long generation,
      String generationId,
      String generationManifestSha256,
      long tufRootVersion,
      long tufTargetsVersion,
      String trustedRootSha256,
      String signingConfigSha256,
      String initializedAtUtc) {
    ClientTrustStatus withAvailability(
        boolean currentReady,
        String currentLastError) {
      return new ClientTrustStatus(
          schemaVersion,
          resource,
          language,
          currentReady,
          currentLastError,
          trustDomainId,
          generation,
          generationId,
          generationManifestSha256,
          tufRootVersion,
          tufTargetsVersion,
          trustedRootSha256,
          signingConfigSha256,
          initializedAtUtc);
    }
  }

  private static byte[] readVerifiedCachedTarget(
      Path cachePath,
      String targetName)
      throws Exception {
    return verifyTarget(
        cachePath,
        targetName,
        Files.readAllBytes(
            cachePath.resolve("targets").resolve(targetName)));
  }

  private static byte[] readVerifiedMountedTarget(
      Path cachePath,
      Path targetPath,
      String targetName)
      throws Exception {
    return verifyTarget(
        cachePath,
        targetName,
        Files.readAllBytes(targetPath));
  }

  private static byte[] verifyTarget(
      Path cachePath,
      String targetName,
      byte[] bytes)
      throws Exception {
    JsonObject targets =
        JsonParser.parseString(
                Files.readString(
                    cachePath.resolve("targets.json"),
                    StandardCharsets.UTF_8))
            .getAsJsonObject()
            .getAsJsonObject("signed")
            .getAsJsonObject("targets");
    JsonObject target = targets.getAsJsonObject(targetName);
    if (target == null) {
      throw new IllegalStateException(
          "Verified TUF metadata does not contain " + targetName + ".");
    }
    long expectedLength = target.get("length").getAsLong();
    JsonObject hashes = target.getAsJsonObject("hashes");
    boolean hashPresent = false;
    boolean hashVerified = true;
    if (hashes.has("sha256")) {
      hashPresent = true;
      hashVerified &=
          hashes.get("sha256").getAsString().equals(
              digest("SHA-256", bytes));
    }
    if (hashes.has("sha512")) {
      hashPresent = true;
      hashVerified &=
          hashes.get("sha512").getAsString().equals(
              digest("SHA-512", bytes));
    }
    if (expectedLength != bytes.length
        || !hashPresent
        || !hashVerified) {
      throw new IllegalStateException(
          "TUF target " + targetName + " failed verified hash validation.");
    }
    return bytes;
  }

  private static int readMetadataVersion(Path path)
      throws Exception {
    int version =
        JsonParser.parseString(
                Files.readString(path, StandardCharsets.UTF_8))
            .getAsJsonObject()
            .getAsJsonObject("signed")
            .get("version")
            .getAsInt();
    if (version <= 0) {
      throw new IllegalStateException(
          "TUF metadata " + path.getFileName()
              + " has invalid version " + version + ".");
    }
    return version;
  }

  static ClientTrustStatus createClientTrustStatus(
      byte[] publishedStatusBytes,
      byte[] trustedRootBytes,
      byte[] signingConfigBytes,
      int rootVersion,
      int targetsVersion,
      String initializedAtUtc) {
    PublishedTrustStatus published =
        STATUS_GSON.fromJson(
            new String(publishedStatusBytes, StandardCharsets.UTF_8),
            PublishedTrustStatus.class);
    String trustedRootHash = sha256(trustedRootBytes);
    String signingConfigHash = sha256(signingConfigBytes);
    if (published == null
        || published.schemaVersion() != TRUST_STATUS_SCHEMA_VERSION
        || published.trustDomainId() == null
        || published.trustDomainId().isBlank()
        || published.generation() <= 0
        || published.generationId() == null
        || published.generationId().isBlank()
        || !isLowerHexSha256(published.generationManifestSha256())
        || published.tufRootVersion() != rootVersion
        || published.tufTargetsVersion() != targetsVersion
        || !trustedRootHash.equals(published.trustedRootSha256())
        || !signingConfigHash.equals(published.signingConfigSha256())) {
      throw new IllegalStateException(
          "Published trust status does not match verified TUF material.");
    }

    return new ClientTrustStatus(
        TRUST_STATUS_SCHEMA_VERSION,
        "java-client",
        "java",
        true,
        null,
        published.trustDomainId(),
        published.generation(),
        published.generationId(),
        published.generationManifestSha256(),
        rootVersion,
        targetsVersion,
        trustedRootHash,
        signingConfigHash,
        initializedAtUtc);
  }

  private static void setTrustSpanAttributes(
      Span span,
      ClientTrustStatus status) {
    span.setAttribute(
        "sigstore.trust.domain.id", status.trustDomainId());
    span.setAttribute(
        "sigstore.trust.generation", status.generation());
    span.setAttribute(
        "sigstore.trust.generation.id", status.generationId());
    span.setAttribute(
        "sigstore.trust.generation.manifest.sha256",
        status.generationManifestSha256());
    span.setAttribute(
        "sigstore.trust.tuf.root.version",
        status.tufRootVersion());
    span.setAttribute(
        "sigstore.trust.tuf.targets.version",
        status.tufTargetsVersion());
    span.setAttribute(
        "sigstore.trust.trusted_root.sha256",
        status.trustedRootSha256());
    span.setAttribute(
        "sigstore.trust.signing_config.sha256",
        status.signingConfigSha256());
    span.setAttribute(
        "sigstore.trust.initialized_at",
        status.initializedAtUtc());
  }

  private static String sha256(byte[] value) {
    return digest("SHA-256", value);
  }

  private static String digest(
      String algorithm,
      byte[] value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance(algorithm).digest(value));
    } catch (Exception exception) {
      throw new IllegalStateException(
          algorithm + " is unavailable.", exception);
    }
  }

  private static boolean isLowerHexSha256(String value) {
    return value != null && value.matches("[0-9a-f]{64}");
  }

  private static final class LocalKeylessSigner {
    private static final AlgorithmRegistry.SigningAlgorithm SIGNING_ALGORITHM =
        AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P256_SHA_256;

    private final FulcioClientHttp fulcio;
    private final FulcioVerifier fulcioVerifier;
    private final RekorV2ClientHttp rekor;
    private final RekorVerifier rekorVerifier;
    private final TimestampClientHttp timestamp;
    private final TimestampVerifier timestampVerifier;

    LocalKeylessSigner(
        SigstoreTrustedRoot trustedRoot,
        SigstoreSigningConfig signingConfig)
        throws Exception {
      HttpParams httpParams =
          HttpParams.builder().allowInsecureConnections(true).build();
      Service fulcioService =
          Service.select(signingConfig.getCas(), List.of(1))
              .orElseThrow(
                  () -> new IllegalStateException("No Fulcio service."));
      Service rekorService =
          Service.select(signingConfig.getTLogs(), List.of(2))
              .orElseThrow(
                  () -> new IllegalStateException("No Rekor v2 service."));
      Service tsaService =
          Service.select(signingConfig.getTsas(), List.of(1))
              .orElseThrow(
                  () -> new IllegalStateException("No TSA service."));

      fulcio =
          FulcioClientHttp.builder()
              .setHttpParams(httpParams)
              .setService(fulcioService)
              .build();
      fulcioVerifier = FulcioVerifier.newFulcioVerifier(trustedRoot);
      rekor =
          RekorV2ClientHttp.builder()
              .setHttpParams(httpParams)
              .setService(rekorService)
              .build();
      rekorVerifier = RekorVerifier.newRekorVerifier(trustedRoot);
      timestamp =
          TimestampClientHttp.builder()
              .setHttpParams(httpParams)
              .setService(tsaService)
              .build();
      timestampVerifier =
          TimestampVerifier.newTimestampVerifier(trustedRoot);
    }

    Bundle sign(byte[] artifact, String idToken) throws Exception {
      var hashFunction = Hashers.from(SIGNING_ALGORITHM);
      byte[] artifactDigest = hashFunction.hashBytes(artifact).asBytes();
      var signer = Signers.from(SIGNING_ALGORITHM);
      byte[] signature = signer.signDigest(artifactDigest);

      var token =
          TokenStringOidcClient.from(idToken).getIDToken(Map.of());
      var certificate =
          fulcio.signingCertificate(
              CertificateRequest.newCertificateRequest(
                  signer.getPublicKey(),
                  token.getIdToken(),
                  signer.sign(
                      token
                          .getSubjectAlternativeName()
                          .getBytes(StandardCharsets.UTF_8))));
      certificate =
          fulcioVerifier.trimTrustedParent(certificate);
      fulcioVerifier.verifySigningCertificate(certificate);
      byte[] encodedCertificate =
          Certificates.getLeaf(certificate).getEncoded();

      byte[] signatureDigest =
          hashFunction.hashBytes(signature).asBytes();
      var timestampResponse =
          timestamp.timestamp(
              ImmutableTimestampRequest.builder()
                  .hashAlgorithm(SIGNING_ALGORITHM.getHashAlgorithm())
                  .hash(signatureDigest)
                  .build());
      timestampVerifier.verify(timestampResponse, signature);

      var verifier =
          Verifier.newBuilder()
              .setX509Certificate(
                  X509Certificate.newBuilder()
                      .setRawBytes(
                          ByteString.copyFrom(encodedCertificate))
                      .build())
              .setKeyDetails(
                  ProtoMutators.toPublicKeyDetails(SIGNING_ALGORITHM))
              .build();
      var requestSignature =
          Signature.newBuilder()
              .setContent(ByteString.copyFrom(signature))
              .setVerifier(verifier)
              .build();
      var request =
          HashedRekordRequestV002.newBuilder()
              .setDigest(ByteString.copyFrom(artifactDigest))
              .setSignature(requestSignature)
              .build();
      var entry = rekor.putEntry(request);
      rekorVerifier.verifyEntry(entry);

      return ImmutableBundle.builder()
          .certPath(certificate)
          .messageSignature(
              Bundle.MessageSignature.of(
                  SIGNING_ALGORITHM.getHashAlgorithm(),
                  artifactDigest,
                  signature))
          .addTimestamps(
              ImmutableTimestamp.builder()
                  .rfc3161Timestamp(timestampResponse.getEncoded())
                  .build())
          .addEntries(entry)
          .build();
    }
  }

  private static final class ArtifactStore {
    private final URI baseUrl;
    private final HttpClient client =
        HttpClient.newBuilder()
            .connectTimeout(REQUEST_TIMEOUT)
            .build();

    ArtifactStore(URI baseUrl) {
      this.baseUrl = normalize(baseUrl);
    }

    ArtifactReservation uploadArtifact(byte[] artifact) throws Exception {
      HttpResponse<String> response =
          client.send(
              HttpRequest.newBuilder(baseUrl.resolve("artifacts"))
                  .timeout(REQUEST_TIMEOUT)
                  .header("Content-Type", "application/octet-stream")
                  .POST(HttpRequest.BodyPublishers.ofByteArray(artifact))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      ensureSuccess(response.statusCode());
      ArtifactReservation reservation =
          GSON.fromJson(response.body(), ArtifactReservation.class);
      if (reservation.id() <= 0 || reservation.sealToken().isBlank()) {
        throw new IllegalStateException(
            "Artifact store returned an invalid reservation.");
      }
      URI expected = baseUrl.resolve("artifacts/" + reservation.id());
      if (!URI.create(reservation.url()).equals(expected)
          || !URI.create(reservation.signatureUrl())
              .equals(URI.create(expected + "/signature"))
          || !sameOrigin(URI.create(reservation.url()), baseUrl)
          || !sameOrigin(
              URI.create(reservation.signatureUrl()), baseUrl)) {
        throw new IllegalStateException(
            "Artifact store returned an unexpected URL.");
      }
      return reservation;
    }

    void uploadSignature(
        ArtifactReservation reservation,
        String bundleJson)
        throws Exception {
      URI signatureUrl = URI.create(reservation.signatureUrl());
      if (!sameOrigin(signatureUrl, baseUrl)) {
        throw new IllegalStateException(
            "Refusing signature upload outside artifact store.");
      }
      HttpResponse<Void> response =
          client.send(
              HttpRequest.newBuilder(signatureUrl)
                  .timeout(REQUEST_TIMEOUT)
                  .header(
                      "Content-Type",
                      "application/vnd.dev.sigstore.bundle+json")
                  .header(
                      "X-Artifact-Seal-Token",
                      reservation.sealToken())
                  .POST(
                      HttpRequest.BodyPublishers.ofString(bundleJson))
                  .build(),
              HttpResponse.BodyHandlers.discarding());
      ensureSuccess(response.statusCode());
    }

    long head() throws Exception {
      HttpResponse<String> response =
          client.send(
              HttpRequest.newBuilder(baseUrl.resolve("artifacts/head"))
                  .timeout(REQUEST_TIMEOUT)
                  .GET()
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      ensureSuccess(response.statusCode());
      ArtifactHead head = GSON.fromJson(response.body(), ArtifactHead.class);
      if (head.id() < 0) {
        throw new IllegalStateException(
            "Artifact store returned an invalid head.");
      }
      return head.id();
    }

    FetchResult artifact(long id) throws Exception {
      return fetch(baseUrl.resolve("artifacts/" + id));
    }

    FetchResult signature(long id) throws Exception {
      return fetch(baseUrl.resolve("artifacts/" + id + "/signature"));
    }

    private FetchResult fetch(URI uri) throws Exception {
      HttpResponse<byte[]> response =
          client.send(
              HttpRequest.newBuilder(uri)
                  .timeout(REQUEST_TIMEOUT)
                  .GET()
                  .build(),
              HttpResponse.BodyHandlers.ofByteArray());
      if (response.statusCode() == 404) {
        return new FetchResult(FetchState.MISSING, null, Duration.ZERO);
      }
      if (response.statusCode() == 425) {
        return new FetchResult(
            FetchState.PENDING,
            null,
            retryAfter(response));
      }
      ensureSuccess(response.statusCode());
      return new FetchResult(
          FetchState.FOUND,
          response.body(),
          Duration.ZERO);
    }
  }

  private enum FetchState {
    FOUND,
    MISSING,
    PENDING
  }

  private record FetchResult(
      FetchState state,
      byte[] content,
      Duration retryAfter) {}

  private record ArtifactReservation(
      long id,
      String url,
      String signatureUrl,
      String sealToken) {}

  private record ArtifactHead(long id) {}

  private static final class HttpStatusException extends Exception {
    private final int status;

    HttpStatusException(int status) {
      super("HTTP status " + status);
      this.status = status;
    }

    int status() {
      return status;
    }
  }

  private static Duration retryAfter(HttpResponse<?> response) {
    double seconds =
        response
            .headers()
            .firstValue("Retry-After")
            .map(
                value -> {
                  try {
                    return Double.parseDouble(value);
                  } catch (NumberFormatException exception) {
                    return 2.0;
                  }
                })
            .orElse(2.0);
    seconds = Math.max(0.1, Math.min(seconds, 30));
    return Duration.ofMillis((long) (seconds * 1000));
  }

  private static URI normalize(URI uri) {
    String value = uri.toString();
    return URI.create(value.endsWith("/") ? value : value + "/");
  }

  private static boolean sameOrigin(URI left, URI right) {
    return left.getScheme().equalsIgnoreCase(right.getScheme())
        && left.getHost().equalsIgnoreCase(right.getHost())
        && effectivePort(left) == effectivePort(right);
  }

  private static int effectivePort(URI uri) {
    if (uri.getPort() >= 0) {
      return uri.getPort();
    }
    return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
  }

  private static String required(String name) {
    return Optional.ofNullable(System.getenv(name))
        .filter(value -> !value.isBlank())
        .orElseThrow(
            () ->
                new IllegalStateException(name + " must be configured."));
  }

  private static URI requiredUri(String name) {
    URI uri = URI.create(required(name));
    if (!List.of("http", "https").contains(uri.getScheme())
        || uri.getHost() == null) {
      throw new IllegalStateException(
          name + " must be an absolute HTTP(S) URL.");
    }
    return uri;
  }
}
