#:sdk Aspire.AppHost.Sdk@13.5.2
#:property AspireUseCliBundle=false
#:property NoWarn=$(NoWarn);ASPIRE010;ASPIRECERTIFICATES001

using System.Diagnostics;

var builder = DistributedApplication.CreateBuilder(args);

var sigstoreStatePath =
    Environment.GetEnvironmentVariable("SIGSTORE_STATE_PATH")
    ?? Path.Combine(builder.AppHostDirectory, ".sigstore");
sigstoreStatePath = Path.GetFullPath(
    sigstoreStatePath,
    builder.AppHostDirectory);
var shadyBlobStoreStatePath = Path.GetFullPath(
    Path.Combine(
        builder.AppHostDirectory,
        ".shady-blob-store"));
Directory.CreateDirectory(shadyBlobStoreStatePath);
// Materialize bind-mount sources before Docker Desktop resolves the model.
// The tracked resource below repeats validation so failures remain visible.
EnsureSigstoreState(
    builder.AppHostDirectory,
    sigstoreStatePath);

var sigstoreBootstrap = builder
    .AddProject(
        "sigstore-bootstrap",
        "./src/Sigstore.Bootstrap/Sigstore.Bootstrap.csproj")
    .WithEnvironment("SIGSTORE_STATE_PATH", sigstoreStatePath);

var sigstoreStateReady = builder
    .AddContainer(
        "sigstore-state-ready",
        "alpine",
        "3.20")
    .WithBindMount(
        sigstoreStatePath,
        "/var/lib/sigstore",
        isReadOnly: true)
    .WithEntrypoint("/bin/sh")
    .WithArgs(
        "-c",
        "test -f /var/lib/sigstore/bootstrap-manifest.json")
    .WaitForCompletion(sigstoreBootstrap);

var oidc = builder
    .AddDockerfile("oidc", "./src/Sigstore.Oidc")
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "private"),
        "/var/lib/sigstore/private",
        isReadOnly: true)
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "public"),
        "/var/lib/sigstore/public",
        isReadOnly: true)
    .WithEnvironment(
        "SIGSTORE_OIDC_ISSUER",
        "https://oidc-sigstore.dev.localhost:7443")
    .WithEnvironment(
        "SIGSTORE_OIDC_PRIVATE_KEY_PATH",
        "/var/lib/sigstore/private/oidc/signer.key")
    .WithEnvironment(
        "SIGSTORE_OIDC_JWKS_PATH",
        "/var/lib/sigstore/public/oidc/jwks.json")
    .WithEnvironment(
        "SIGSTORE_OIDC_DEFAULT_IDENTITY",
        "demo@sigstore.local")
    .WithEnvironment(
        "ASPNETCORE_URLS",
        "https://+:8443;http://+:8080")
    .WithHttpsDeveloperCertificate()
    .WithHttpsCertificateConfiguration(context =>
    {
        context.EnvironmentVariables[
            "ASPNETCORE_Kestrel__Certificates__Default__Path"] =
            context.CertificatePath;
        context.EnvironmentVariables[
            "ASPNETCORE_Kestrel__Certificates__Default__KeyPath"] =
            context.KeyPath;
        return Task.CompletedTask;
    })
    .WithHttpsEndpoint(
        port: 7443,
        targetPort: 8443,
        name: "https")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "internal")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "https")
    .WithExternalHttpEndpoints()
    .WaitForCompletion(sigstoreStateReady);

oidc.WithUrlForEndpoint(
    "https",
    url => url.DisplayText = "Test OIDC issuer");

var tesseract = builder
    .AddContainer(
        "tesseract",
        "ghcr.io/transparency-dev/tesseract/posix",
        "v0.1.2")
    .WithContainerRuntimeArgs("--user", "root")
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "private"),
        "/var/lib/sigstore/private",
        isReadOnly: true)
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "public"),
        "/var/lib/sigstore/public",
        isReadOnly: true)
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "data"),
        "/var/lib/sigstore/data")
    .WithArgs(
        "--private_key=/var/lib/sigstore/private/ctlog/privkey.pem",
        // The origin is the signed log identity; its endpoint port is separate.
        "--origin=tesseract-sigstore.dev.localhost",
        "--storage_dir=/var/lib/sigstore/data/ctlog",
        "--roots_pem_file=/var/lib/sigstore/public/fulcio/root.pem",
        "--ext_key_usages=CodeSigning",
        "--http_endpoint=0.0.0.0:6962",
        "--slog_level=1")
    .WithHttpEndpoint(
        port: 6962,
        targetPort: 6962,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WaitForCompletion(sigstoreStateReady);

tesseract.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Certificate transparency log");

var fulcio = builder
    .AddDockerfile("fulcio", "./src/Sigstore.Fulcio")
    .WithContainerRuntimeArgs(
        "--user",
        "root",
        "--add-host",
        "oidc-sigstore.dev.localhost:host-gateway")
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "private"),
        "/var/lib/sigstore/private",
        isReadOnly: true)
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "public"),
        "/var/lib/sigstore/public",
        isReadOnly: true)
    .WithBindMount(
        "./src/Sigstore.Fulcio/config.yaml",
        "/etc/fulcio-config/config.yaml",
        isReadOnly: true)
    .WithArgs(
        "serve",
        "--host=0.0.0.0",
        "--port=5555",
        "--grpc-host=0.0.0.0",
        "--grpc-port=5554",
        "--ca=fileca",
        "--fileca-cert=/var/lib/sigstore/public/fulcio/root.pem",
        "--fileca-key=/var/lib/sigstore/private/fulcio/root.key",
        "--fileca-watch=false",
        "--ct-log-url",
        tesseract.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork),
        "--ct-log-origin=tesseract-sigstore.dev.localhost",
        "--ct-log-public-key-path=/var/lib/sigstore/public/ctlog/pubkey.pem",
        "--config-path=/etc/fulcio-config/config.yaml")
    .WithDeveloperCertificateTrust(true)
    .WithHttpEndpoint(
        port: 5555,
        targetPort: 5555,
        name: "http")
    .WithEndpoint(
        name: "grpc",
        scheme: "http",
        port: 5554,
        targetPort: 5554)
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WaitForCompletion(sigstoreStateReady)
    .WaitFor(oidc)
    .WaitFor(tesseract);

fulcio.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Fulcio certificate authority");

var timestamp = builder
    .AddDockerfile("timestamp", "./src/Sigstore.Timestamp")
    .WithContainerRuntimeArgs("--user", "root")
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "private"),
        "/var/lib/sigstore/private",
        isReadOnly: true)
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "public"),
        "/var/lib/sigstore/public",
        isReadOnly: true)
    .WithArgs(
        "serve",
        "--host=0.0.0.0",
        "--port=3004",
        "--timestamp-signer=file",
        "--timestamp-signer-hash=sha256",
        "--file-signer-key-path=/var/lib/sigstore/private/tsa/signer.key",
        "--certificate-chain-path=/var/lib/sigstore/public/tsa/cert-chain.pem",
        "--include-chain-in-response=false",
        "--disable-ntp-monitoring")
    .WithHttpEndpoint(
        port: 3004,
        targetPort: 3004,
        name: "http")
    .WithHttpHealthCheck(
        "/ping",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WaitForCompletion(sigstoreStateReady);

timestamp.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "RFC 3161 timestamp authority");

var rekorServer = builder
    .AddContainer(
        "rekor-server",
        "ghcr.io/sigstore/rekor-tiles/posix",
        "v2.3.0@sha256:a5ceeff41b2468f965f7259685a9553c6dbba6870108ffebfa6584df5ae22504")
    .WithContainerRuntimeArgs("--user", "root")
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "private"),
        "/var/lib/sigstore/private",
        isReadOnly: true)
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "data"),
        "/var/lib/sigstore/data")
    .WithArgs(
        "rekor-server",
        "serve",
        "--http-address=0.0.0.0",
        "--http-port=3000",
        "--grpc-address=0.0.0.0",
        "--grpc-port=3001",
        "--hostname=rekor-sigstore.dev.localhost",
        "--storage-dir=/var/lib/sigstore/data/rekor",
        "--signer-filepath=/var/lib/sigstore/private/rekor/signer.key",
        "--checkpoint-interval=2s",
        "--persistent-antispam",
        "--log-level=info")
    .WithEnvironment("GOMEMLIMIT", "512MiB")
    .WithHttpEndpoint(
        targetPort: 3000,
        name: "http")
    .WithEndpoint(
        name: "grpc",
        scheme: "http",
        targetPort: 3001)
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WaitForCompletion(sigstoreStateReady);

var rekor = builder
    .AddContainer(
        "rekor",
        "nginx",
        "1.31.1@sha256:5aca99593157f4ae539a5dec1092a0ad8762f8e2eb1789085a13a0f5622369f6")
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "data"),
        "/var/lib/sigstore/data",
        isReadOnly: true)
    .WithBindMount(
        "./src/Sigstore.Rekor/nginx.conf",
        "/etc/nginx/conf.d/default.conf",
        isReadOnly: true)
    .WithHttpEndpoint(
        port: 3000,
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WaitFor(rekorServer);

rekor.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Rekor v2 transparency log");

var tufBootstrap = builder
    .AddDockerfile("tuf-bootstrap", "./src/Sigstore.Tuf")
    .WithBindMount(
        sigstoreStatePath,
        "/var/lib/sigstore")
    .WithEnvironment(
        "SIGSTORE_STATE_PATH",
        "/var/lib/sigstore")
    .WaitForCompletion(sigstoreStateReady);

var tufStateReady = builder
    .AddContainer(
        "tuf-state-ready",
        "alpine",
        "3.20")
    .WithBindMount(
        sigstoreStatePath,
        "/var/lib/sigstore",
        isReadOnly: true)
    .WithEntrypoint("/bin/sh")
    .WithArgs(
        "-c",
        "test -f /var/lib/sigstore/tuf/repository/root.json && " +
        "test -f /var/lib/sigstore/tuf/targets/trusted_root.json && " +
        "test -f /var/lib/sigstore/tuf/targets/signing_config.v0.2.json")
    .WaitForCompletion(tufBootstrap);

var tuf = builder
    .AddContainer(
        "tuf",
        "nginx",
        "1.31.1@sha256:5aca99593157f4ae539a5dec1092a0ad8762f8e2eb1789085a13a0f5622369f6")
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "tuf", "repository"),
        "/usr/share/nginx/html",
        isReadOnly: true)
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "tuf", "targets"),
        "/usr/share/nginx/bootstrap",
        isReadOnly: true)
    .WithBindMount(
        "./src/Sigstore.Tuf/nginx.conf",
        "/etc/nginx/conf.d/default.conf",
        isReadOnly: true)
    .WithHttpEndpoint(
        port: 8080,
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WaitForCompletion(tufStateReady);

tuf.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Sigstore TUF repository");

var shadyBlobStore = builder
    .AddDockerfile(
        "shady-blob-store",
        "./src/ShadyBlobStore")
    .WithBindMount(
        shadyBlobStoreStatePath,
        "/var/lib/shady-blob-store")
    .WithEnvironment(
        "ASPNETCORE_URLS",
        "http://+:8080")
    .WithEnvironment(
        "SHADY_BLOB_STORE_DATA_PATH",
        "/var/lib/shady-blob-store")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc);

shadyBlobStore
    .WithEnvironment(
        "SHADY_BLOB_STORE_BASE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork));

shadyBlobStore.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Shady artifact store");

var dotnetClient = builder
    .AddDockerfile(
        "dotnet-client",
        "./src/dotnet-client")
    .WithBindMount(
        Path.Combine(
            sigstoreStatePath,
            "tuf",
            "repository",
            "root.json"),
        "/var/lib/sigstore/tuf/root.json",
        isReadOnly: true)
    .WithEnvironment(
        "ASPNETCORE_URLS",
        "http://+:8080")
    .WithEnvironment("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
    .WithEnvironment(
        "SIGSTORE_TUF_ROOT_PATH",
        "/var/lib/sigstore/tuf/root.json")
    .WithEnvironment("SIGSTORE_TUF_CACHE_PATH", "/tmp/sigstore-tuf-cache")
    .WithEnvironment(
        "SIGSTORE_EXPECTED_IDENTITY",
        "demo@sigstore.local")
    .WithEnvironment(
        "SIGSTORE_EXPECTED_ISSUER",
        "https://oidc-sigstore.dev.localhost:7443")
    .WithEnvironment(
        "SHADY_BLOB_STORE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_TUF_URL",
        tuf.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_OIDC_URL",
        oidc.GetEndpoint(
            "internal",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_FULCIO_URL",
        fulcio.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_REKOR_URL",
        rekor.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_TIMESTAMP_URL",
        timestamp.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc)
    .WaitFor(shadyBlobStore)
    .WaitFor(tuf)
    .WaitFor(oidc)
    .WaitFor(fulcio)
    .WaitFor(timestamp)
    .WaitFor(rekor);

dotnetClient.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = ".NET producer and validator");

var goClient = builder
    .AddDockerfile("go-client", "./src/go-client")
    .WithContainerRuntimeArgs(
        "--add-host",
        "tuf-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "oidc-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "fulcio-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "rekor-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "timestamp-sigstore.dev.localhost:host-gateway")
    .WithBindMount(
        Path.Combine(sigstoreStatePath, "tuf", "repository"),
        "/var/lib/sigstore/tuf/repository",
        isReadOnly: true)
    .WithEnvironment(
        "SIGSTORE_TUF_ROOT_PATH",
        "/var/lib/sigstore/tuf/repository/root.json")
    .WithEnvironment(
        "SHADY_BLOB_STORE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_TUF_URL",
        tuf.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_OIDC_URL",
        oidc.GetEndpoint(
            "internal",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_EXPECTED_IDENTITY",
        "demo@sigstore.local")
    .WithEnvironment(
        "SIGSTORE_EXPECTED_ISSUER",
        "https://oidc-sigstore.dev.localhost:7443")
    .WithEnvironment("GO_CLIENT_PORT", "8080")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc)
    .WaitFor(shadyBlobStore)
    .WaitFor(tuf)
    .WaitFor(oidc)
    .WaitFor(fulcio)
    .WaitFor(timestamp)
    .WaitFor(rekor);

goClient.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Go producer and validator");

var pythonClient = builder
    .AddDockerfile("python-client", "./src/python-client")
    .WithContainerRuntimeArgs(
        "--add-host",
        "tuf-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "oidc-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "fulcio-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "rekor-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "timestamp-sigstore.dev.localhost:host-gateway")
    .WithBindMount(
        Path.Combine(
            sigstoreStatePath,
            "tuf",
            "repository",
            "root.json"),
        "/var/lib/sigstore/tuf/root.json",
        isReadOnly: true)
    .WithEnvironment(
        "SHADY_BLOB_STORE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_TUF_URL",
        tuf.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_TUF_ROOT_PATH",
        "/var/lib/sigstore/tuf/root.json")
    .WithEnvironment(
        "SIGSTORE_OIDC_URL",
        oidc.GetEndpoint(
            "internal",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_EXPECTED_IDENTITY",
        "demo@sigstore.local")
    .WithEnvironment(
        "SIGSTORE_EXPECTED_ISSUER",
        "https://oidc-sigstore.dev.localhost:7443")
    .WithEnvironment("PYTHON_CLIENT_PORT", "8080")
    .WithEnvironment("OTEL_TRACES_EXPORTER", "otlp")
    .WithEnvironment("OTEL_METRICS_EXPORTER", "otlp")
    .WithEnvironment("OTEL_LOGS_EXPORTER", "otlp")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc)
    .WaitFor(shadyBlobStore)
    .WaitFor(tuf)
    .WaitFor(oidc)
    .WaitFor(fulcio)
    .WaitFor(timestamp)
    .WaitFor(rekor);

pythonClient.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Python producer and validator");

var javascriptClient = builder
    .AddDockerfile(
        "javascript-client",
        "./src/javascript-client")
    .WithContainerRuntimeArgs(
        "--add-host",
        "tuf-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "oidc-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "fulcio-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "rekor-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "timestamp-sigstore.dev.localhost:host-gateway")
    .WithBindMount(
        Path.Combine(
            sigstoreStatePath,
            "tuf",
            "repository",
            "root.json"),
        "/var/lib/sigstore/tuf/root.json",
        isReadOnly: true)
    .WithEnvironment(
        "SHADY_BLOB_STORE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_TUF_URL",
        tuf.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_TUF_ROOT_PATH",
        "/var/lib/sigstore/tuf/root.json")
    .WithEnvironment(
        "SIGSTORE_OIDC_URL",
        oidc.GetEndpoint(
            "internal",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_EXPECTED_IDENTITY",
        "demo@sigstore.local")
    .WithEnvironment(
        "SIGSTORE_EXPECTED_ISSUER",
        "https://oidc-sigstore.dev.localhost:7443")
    .WithEnvironment(
        "JAVASCRIPT_CLIENT_PORT",
        "8080")
    .WithEnvironment("OTEL_METRICS_EXPORTER", "none")
    .WithEnvironment("OTEL_LOGS_EXPORTER", "none")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc)
    .WaitFor(shadyBlobStore)
    .WaitFor(tuf)
    .WaitFor(oidc)
    .WaitFor(fulcio)
    .WaitFor(timestamp)
    .WaitFor(rekor);

javascriptClient.WithUrlForEndpoint(
    "http",
    url => url.DisplayText =
        "JavaScript producer and validator");

var javaClient = builder
    .AddDockerfile("java-client", "./src/java-client")
    .WithContainerRuntimeArgs(
        "--add-host",
        "tuf-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "oidc-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "fulcio-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "rekor-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "timestamp-sigstore.dev.localhost:host-gateway")
    .WithBindMount(
        Path.Combine(
            sigstoreStatePath,
            "tuf",
            "repository",
            "root.json"),
        "/var/lib/sigstore/tuf/root.json",
        isReadOnly: true)
    .WithEnvironment(
        "SHADY_BLOB_STORE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_TUF_URL",
        tuf.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_TUF_ROOT_PATH",
        "/var/lib/sigstore/tuf/root.json")
    .WithEnvironment(
        "SIGSTORE_OIDC_URL",
        oidc.GetEndpoint(
            "internal",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_EXPECTED_IDENTITY",
        "demo@sigstore.local")
    .WithEnvironment(
        "SIGSTORE_EXPECTED_ISSUER",
        "https://oidc-sigstore.dev.localhost:7443")
    .WithEnvironment("JAVA_CLIENT_PORT", "8080")
    .WithEnvironment("OTEL_METRICS_EXPORTER", "none")
    .WithEnvironment("OTEL_LOGS_EXPORTER", "none")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc)
    .WaitFor(shadyBlobStore)
    .WaitFor(tuf)
    .WaitFor(oidc)
    .WaitFor(fulcio)
    .WaitFor(timestamp)
    .WaitFor(rekor);

javaClient.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Java producer and validator");

var rustClient = builder
    .AddDockerfile("rust-client", "./src/rust-client")
    .WithContainerRuntimeArgs(
        "--add-host",
        "tuf-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "oidc-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "fulcio-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "rekor-sigstore.dev.localhost:host-gateway",
        "--add-host",
        "timestamp-sigstore.dev.localhost:host-gateway")
    .WithBindMount(
        Path.Combine(
            sigstoreStatePath,
            "tuf",
            "repository",
            "root.json"),
        "/var/lib/sigstore/tuf/root.json",
        isReadOnly: true)
    .WithEnvironment(
        "SHADY_BLOB_STORE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_TUF_URL",
        tuf.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_TUF_ROOT_PATH",
        "/var/lib/sigstore/tuf/root.json")
    .WithEnvironment(
        "SIGSTORE_OIDC_URL",
        oidc.GetEndpoint(
            "internal",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "SIGSTORE_EXPECTED_IDENTITY",
        "demo@sigstore.local")
    .WithEnvironment(
        "SIGSTORE_EXPECTED_ISSUER",
        "https://oidc-sigstore.dev.localhost:7443")
    .WithEnvironment("RUST_CLIENT_PORT", "8080")
    .WithEnvironment("OTEL_METRICS_EXPORTER", "none")
    .WithEnvironment("OTEL_LOGS_EXPORTER", "none")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc)
    .WaitFor(shadyBlobStore)
    .WaitFor(tuf)
    .WaitFor(oidc)
    .WaitFor(fulcio)
    .WaitFor(timestamp)
    .WaitFor(rekor);

rustClient.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Rust producer and validator");

builder.Build().Run();

static void EnsureSigstoreState(
    string appHostDirectory,
    string statePath)
{
    var startInfo = new ProcessStartInfo
    {
        FileName = "dotnet",
        WorkingDirectory = appHostDirectory,
        UseShellExecute = false
    };
    startInfo.ArgumentList.Add("run");
    startInfo.ArgumentList.Add("--project");
    startInfo.ArgumentList.Add(
        "./src/Sigstore.Bootstrap/Sigstore.Bootstrap.csproj");
    startInfo.ArgumentList.Add("--configuration");
    startInfo.ArgumentList.Add("Debug");
    startInfo.ArgumentList.Add("--no-launch-profile");
    startInfo.Environment["SIGSTORE_STATE_PATH"] = statePath;

    using var process = Process.Start(startInfo)
        ?? throw new InvalidOperationException(
            "Unable to start the Sigstore bootstrapper.");
    process.WaitForExit();

    if (process.ExitCode != 0)
    {
        throw new InvalidOperationException(
            $"The Sigstore bootstrapper exited with code " +
            $"{process.ExitCode}.");
    }
}
