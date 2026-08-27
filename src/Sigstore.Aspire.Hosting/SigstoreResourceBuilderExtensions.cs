using Aspire.Hosting.ApplicationModel;

namespace Aspire.Hosting;

public static class SigstoreResourceBuilderExtensions
{
    public static SigstoreComponents AddSigstore(
        this IDistributedApplicationBuilder builder,
        [ResourceName] string name,
        SigstoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(options);

        var appHostDirectory = Path.GetFullPath(builder.AppHostDirectory);
        var statePath = ResolveDirectoryPath(
            appHostDirectory,
            SigstoreOptions.StateDirectoryName,
            "Sigstore state");
        var sourcePath = ResolveDirectoryPath(
            appHostDirectory,
            options.SourcePath,
            nameof(options.SourcePath));

        var parent = builder
            .AddResource(
                new SigstoreResource(
                    name,
                    statePath,
                    sourcePath))
            .WithInitialState(new CustomResourceSnapshot
            {
                ResourceType = "Sigstore",
                CreationTimeStamp = DateTime.UtcNow,
                State = KnownResourceStates.Active,
                Properties = []
            })
            .ExcludeFromManifest();

        var bootstrap = builder
            .AddProject(
                "sigstore-bootstrap",
                Path.Combine(
                    sourcePath,
                    "Sigstore.Bootstrap",
                    "Sigstore.Bootstrap.csproj"))
            .WithEnvironment("SIGSTORE_STATE_PATH", statePath)
            .WithParentRelationship(parent.Resource);

        var stateReady = builder
            .AddContainer(
                "sigstore-state-ready",
                "alpine",
                "3.20")
            .WithBindMount(
                statePath,
                "/var/lib/sigstore",
                isReadOnly: true)
            .WithEntrypoint("/bin/sh")
            .WithArgs(
                "-c",
                "test -f /var/lib/sigstore/bootstrap-manifest.json")
            .WaitForCompletion(bootstrap)
            .WithParentRelationship(parent.Resource);

        var oidc = builder
            .AddDockerfile(
                "oidc",
                Path.Combine(sourcePath, "Sigstore.Oidc"))
            .WithBindMount(
                Path.Combine(statePath, "private"),
                "/var/lib/sigstore/private",
                isReadOnly: true)
            .WithBindMount(
                Path.Combine(statePath, "public"),
                "/var/lib/sigstore/public",
                isReadOnly: true)
            .WithEnvironment(
                "SIGSTORE_OIDC_ISSUER",
                SigstoreDefaults.ExpectedIssuer)
            .WithEnvironment(
                "SIGSTORE_OIDC_PRIVATE_KEY_PATH",
                "/var/lib/sigstore/private/oidc/signer.key")
            .WithEnvironment(
                "SIGSTORE_OIDC_JWKS_PATH",
                "/var/lib/sigstore/public/oidc/jwks.json")
            .WithEnvironment(
                "SIGSTORE_OIDC_DEFAULT_IDENTITY",
                SigstoreDefaults.ExpectedIdentity)
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
            .WaitForCompletion(stateReady)
            .WithParentRelationship(parent.Resource);

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
                Path.Combine(statePath, "private"),
                "/var/lib/sigstore/private",
                isReadOnly: true)
            .WithBindMount(
                Path.Combine(statePath, "public"),
                "/var/lib/sigstore/public",
                isReadOnly: true)
            .WithBindMount(
                Path.Combine(statePath, "data"),
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
            .WaitForCompletion(stateReady)
            .WithParentRelationship(parent.Resource);

        tesseract.WithUrlForEndpoint(
            "http",
            url => url.DisplayText = "Certificate transparency log");

        var fulcio = builder
            .AddDockerfile(
                "fulcio",
                Path.Combine(sourcePath, "Sigstore.Fulcio"))
            .WithContainerRuntimeArgs(
                "--user",
                "root",
                "--add-host",
                "oidc-sigstore.dev.localhost:host-gateway")
            .WithBindMount(
                Path.Combine(statePath, "private"),
                "/var/lib/sigstore/private",
                isReadOnly: true)
            .WithBindMount(
                Path.Combine(statePath, "public"),
                "/var/lib/sigstore/public",
                isReadOnly: true)
            .WithBindMount(
                Path.Combine(
                    sourcePath,
                    "Sigstore.Fulcio",
                    "config.yaml"),
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
            .WaitForCompletion(stateReady)
            .WaitFor(oidc)
            .WaitFor(tesseract)
            .WithParentRelationship(parent.Resource);

        fulcio.WithUrlForEndpoint(
            "http",
            url => url.DisplayText = "Fulcio certificate authority");

        var timestamp = builder
            .AddDockerfile(
                "timestamp",
                Path.Combine(sourcePath, "Sigstore.Timestamp"))
            .WithContainerRuntimeArgs("--user", "root")
            .WithBindMount(
                Path.Combine(statePath, "private"),
                "/var/lib/sigstore/private",
                isReadOnly: true)
            .WithBindMount(
                Path.Combine(statePath, "public"),
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
            .WaitForCompletion(stateReady)
            .WithParentRelationship(parent.Resource);

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
                Path.Combine(statePath, "private"),
                "/var/lib/sigstore/private",
                isReadOnly: true)
            .WithBindMount(
                Path.Combine(statePath, "data"),
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
            .WaitForCompletion(stateReady)
            .WithParentRelationship(parent.Resource);

        var rekor = builder
            .AddContainer(
                "rekor",
                "nginx",
                "1.31.1@sha256:5aca99593157f4ae539a5dec1092a0ad8762f8e2eb1789085a13a0f5622369f6")
            .WithBindMount(
                Path.Combine(statePath, "data"),
                "/var/lib/sigstore/data",
                isReadOnly: true)
            .WithBindMount(
                Path.Combine(
                    sourcePath,
                    "Sigstore.Rekor",
                    "nginx.conf"),
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
            .WaitFor(rekorServer)
            .WithParentRelationship(parent.Resource);

        rekor.WithUrlForEndpoint(
            "http",
            url => url.DisplayText = "Rekor v2 transparency log");

        var tufBootstrap = builder
            .AddDockerfile(
                "tuf-bootstrap",
                Path.Combine(sourcePath, "Sigstore.Tuf"))
            .WithBindMount(
                statePath,
                "/var/lib/sigstore")
            .WithEnvironment(
                "SIGSTORE_STATE_PATH",
                "/var/lib/sigstore")
            .WaitForCompletion(stateReady)
            .WithParentRelationship(parent.Resource);

        var tufStateReady = builder
            .AddContainer(
                "tuf-state-ready",
                "alpine",
                "3.20")
            .WithBindMount(
                statePath,
                "/var/lib/sigstore",
                isReadOnly: true)
            .WithEntrypoint("/bin/sh")
            .WithArgs(
                "-c",
                "test -f /var/lib/sigstore/tuf/repository/root.json && " +
                "test -f /var/lib/sigstore/tuf/targets/trusted_root.json && " +
                "test -f /var/lib/sigstore/tuf/targets/signing_config.v0.2.json")
            .WaitForCompletion(tufBootstrap)
            .WithParentRelationship(parent.Resource);

        var tuf = builder
            .AddContainer(
                "tuf",
                "nginx",
                "1.31.1@sha256:5aca99593157f4ae539a5dec1092a0ad8762f8e2eb1789085a13a0f5622369f6")
            .WithBindMount(
                Path.Combine(statePath, "tuf", "repository"),
                "/usr/share/nginx/html",
                isReadOnly: true)
            .WithBindMount(
                Path.Combine(statePath, "tuf", "targets"),
                "/usr/share/nginx/bootstrap",
                isReadOnly: true)
            .WithBindMount(
                Path.Combine(
                    sourcePath,
                    "Sigstore.Tuf",
                    "nginx.conf"),
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
            .WaitForCompletion(tufStateReady)
            .WithParentRelationship(parent.Resource);

        tuf.WithUrlForEndpoint(
            "http",
            url => url.DisplayText = "Sigstore TUF repository");

        return new SigstoreComponents(
            parent,
            bootstrap,
            stateReady,
            oidc,
            tesseract,
            fulcio,
            timestamp,
            rekorServer,
            rekor,
            tufBootstrap,
            tufStateReady,
            tuf);
    }

    private static string ResolveDirectoryPath(
        string appHostDirectory,
        string path,
        string optionName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path, optionName);

        var resolvedPath = Path.GetFullPath(
            path,
            appHostDirectory);
        if (!Directory.Exists(resolvedPath))
        {
            throw new DirectoryNotFoundException(
                $"{optionName} directory '{resolvedPath}' does not exist.");
        }

        return Path.TrimEndingDirectorySeparator(resolvedPath);
    }
}
