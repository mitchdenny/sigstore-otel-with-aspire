using Aspire.Hosting.ApplicationModel;

namespace Aspire.Hosting;

public static class SigstoreClientResourceBuilderExtensions
{
    private const string BootstrapRootTargetPath =
        "/var/lib/sigstore/tuf/root.json";
    private const string RepositoryTargetPath =
        "/var/lib/sigstore/tuf/repository";

    public static IResourceBuilder<ContainerResource> WithSigstoreReference(
        this IResourceBuilder<ContainerResource> client,
        SigstoreComponents sigstore,
        SigstoreClientOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(sigstore);

        options ??= new SigstoreClientOptions();
        if (!Enum.IsDefined(options.TufMount))
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.TufMount),
                options.TufMount,
                "The TUF mount kind is not supported.");
        }

        if (options.AddCanonicalHostMappings)
        {
            client.WithContainerRuntimeArgs(
                "--add-host",
                "tuf-sigstore.dev.localhost:host-gateway",
                "--add-host",
                "oidc-sigstore.dev.localhost:host-gateway",
                "--add-host",
                "fulcio-sigstore.dev.localhost:host-gateway",
                "--add-host",
                "rekor-sigstore.dev.localhost:host-gateway",
                "--add-host",
                "timestamp-sigstore.dev.localhost:host-gateway");
        }

        var tufRepositoryPath = Path.Combine(
            sigstore.Parent.Resource.StatePath,
            "tuf",
            "repository");
        var (mountSource, mountTarget, bootstrapRootPath) =
            options.TufMount switch
            {
                SigstoreTufMountKind.BootstrapRootFile => (
                    Path.Combine(tufRepositoryPath, "root.json"),
                    BootstrapRootTargetPath,
                    BootstrapRootTargetPath),
                SigstoreTufMountKind.RepositoryDirectory => (
                    tufRepositoryPath,
                    RepositoryTargetPath,
                    Path.Combine(RepositoryTargetPath, "root.json")),
                _ => throw new ArgumentOutOfRangeException(
                    nameof(options.TufMount),
                    options.TufMount,
                    "The TUF mount kind is not supported.")
            };

        client
            .WithBindMount(
                mountSource,
                mountTarget,
                isReadOnly: true)
            .WithEnvironment(
                "SIGSTORE_TUF_ROOT_PATH",
                bootstrapRootPath)
            .WithEnvironment(
                "SIGSTORE_TUF_URL",
                sigstore.Tuf.GetEndpoint(
                    "http",
                    KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
            .WithEnvironment(
                "SIGSTORE_OIDC_URL",
                sigstore.Oidc.GetEndpoint(
                    "internal",
                    KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
            .WithEnvironment(
                "SIGSTORE_EXPECTED_IDENTITY",
                SigstoreDefaults.ExpectedIdentity)
            .WithEnvironment(
                "SIGSTORE_EXPECTED_ISSUER",
                SigstoreDefaults.ExpectedIssuer);

        if (options.IncludeDirectServiceEndpointVariables)
        {
            client
                .WithEnvironment(
                    "SIGSTORE_FULCIO_URL",
                    sigstore.Fulcio.GetEndpoint(
                        "http",
                        KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
                .WithEnvironment(
                    "SIGSTORE_REKOR_URL",
                    sigstore.Rekor.GetEndpoint(
                        "http",
                        KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
                .WithEnvironment(
                    "SIGSTORE_TIMESTAMP_URL",
                    sigstore.Timestamp.GetEndpoint(
                        "http",
                        KnownNetworkIdentifiers.DefaultAspireContainerNetwork));
        }

        return client
            .WaitFor(sigstore.Tuf)
            .WaitFor(sigstore.Oidc)
            .WaitFor(sigstore.Fulcio)
            .WaitFor(sigstore.Timestamp)
            .WaitFor(sigstore.Rekor);
    }
}

internal static class SigstoreDefaults
{
    public const string ExpectedIdentity = "demo@sigstore.local";
    public const string ExpectedIssuer =
        "https://oidc-sigstore.dev.localhost:7443";
}
