using Aspire.Hosting.ApplicationModel;

namespace Aspire.Hosting;

public static class SigstoreClientReferenceExtensions
{
    private const string BootstrapRootTargetPath =
        "/var/lib/sigstore/tuf/root.json";
    private const string RepositoryTargetPath =
        "/var/lib/sigstore/tuf/repository";

    public static IResourceBuilder<ContainerResource> WithReference(
        this IResourceBuilder<ContainerResource> client,
        IResourceBuilder<SigstoreResource> sigstore,
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

        var components = sigstore.Resource.Components;
        var tufRepositoryPath = Path.Combine(
            sigstore.Resource.StatePath,
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
                components.Tuf.GetEndpoint(
                    "http",
                    KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
            .WithEnvironment(
                "SIGSTORE_OIDC_URL",
                components.Oidc.GetEndpoint(
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
                    components.Fulcio.GetEndpoint(
                        "http",
                        KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
                .WithEnvironment(
                    "SIGSTORE_REKOR_URL",
                    components.Rekor.GetEndpoint(
                        "http",
                        KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
                .WithEnvironment(
                    "SIGSTORE_TIMESTAMP_URL",
                    components.Timestamp.GetEndpoint(
                        "http",
                        KnownNetworkIdentifiers.DefaultAspireContainerNetwork));
        }

        return client
            .WaitFor(components.Tuf)
            .WaitFor(components.Oidc)
            .WaitFor(components.Fulcio)
            .WaitFor(components.Timestamp)
            .WaitFor(components.Rekor);
    }
}

internal static class SigstoreDefaults
{
    public const string ExpectedIdentity = "demo@sigstore.local";
    public const string ExpectedIssuer =
        "https://oidc-sigstore.dev.localhost:7443";
}
