using Aspire.Hosting.ApplicationModel;

namespace Aspire.Hosting;

public static class SigstoreClientReferenceExtensions
{
    private const string TufTargetPath =
        "/var/lib/sigstore/tuf";
    private const string BootstrapRootTargetPath =
        "/var/lib/sigstore/tuf/bootstrap/root.json";
    private const string TrustStatusTargetPath =
        "/var/lib/sigstore/tuf/active/targets/trust_status.v1.json";

    public static IResourceBuilder<ContainerResource> WithReference(
        this IResourceBuilder<ContainerResource> client,
        IResourceBuilder<SigstoreResource> sigstore,
        SigstoreClientOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(sigstore);

        options ??= new SigstoreClientOptions();
        if (options.TrustStatusEndpointName is not null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(
                options.TrustStatusEndpointName);
            ArgumentException.ThrowIfNullOrWhiteSpace(options.Language);
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
        var tufPath = Path.Combine(
            sigstore.Resource.StatePath,
            "tuf");

        client
            .WithBindMount(
                tufPath,
                TufTargetPath,
                isReadOnly: true)
            .WithEnvironment(
                "SIGSTORE_TUF_ROOT_PATH",
                BootstrapRootTargetPath)
            .WithEnvironment(
                "SIGSTORE_TUF_URL",
                components.Tuf.GetEndpoint(
                    "http",
                    KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
            .WithEnvironment(
                "SIGSTORE_TUF_TRUST_STATUS_PATH",
                TrustStatusTargetPath)
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

        client
            .WaitFor(components.Tuf)
            .WaitFor(components.Oidc)
            .WaitFor(components.Fulcio)
            .WaitFor(components.Timestamp)
            .WaitFor(components.Rekor)
            .WithParentRelationship(sigstore.Resource);

        sigstore.Resource.RegisterRequiredResource(client.Resource);
        if (options.TrustStatusEndpointName is not null)
        {
            sigstore.Resource.RegisterClient(
                new SigstoreClientRegistration(
                    options.Language!,
                    client.Resource,
                    client.GetEndpoint(
                        options.TrustStatusEndpointName)));
        }

        return client;
    }
}

internal static class SigstoreDefaults
{
    public const string ExpectedIdentity = "demo@sigstore.local";
    public const string ExpectedIssuer =
        "https://oidc-sigstore.dev.localhost:7443";
}
