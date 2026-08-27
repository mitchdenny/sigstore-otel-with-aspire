namespace Aspire.Hosting;

public sealed class SigstoreClientOptions
{
    public string? Language { get; init; }

    public string? TrustStatusEndpointName { get; init; }

    public bool AddCanonicalHostMappings { get; init; } = true;

    public bool IncludeDirectServiceEndpointVariables { get; init; }
}
