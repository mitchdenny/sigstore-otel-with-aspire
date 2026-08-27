namespace Aspire.Hosting;

public sealed class SigstoreClientOptions
{
    public bool AddCanonicalHostMappings { get; init; } = true;

    public bool IncludeDirectServiceEndpointVariables { get; init; }
}
