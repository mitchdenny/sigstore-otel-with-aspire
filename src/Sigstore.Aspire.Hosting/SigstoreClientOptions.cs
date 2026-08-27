namespace Aspire.Hosting;

public enum SigstoreTufMountKind
{
    BootstrapRootFile,
    RepositoryDirectory
}

public sealed class SigstoreClientOptions
{
    public SigstoreTufMountKind TufMount { get; init; } =
        SigstoreTufMountKind.BootstrapRootFile;

    public bool AddCanonicalHostMappings { get; init; } = true;

    public bool IncludeDirectServiceEndpointVariables { get; init; }
}
