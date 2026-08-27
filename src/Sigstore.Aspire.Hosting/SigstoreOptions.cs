namespace Aspire.Hosting;

public sealed class SigstoreOptions
{
    public const string StateDirectoryName = ".sigstore";

    public required string SourcePath { get; init; }
}
