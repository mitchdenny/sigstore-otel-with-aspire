namespace Aspire.Hosting.ApplicationModel;

public sealed class SigstoreResource(
    string name,
    string statePath,
    string sourcePath)
    : Resource(name)
{
    public string StatePath { get; } = statePath;

    public string SourcePath { get; } = sourcePath;
}
