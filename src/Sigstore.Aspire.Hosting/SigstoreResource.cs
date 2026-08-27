namespace Aspire.Hosting.ApplicationModel;

public sealed class SigstoreResource(
    string name,
    string statePath,
    string sourcePath)
    : Resource(name)
{
    private SigstoreComponents? _components;

    public string StatePath { get; } = statePath;

    public string SourcePath { get; } = sourcePath;

    public SigstoreComponents Components =>
        _components
        ?? throw new InvalidOperationException(
            "The Sigstore components have not been initialized. Add the " +
            "resource through AddSigstore.");

    internal void SetComponents(SigstoreComponents components)
    {
        ArgumentNullException.ThrowIfNull(components);

        if (_components is not null)
        {
            throw new InvalidOperationException(
                "The Sigstore components have already been initialized.");
        }

        _components = components;
    }
}
