namespace Aspire.Hosting.ApplicationModel;

public sealed class SigstoreResource(
    string name,
    string statePath,
    string sourcePath)
    : Resource(name)
{
    private readonly Lock _sync = new();
    private readonly List<IResource> _requiredResources = [];
    private readonly List<SigstoreClientRegistration> _clients = [];
    private SigstoreComponents? _components;
    private EndpointReference? _tufEndpoint;
    private SigstoreRuntimeHealthSnapshot _runtimeHealth =
        SigstoreRuntimeHealthSnapshot.Starting([]);

    public string StatePath { get; } = statePath;

    public string SourcePath { get; } = sourcePath;

    public SigstoreComponents Components =>
        _components
        ?? throw new InvalidOperationException(
            "The Sigstore components have not been initialized. Add the " +
            "resource through AddSigstore.");

    internal EndpointReference TufEndpoint =>
        _tufEndpoint
        ?? throw new InvalidOperationException(
            "The Sigstore TUF endpoint has not been initialized.");

    internal void SetComponents(
        SigstoreComponents components,
        EndpointReference tufEndpoint)
    {
        ArgumentNullException.ThrowIfNull(components);
        ArgumentNullException.ThrowIfNull(tufEndpoint);

        if (_components is not null)
        {
            throw new InvalidOperationException(
                "The Sigstore components have already been initialized.");
        }

        _components = components;
        _tufEndpoint = tufEndpoint;
        RegisterRequiredResource(components.Oidc.Resource);
        RegisterRequiredResource(components.Tesseract.Resource);
        RegisterRequiredResource(components.Fulcio.Resource);
        RegisterRequiredResource(components.Timestamp.Resource);
        RegisterRequiredResource(components.RekorServer.Resource);
        RegisterRequiredResource(components.Rekor.Resource);
        RegisterRequiredResource(components.Tuf.Resource);
    }

    internal void RegisterRequiredResource(IResource resource)
    {
        ArgumentNullException.ThrowIfNull(resource);

        lock (_sync)
        {
            if (_requiredResources.Any(
                    existing => ReferenceEquals(existing, resource)
                        || string.Equals(
                            existing.Name,
                            resource.Name,
                            StringComparison.Ordinal)))
            {
                return;
            }

            _requiredResources.Add(resource);
        }
    }

    internal void RegisterClient(SigstoreClientRegistration client)
    {
        ArgumentNullException.ThrowIfNull(client);

        lock (_sync)
        {
            if (_clients.Any(
                    existing => string.Equals(
                        existing.Resource.Name,
                        client.Resource.Name,
                        StringComparison.Ordinal)
                        || string.Equals(
                            existing.Language,
                            client.Language,
                            StringComparison.Ordinal)))
            {
                throw new InvalidOperationException(
                    $"A Sigstore client named '{client.Resource.Name}' or " +
                    $"language '{client.Language}' is already registered.");
            }

            _clients.Add(client);
        }

        RegisterRequiredResource(client.Resource);
    }

    internal SigstoreResourceRegistrationSnapshot GetRegistrations()
    {
        lock (_sync)
        {
            return new SigstoreResourceRegistrationSnapshot(
                [.. _requiredResources],
                [.. _clients]);
        }
    }

    internal void SetRuntimeHealth(SigstoreRuntimeHealthSnapshot health)
    {
        ArgumentNullException.ThrowIfNull(health);

        lock (_sync)
        {
            _runtimeHealth = health;
        }
    }

    internal SigstoreRuntimeHealthSnapshot GetRuntimeHealth()
    {
        lock (_sync)
        {
            return _runtimeHealth;
        }
    }
}

internal sealed record SigstoreClientRegistration(
    string Language,
    ContainerResource Resource,
    EndpointReference Endpoint);

internal sealed record SigstoreResourceRegistrationSnapshot(
    IReadOnlyList<IResource> RequiredResources,
    IReadOnlyList<SigstoreClientRegistration> Clients);
