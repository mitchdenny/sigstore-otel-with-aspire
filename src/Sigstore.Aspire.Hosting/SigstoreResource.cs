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
    private EndpointReference? _artifactStoreEndpoint;
    private SigstoreRuntimeHealthSnapshot _runtimeHealth =
        SigstoreRuntimeHealthSnapshot.Starting([]);
    private SigstoreOperationState? _operation;
    private SigstoreOperationRecoveryState? _recovery;

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

    internal EndpointReference ArtifactStoreEndpoint =>
        _artifactStoreEndpoint
        ?? throw new InvalidOperationException(
            "The Sigstore artifact-store endpoint has not been initialized.");

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

    internal void SetArtifactStore(
        IResource resource,
        EndpointReference endpoint)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ArgumentNullException.ThrowIfNull(endpoint);
        lock (_sync)
        {
            if (_artifactStoreEndpoint is not null)
            {
                throw new InvalidOperationException(
                    "The Sigstore artifact store has already been registered.");
            }
            _artifactStoreEndpoint = endpoint;
        }
        RegisterRequiredResource(resource);
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

    internal bool TryBeginOperation(
        string command,
        string displayState,
        out SigstoreOperationLease? lease,
        out SigstoreOperationState? activeOperation)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(command);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayState);

        lock (_sync)
        {
            activeOperation = _operation;
            if (activeOperation is not null)
            {
                lease = null;
                return false;
            }

            var operation = new SigstoreOperationState(
                Guid.NewGuid(),
                command,
                displayState,
                "Starting",
                0,
                1,
                "Preparing the operation.",
                DateTimeOffset.UtcNow);
            _operation = operation;
            lease = new SigstoreOperationLease(this, operation);
            return true;
        }
    }

    internal void UpdateOperation(
        Guid operationId,
        string phase,
        int completed,
        int total,
        string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(phase);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        if (completed < 0 || total <= 0 || completed > total)
        {
            throw new ArgumentOutOfRangeException(
                nameof(completed),
                "Operation progress must be within its declared total.");
        }

        lock (_sync)
        {
            if (_operation is null || _operation.Id != operationId)
            {
                throw new InvalidOperationException(
                    "The Sigstore operation is no longer active.");
            }

            _operation = _operation with
            {
                Phase = phase,
                Completed = completed,
                Total = total,
                Message = message
            };
        }
    }

    internal SigstoreParentPresentationSnapshot GetPresentation()
    {
        lock (_sync)
        {
            return new SigstoreParentPresentationSnapshot(
                _runtimeHealth,
                _operation,
                _recovery);
        }
    }

    internal void SetOperationRecovery(
        string command,
        string phase,
        string displayState,
        string message)
    {
        lock (_sync)
        {
            _recovery = new SigstoreOperationRecoveryState(
                command,
                phase,
                displayState,
                message,
                DateTimeOffset.UtcNow);
        }
    }

    internal void ClearOperationRecovery(string command)
    {
        lock (_sync)
        {
            if (_recovery?.Command == command)
            {
                _recovery = null;
            }
        }
    }

    private void EndOperation(Guid operationId)
    {
        lock (_sync)
        {
            if (_operation is not null && _operation.Id == operationId)
            {
                _operation = null;
            }
        }
    }

    internal sealed class SigstoreOperationLease : IDisposable
    {
        private SigstoreResource? _resource;

        internal SigstoreOperationLease(
            SigstoreResource resource,
            SigstoreOperationState operation)
        {
            _resource = resource;
            Operation = operation;
        }

        public SigstoreOperationState Operation { get; }

        public void Report(
            string phase,
            int completed,
            int total,
            string message)
        {
            var resource = _resource
                ?? throw new ObjectDisposedException(
                    nameof(SigstoreOperationLease));
            resource.UpdateOperation(
                Operation.Id,
                phase,
                completed,
                total,
                message);
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _resource, null)
                ?.EndOperation(Operation.Id);
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

internal sealed record SigstoreOperationState(
    Guid Id,
    string Command,
    string DisplayState,
    string Phase,
    int Completed,
    int Total,
    string Message,
    DateTimeOffset StartedAtUtc);

internal sealed record SigstoreParentPresentationSnapshot(
    SigstoreRuntimeHealthSnapshot RuntimeHealth,
    SigstoreOperationState? Operation,
    SigstoreOperationRecoveryState? Recovery);

internal sealed record SigstoreOperationRecoveryState(
    string Command,
    string Phase,
    string DisplayState,
    string Message,
    DateTimeOffset UpdatedAtUtc);
