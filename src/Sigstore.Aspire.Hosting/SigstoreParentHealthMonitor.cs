using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Aspire.Hosting.ApplicationModel;

public sealed record SigstoreRequiredResourceStatus(
    string Resource,
    string State,
    string Health);

internal sealed record SigstoreObservedResource(
    string? State,
    HealthStatus? HealthStatus);

internal sealed record SigstoreRuntimeHealthSnapshot(
    string State,
    string? Reason,
    IReadOnlyList<SigstoreRequiredResourceStatus> Resources,
    int HealthyCount,
    int RequiredCount)
{
    public static SigstoreRuntimeHealthSnapshot Starting(
        IReadOnlyList<SigstoreRequiredResourceStatus> resources) =>
        new(
            "Starting",
            "Waiting for required resources.",
            resources,
            0,
            resources.Count);
}

internal static class SigstoreParentHealthMonitor
{
    public static async Task RunAsync(
        SigstoreResource resource,
        ResourceNotificationService notifications,
        CancellationToken cancellationToken)
    {
        var requiredResources = resource
            .GetRegistrations()
            .RequiredResources
            .OrderBy(item => item.Name, StringComparer.Ordinal)
            .ToArray();
        var requiredNames = requiredResources
            .Select(item => item.Name)
            .ToHashSet(StringComparer.Ordinal);
        var observed = new Dictionary<string, SigstoreObservedResource>(
            StringComparer.Ordinal);
        var wasHealthy = false;
        SigstoreRuntimeHealthSnapshot? last = null;

        foreach (var required in requiredResources)
        {
            if (notifications.TryGetCurrentState(
                    required.Name,
                    out var current))
            {
                observed[required.Name] = Observe(current);
            }
        }

        await PublishIfChangedAsync();

        try
        {
            await foreach (var resourceEvent in notifications
                .WatchAsync(cancellationToken)
                .ConfigureAwait(false))
            {
                if (!requiredNames.Contains(resourceEvent.Resource.Name))
                {
                    continue;
                }

                observed[resourceEvent.Resource.Name] = Observe(resourceEvent);
                await PublishIfChangedAsync();
            }
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
        }

        async Task PublishIfChangedAsync()
        {
            var current = Evaluate(
                requiredNames,
                observed,
                wasHealthy);
            wasHealthy |= current.State == "Healthy";
            if (Equivalent(last, current))
            {
                return;
            }

            last = current;
            resource.SetRuntimeHealth(current);
            await notifications.PublishUpdateAsync(
                resource,
                snapshot => snapshot with
                {
                    State = new ResourceStateSnapshot(
                        current.State,
                        current.State switch
                        {
                            "Healthy" => KnownResourceStateStyles.Success,
                            "Degraded" => KnownResourceStateStyles.Warn,
                            _ => KnownResourceStateStyles.Info
                        }),
                    Properties =
                    [
                        new(
                            "Health reason",
                            current.Reason ?? "All required resources are healthy."),
                        new(
                            "Healthy resources",
                            $"{current.HealthyCount}/{current.RequiredCount}")
                    ]
                });
        }
    }

    internal static SigstoreRuntimeHealthSnapshot Evaluate(
        IReadOnlySet<string> requiredNames,
        IReadOnlyDictionary<string, SigstoreObservedResource> observed,
        bool wasHealthy)
    {
        var resources = requiredNames
            .Order(StringComparer.Ordinal)
            .Select(name =>
            {
                observed.TryGetValue(name, out var status);
                return new SigstoreRequiredResourceStatus(
                    name,
                    status?.State ?? "Unavailable",
                    status?.HealthStatus?.ToString() ?? "Unknown");
            })
            .ToArray();
        var healthyCount = resources.Count(
            status => status.State == KnownResourceStates.Running
                && status.Health == nameof(HealthStatus.Healthy));

        var definitiveFailure = resources.FirstOrDefault(
            status => status.State == KnownResourceStates.Stopping
                || status.State == KnownResourceStates.Exited
                || status.State == KnownResourceStates.FailedToStart
                || status.Health == nameof(HealthStatus.Degraded)
                || status.Health == nameof(HealthStatus.Unhealthy));
        if (definitiveFailure is not null)
        {
            return new SigstoreRuntimeHealthSnapshot(
                "Degraded",
                $"{definitiveFailure.Resource} is " +
                $"{definitiveFailure.State} " +
                $"(health {definitiveFailure.Health}).",
                resources,
                healthyCount,
                resources.Length);
        }

        foreach (var status in resources)
        {
            if (status.State != KnownResourceStates.Running)
            {
                return new SigstoreRuntimeHealthSnapshot(
                    wasHealthy ? "Degraded" : "Starting",
                    $"{status.Resource} is {status.State} " +
                    $"(health {status.Health}).",
                    resources,
                    healthyCount,
                    resources.Length);
            }

            if (status.Health != nameof(HealthStatus.Healthy))
            {
                return new SigstoreRuntimeHealthSnapshot(
                    wasHealthy ? "Degraded" : "Starting",
                    $"{status.Resource} is {status.State} " +
                    $"(health {status.Health}).",
                    resources,
                    healthyCount,
                    resources.Length);
            }
        }

        return new SigstoreRuntimeHealthSnapshot(
            "Healthy",
            null,
            resources,
            healthyCount,
            resources.Length);
    }

    private static SigstoreObservedResource Observe(ResourceEvent resourceEvent) =>
        new(
            resourceEvent.Snapshot.State?.Text,
            resourceEvent.Snapshot.HealthStatus);

    private static bool Equivalent(
        SigstoreRuntimeHealthSnapshot? first,
        SigstoreRuntimeHealthSnapshot second) =>
        first is not null
        && first.State == second.State
        && first.Reason == second.Reason
        && first.HealthyCount == second.HealthyCount
        && first.RequiredCount == second.RequiredCount
        && first.Resources.SequenceEqual(second.Resources);
}
