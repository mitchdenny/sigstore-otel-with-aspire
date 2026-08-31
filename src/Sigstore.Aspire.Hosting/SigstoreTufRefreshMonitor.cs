using Microsoft.Extensions.Logging;

namespace Aspire.Hosting.ApplicationModel;

internal static class SigstoreTufMetadataPolicy
{
    internal static readonly TimeSpan AutomaticRefreshLeadTime =
        TimeSpan.FromHours(6);
    internal static readonly TimeSpan TrustMaintenanceLeadTime =
        TimeSpan.FromDays(7);

    public static SigstoreTufMetadataFreshnessStatus Evaluate(
        SigstoreTufMetadataStatus metadata,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        var roles = new[]
        {
            EvaluateRole(
                "root",
                metadata.Root,
                now,
                TrustMaintenanceLeadTime),
            EvaluateRole(
                "targets",
                metadata.Targets,
                now,
                TrustMaintenanceLeadTime),
            EvaluateRole(
                "snapshot",
                metadata.Snapshot,
                now,
                AutomaticRefreshLeadTime),
            EvaluateRole(
                "timestamp",
                metadata.Timestamp,
                now,
                AutomaticRefreshLeadTime)
        };
        var state = roles.Any(role => role.State == "Expired")
            ? "Expired"
            : roles.Any(role => role.State == "RefreshNeeded")
                ? "RefreshNeeded"
                : "Current";
        var automaticRefreshRequired = roles.Any(
            role => role.Role is "snapshot" or "timestamp"
                && role.State != "Current");
        var trustMaintenanceRequired = roles.Any(
            role => role.Role is "root" or "targets"
                && role.State != "Current");
        var refreshAtUtc = new[]
        {
            metadata.Snapshot.ExpiresAtUtc,
            metadata.Timestamp.ExpiresAtUtc
        }.Min() - AutomaticRefreshLeadTime;
        var reason = state switch
        {
            "Expired" =>
                $"{roles.First(role => role.State == "Expired").Role} " +
                "metadata is expired.",
            "RefreshNeeded" =>
                $"{roles.First(role => role.State == "RefreshNeeded").Role} " +
                "metadata is near expiry.",
            _ => null
        };

        return new SigstoreTufMetadataFreshnessStatus(
            state,
            reason,
            refreshAtUtc,
            automaticRefreshRequired,
            trustMaintenanceRequired,
            roles);
    }

    public static SigstoreTufMetadataFreshnessStatus Unavailable() =>
        new(
            "Unavailable",
            "TUF metadata could not be inspected; automatic refresh and " +
                "trust mutations are deferred.",
            DateTimeOffset.MinValue,
            false,
            false,
            []);

    private static SigstoreTufMetadataRoleFreshnessStatus EvaluateRole(
        string role,
        SigstoreTufMetadataRoleStatus metadata,
        DateTimeOffset now,
        TimeSpan leadTime)
    {
        var remaining = metadata.ExpiresAtUtc - now;
        var state = remaining <= TimeSpan.Zero
            ? "Expired"
            : remaining <= leadTime
                ? "RefreshNeeded"
                : "Current";
        return new SigstoreTufMetadataRoleFreshnessStatus(
            role,
            state,
            metadata.ExpiresAtUtc,
            (long)Math.Floor(remaining.TotalSeconds));
    }
}

internal interface ISigstoreTufRefreshOperation
{
    Task<ExecuteCommandResult> ExecuteAsync(
        CancellationToken cancellationToken);
}

internal sealed class SigstoreTufRefreshOperation(
    SigstoreOperationExecutor executor) : ISigstoreTufRefreshOperation
{
    public Task<ExecuteCommandResult> ExecuteAsync(
        CancellationToken cancellationToken) =>
        executor.ExecuteRefreshTufAsync(cancellationToken);
}

internal sealed record SigstoreTufRefreshTickResult(
    SigstoreTufMetadataFreshnessStatus? Freshness,
    bool FreshnessChanged,
    bool Attempted,
    bool Succeeded,
    string Outcome,
    TimeSpan NextCheck);

internal sealed class SigstoreTufRefreshMonitor(
    SigstoreResource resource,
    ISigstoreStateInspector stateInspector,
    ISigstoreTufRefreshOperation refreshOperation,
    Func<CancellationToken, Task<SigstoreServedTufSnapshot>> servedProbe,
    TimeProvider timeProvider,
    ILogger logger)
{
    internal static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(30);
    internal static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);
    internal static readonly TimeSpan InitialRefreshDelay =
        TimeSpan.FromMinutes(5);
    private readonly DateTimeOffset _startedAtUtc = timeProvider.GetUtcNow();

    public async Task RunAsync(
        ResourceNotificationService notifications,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var delay = RetryInterval;
            try
            {
                var result = await RunOnceAsync(cancellationToken);
                delay = result.NextCheck;
                if (result.FreshnessChanged)
                {
                    await notifications.PublishUpdateAsync(
                        resource,
                        snapshot =>
                            SigstoreParentHealthMonitor.CreateParentSnapshot(
                                resource,
                                snapshot));
                }
                if (result.Attempted && !result.Succeeded)
                {
                    logger.LogWarning(
                        "Automatic TUF metadata refresh was deferred or failed: {Outcome}",
                        result.Outcome);
                }
            }
            catch (Exception exception)
                when (exception is FileNotFoundException
                    or DirectoryNotFoundException
                    or HttpRequestException
                    or IOException
                    or InvalidDataException
                    or SigstoreStatusException
                    or UnauthorizedAccessException)
            {
                var freshnessChanged = resource.SetTufMetadataFreshness(
                    SigstoreTufMetadataPolicy.Unavailable(),
                    repositoryCoherent: false);
                if (freshnessChanged)
                {
                    await notifications.PublishUpdateAsync(
                        resource,
                        snapshot =>
                            SigstoreParentHealthMonitor.CreateParentSnapshot(
                                resource,
                                snapshot));
                }
                logger.LogDebug(
                    exception,
                    "TUF metadata is not ready for automatic refresh inspection.");
            }
            catch (OperationCanceledException exception)
                when (!cancellationToken.IsCancellationRequested)
            {
                logger.LogDebug(
                    exception,
                    "TUF metadata refresh inspection timed out.");
            }

            try
            {
                await Task.Delay(delay, timeProvider, cancellationToken);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    internal async Task<SigstoreTufRefreshTickResult> RunOnceAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!resource.TryBeginOperation(
                "automatic-tuf-refresh-inspection",
                "Inspecting TUF Metadata",
                out var inspectionLease,
                out var activeOperation))
        {
            return new(
                resource.GetPresentation().TufMetadataFreshness,
                false,
                false,
                false,
                $"operation-active:{activeOperation!.Command}",
                RetryInterval);
        }

        SigstoreTufStateSnapshot state;
        SigstoreTufMetadataFreshnessStatus freshness;
        bool freshnessChanged;
        using (inspectionLease!)
        {
            var presentation = resource.GetPresentation();
            if (presentation.Recovery is not null)
            {
                return new(
                    presentation.TufMetadataFreshness,
                    false,
                    false,
                    false,
                    $"recovery-pending:{presentation.Recovery.Command}",
                    RetryInterval);
            }

            IDisposable stateLock;
            try
            {
                stateLock = stateInspector.AcquireLock(
                    resource.StatePath,
                    "automatic-tuf-refresh-inspection");
            }
            catch (InvalidOperationException exception)
            {
                return new(
                    null,
                    false,
                    false,
                    false,
                    exception.Message,
                    RetryInterval);
            }

            SigstoreServedTufSnapshot served;
            try
            {
                using (stateLock)
                {
                    state = stateInspector.ReadTufState(resource.StatePath);
                }
                served = await servedProbe(cancellationToken);
            }
            catch (Exception exception)
                when (IsMetadataInspectionFailure(
                    exception,
                    cancellationToken))
            {
                var unavailable = SigstoreTufMetadataPolicy.Unavailable();
                return new(
                    unavailable,
                    resource.SetTufMetadataFreshness(
                        unavailable,
                        repositoryCoherent: false),
                    false,
                    false,
                    "metadata-inspection-failed",
                    RetryInterval);
            }
            var repositoryCoherent = IsRepositoryCoherent(state, served);

            freshness = SigstoreTufMetadataPolicy.Evaluate(
                state.Metadata,
                timeProvider.GetUtcNow());
            freshnessChanged = resource.SetTufMetadataFreshness(
                freshness,
                repositoryCoherent);
            if (!repositoryCoherent)
            {
                return new(
                    freshness,
                    freshnessChanged,
                    false,
                    false,
                    "disk-served-mismatch",
                    RetryInterval);
            }
            var initialPublication =
                state.Metadata.Snapshot.Version == 1
                && state.Metadata.Timestamp.Version == 1;
            var initialRefreshDue = initialPublication
                && timeProvider.GetUtcNow() - _startedAtUtc
                    >= InitialRefreshDelay;
            if (!initialRefreshDue && !freshness.AutomaticRefreshRequired)
            {
                return new(
                    freshness,
                    freshnessChanged,
                    false,
                    false,
                    "metadata-current",
                    PollInterval);
            }

            if (!SigstoreOperationCommand.HasHealthyInfrastructure(resource))
            {
                return new(
                    freshness,
                    freshnessChanged,
                    false,
                    false,
                    "infrastructure-not-ready",
                    RetryInterval);
            }
        }

        var result = await refreshOperation.ExecuteAsync(cancellationToken);
        if (result.Success)
        {
            if (!resource.TryBeginOperation(
                    "automatic-tuf-refresh-postconditions",
                    "Inspecting Refreshed TUF Metadata",
                    out var postconditionLease,
                    out var postconditionActive))
            {
                return new(
                    freshness,
                    freshnessChanged,
                    true,
                    true,
                    "post-refresh-observation-deferred:" +
                        postconditionActive!.Command,
                    RetryInterval);
            }
            using (postconditionLease!)
            {
                IDisposable refreshedLock;
                try
                {
                    refreshedLock = stateInspector.AcquireLock(
                        resource.StatePath,
                        "automatic-tuf-refresh-postconditions");
                }
                catch (InvalidOperationException exception)
                {
                    return new(
                        freshness,
                        freshnessChanged,
                        true,
                        true,
                        "post-refresh-observation-deferred:" +
                            exception.Message,
                        RetryInterval);
                }
                SigstoreTufStateSnapshot refreshed;
                try
                {
                    using (refreshedLock)
                    {
                        refreshed = stateInspector.ReadTufState(
                            resource.StatePath);
                    }
                    var refreshedServed = await servedProbe(cancellationToken);
                    var refreshedCoherent =
                        IsRepositoryCoherent(refreshed, refreshedServed);
                    var refreshedFreshness = SigstoreTufMetadataPolicy.Evaluate(
                        refreshed.Metadata,
                        timeProvider.GetUtcNow());
                    freshnessChanged |=
                        resource.SetTufMetadataFreshness(
                            refreshedFreshness,
                            refreshedCoherent);
                    return new(
                        refreshedFreshness,
                        freshnessChanged,
                        true,
                        refreshedCoherent,
                        refreshedCoherent
                            ? result.Message ?? "refreshed"
                            : "post-refresh-disk-served-mismatch",
                        RetryInterval);
                }
                catch (Exception exception)
                    when (IsMetadataInspectionFailure(
                        exception,
                        cancellationToken))
                {
                    var unavailable =
                        SigstoreTufMetadataPolicy.Unavailable();
                    freshnessChanged |= resource.SetTufMetadataFreshness(
                        unavailable,
                        repositoryCoherent: false);
                    return new(
                        unavailable,
                        freshnessChanged,
                        true,
                        true,
                        "post-refresh-metadata-inspection-failed",
                        RetryInterval);
                }
            }
        }
        return new(
            freshness,
            freshnessChanged,
            true,
            false,
            result.Message
                ?? (result.Success ? "refreshed" : "refresh-failed"),
            RetryInterval);
    }

    private static bool IsMetadataInspectionFailure(
        Exception exception,
        CancellationToken cancellationToken) =>
        exception is FileNotFoundException
            or DirectoryNotFoundException
            or HttpRequestException
            or IOException
            or InvalidDataException
            or SigstoreStatusException
            or UnauthorizedAccessException
        || exception is OperationCanceledException
            && !cancellationToken.IsCancellationRequested;

    internal static bool IsRepositoryCoherent(
        SigstoreTufStateSnapshot disk,
        SigstoreServedTufSnapshot served) =>
        disk.Metadata == served.Metadata
        && disk.Trust.TrustDomainId == served.Trust.TrustDomainId
        && disk.Trust.Generation == served.Trust.Generation
        && disk.Trust.GenerationId == served.Trust.GenerationId
        && disk.Trust.GenerationManifestSha256
            == served.Trust.GenerationManifestSha256
        && disk.Trust.TufRootVersion == served.Trust.TufRootVersion
        && disk.Trust.TufTargetsVersion == served.Trust.TufTargetsVersion
        && disk.Trust.TrustedRootSha256
            == served.Trust.TrustedRootSha256
        && disk.Trust.SigningConfigSha256
            == served.Trust.SigningConfigSha256;
}
