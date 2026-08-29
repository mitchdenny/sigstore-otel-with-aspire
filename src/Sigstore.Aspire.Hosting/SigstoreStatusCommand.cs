using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sigstore.Bootstrap;

namespace Aspire.Hosting.ApplicationModel;

public sealed record SigstoreClientTrustStatus(
    int SchemaVersion,
    string Resource,
    string Language,
    bool Ready,
    string? LastError,
    string TrustDomainId,
    int Generation,
    string GenerationId,
    string GenerationManifestSha256,
    int TufRootVersion,
    int TufTargetsVersion,
    string TrustedRootSha256,
    string SigningConfigSha256,
    DateTimeOffset InitializedAtUtc);

public sealed record SigstoreDiskTrustStatus(
    string TrustDomainId,
    int Generation,
    string GenerationId,
    string GenerationManifestSha256,
    int TufRootVersion,
    int TufTargetsVersion,
    string TrustedRootSha256,
    string SigningConfigSha256,
    string PublicationId,
    string PublicationManifestSha256);

public sealed record SigstoreServedTrustStatus(
    string TrustDomainId,
    int Generation,
    string GenerationId,
    string GenerationManifestSha256,
    int TufRootVersion,
    int TufTargetsVersion,
    string TrustedRootSha256,
    string SigningConfigSha256);

public sealed record SigstoreTufMetadataRoleStatus(
    int Version,
    string Sha256,
    DateTimeOffset ExpiresAtUtc);

public sealed record SigstoreTufMetadataStatus(
    SigstoreTufMetadataRoleStatus Root,
    SigstoreTufMetadataRoleStatus Targets,
    SigstoreTufMetadataRoleStatus Snapshot,
    SigstoreTufMetadataRoleStatus Timestamp,
    string TrustedRootSha256,
    string SigningConfigSha256);

public sealed record SigstoreTufStateSnapshot(
    SigstoreDiskTrustStatus Trust,
    SigstoreTufMetadataStatus Metadata,
    string BootstrapRootSha256,
    string SourceFingerprint,
    string StableContentSha256,
    string? PreviousPublicationId,
    string? PreviousPublicationManifestSha256);

public sealed record SigstoreServedTufSnapshot(
    SigstoreServedTrustStatus Trust,
    SigstoreTufMetadataStatus Metadata);

public sealed record SigstoreStatusError(
    string Source,
    string Message);

public sealed record SigstoreActiveOperationStatus(
    string Command,
    string Phase,
    int Completed,
    int Total,
    string Message,
    DateTimeOffset StartedAtUtc);

public sealed record SigstoreRecoveryStatus(
    string Command,
    string Phase,
    string State,
    string Message,
    DateTimeOffset UpdatedAtUtc);

public sealed record SigstoreRekorShardHealthStatus(
    string ShardId,
    string Slot,
    string Status,
    string BaseUrl,
    string Origin,
    string Resource,
    string PublicKeySha256,
    string StateId,
    long TreeSize,
    string CheckpointSha256,
    bool StaticRouteReady,
    bool ComputeRequired,
    bool? ComputeHealthy);

public sealed record SigstoreRekorStatus(
    string ActiveShardId,
    string ActiveSigningConfigUrl,
    int TrustedRootTlogCount,
    IReadOnlyList<SigstoreRekorShardHealthStatus> Shards);

public sealed record SigstoreAggregateTrustStatus(
    int SchemaVersion,
    string Resource,
    bool Ready,
    string State,
    string? Reason,
    DateTimeOffset ObservedAtUtc,
    SigstoreDiskTrustStatus? Disk,
    SigstoreServedTrustStatus? Served,
    IReadOnlyList<SigstoreClientTrustStatus> Clients,
    IReadOnlyList<SigstoreRequiredResourceStatus> RequiredResources,
    IReadOnlyList<SigstoreStatusError> Errors,
    SigstoreTimestampAuthorityStatus? TimestampAuthority = null,
    SigstoreActiveOperationStatus? Operation = null,
    SigstoreRecoveryStatus? Recovery = null,
    SigstoreFulcioStatus? Fulcio = null,
    SigstoreRekorStatus? Rekor = null,
    SigstoreCtLogStatus? CtLog = null);

internal sealed record PublishedTrustStatus(
    int SchemaVersion,
    string TrustDomainId,
    int Generation,
    string GenerationId,
    string GenerationManifestSha256,
    int TufRootVersion,
    int TufTargetsVersion,
    string TrustedRootSha256,
    string SigningConfigSha256);

internal sealed record GenerationManifestStatus(
    int SchemaVersion,
    int Generation,
    string GenerationId,
    string TrustDomainId,
    DateTimeOffset CreatedAtUtc,
    int SourceSchemaVersion,
    string? SourceManifestSha256,
    string FulcioRootSha256,
    string? FulcioRotationOperationId,
    int FulcioPriorGeneration,
    string? FulcioPriorGenerationId,
    string? FulcioPriorRootSha256,
    string CtLogPublicKeySha256,
    string RekorPublicKeySha256,
    string TsaRootSha256,
    string TsaLeafSha256,
    string OidcKeyId,
    string? OidcRotationOperationId,
    int OidcPriorGeneration,
    string? OidcPriorGenerationId,
    string? OidcPriorKeyId,
    DateTimeOffset? OidcOverlapExpiresAtUtc,
    IReadOnlyList<string>? OidcRetainedPrivateKeyPaths,
    string? TsaRotationOperationId,
    int TsaPriorGeneration,
    string? TsaPriorGenerationId,
    string? TsaPriorRootSha256,
    string? TsaPriorLeafSha256,
    string? RekorRotationOperationId,
    int RekorPriorGeneration,
    string? RekorPriorGenerationId,
    string? RekorPriorPublicKeySha256,
    string? RekorPriorShardId,
    string? RekorPriorBaseUrl,
    string? RekorShardId,
    string? RekorBaseUrl,
    string? CtLogRotationOperationId,
    int CtLogPriorGeneration,
    string? CtLogPriorGenerationId,
    string? CtLogPriorPublicKeySha256,
    string? CtLogPriorShardId,
    string? CtLogPriorBaseUrl,
    string? CtLogShardId,
    string? CtLogBaseUrl,
    SortedDictionary<string, string> Files);

internal sealed record TrustDomainManifestStatus(
    int SchemaVersion,
    string TrustDomainId,
    DateTimeOffset CreatedAtUtc,
    string CtLogStateId,
    string RekorStateId);

internal sealed record GenerationReferenceStatus(
    int Generation,
    string GenerationId,
    string ManifestSha256);

internal sealed record TransitionJournalStatus(
    int SchemaVersion,
    string? TransitionId,
    string? Operation,
    string Status,
    string LastCheckpoint,
    GenerationReferenceStatus? PriorGeneration,
    GenerationReferenceStatus? Candidate,
    string TrustDomainManifestSha256,
    TrustDomainManifestStatus TrustDomain,
    GenerationManifestStatus CandidateManifest);

internal sealed record PublicationReferenceStatus(
    string Id,
    string ManifestSha256);

internal sealed record PublicationStateStatus(
    int SchemaVersion,
    string Status,
    string BootstrapRootSha256,
    PublicationReferenceStatus? Active,
    PublicationReferenceStatus? Candidate,
    PublicationReferenceStatus? Previous);

internal sealed record TufManifestStatus(
    int SchemaVersion,
    string SourceFingerprint,
    SortedDictionary<string, string> Files);

internal sealed record CtLogShardCatalogStatus(
    int SchemaVersion,
    string TrustDomainId,
    string ActiveShardId,
    DateTimeOffset UpdatedAtUtc,
    IReadOnlyList<CtLogShardCatalogEntryStatus> Shards);

internal sealed record CtLogShardCatalogEntryStatus(
    string ShardId,
    string Slot,
    string BaseUrl,
    string Origin,
    string PublicKeySha256,
    string LogIdSha256,
    string StateId,
    string DataPath,
    string ResourceName,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ActivatedAtUtc,
    string Status,
    string AcceptedRootsSha256,
    int AcceptedRootCount,
    IReadOnlyList<string> AcceptedRootFingerprints);

internal sealed record RekorShardCatalogStatus(
    int SchemaVersion,
    string TrustDomainId,
    string ActiveShardId,
    DateTimeOffset UpdatedAtUtc,
    IReadOnlyList<RekorShardCatalogEntryStatus> Shards);

internal sealed record RekorShardCatalogEntryStatus(
    string ShardId,
    string Slot,
    string BaseUrl,
    string Origin,
    string PublicKeySha256,
    string LogIdSha256,
    string StateId,
    string DataPath,
    string ResourceName,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ActivatedAtUtc,
    string Status);

internal sealed record RekorShardMetadataStatus(
    int SchemaVersion,
    string OperationId,
    string TrustDomainId,
    string ShardId,
    string Slot,
    string BaseUrl,
    string Origin,
    string PublicKeySha256,
    string LogIdSha256,
    string StateId,
    string DataPath,
    string ResourceName,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ActivatedAtUtc,
    string? Status);

internal sealed class SigstoreStatusException(string message)
    : Exception(message);

internal static class SigstoreStatusCommand
{
    private const int StatusSchemaVersion = 1;
    private const int TrustStateSchemaVersion = 5;
    private const int TransitionSchemaVersion = 1;
    private const int PublicationSchemaVersion = 1;
    private const int TufManifestSchemaVersion = 3;
    private const string TrustStatusTargetName = "trust_status.v1.json";
    private const int MaximumStatusBytes = 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            WriteIndented = true
        };

    private static readonly JsonSerializerOptions StrictJsonOptions =
        new(JsonOptions)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };

    public static async Task<ExecuteCommandResult> ExecuteAsync(
        SigstoreResource resource,
        ExecuteCommandContext context)
    {
        var status = await CollectAsync(
            resource,
            context.CancellationToken);
        var json = JsonSerializer.Serialize(status, JsonOptions);
        return CreateResult(status, json);
    }

    internal static ExecuteCommandResult CreateResult(
        SigstoreAggregateTrustStatus status,
        string? serialized = null)
    {
        serialized ??= JsonSerializer.Serialize(status, JsonOptions);
        return status.Ready
            ? CommandResults.Success(
                message: "Sigstore trust status is healthy.",
                result: serialized,
                resultFormat: CommandResultFormat.Json)
            : CommandResults.Failure(
                errorMessage: status.Reason
                    ?? "Sigstore trust status is degraded.",
                result: serialized,
                resultFormat: CommandResultFormat.Json);
    }

    internal static async Task<SigstoreAggregateTrustStatus> CollectAsync(
        SigstoreResource resource,
        CancellationToken cancellationToken)
    {
        var registrations = resource.GetRegistrations();
        var runtime = resource.GetRuntimeHealth();
        var errors = new List<SigstoreStatusError>();
        SigstoreDiskTrustStatus? disk = null;
        SigstoreServedTrustStatus? served = null;
        SigstoreTimestampAuthorityStatus? timestampAuthority = null;
        SigstoreFulcioStatus? fulcio = null;
        SigstoreRekorStatus? rekor = null;
        SigstoreCtLogStatus? ctLog = null;

        try
        {
            disk = ReadDiskStatus(resource.StatePath);
        }
        catch (Exception exception)
            when (IsExpectedStatusFailure(exception))
        {
            errors.Add(new("disk", exception.Message));
        }

        try
        {
            var endpoint = await resource.TufEndpoint.GetValueAsync(
                cancellationToken)
                ?? throw new SigstoreStatusException(
                    "The TUF endpoint is not allocated.");
            served = await ReadServedStatusAsync(
                new Uri(endpoint, UriKind.Absolute),
                cancellationToken);
        }
        catch (Exception exception)
            when (IsExpectedStatusFailure(exception))
        {
            errors.Add(new("tuf", exception.Message));
        }

        var clientResults = await Task.WhenAll(
            registrations.Clients.Select(
                registration =>
                {
                    var runtimeStatus = runtime.Resources.SingleOrDefault(
                        item => item.Resource
                            == registration.Resource.Name);
                    return runtimeStatus is not null
                        && runtimeStatus.State
                            == KnownResourceStates.Running
                        && runtimeStatus.Health == "Healthy"
                            ? ReadClientStatusAsync(
                                registration,
                                cancellationToken)
                            : Task.FromResult(
                                new ClientStatusResult(
                                    registration.Resource.Name,
                                    null,
                                    new(
                                        registration.Resource.Name,
                                        runtimeStatus is null
                                            ? "resource state is unavailable."
                                            : $"resource is {runtimeStatus.State} " +
                                                $"(health {runtimeStatus.Health}); " +
                                                "the status endpoint was not queried.")));
                }));
        var clients = new List<SigstoreClientTrustStatus>();
        foreach (var result in clientResults
            .OrderBy(item => item.Source, StringComparer.Ordinal))
        {
            if (result.Status is not null)
            {
                clients.Add(result.Status);
            }
            if (result.Error is not null)
            {
                errors.Add(result.Error);
            }
        }

        if (disk is not null && served is not null)
        {
            AddMismatchErrors(
                "tuf",
                disk,
                served,
                errors);
        }
        if (disk is not null)
        {
            foreach (var client in clients)
            {
                AddMismatchErrors(
                    client.Resource,
                    disk,
                    client,
                    errors);
            }
        }

        if (disk is not null)
        {
            try
            {
                var fulcioEndpoint = await resource.Components.Fulcio
                    .GetEndpoint("http")
                    .GetValueAsync(cancellationToken)
                    ?? throw new SigstoreStatusException(
                        "The Fulcio endpoint is not allocated.");
                fulcio = await SigstoreFulcio.ReadStatusAsync(
                    resource.StatePath,
                    new Uri(fulcioEndpoint, UriKind.Absolute),
                    cancellationToken);
                if (!fulcio.ActiveCertificateMatchesPrivateKey)
                {
                    errors.Add(
                        new(
                            "fulcio",
                            "the active Fulcio root certificate and key do not match."));
                }
                if (!fulcio.RuntimeFulcioMatchesActive)
                {
                    errors.Add(
                        new(
                            "fulcio",
                            "activation is pending: the component runtime " +
                            "projection does not match the active generation."));
                }
                if (!fulcio.LiveRootMatchesActive)
                {
                    errors.Add(
                        new(
                            "fulcio",
                            "activation is pending: running root " +
                            $"{fulcio.LiveRootSha256}, active generation " +
                            $"{fulcio.ActiveRootSha256}."));
                }
                if (!fulcio.TesseractAcceptedRootsMatch)
                {
                    errors.Add(
                        new(
                            "tesseract",
                            "the accepted-root bundle does not exactly match " +
                            "the ordered Fulcio TrustedRoot history."));
                }
                if (fulcio.TrustedRoots.Count == 0
                    || fulcio.TrustedRoots[^1].RootSha256
                        != fulcio.ActiveRootSha256)
                {
                    errors.Add(
                        new(
                            "fulcio",
                            "the active Fulcio root is not the final additive " +
                            "TrustedRoot certificate authority."));
                }
            }
            catch (Exception exception)
                when (IsExpectedStatusFailure(exception))
            {
                errors.Add(new("fulcio", exception.Message));
            }
        }

        if (disk is not null)
        {
            try
            {
                var trustedAuthorities =
                    SigstoreTimestampAuthority.ReadTrustedAuthorities(
                        resource.StatePath);
                var endpoint = await resource.Components.Timestamp
                    .GetEndpoint("http")
                    .GetValueAsync(cancellationToken)
                    ?? throw new SigstoreStatusException(
                        "The timestamp authority endpoint is not allocated.");
                var probe = await SigstoreTimestampAuthority.ProbeAsync(
                    new Uri(
                        new Uri(endpoint, UriKind.Absolute),
                        "api/v1/timestamp"),
                    trustedAuthorities,
                    cancellationToken);
                timestampAuthority = SigstoreTimestampAuthority.ReadStatus(
                    resource.StatePath,
                    probe.Evidence);
                if (!timestampAuthority.ActiveSignerMatches)
                {
                    errors.Add(
                        new(
                            "timestamp",
                            "signer activation is pending: running " +
                            $"{timestampAuthority.RunningSigner.RootSha256}/" +
                            $"{timestampAuthority.RunningSigner.LeafSha256}, " +
                            "active generation " +
                            $"{timestampAuthority.ActiveRootSha256}/" +
                            $"{timestampAuthority.ActiveLeafSha256}."));
                }
            }
            catch (Exception exception)
                when (IsExpectedStatusFailure(exception))
            {
                errors.Add(new("timestamp", exception.Message));
            }
        }

        if (disk is not null)
        {
            try
            {
                rekor = await ReadRekorStatusAsync(
                    resource,
                    cancellationToken);
            }
            catch (Exception exception)
                when (IsExpectedStatusFailure(exception))
            {
                errors.Add(new("rekor", exception.Message));
            }
        }

        if (disk is not null)
        {
            try
            {
                ctLog = await ReadCtLogStatusAsync(
                    resource,
                    cancellationToken);
                AppendCtLogStatusErrors(ctLog, errors);
            }
            catch (Exception exception)
                when (IsExpectedStatusFailure(exception))
            {
                errors.Add(new("ctlog", exception.Message));
            }
        }

        if (runtime.State != "Healthy")
        {
            errors.Add(
                new(
                    "resources",
                    runtime.Reason
                        ?? $"Parent resource state is {runtime.State}."));
        }
        SigstoreOperationExecutor.RefreshDurableRecoveryState(resource);
        var presentation = resource.GetPresentation();
        if (presentation.Operation is not null)
        {
            errors.Add(
                new(
                    "operation",
                    $"{presentation.Operation.Command} is active in phase " +
                    $"{presentation.Operation.Phase}: " +
                    presentation.Operation.Message));
        }
        else if (presentation.Recovery is not null)
        {
            errors.Add(
                new(
                    "operation",
                    $"{presentation.Recovery.Command} recovery is pending in " +
                    $"phase {presentation.Recovery.Phase}: " +
                    presentation.Recovery.Message));
        }

        errors.Sort(
            (left, right) =>
            {
                var source = StringComparer.Ordinal.Compare(
                    left.Source,
                    right.Source);
                return source != 0
                    ? source
                    : StringComparer.Ordinal.Compare(
                        left.Message,
                        right.Message);
            });
        clients.Sort(
            (left, right) => StringComparer.Ordinal.Compare(
                left.Resource,
                right.Resource));
        var ready = errors.Count == 0
            && disk is not null
            && served is not null
            && timestampAuthority is not null
            && fulcio is not null
            && rekor is not null
            && ctLog is not null
            && clients.Count == registrations.Clients.Count;
        var reason = errors.Count == 0
            ? null
            : $"{errors[0].Source}: {errors[0].Message}";

        var operation = presentation.Operation;
        var recovery = presentation.Recovery;
        return new SigstoreAggregateTrustStatus(
            StatusSchemaVersion,
            resource.Name,
            ready,
            ready ? "Healthy" : "Degraded",
            reason,
            DateTimeOffset.UtcNow,
            disk,
            served,
            clients,
            runtime.Resources,
            errors,
            timestampAuthority,
            operation is null
                ? null
                : new SigstoreActiveOperationStatus(
                    operation.Command,
                    operation.Phase,
                    operation.Completed,
                    operation.Total,
                    operation.Message,
                    operation.StartedAtUtc),
            recovery is null
                ? null
                : new SigstoreRecoveryStatus(
                    recovery.Command,
                    recovery.Phase,
                    recovery.DisplayState,
                    recovery.Message,
                    recovery.UpdatedAtUtc),
            fulcio,
            rekor,
            ctLog);
    }

    internal static void AppendCtLogStatusErrors(
        SigstoreCtLogStatus ctLog,
        ICollection<SigstoreStatusError> errors)
    {
        ArgumentNullException.ThrowIfNull(ctLog);
        ArgumentNullException.ThrowIfNull(errors);

        foreach (var shard in ctLog.Shards)
        {
            if (!shard.InTrustedRoot)
            {
                errors.Add(
                    new(
                        "ctlog",
                        $"the {shard.Slot} certificate-transparency shard is " +
                        "not published in TrustedRoot."));
            }
            if (shard.ComputeRequired && shard.ComputeHealthy != true)
            {
                errors.Add(
                    new(
                        "ctlog",
                        $"the required {shard.Slot} certificate-transparency " +
                        "compute resource is not healthy."));
            }
            if (!shard.AcceptedRootsMatchRuntime)
            {
                errors.Add(
                    new(
                        "ctlog",
                        $"the {shard.Slot} certificate-transparency shard's " +
                        "accepted-root projection does not match its catalog."));
            }
        }
        if (ctLog.TrustedRootCtlogCount != ctLog.Shards.Count)
        {
            errors.Add(
                new(
                    "ctlog",
                    "TrustedRoot certificate-transparency entry count does " +
                    "not match the shard catalog."));
        }
        if (ctLog.FulcioCtPromotionPending)
        {
            errors.Add(
                new(
                    "ctlog",
                    "certificate-transparency cutover is pending: Fulcio is " +
                    $"still bound to the {ctLog.SelectedFulcioShardSlot} shard " +
                    "while a replacement selection is staged."));
        }
        if (ctLog.IncompleteRotationOperationId is not null)
        {
            errors.Add(
                new(
                    "ctlog",
                    "certificate-transparency recovery is pending for operation " +
                    $"{ctLog.IncompleteRotationOperationId} in phase " +
                    $"{ctLog.IncompleteRotationStatus ?? "unknown"}."));
        }
    }

    /// <summary>
    /// Collects the certificate-transparency status: every logical shard
    /// with its verified checkpoint and TrustedRoot membership, and the
    /// shard the running Fulcio is currently bound to. The historical
    /// primary shard's compute stays required forever, because its
    /// append-only tiles and signed checkpoint must remain live for
    /// certificates that were logged there.
    /// </summary>
    internal static async Task<SigstoreCtLogStatus> ReadCtLogStatusAsync(
        SigstoreResource resource,
        CancellationToken cancellationToken)
    {
        var statePath = resource.StatePath;
        var generationLink = ReadRequiredLink(
            Path.Combine(statePath, "active-generation"));
        var activeGenerationPath = Path.Combine(statePath, generationLink);
        var generation = DeserializeRequired<GenerationManifestStatus>(
            ReadRequiredBytes(
                Path.Combine(activeGenerationPath, "manifest.json")),
            "active generation manifest");
        var trustDomain = DeserializeRequired<TrustDomainManifestStatus>(
            ReadRequiredBytes(Path.Combine(statePath, "trust-domain.json")),
            "trust-domain manifest");

        var catalogPath = SigstoreCtLogShard.ShardCatalogPath(statePath);
        CtLogShardCatalogStatus catalog;
        if (File.Exists(catalogPath))
        {
            catalog = DeserializeStrict<CtLogShardCatalogStatus>(
                ReadRequiredBytes(catalogPath),
                "CT shard catalog");
        }
        else
        {
            if (generation.CtLogRotationOperationId is not null)
            {
                throw new SigstoreStatusException(
                    "The rotated CT log generation has no shard catalog.");
            }
            var primaryMaterial =
                SigstoreStateBootstrapper.ValidateCtLogShardMaterial(
                    Path.Combine(
                        statePath,
                        "generations",
                        "generation-00000001"));
            // Before any CT rotation the catalog is not materialized yet,
            // so the single primary shard's accepted-root identity is read
            // directly from the bundle its runtime projection enforces.
            var primaryRuntimeRoots =
                SigstoreCtLogShard.ReadRuntimeAcceptedRoots(
                    statePath,
                    SigstoreCtLogShard.PrimarySlot);
            catalog = new CtLogShardCatalogStatus(
                1,
                trustDomain.TrustDomainId,
                primaryMaterial.ShardId,
                trustDomain.CreatedAtUtc,
                [
                    new CtLogShardCatalogEntryStatus(
                        primaryMaterial.ShardId,
                        "primary",
                        SigstoreCtLogShard.PrimaryUrl,
                        SigstoreCtLogShard.PrimaryOrigin,
                        primaryMaterial.PublicKeySha256,
                        primaryMaterial.LogId,
                        trustDomain.CtLogStateId,
                        SigstoreCtLogShard.PrimaryDataRelativePath,
                        SigstoreCtLogShard.PrimaryResourceName,
                        trustDomain.CreatedAtUtc,
                        trustDomain.CreatedAtUtc,
                        "active",
                        primaryRuntimeRoots.BundleSha256,
                        primaryRuntimeRoots.Fingerprints.Count,
                        primaryRuntimeRoots.Fingerprints)
                ]);
        }
        if (catalog.SchemaVersion != 1
            || catalog.TrustDomainId != trustDomain.TrustDomainId
            || catalog.Shards.Count is not (1 or 2)
            || catalog.Shards[0].Slot != "primary"
            || (catalog.Shards.Count == 2
                && (catalog.Shards[1].Slot != "secondary"
                    || catalog.Shards[0].Status != "historical"
                    || catalog.Shards[1].Status != "active"
                    || catalog.ActiveShardId != catalog.Shards[1].ShardId
                    || generation.CtLogShardId != catalog.Shards[1].ShardId
                    || generation.CtLogPriorShardId
                        != catalog.Shards[0].ShardId)))
        {
            throw new SigstoreStatusException(
                "The CT shard catalog does not agree with the active " +
                "generation.");
        }

        var ctlogs = SigstoreCtLogShard.ReadCtlogEntries(
            ReadRequiredBytes(
                Path.Combine(
                    statePath,
                    "tuf",
                    "active",
                    "targets",
                    "trusted_root.json")));
        var selection =
            SigstoreStateBootstrapper.ReadFulcioCtRuntimeProjection(
                statePath);

        var shards = new List<SigstoreCtLogShardHealthStatus>();
        foreach (var shard in catalog.Shards)
        {
            var generationPath =
                SigstoreCtLogShard.ResolveShardGenerationPath(
                    statePath,
                    shard.Slot,
                    generation.CtLogPriorGenerationId);
            var material =
                SigstoreStateBootstrapper.ValidateCtLogShardMaterial(
                    generationPath);
            if (material.PublicKeySha256 != shard.PublicKeySha256
                || material.LogId != shard.LogIdSha256
                || material.ShardId != shard.ShardId)
            {
                throw new SigstoreStatusException(
                    $"The {shard.Slot} CT log signer does not match its " +
                    "shard catalog entry.");
            }
            var dataPath = Path.Combine(
                statePath,
                shard.DataPath.Replace(
                    '/',
                    Path.DirectorySeparatorChar));
            var stateId = File.ReadAllText(
                Path.Combine(dataPath, "bootstrap-state"));
            if (stateId != shard.StateId)
            {
                throw new SigstoreStatusException(
                    $"The {shard.Slot} CT log data does not match its shard " +
                    "state ID.");
            }
            using var publicKey = SigstoreCtLogShard.ReadPublicKey(
                generationPath);
            var checkpoint = SigstoreCtLogShard.ReadAndVerifyCheckpoint(
                ReadRequiredBytes(Path.Combine(dataPath, "checkpoint")),
                shard.Origin,
                publicKey);
            var inTrustedRoot = ctlogs.Count(
                entry => entry.BaseUrl == shard.BaseUrl
                    && entry.PublicKeySha256 == shard.PublicKeySha256) == 1;

            // Both shards keep running compute: the historical primary is
            // append-only and must stay live so previously issued
            // certificates remain auditable against it.
            bool? computeHealthy = null;
            var computeRequired = true;
            if (shard.Slot == "primary"
                || resource.IsConditionalResourceActive(
                    resource.Components.TesseractSecondary.Resource.Name))
            {
                computeHealthy = await ProbeCtLogAsync(
                    resource,
                    shard.Slot,
                    cancellationToken);
            }
            shards.Add(
                new SigstoreCtLogShardHealthStatus(
                    shard.ShardId,
                    shard.Slot,
                    shard.Status,
                    shard.BaseUrl,
                    shard.Origin,
                    shard.ResourceName,
                    shard.PublicKeySha256,
                    shard.LogIdSha256,
                    shard.StateId,
                    checkpoint.TreeSize,
                    checkpoint.Timestamp,
                    checkpoint.RootHash,
                    checkpoint.SignatureSha256,
                    inTrustedRoot,
                    computeRequired,
                    computeHealthy,
                    shard.AcceptedRootsSha256,
                    shard.AcceptedRootCount,
                    shard.AcceptedRootFingerprints,
                    AcceptedRootsMatchRuntime(statePath, shard)));
        }

        var incomplete = SigstoreCtLogShard.ReadRotationJournals(statePath)
            .Where(journal => journal.Status
                != SigstoreCtLogShard.StatusCompleted)
            .OrderByDescending(journal => journal.StartedAtUtc)
            .FirstOrDefault();

        return new SigstoreCtLogStatus(
            catalog.ActiveShardId,
            selection.Selector,
            selection.Origin,
            selection.CtLogPublicKeySha256,
            selection.PromotionPending,
            selection.StagedCtLogPublicKeySha256,
            ctlogs.Count,
            ctlogs,
            shards,
            incomplete?.OperationId,
            incomplete?.Status);
    }

    /// <summary>
    /// Binds one shard's recorded accepted-root identity to the bytes its
    /// runtime projection enforces. The historical primary shard is frozen
    /// at the cutover so it must render exactly what is recorded; the
    /// secondary shard was created accepting that same complete bundle, so
    /// its live bundle must still begin with it after later Fulcio CA
    /// rotations extended it.
    /// </summary>
    private static bool AcceptedRootsMatchRuntime(
        string statePath,
        CtLogShardCatalogEntryStatus shard)
    {
        try
        {
            var frozen = SigstoreCtLogShard.ReadRuntimeAcceptedRoots(
                statePath,
                SigstoreCtLogShard.PrimarySlot);
            if (shard.AcceptedRootsSha256 != frozen.BundleSha256
                || shard.AcceptedRootCount != frozen.Fingerprints.Count
                || !shard.AcceptedRootFingerprints.SequenceEqual(
                    frozen.Fingerprints,
                    StringComparer.Ordinal))
            {
                return false;
            }
            if (shard.Slot != SigstoreCtLogShard.SecondarySlot)
            {
                return true;
            }
            var live = SigstoreCtLogShard.ReadRuntimeAcceptedRoots(
                statePath,
                SigstoreCtLogShard.SecondarySlot);
            return live.Bundle.Length >= frozen.Bundle.Length
                && live.Bundle.AsSpan(0, frozen.Bundle.Length)
                    .SequenceEqual(frozen.Bundle);
        }
        catch (Exception exception)
            when (exception is IOException
                or InvalidDataException
                or System.Security.Cryptography.CryptographicException
                or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static async Task<bool> ProbeCtLogAsync(
        SigstoreResource resource,
        string slot,
        CancellationToken cancellationToken)
    {
        var component = slot == "primary"
            ? resource.Components.Tesseract
            : resource.Components.TesseractSecondary;
        var endpoint = await component
            .GetEndpoint("http")
            .GetValueAsync(cancellationToken)
            ?? throw new SigstoreStatusException(
                $"The {slot} certificate-transparency endpoint is not " +
                "allocated.");
        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        using var response = await client.GetAsync(
            new Uri(
                EnsureTrailingSlash(new Uri(endpoint, UriKind.Absolute)),
                "healthz"),
            cancellationToken);
        return response.IsSuccessStatusCode;
    }

    internal static async Task<SigstoreRekorStatus> ReadRekorStatusAsync(
        SigstoreResource resource,
        CancellationToken cancellationToken)
    {
        var statePath = resource.StatePath;
        var generationLink = ReadRequiredLink(
            Path.Combine(statePath, "active-generation"));
        var activeGenerationPath = Path.Combine(statePath, generationLink);
        var generation = DeserializeRequired<GenerationManifestStatus>(
            ReadRequiredBytes(
                Path.Combine(activeGenerationPath, "manifest.json")),
            "active generation manifest");
        var trustDomain = DeserializeRequired<TrustDomainManifestStatus>(
            ReadRequiredBytes(Path.Combine(statePath, "trust-domain.json")),
            "trust-domain manifest");

        var catalogPath = Path.Combine(
            statePath,
            "data",
            "rekor-shards",
            "state.json");
        RekorShardCatalogStatus catalog;
        if (File.Exists(catalogPath))
        {
            catalog = DeserializeStrict<RekorShardCatalogStatus>(
                ReadRequiredBytes(catalogPath),
                "Rekor shard catalog");
        }
        else
        {
            if (generation.RekorRotationOperationId is not null)
            {
                throw new SigstoreStatusException(
                    "The rotated Rekor generation has no shard catalog.");
            }
            var primaryMaterial =
                SigstoreStateBootstrapper.ValidateRekorShardMaterial(
                    Path.Combine(
                        statePath,
                        "generations",
                        "generation-00000001"));
            catalog = new RekorShardCatalogStatus(
                1,
                trustDomain.TrustDomainId,
                primaryMaterial.ShardId,
                trustDomain.CreatedAtUtc,
                [
                    new RekorShardCatalogEntryStatus(
                        primaryMaterial.ShardId,
                        "primary",
                        "http://rekor-sigstore.dev.localhost:3000",
                        "rekor-sigstore.dev.localhost",
                        primaryMaterial.PublicKeySha256,
                        primaryMaterial.LogId,
                        trustDomain.RekorStateId,
                        "data/rekor",
                        "rekor-server",
                        trustDomain.CreatedAtUtc,
                        trustDomain.CreatedAtUtc,
                        "active")
                ]);
        }

        ValidateRekorCatalog(catalog, generation, trustDomain);
        var trustedRootPath = Path.Combine(
            statePath,
            "tuf",
            "active",
            "targets",
            "trusted_root.json");
        var tlogs = SigstoreRekorShard.ReadTlogEntries(
            ReadRequiredBytes(trustedRootPath));
        var signingConfigUrl = ReadActiveRekorSigningConfigUrl(
            ReadRequiredBytes(
                Path.Combine(
                    statePath,
                    "tuf",
                    "active",
                    "targets",
                    "signing_config.v0.2.json")));
        var activeShard = catalog.Shards.Single(
            shard => shard.ShardId == catalog.ActiveShardId);
        if (signingConfigUrl != activeShard.BaseUrl)
        {
            throw new SigstoreStatusException(
                $"SigningConfig routes Rekor to '{signingConfigUrl}', expected " +
                $"active shard '{activeShard.BaseUrl}'.");
        }

        var gatewayValue = await resource.Components.Rekor
            .GetEndpoint("http")
            .GetValueAsync(cancellationToken)
            ?? throw new SigstoreStatusException(
                "The Rekor gateway endpoint is not allocated.");
        var gateway = EnsureTrailingSlash(
            new Uri(gatewayValue, UriKind.Absolute));
        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        var results = new List<SigstoreRekorShardHealthStatus>();
        foreach (var shard in catalog.Shards)
        {
            var signerGenerationPath = shard.Slot == "primary"
                ? Path.Combine(
                    statePath,
                    "generations",
                    "generation-00000001")
                : activeGenerationPath;
            var material =
                SigstoreStateBootstrapper.ValidateRekorShardMaterial(
                    signerGenerationPath);
            if (material.PublicKeySha256 != shard.PublicKeySha256
                || material.LogId != shard.LogIdSha256
                || material.ShardId != shard.ShardId)
            {
                throw new SigstoreStatusException(
                    $"{shard.Slot} Rekor signer does not match its shard catalog.");
            }

            var spki = ReadRekorSpki(
                Path.Combine(
                    signerGenerationPath,
                    "public",
                    "rekor",
                    "signer.pub"));
            var dataPath = Path.Combine(
                statePath,
                shard.DataPath.Replace(
                    '/',
                    Path.DirectorySeparatorChar));
            var stateId = File.ReadAllText(
                Path.Combine(dataPath, "bootstrap-state"));
            if (stateId != shard.StateId)
            {
                throw new SigstoreStatusException(
                    $"{shard.Slot} Rekor data does not match its shard state ID.");
            }
            if (shard.Slot == "secondary")
            {
                ValidateSecondaryRekorMetadata(
                    statePath,
                    shard,
                    generation.RekorRotationOperationId
                        ?? throw new SigstoreStatusException(
                            "Secondary Rekor shard has no rotation operation."),
                    trustDomain.TrustDomainId);
            }

            var checkpointBytes = ReadRequiredBytes(
                Path.Combine(dataPath, "checkpoint"));
            var checkpoint = SigstoreRekorShard.ReadAndVerifyCheckpoint(
                checkpointBytes,
                shard.Origin,
                spki);
            var tlogMatches = tlogs.Count(
                tlog => tlog.BaseUrl == shard.BaseUrl
                    && tlog.PublicKeySha256 == shard.PublicKeySha256);
            if (tlogMatches != 1)
            {
                throw new SigstoreStatusException(
                    $"{shard.Slot} Rekor shard does not have exactly one " +
                    "matching TrustedRoot entry.");
            }

            var routeBytes = await ReadGatewayBytesAsync(
                client,
                gateway,
                "checkpoint",
                new Uri(shard.BaseUrl, UriKind.Absolute).Authority,
                cancellationToken);
            var routeCheckpoint =
                SigstoreRekorShard.ReadAndVerifyCheckpoint(
                    routeBytes,
                    shard.Origin,
                    spki);
            if (routeCheckpoint.TreeSize < checkpoint.TreeSize)
            {
                throw new SigstoreStatusException(
                    $"{shard.Slot} Rekor checkpoint route regressed from " +
                    $"{checkpoint.TreeSize} to {routeCheckpoint.TreeSize}.");
            }

            var computeRequired = shard.Status == "active";
            bool? computeHealthy = null;
            if (computeRequired)
            {
                await ProbeGatewayAsync(
                    client,
                    gateway,
                    "healthz",
                    new Uri(shard.BaseUrl, UriKind.Absolute).Authority,
                    cancellationToken);
                computeHealthy = true;
            }

            results.Add(
                new SigstoreRekorShardHealthStatus(
                    shard.ShardId,
                    shard.Slot,
                    shard.Status,
                    shard.BaseUrl,
                    shard.Origin,
                    shard.ResourceName,
                    shard.PublicKeySha256,
                    shard.StateId,
                    routeCheckpoint.TreeSize,
                    Hash(routeBytes),
                    true,
                    computeRequired,
                    computeHealthy));
        }

        return new SigstoreRekorStatus(
            catalog.ActiveShardId,
            signingConfigUrl,
            tlogs.Count,
            results);
    }

    internal static SigstoreDiskTrustStatus ReadDiskStatus(string statePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);

        var generationLinkPath = Path.Combine(
            statePath,
            "active-generation");
        var generationLink = ReadRequiredLink(generationLinkPath);
        var generationId = Path.GetFileName(generationLink);
        var expectedGenerationLink = Path.Combine(
            "generations",
            generationId);
        if (!PathsEqual(generationLink, expectedGenerationLink))
        {
            throw new SigstoreStatusException(
                $"Active generation link '{generationLink}' is not normalized.");
        }

        var trustDomainBytes = ReadRequiredBytes(
            Path.Combine(statePath, "trust-domain.json"));
        var trustDomain = DeserializeRequired<TrustDomainManifestStatus>(
            trustDomainBytes,
            "trust-domain manifest");
        if (trustDomain.SchemaVersion != TrustStateSchemaVersion
            || string.IsNullOrWhiteSpace(trustDomain.TrustDomainId)
            || trustDomain.CreatedAtUtc == default
            || string.IsNullOrWhiteSpace(trustDomain.CtLogStateId)
            || string.IsNullOrWhiteSpace(trustDomain.RekorStateId))
        {
            throw new SigstoreStatusException(
                "The immutable trust-domain manifest is invalid.");
        }

        var generationPath = Path.Combine(
            statePath,
            generationLink);
        var generationManifestPath = Path.Combine(
            generationPath,
            "manifest.json");
        var generationManifestBytes = ReadRequiredBytes(
            generationManifestPath);
        var generationManifest = DeserializeRequired<GenerationManifestStatus>(
            generationManifestBytes,
            "generation manifest");
        if (generationManifest.SchemaVersion != TrustStateSchemaVersion
            || generationManifest.Generation <= 0
            || generationManifest.GenerationId != generationId
            || generationManifest.TrustDomainId
                != trustDomain.TrustDomainId
            || (generationManifest.Generation == 1
                && generationManifest.CreatedAtUtc
                    != trustDomain.CreatedAtUtc)
            || generationManifest.SourceSchemaVersion is not (4 or 5)
            || generationManifest.SourceSchemaVersion == 4
                && !IsLowerHexSha256(
                    generationManifest.SourceManifestSha256 ?? "")
            || generationManifest.SourceSchemaVersion == 5
                && generationManifest.SourceManifestSha256 is not null
            || !IsLowerHexSha256(generationManifest.FulcioRootSha256)
            || !IsLowerHexSha256(
                generationManifest.CtLogPublicKeySha256)
            || !IsLowerHexSha256(
                generationManifest.RekorPublicKeySha256)
            || !IsLowerHexSha256(generationManifest.TsaRootSha256)
            || !IsLowerHexSha256(generationManifest.TsaLeafSha256)
            || string.IsNullOrWhiteSpace(generationManifest.OidcKeyId)
            || generationManifest.Files is null)
        {
            throw new SigstoreStatusException(
                "The active generation manifest is invalid.");
        }
        ValidateGenerationFiles(
            generationPath,
            generationManifest.Files);
        ValidateFulcioRotationMetadata(generationManifest);
        ValidateTimestampRotationMetadata(generationManifest);
        ValidateRekorRotationMetadata(generationManifest);
        ValidateCtLogRotationMetadata(generationManifest);
        var generationManifestHash = Hash(generationManifestBytes);

        var transition = DeserializeRequired<TransitionJournalStatus>(
            ReadRequiredBytes(
                Path.Combine(
                    statePath,
                    "transition",
                    "state.json")),
            "trust transition journal");
        if (transition.SchemaVersion != TransitionSchemaVersion
            || transition.Status is not ("committed" or "recovered")
            || transition.LastCheckpoint != "transition-finalized"
            || (generationManifest.Generation == 1
                && transition.PriorGeneration is not null)
            || (generationManifest.Generation > 1
                && transition.PriorGeneration is null)
            || transition.Candidate is null
            || transition.TrustDomain is null
            || transition.CandidateManifest is null
            || transition.TrustDomainManifestSha256
                != Hash(trustDomainBytes)
            || !TrustDomainsEqual(
                transition.TrustDomain,
                trustDomain)
            || !GenerationManifestsEqual(
                transition.CandidateManifest,
                generationManifest)
            || transition.Candidate.Generation
                != generationManifest.Generation
            || transition.Candidate.GenerationId
                != generationManifest.GenerationId
            || transition.Candidate.ManifestSha256
                != generationManifestHash
            || generationManifest.TsaRotationOperationId is not null
                && generationManifest.TsaPriorGeneration
                    == generationManifest.Generation - 1
                && generationManifest.OidcRotationOperationId is null
                && (transition.Operation != "tsa-rotation"
                    || transition.TransitionId
                        != generationManifest.TsaRotationOperationId)
            || generationManifest.FulcioRotationOperationId is not null
                && generationManifest.FulcioPriorGeneration
                    == generationManifest.Generation - 1
                && (transition.Operation != "fulcio-rotation"
                    || transition.TransitionId
                        != generationManifest.FulcioRotationOperationId)
            || generationManifest.RekorRotationOperationId is not null
                && generationManifest.RekorPriorGeneration
                    == generationManifest.Generation - 1
                && (transition.Operation != "rekor-shard-rotation"
                    || transition.TransitionId
                        != generationManifest.RekorRotationOperationId))
        {
            throw new SigstoreStatusException(
                "The active generation does not match the committed transition.");
        }
        var ctState = File.ReadAllText(
            Path.Combine(
                statePath,
                "data",
                "ctlog",
                "bootstrap-state"));
        var rekorState = File.ReadAllText(
            Path.Combine(
                statePath,
                "data",
                "rekor",
                "bootstrap-state"));
        if (ctState != trustDomain.CtLogStateId
            || rekorState != trustDomain.RekorStateId)
        {
            throw new SigstoreStatusException(
                "Transparency-log state does not match the trust domain.");
        }

        var tufPath = Path.Combine(statePath, "tuf");
        var publication = DeserializeRequired<PublicationStateStatus>(
            ReadRequiredBytes(
                Path.Combine(
                    tufPath,
                    "publication",
                    "state.json")),
            "TUF publication state");
        if (publication.SchemaVersion != PublicationSchemaVersion
            || publication.Status != "committed"
            || publication.Active is null
            || publication.Candidate is not null
            || !IsLowerHexSha256(
                publication.BootstrapRootSha256))
        {
            throw new SigstoreStatusException(
                "The TUF publication state is not committed.");
        }
        ValidatePublicationReference(
            publication.Active,
            "active");
        if (publication.Previous is not null)
        {
            ValidatePublicationReference(
                publication.Previous,
                "previous");
            if (publication.Previous.Id == publication.Active.Id)
            {
                throw new SigstoreStatusException(
                    "Active and previous TUF publications are identical.");
            }
        }
        var bootstrapRootPath = Path.Combine(
            tufPath,
            "bootstrap",
            "root.json");
        var bootstrapRootBytes = ReadRequiredBytes(bootstrapRootPath);
        if (Hash(bootstrapRootBytes)
            != publication.BootstrapRootSha256
            || ReadMetadataVersion(
                bootstrapRootBytes,
                "bootstrap root") != 1)
        {
            throw new SigstoreStatusException(
                "The immutable bootstrap root does not match publication state.");
        }
        var activeLink = ReadRequiredLink(
            Path.Combine(tufPath, "active"));
        var expectedActiveLink = Path.Combine(
            "committed",
            publication.Active.Id);
        if (!PathsEqual(activeLink, expectedActiveLink))
        {
            throw new SigstoreStatusException(
                $"Active TUF link '{activeLink}' does not match publication " +
                $"'{publication.Active.Id}'.");
        }

        var activePath = Path.Combine(tufPath, activeLink);
        var tufManifestPath = Path.Combine(activePath, "manifest.json");
        var tufManifestBytes = ReadRequiredBytes(tufManifestPath);
        if (Hash(tufManifestBytes) != publication.Active.ManifestSha256)
        {
            throw new SigstoreStatusException(
                "The active TUF manifest hash does not match publication state.");
        }
        var tufManifest = DeserializeRequired<TufManifestStatus>(
            tufManifestBytes,
            "TUF manifest");
        ValidateTufManifest(activePath, tufManifest);
        if (string.IsNullOrWhiteSpace(tufManifest.SourceFingerprint)
            || !IsLowerHexSha256(tufManifest.SourceFingerprint))
        {
            throw new SigstoreStatusException(
                "The active TUF source fingerprint is invalid.");
        }
        ValidateTufLayout(
            tufPath,
            publication,
            tufManifest.SourceFingerprint);

        var rootVersion = ReadMetadataVersion(
            Path.Combine(activePath, "repository", "root.json"),
            "root");
        var targetsVersion = ReadMetadataVersion(
            Path.Combine(activePath, "repository", "targets.json"),
            "targets");
        var trustedRootHash = Hash(
            ReadRequiredBytes(
                Path.Combine(
                    activePath,
                    "targets",
                    "trusted_root.json")));
        var signingConfigHash = Hash(
            ReadRequiredBytes(
                Path.Combine(
                    activePath,
                    "targets",
                    "signing_config.v0.2.json")));
        var published = DeserializeRequired<PublishedTrustStatus>(
            ReadRequiredBytes(
                Path.Combine(
                    activePath,
                    "targets",
                    TrustStatusTargetName)),
            "published trust status");
        ValidatePublishedStatus(
            published,
            generationManifest.TrustDomainId,
            generationManifest.Generation,
            generationManifest.GenerationId,
            generationManifestHash,
            rootVersion,
            targetsVersion,
            trustedRootHash,
            signingConfigHash);

        return new SigstoreDiskTrustStatus(
            published.TrustDomainId,
            published.Generation,
            published.GenerationId,
            published.GenerationManifestSha256,
            published.TufRootVersion,
            published.TufTargetsVersion,
            published.TrustedRootSha256,
            published.SigningConfigSha256,
            publication.Active.Id,
            publication.Active.ManifestSha256);
    }

    internal static SigstoreTufStateSnapshot ReadTufStateSnapshot(
        string statePath)
    {
        var trust = ReadDiskStatus(statePath);
        var tufPath = Path.Combine(statePath, "tuf");
        var publication = DeserializeRequired<PublicationStateStatus>(
            ReadRequiredBytes(
                Path.Combine(
                    tufPath,
                    "publication",
                    "state.json")),
            "TUF publication state");
        var activePath = Path.Combine(
            tufPath,
            "committed",
            trust.PublicationId);
        var manifest = DeserializeRequired<TufManifestStatus>(
            ReadRequiredBytes(
                Path.Combine(activePath, "manifest.json")),
            "TUF manifest");

        return new SigstoreTufStateSnapshot(
            trust,
            ReadTufMetadataStatus(
                ReadRequiredBytes(
                    Path.Combine(
                        activePath,
                        "repository",
                        "root.json")),
                ReadRequiredBytes(
                    Path.Combine(
                        activePath,
                        "repository",
                        "targets.json")),
                ReadRequiredBytes(
                    Path.Combine(
                        activePath,
                        "repository",
                        "snapshot.json")),
                ReadRequiredBytes(
                    Path.Combine(
                        activePath,
                        "repository",
                        "timestamp.json")),
                ReadRequiredBytes(
                    Path.Combine(
                        activePath,
                        "targets",
                        "trusted_root.json")),
                ReadRequiredBytes(
                    Path.Combine(
                        activePath,
                        "targets",
                        "signing_config.v0.2.json"))),
            Hash(
                ReadRequiredBytes(
                    Path.Combine(
                        tufPath,
                        "bootstrap",
                        "root.json"))),
            manifest.SourceFingerprint,
            HashNamedValues(
                manifest.Files.Where(
                    pair => !IsRefreshableMetadataPath(pair.Key))),
            publication.Previous?.Id,
            publication.Previous?.ManifestSha256);
    }

    internal static string ReadTrustStateFingerprint(string statePath)
    {
        var entries = ReadTrustStateEntries(
            statePath,
            includeTuf: true);
        return HashNamedValues(entries);
    }

    internal static string ReadTrustMaterialFingerprint(string statePath)
    {
        var entries = ReadTrustStateEntries(
            statePath,
            includeTuf: false);
        return HashNamedValues(entries);
    }

    private static SortedDictionary<string, string> ReadTrustStateEntries(
        string statePath,
        bool includeTuf)
    {
        _ = ReadDiskStatus(statePath);
        var entries = new SortedDictionary<string, string>(
            StringComparer.Ordinal);
        var relativePaths = new List<string>
        {
            "trust-domain.json",
            "active-generation",
            "generations",
            "transition",
            "migration"
        };
        if (Directory.Exists(Path.Combine(statePath, "runtime")))
        {
            relativePaths.Add("runtime");
        }
        if (includeTuf)
        {
            relativePaths.Add("tuf");
        }
        foreach (var relativePath in relativePaths)
        {
            CollectFingerprintEntry(
                statePath,
                Path.Combine(statePath, relativePath),
                entries);
        }

        return entries;
    }

    internal static SigstoreClientTrustStatus ParseClientStatus(
        ReadOnlySpan<byte> payload,
        SigstoreClientRegistration registration)
    {
        var status = DeserializeRequired<SigstoreClientTrustStatus>(
            payload,
            $"{registration.Resource.Name} trust status");
        if (status.SchemaVersion != StatusSchemaVersion)
        {
            throw new SigstoreStatusException(
                $"{registration.Resource.Name} reported unsupported status " +
                $"schema {status.SchemaVersion}.");
        }
        if (status.Resource != registration.Resource.Name
            || status.Language != registration.Language)
        {
            throw new SigstoreStatusException(
                $"{registration.Resource.Name} reported identity " +
                $"'{status.Resource}/{status.Language}'.");
        }
        ValidateCommonStatus(
            status.TrustDomainId,
            status.Generation,
            status.GenerationId,
            status.GenerationManifestSha256,
            status.TufRootVersion,
            status.TufTargetsVersion,
            status.TrustedRootSha256,
            status.SigningConfigSha256);
        if (status.InitializedAtUtc == default)
        {
            throw new SigstoreStatusException(
                $"{registration.Resource.Name} omitted initialization time.");
        }
        if (status.Ready && status.LastError is not null)
        {
            throw new SigstoreStatusException(
                $"{registration.Resource.Name} is ready but reported an error.");
        }
        if (!status.Ready && string.IsNullOrWhiteSpace(status.LastError))
        {
            throw new SigstoreStatusException(
                $"{registration.Resource.Name} is not ready without an error.");
        }
        if (!status.Ready)
        {
            throw new SigstoreStatusException(
                $"{registration.Resource.Name} is not ready: " +
                status.LastError);
        }

        return status;
    }

    internal static async Task<SigstoreServedTufSnapshot>
        ReadServedTufSnapshotAsync(
        Uri endpoint,
        CancellationToken cancellationToken)
    {
        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        var root = await ReadHttpBytesAsync(
            client,
            new Uri(EnsureTrailingSlash(endpoint), "root.json"),
            cancellationToken);
        var targets = await ReadHttpBytesAsync(
            client,
            new Uri(EnsureTrailingSlash(endpoint), "targets.json"),
            cancellationToken);
        var snapshot = await ReadHttpBytesAsync(
            client,
            new Uri(EnsureTrailingSlash(endpoint), "snapshot.json"),
            cancellationToken);
        var timestamp = await ReadHttpBytesAsync(
            client,
            new Uri(EnsureTrailingSlash(endpoint), "timestamp.json"),
            cancellationToken);
        var trustedRoot = await ReadHttpBytesAsync(
            client,
            new Uri(EnsureTrailingSlash(endpoint), "trusted_root.json"),
            cancellationToken);
        var signingConfig = await ReadHttpBytesAsync(
            client,
            new Uri(
                EnsureTrailingSlash(endpoint),
                "signing_config.v0.2.json"),
            cancellationToken);
        var publishedBytes = await ReadHttpBytesAsync(
            client,
            new Uri(
                EnsureTrailingSlash(endpoint),
                TrustStatusTargetName),
            cancellationToken);

        return new SigstoreServedTufSnapshot(
            CreateServedTrustStatus(
                root,
                targets,
                trustedRoot,
                signingConfig,
                publishedBytes),
            ReadTufMetadataStatus(
                root,
                targets,
                snapshot,
                timestamp,
                trustedRoot,
                signingConfig));
    }

    private static async Task<SigstoreServedTrustStatus>
        ReadServedStatusAsync(
        Uri endpoint,
        CancellationToken cancellationToken)
    {
        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        var baseUri = EnsureTrailingSlash(endpoint);
        var root = await ReadHttpBytesAsync(
            client,
            new Uri(baseUri, "root.json"),
            cancellationToken);
        var targets = await ReadHttpBytesAsync(
            client,
            new Uri(baseUri, "targets.json"),
            cancellationToken);
        var trustedRoot = await ReadHttpBytesAsync(
            client,
            new Uri(baseUri, "trusted_root.json"),
            cancellationToken);
        var signingConfig = await ReadHttpBytesAsync(
            client,
            new Uri(baseUri, "signing_config.v0.2.json"),
            cancellationToken);
        var published = await ReadHttpBytesAsync(
            client,
            new Uri(baseUri, TrustStatusTargetName),
            cancellationToken);

        return CreateServedTrustStatus(
            root,
            targets,
            trustedRoot,
            signingConfig,
            published);
    }

    private static SigstoreServedTrustStatus CreateServedTrustStatus(
        byte[] root,
        byte[] targets,
        byte[] trustedRoot,
        byte[] signingConfig,
        byte[] publishedBytes)
    {
        var rootVersion = ReadMetadataVersion(root, "served root");
        var targetsVersion = ReadMetadataVersion(
            targets,
            "served targets");
        var trustedRootHash = Hash(trustedRoot);
        var signingConfigHash = Hash(signingConfig);
        var published = DeserializeRequired<PublishedTrustStatus>(
            publishedBytes,
            "served trust status");
        ValidatePublishedStatus(
            published,
            published.TrustDomainId,
            published.Generation,
            published.GenerationId,
            published.GenerationManifestSha256,
            rootVersion,
            targetsVersion,
            trustedRootHash,
            signingConfigHash);

        return new SigstoreServedTrustStatus(
            published.TrustDomainId,
            published.Generation,
            published.GenerationId,
            published.GenerationManifestSha256,
            published.TufRootVersion,
            published.TufTargetsVersion,
            published.TrustedRootSha256,
            published.SigningConfigSha256);
    }

    private static async Task<ClientStatusResult> ReadClientStatusAsync(
        SigstoreClientRegistration registration,
        CancellationToken cancellationToken)
    {
        try
        {
            return new ClientStatusResult(
                registration.Resource.Name,
                await ReadRequiredClientStatusAsync(
                    registration,
                    cancellationToken),
                null);
        }
        catch (Exception exception)
            when (IsExpectedStatusFailure(exception))
        {
            return new ClientStatusResult(
                registration.Resource.Name,
                null,
                new(
                    registration.Resource.Name,
                    exception.Message));
        }
    }

    internal static async Task<SigstoreClientTrustStatus>
        ReadRequiredClientStatusAsync(
            SigstoreClientRegistration registration,
            CancellationToken cancellationToken)
    {
        var endpoint = await registration.Endpoint.GetValueAsync(
            cancellationToken)
            ?? throw new SigstoreStatusException(
                $"{registration.Resource.Name} endpoint is not allocated.");
        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        var payload = await ReadHttpBytesAsync(
            client,
            new Uri(
                EnsureTrailingSlash(
                    new Uri(endpoint, UriKind.Absolute)),
                "trust/status"),
            cancellationToken);
        return ParseClientStatus(payload, registration);
    }

    private static void ValidateRekorCatalog(
        RekorShardCatalogStatus catalog,
        GenerationManifestStatus generation,
        TrustDomainManifestStatus trustDomain)
    {
        if (catalog.SchemaVersion != 1
            || catalog.TrustDomainId != trustDomain.TrustDomainId
            || catalog.UpdatedAtUtc == default
            || catalog.UpdatedAtUtc.Offset != TimeSpan.Zero
            || catalog.Shards is null
            || catalog.Shards.Count is not (1 or 2)
            || catalog.Shards.Select(shard => shard.ShardId)
                .Distinct(StringComparer.Ordinal)
                .Count() != catalog.Shards.Count
            || catalog.Shards.Count(shard => shard.Status == "active") != 1
            || catalog.UpdatedAtUtc
                < catalog.Shards.Max(shard => shard.ActivatedAtUtc))
        {
            throw new SigstoreStatusException(
                "The Rekor shard catalog is malformed.");
        }

        foreach (var shard in catalog.Shards)
        {
            if (!IsLowerHexSha256(shard.PublicKeySha256)
                || shard.LogIdSha256 != shard.PublicKeySha256
                || shard.ShardId != $"sha256-{shard.PublicKeySha256}"
                || shard.CreatedAtUtc == default
                || shard.ActivatedAtUtc == default
                || shard.CreatedAtUtc.Offset != TimeSpan.Zero
                || shard.ActivatedAtUtc.Offset != TimeSpan.Zero
                || shard.ActivatedAtUtc < shard.CreatedAtUtc
                || shard.Status is not ("active" or "historical")
                || !Guid.TryParseExact(shard.StateId, "D", out _)
                || shard.StateId.Any(char.IsUpper))
            {
                throw new SigstoreStatusException(
                    $"The {shard.Slot} Rekor shard catalog entry is malformed.");
            }
        }

        var primary = catalog.Shards[0];
        if (primary.Slot != "primary"
            || primary.BaseUrl
                != "http://rekor-sigstore.dev.localhost:3000"
            || primary.Origin != "rekor-sigstore.dev.localhost"
            || primary.DataPath != "data/rekor"
            || primary.ResourceName != "rekor-server"
            || primary.StateId != trustDomain.RekorStateId
            || primary.CreatedAtUtc != trustDomain.CreatedAtUtc
            || primary.ActivatedAtUtc != trustDomain.CreatedAtUtc)
        {
            throw new SigstoreStatusException(
                "The primary Rekor shard does not match the trust domain.");
        }

        if (catalog.Shards.Count == 1)
        {
            if (catalog.ActiveShardId != primary.ShardId
                || primary.Status != "active"
                || generation.RekorRotationOperationId is not null
                || generation.RekorPublicKeySha256
                    != primary.PublicKeySha256)
            {
                throw new SigstoreStatusException(
                    "The single-shard Rekor catalog does not match the " +
                    "active generation.");
            }
            return;
        }

        var secondary = catalog.Shards[1];
        if (primary.Status != "historical"
            || secondary.Status != "active"
            || catalog.ActiveShardId != secondary.ShardId
            || secondary.Slot != "secondary"
            || secondary.BaseUrl
                != "http://rekor-secondary-sigstore.dev.localhost:3000"
            || secondary.Origin
                != "rekor-secondary-sigstore.dev.localhost"
            || secondary.DataPath != "data/rekor-shards/secondary"
            || secondary.ResourceName != "rekor-server-secondary"
            || generation.RekorRotationOperationId is null
            || generation.RekorPriorPublicKeySha256
                != primary.PublicKeySha256
            || generation.RekorPriorShardId != primary.ShardId
            || generation.RekorPriorBaseUrl != primary.BaseUrl
            || generation.RekorPublicKeySha256
                != secondary.PublicKeySha256
            || generation.RekorShardId != secondary.ShardId
            || generation.RekorBaseUrl != secondary.BaseUrl)
        {
            throw new SigstoreStatusException(
                "The rotated Rekor shard catalog does not match the active " +
                "generation.");
        }
    }

    private static void ValidateSecondaryRekorMetadata(
        string statePath,
        RekorShardCatalogEntryStatus shard,
        string operationId,
        string trustDomainId)
    {
        var metadata = DeserializeStrict<RekorShardMetadataStatus>(
            ReadRequiredBytes(
                Path.Combine(
                    statePath,
                    "data",
                    "rekor-shards",
                    "secondary",
                    "shard.json")),
            "secondary Rekor shard metadata");
        if (metadata.SchemaVersion != 1
            || metadata.OperationId != operationId
            || metadata.TrustDomainId != trustDomainId
            || metadata.ShardId != shard.ShardId
            || metadata.Slot != shard.Slot
            || metadata.BaseUrl != shard.BaseUrl
            || metadata.Origin != shard.Origin
            || metadata.PublicKeySha256 != shard.PublicKeySha256
            || metadata.LogIdSha256 != shard.LogIdSha256
            || metadata.StateId != shard.StateId
            || metadata.DataPath != shard.DataPath
            || metadata.ResourceName != shard.ResourceName
            || metadata.CreatedAtUtc != shard.CreatedAtUtc
            || metadata.ActivatedAtUtc != shard.ActivatedAtUtc
            || metadata.Status != shard.Status)
        {
            throw new SigstoreStatusException(
                "The secondary Rekor shard metadata does not match the catalog.");
        }
    }

    private static string ReadActiveRekorSigningConfigUrl(
        ReadOnlySpan<byte> payload)
    {
        try
        {
            using var document = JsonDocument.Parse(payload.ToArray());
            var services = document.RootElement
                .GetProperty("rekorTlogUrls")
                .EnumerateArray()
                .Where(
                    service => service
                        .GetProperty("majorApiVersion")
                        .GetInt32() == 2)
                .Select(
                    service => service.GetProperty("url").GetString())
                .ToArray();
            if (services is not [var selected]
                || !Uri.TryCreate(
                    selected,
                    UriKind.Absolute,
                    out var uri)
                || uri.Scheme is not ("http" or "https"))
            {
                throw new SigstoreStatusException(
                    "SigningConfig must select exactly one absolute Rekor v2 URL.");
            }
            return uri.AbsoluteUri.TrimEnd('/');
        }
        catch (Exception exception)
            when (exception is JsonException
                or InvalidOperationException
                or KeyNotFoundException)
        {
            throw new SigstoreStatusException(
                $"SigningConfig Rekor routing is malformed: {exception.Message}");
        }
    }

    private static byte[] ReadRekorSpki(string path)
    {
        using var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(
                Encoding.UTF8.GetString(ReadRequiredBytes(path)));
        }
        catch (CryptographicException exception)
        {
            throw new SigstoreStatusException(
                $"Rekor public key '{path}' is malformed: {exception.Message}");
        }
        if (key.KeySize != 256)
        {
            throw new SigstoreStatusException(
                $"Rekor public key '{path}' is not ECDSA P-256.");
        }
        return key.ExportSubjectPublicKeyInfo();
    }

    private static async Task<byte[]> ReadGatewayBytesAsync(
        HttpClient client,
        Uri gateway,
        string relativePath,
        string host,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(gateway, relativePath));
        request.Headers.Host = host;
        using var response = await client.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new SigstoreStatusException(
                $"{host}/{relativePath} returned HTTP " +
                $"{(int)response.StatusCode}.");
        }
        var payload = await response.Content.ReadAsByteArrayAsync(
            cancellationToken);
        if (payload.Length is 0 or > MaximumStatusBytes)
        {
            throw new SigstoreStatusException(
                $"{host}/{relativePath} returned an invalid payload length.");
        }
        return payload;
    }

    private static async Task ProbeGatewayAsync(
        HttpClient client,
        Uri gateway,
        string relativePath,
        string host,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(gateway, relativePath));
        request.Headers.Host = host;
        using var response = await client.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new SigstoreStatusException(
                $"{host}/{relativePath} returned HTTP " +
                $"{(int)response.StatusCode}.");
        }
    }

    private static async Task<byte[]> ReadHttpBytesAsync(
        HttpClient client,
        Uri uri,
        CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync(
            uri,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new SigstoreStatusException(
                $"{uri} returned HTTP {(int)response.StatusCode}.");
        }
        var length = response.Content.Headers.ContentLength;
        if (length > MaximumStatusBytes)
        {
            throw new SigstoreStatusException(
                $"{uri} exceeded {MaximumStatusBytes} bytes.");
        }
        var payload = await response.Content.ReadAsByteArrayAsync(
            cancellationToken);
        if (payload.Length is 0 or > MaximumStatusBytes)
        {
            throw new SigstoreStatusException(
                $"{uri} returned an invalid payload length.");
        }
        return payload;
    }

    private static T DeserializeStrict<T>(
        ReadOnlySpan<byte> payload,
        string description)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(
                    payload,
                    StrictJsonOptions)
                ?? throw new SigstoreStatusException(
                    $"{description} is empty.");
        }
        catch (JsonException exception)
        {
            throw new SigstoreStatusException(
                $"{description} is malformed: {exception.Message}");
        }
    }

    private static void ValidateGenerationFiles(
        string generationPath,
        SortedDictionary<string, string> expected)
    {
        EnsureOnlyEntries(
            generationPath,
            ["manifest.json", "private", "public"],
            "active generation");
        var actual = new SortedDictionary<string, string>(
            StringComparer.Ordinal);
        foreach (var directoryName in new[] { "private", "public" })
        {
            var directoryPath = Path.Combine(
                generationPath,
                directoryName);
            var directory = new DirectoryInfo(directoryPath);
            if (!directory.Exists || directory.LinkTarget is not null)
            {
                throw new SigstoreStatusException(
                    $"Generation directory '{directoryName}' is missing or linked.");
            }

            foreach (var file in Directory.EnumerateFiles(
                directoryPath,
                "*",
                SearchOption.AllDirectories))
            {
                var info = new FileInfo(file);
                if (info.LinkTarget is not null)
                {
                    throw new SigstoreStatusException(
                        $"Generation file '{file}' is a symbolic link.");
                }
                var relative = Path.GetRelativePath(
                        generationPath,
                        file)
                    .Replace(Path.DirectorySeparatorChar, '/');
                actual.Add(
                    relative,
                    Hash(ReadRequiredBytes(file)));
            }
        }

        if (expected.Any(
                pair => !IsLowerHexSha256(pair.Value))
            || !DictionariesEqual(actual, expected))
        {
            throw new SigstoreStatusException(
                "The active generation file set does not match its manifest.");
        }
    }

    private static bool TrustDomainsEqual(
        TrustDomainManifestStatus first,
        TrustDomainManifestStatus second) =>
        first.SchemaVersion == second.SchemaVersion
        && first.TrustDomainId == second.TrustDomainId
        && first.CreatedAtUtc == second.CreatedAtUtc
        && first.CtLogStateId == second.CtLogStateId
        && first.RekorStateId == second.RekorStateId;

    private static bool GenerationManifestsEqual(
        GenerationManifestStatus first,
        GenerationManifestStatus second) =>
        first.SchemaVersion == second.SchemaVersion
        && first.Generation == second.Generation
        && first.GenerationId == second.GenerationId
        && first.TrustDomainId == second.TrustDomainId
        && first.CreatedAtUtc == second.CreatedAtUtc
        && first.SourceSchemaVersion == second.SourceSchemaVersion
        && first.SourceManifestSha256 == second.SourceManifestSha256
        && first.FulcioRootSha256 == second.FulcioRootSha256
        && first.FulcioRotationOperationId
            == second.FulcioRotationOperationId
        && first.FulcioPriorGeneration
            == second.FulcioPriorGeneration
        && first.FulcioPriorGenerationId
            == second.FulcioPriorGenerationId
        && first.FulcioPriorRootSha256
            == second.FulcioPriorRootSha256
        && first.CtLogPublicKeySha256 == second.CtLogPublicKeySha256
        && first.RekorPublicKeySha256 == second.RekorPublicKeySha256
        && first.TsaRootSha256 == second.TsaRootSha256
        && first.TsaLeafSha256 == second.TsaLeafSha256
        && first.OidcKeyId == second.OidcKeyId
        && first.OidcRotationOperationId
            == second.OidcRotationOperationId
        && first.OidcPriorGeneration == second.OidcPriorGeneration
        && first.OidcPriorGenerationId
            == second.OidcPriorGenerationId
        && first.OidcPriorKeyId == second.OidcPriorKeyId
        && first.OidcOverlapExpiresAtUtc
            == second.OidcOverlapExpiresAtUtc
        && (first.OidcRetainedPrivateKeyPaths ?? [])
            .SequenceEqual(
                second.OidcRetainedPrivateKeyPaths ?? [],
                StringComparer.Ordinal)
        && first.TsaRotationOperationId
            == second.TsaRotationOperationId
        && first.TsaPriorGeneration == second.TsaPriorGeneration
        && first.TsaPriorGenerationId
            == second.TsaPriorGenerationId
        && first.TsaPriorRootSha256
            == second.TsaPriorRootSha256
        && first.TsaPriorLeafSha256
            == second.TsaPriorLeafSha256
        && first.RekorRotationOperationId
            == second.RekorRotationOperationId
        && first.RekorPriorGeneration
            == second.RekorPriorGeneration
        && first.RekorPriorGenerationId
            == second.RekorPriorGenerationId
        && first.RekorPriorPublicKeySha256
            == second.RekorPriorPublicKeySha256
        && first.RekorPriorShardId
            == second.RekorPriorShardId
        && first.RekorPriorBaseUrl
            == second.RekorPriorBaseUrl
        && first.RekorShardId
            == second.RekorShardId
        && first.RekorBaseUrl
            == second.RekorBaseUrl
        && first.CtLogRotationOperationId
            == second.CtLogRotationOperationId
        && first.CtLogPriorGeneration
            == second.CtLogPriorGeneration
        && first.CtLogPriorGenerationId
            == second.CtLogPriorGenerationId
        && first.CtLogPriorPublicKeySha256
            == second.CtLogPriorPublicKeySha256
        && first.CtLogPriorShardId
            == second.CtLogPriorShardId
        && first.CtLogPriorBaseUrl
            == second.CtLogPriorBaseUrl
        && first.CtLogShardId
            == second.CtLogShardId
        && first.CtLogBaseUrl
            == second.CtLogBaseUrl
        && DictionariesEqual(first.Files, second.Files);

    internal static void ValidateFulcioRotationMetadata(
        GenerationManifestStatus generation)
    {
        if (generation.FulcioRotationOperationId is null)
        {
            if (generation.FulcioPriorGeneration != 0
                || generation.FulcioPriorGenerationId is not null
                || generation.FulcioPriorRootSha256 is not null)
            {
                throw new SigstoreStatusException(
                    "The active generation has partial Fulcio rotation metadata.");
            }
            return;
        }
        if (!Guid.TryParseExact(
                generation.FulcioRotationOperationId,
                "N",
                out _)
            || generation.FulcioRotationOperationId.Any(char.IsUpper)
            || generation.FulcioPriorGeneration < 1
            || generation.FulcioPriorGeneration >= generation.Generation
            || generation.FulcioPriorGenerationId
                != $"generation-{generation.FulcioPriorGeneration:D8}"
            || !IsLowerHexSha256(
                generation.FulcioPriorRootSha256 ?? "")
            || generation.FulcioPriorRootSha256
                == generation.FulcioRootSha256)
        {
            throw new SigstoreStatusException(
                "The active generation has invalid Fulcio rotation metadata.");
        }
    }

    private static void ValidateTimestampRotationMetadata(
        GenerationManifestStatus generation)
    {
        if (generation.TsaRotationOperationId is null)
        {
            if (generation.TsaPriorGeneration != 0
                || generation.TsaPriorGenerationId is not null
                || generation.TsaPriorRootSha256 is not null
                || generation.TsaPriorLeafSha256 is not null)
            {
                throw new SigstoreStatusException(
                    "The active generation has partial TSA rotation metadata.");
            }

            return;
        }
        if (!Guid.TryParseExact(
                generation.TsaRotationOperationId,
                "N",
                out _)
            || generation.TsaRotationOperationId.Any(char.IsUpper)
            || generation.TsaPriorGeneration < 1
            || generation.TsaPriorGeneration >= generation.Generation
            || generation.TsaPriorGenerationId
                != $"generation-{generation.TsaPriorGeneration:D8}"
            || !IsLowerHexSha256(
                generation.TsaPriorRootSha256 ?? "")
            || !IsLowerHexSha256(
                generation.TsaPriorLeafSha256 ?? "")
            || generation.TsaPriorRootSha256
                == generation.TsaRootSha256
            || generation.TsaPriorLeafSha256
                == generation.TsaLeafSha256)
        {
            throw new SigstoreStatusException(
                "The active generation has invalid TSA rotation metadata.");
        }
    }

    internal static void ValidateRekorRotationMetadata(
        GenerationManifestStatus generation)
    {
        if (generation.RekorRotationOperationId is null)
        {
            if (generation.RekorPriorGeneration != 0
                || generation.RekorPriorGenerationId is not null
                || generation.RekorPriorPublicKeySha256 is not null
                || generation.RekorPriorShardId is not null
                || generation.RekorPriorBaseUrl is not null
                || generation.RekorShardId is not null
                || generation.RekorBaseUrl is not null)
            {
                throw new SigstoreStatusException(
                    "The active generation has partial Rekor shard rotation metadata.");
            }
            return;
        }

        if (!Guid.TryParseExact(
                generation.RekorRotationOperationId,
                "N",
                out _)
            || generation.RekorRotationOperationId.Any(char.IsUpper)
            || generation.RekorPriorGeneration < 1
            || generation.RekorPriorGeneration >= generation.Generation
            || generation.RekorPriorGenerationId
                != $"generation-{generation.RekorPriorGeneration:D8}"
            || !IsLowerHexSha256(
                generation.RekorPriorPublicKeySha256 ?? "")
            || generation.RekorPriorPublicKeySha256
                == generation.RekorPublicKeySha256
            || generation.RekorPriorShardId
                != $"sha256-{generation.RekorPriorPublicKeySha256}"
            || generation.RekorPriorBaseUrl
                != "http://rekor-sigstore.dev.localhost:3000"
            || generation.RekorShardId
                != $"sha256-{generation.RekorPublicKeySha256}"
            || generation.RekorBaseUrl
                != "http://rekor-secondary-sigstore.dev.localhost:3000")
        {
            throw new SigstoreStatusException(
                "The active generation has invalid Rekor shard rotation metadata.");
        }
    }

    private static void ValidateCtLogRotationMetadata(
        GenerationManifestStatus generation)
    {
        if (generation.CtLogRotationOperationId is null)
        {
            if (generation.CtLogPriorGeneration != 0
                || generation.CtLogPriorGenerationId is not null
                || generation.CtLogPriorPublicKeySha256 is not null
                || generation.CtLogPriorShardId is not null
                || generation.CtLogPriorBaseUrl is not null
                || generation.CtLogShardId is not null
                || generation.CtLogBaseUrl is not null)
            {
                throw new SigstoreStatusException(
                    "The active generation has partial CT log shard rotation " +
                    "metadata.");
            }
            return;
        }

        if (!Guid.TryParseExact(
                generation.CtLogRotationOperationId,
                "N",
                out _)
            || generation.CtLogRotationOperationId.Any(char.IsUpper)
            || generation.CtLogPriorGeneration
                != generation.Generation - 1
            || generation.CtLogPriorGenerationId
                != $"generation-{generation.CtLogPriorGeneration:D8}"
            || !IsLowerHexSha256(
                generation.CtLogPriorPublicKeySha256 ?? "")
            || generation.CtLogPriorPublicKeySha256
                == generation.CtLogPublicKeySha256
            || generation.CtLogPriorShardId
                != $"sha256-{generation.CtLogPriorPublicKeySha256}"
            || generation.CtLogPriorBaseUrl
                != "http://tesseract-sigstore.dev.localhost:6962"
            || generation.CtLogShardId
                != $"sha256-{generation.CtLogPublicKeySha256}"
            || generation.CtLogBaseUrl
                != "http://tesseract-secondary-sigstore.dev.localhost:6963")
        {
            throw new SigstoreStatusException(
                "The active generation has invalid CT log shard rotation " +
                "metadata.");
        }
    }

    private static void ValidatePublicationReference(
        PublicationReferenceStatus reference,
        string description)
    {
        if (!IsLowerHexSha256(reference.ManifestSha256)
            || reference.Id
                != $"sha256-{reference.ManifestSha256}")
        {
            throw new SigstoreStatusException(
                $"The {description} TUF publication reference is invalid.");
        }
    }

    private static void ValidateTufLayout(
        string tufPath,
        PublicationStateStatus publication,
        string sourceFingerprint)
    {
        EnsureOnlyEntries(
            tufPath,
            [
                "active",
                "bootstrap",
                "committed",
                "history",
                "publication",
                "staging"
            ],
            "stable TUF parent");
        EnsureOnlyEntries(
            Path.Combine(tufPath, "bootstrap"),
            ["root.json"],
            "immutable TUF bootstrap");
        EnsureOnlyEntries(
            Path.Combine(tufPath, "committed"),
            [publication.Active!.Id],
            "committed TUF directory");
        EnsureOnlyEntries(
            Path.Combine(tufPath, "staging"),
            [],
            "TUF staging directory");
        EnsureOnlyEntries(
            Path.Combine(tufPath, "publication"),
            ["state.json"],
            "TUF publication directory");

        var historyPath = Path.Combine(tufPath, "history");
        if (publication.Previous is null)
        {
            EnsureOnlyEntries(
                historyPath,
                [],
                "TUF history directory");
            return;
        }

        EnsureOnlyEntries(
            historyPath,
            ["previous"],
            "TUF history directory");
        ValidateTufReference(
            Path.Combine(historyPath, "previous"),
            publication.Previous,
            null,
            "previous");
    }

    private static void ValidateTufReference(
        string path,
        PublicationReferenceStatus reference,
        string? sourceFingerprint,
        string description)
    {
        var manifestBytes = ReadRequiredBytes(
            Path.Combine(path, "manifest.json"));
        if (Hash(manifestBytes) != reference.ManifestSha256)
        {
            throw new SigstoreStatusException(
                $"The {description} TUF manifest hash is invalid.");
        }
        var manifest = DeserializeRequired<TufManifestStatus>(
            manifestBytes,
            $"{description} TUF manifest");
        if (manifest.SchemaVersion != TufManifestSchemaVersion
            || (sourceFingerprint is not null
                && manifest.SourceFingerprint != sourceFingerprint))
        {
            throw new SigstoreStatusException(
                $"The {description} TUF manifest is inconsistent.");
        }
        ValidateTufManifest(path, manifest);
    }

    private static void EnsureOnlyEntries(
        string directory,
        IEnumerable<string> expectedNames,
        string description)
    {
        var info = new DirectoryInfo(directory);
        if (!info.Exists || info.LinkTarget is not null)
        {
            throw new SigstoreStatusException(
                $"The {description} is missing or linked.");
        }
        var expected = expectedNames.ToHashSet(StringComparer.Ordinal);
        var actual = Directory.EnumerateFileSystemEntries(directory)
            .Select(Path.GetFileName)
            .ToHashSet(StringComparer.Ordinal);
        if (!actual.SetEquals(expected))
        {
            throw new SigstoreStatusException(
                $"The {description} has an unexpected file set.");
        }
    }

    private static void ValidateTufManifest(
        string activePath,
        TufManifestStatus manifest)
    {
        if (manifest.SchemaVersion != TufManifestSchemaVersion
            || manifest.Files is null)
        {
            throw new SigstoreStatusException(
                "The active TUF manifest is invalid.");
        }

        var actual = new SortedDictionary<string, string>(
            StringComparer.Ordinal);
        foreach (var file in Directory.EnumerateFiles(
            activePath,
            "*",
            SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(activePath, file)
                .Replace(Path.DirectorySeparatorChar, '/');
            if (relative == "manifest.json")
            {
                continue;
            }
            if (new FileInfo(file).LinkTarget is not null)
            {
                throw new SigstoreStatusException(
                    $"TUF file '{relative}' is a symbolic link.");
            }
            actual.Add(relative, Hash(ReadRequiredBytes(file)));
        }

        if (actual.Count != manifest.Files.Count
            || actual.Any(
                pair => !manifest.Files.TryGetValue(
                        pair.Key,
                        out var expected)
                    || expected != pair.Value))
        {
            throw new SigstoreStatusException(
                "The active TUF file set does not match its manifest.");
        }
    }

    private static bool DictionariesEqual(
        IReadOnlyDictionary<string, string> first,
        IReadOnlyDictionary<string, string> second) =>
        first.Count == second.Count
        && first.All(
            pair => second.TryGetValue(
                    pair.Key,
                    out var value)
                && value == pair.Value);

    private static void ValidatePublishedStatus(
        PublishedTrustStatus status,
        string trustDomainId,
        int generation,
        string generationId,
        string generationManifestHash,
        int rootVersion,
        int targetsVersion,
        string trustedRootHash,
        string signingConfigHash)
    {
        ValidateCommonStatus(
            status.TrustDomainId,
            status.Generation,
            status.GenerationId,
            status.GenerationManifestSha256,
            status.TufRootVersion,
            status.TufTargetsVersion,
            status.TrustedRootSha256,
            status.SigningConfigSha256);
        if (status.SchemaVersion != StatusSchemaVersion
            || status.TrustDomainId != trustDomainId
            || status.Generation != generation
            || status.GenerationId != generationId
            || status.GenerationManifestSha256
                != generationManifestHash
            || status.TufRootVersion != rootVersion
            || status.TufTargetsVersion != targetsVersion
            || status.TrustedRootSha256 != trustedRootHash
            || status.SigningConfigSha256 != signingConfigHash)
        {
            throw new SigstoreStatusException(
                "Published trust status does not match the initialized material.");
        }
    }

    private static void ValidateCommonStatus(
        string trustDomainId,
        int generation,
        string generationId,
        string generationManifestHash,
        int rootVersion,
        int targetsVersion,
        string trustedRootHash,
        string signingConfigHash)
    {
        if (string.IsNullOrWhiteSpace(trustDomainId)
            || generation <= 0
            || string.IsNullOrWhiteSpace(generationId)
            || rootVersion <= 0
            || targetsVersion <= 0
            || !IsLowerHexSha256(generationManifestHash)
            || !IsLowerHexSha256(trustedRootHash)
            || !IsLowerHexSha256(signingConfigHash))
        {
            throw new SigstoreStatusException(
                "Trust status contains invalid identity, version, or hash values.");
        }
    }

    private static void AddMismatchErrors(
        string source,
        SigstoreDiskTrustStatus disk,
        SigstoreServedTrustStatus status,
        ICollection<SigstoreStatusError> errors) =>
        AddMismatchErrors(
            source,
            disk,
            status.TrustDomainId,
            status.Generation,
            status.GenerationId,
            status.GenerationManifestSha256,
            status.TufRootVersion,
            status.TufTargetsVersion,
            status.TrustedRootSha256,
            status.SigningConfigSha256,
            errors);

    private static void AddMismatchErrors(
        string source,
        SigstoreDiskTrustStatus disk,
        SigstoreClientTrustStatus status,
        ICollection<SigstoreStatusError> errors) =>
        AddMismatchErrors(
            source,
            disk,
            status.TrustDomainId,
            status.Generation,
            status.GenerationId,
            status.GenerationManifestSha256,
            status.TufRootVersion,
            status.TufTargetsVersion,
            status.TrustedRootSha256,
            status.SigningConfigSha256,
            errors);

    private static void AddMismatchErrors(
        string source,
        SigstoreDiskTrustStatus disk,
        string trustDomainId,
        int generation,
        string generationId,
        string generationManifestHash,
        int rootVersion,
        int targetsVersion,
        string trustedRootHash,
        string signingConfigHash,
        ICollection<SigstoreStatusError> errors)
    {
        AddIfDifferent(
            source,
            "trustDomainId",
            disk.TrustDomainId,
            trustDomainId,
            errors);
        AddIfDifferent(
            source,
            "generation",
            disk.Generation,
            generation,
            errors);
        AddIfDifferent(
            source,
            "generationId",
            disk.GenerationId,
            generationId,
            errors);
        AddIfDifferent(
            source,
            "generationManifestSha256",
            disk.GenerationManifestSha256,
            generationManifestHash,
            errors);
        AddIfDifferent(
            source,
            "tufRootVersion",
            disk.TufRootVersion,
            rootVersion,
            errors);
        AddIfDifferent(
            source,
            "tufTargetsVersion",
            disk.TufTargetsVersion,
            targetsVersion,
            errors);
        AddIfDifferent(
            source,
            "trustedRootSha256",
            disk.TrustedRootSha256,
            trustedRootHash,
            errors);
        AddIfDifferent(
            source,
            "signingConfigSha256",
            disk.SigningConfigSha256,
            signingConfigHash,
            errors);
    }

    private static void AddIfDifferent<T>(
        string source,
        string field,
        T expected,
        T actual,
        ICollection<SigstoreStatusError> errors)
        where T : notnull
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            errors.Add(
                new(
                    source,
                    $"{field} is '{actual}', expected '{expected}'."));
        }
    }

    private static T DeserializeRequired<T>(
        ReadOnlySpan<byte> payload,
        string description)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(
                    payload,
                    JsonOptions)
                ?? throw new SigstoreStatusException(
                    $"{description} is empty.");
        }
        catch (JsonException exception)
        {
            throw new SigstoreStatusException(
                $"{description} is malformed: {exception.Message}");
        }
    }

    private static int ReadMetadataVersion(
        string path,
        string role) =>
        ReadMetadataVersion(ReadRequiredBytes(path), role);

    private static int ReadMetadataVersion(
        ReadOnlySpan<byte> payload,
        string role)
    {
        try
        {
            using var document = JsonDocument.Parse(payload.ToArray());
            var version = document.RootElement
                .GetProperty("signed")
                .GetProperty("version")
                .GetInt32();
            if (version <= 0)
            {
                throw new SigstoreStatusException(
                    $"{role} metadata has invalid version {version}.");
            }
            return version;
        }
        catch (Exception exception)
            when (exception is JsonException
                or InvalidOperationException
                or KeyNotFoundException)
        {
            throw new SigstoreStatusException(
                $"{role} metadata is malformed: {exception.Message}");
        }
    }

    private static SigstoreTufMetadataStatus ReadTufMetadataStatus(
        byte[] root,
        byte[] targets,
        byte[] snapshot,
        byte[] timestamp,
        byte[] trustedRoot,
        byte[] signingConfig)
    {
        var rootStatus = ReadMetadataRoleStatus(root, "root");
        var targetsStatus = ReadMetadataRoleStatus(targets, "targets");
        var snapshotStatus = ReadMetadataRoleStatus(snapshot, "snapshot");
        var timestampStatus = ReadMetadataRoleStatus(timestamp, "timestamp");
        ValidateMetadataReference(
            timestamp,
            "timestamp",
            "snapshot.json",
            snapshot,
            snapshotStatus);
        ValidateMetadataReference(
            snapshot,
            "snapshot",
            "targets.json",
            targets,
            targetsStatus);

        return new SigstoreTufMetadataStatus(
            rootStatus,
            targetsStatus,
            snapshotStatus,
            timestampStatus,
            Hash(trustedRoot),
            Hash(signingConfig));
    }

    private static SigstoreTufMetadataRoleStatus ReadMetadataRoleStatus(
        ReadOnlySpan<byte> payload,
        string role)
    {
        try
        {
            using var document = JsonDocument.Parse(payload.ToArray());
            var signed = document.RootElement.GetProperty("signed");
            var version = signed.GetProperty("version").GetInt32();
            var expires = signed
                .GetProperty("expires")
                .GetDateTimeOffset();
            if (version <= 0 || expires == default)
            {
                throw new SigstoreStatusException(
                    $"{role} metadata has an invalid version or expiration.");
            }

            return new SigstoreTufMetadataRoleStatus(
                version,
                Hash(payload),
                expires);
        }
        catch (Exception exception)
            when (exception is JsonException
                or InvalidOperationException
                or KeyNotFoundException
                or FormatException)
        {
            throw new SigstoreStatusException(
                $"{role} metadata is malformed: {exception.Message}");
        }
    }

    private static void ValidateMetadataReference(
        ReadOnlySpan<byte> parentPayload,
        string parentRole,
        string childName,
        ReadOnlySpan<byte> childPayload,
        SigstoreTufMetadataRoleStatus child)
    {
        try
        {
            using var document = JsonDocument.Parse(
                parentPayload.ToArray());
            var reference = document.RootElement
                .GetProperty("signed")
                .GetProperty("meta")
                .GetProperty(childName);
            var expectedVersion = reference
                .GetProperty("version")
                .GetInt32();
            var expectedLength = reference
                .GetProperty("length")
                .GetInt64();
            if (expectedVersion != child.Version
                || expectedLength != childPayload.Length)
            {
                throw new SigstoreStatusException(
                    $"{parentRole} metadata does not bind the current " +
                    $"{childName} bytes.");
            }

            var supportedHashCount = 0;
            foreach (var hash in reference
                .GetProperty("hashes")
                .EnumerateObject())
            {
                var actual = hash.Name switch
                {
                    "sha256" => Hash(childPayload),
                    "sha512" => HashSha512(childPayload),
                    _ => null
                };
                if (actual is null)
                {
                    continue;
                }

                supportedHashCount++;
                if (hash.Value.GetString() != actual)
                {
                    throw new SigstoreStatusException(
                        $"{parentRole} metadata has an invalid {hash.Name} " +
                        $"hash for {childName}.");
                }
            }
            if (supportedHashCount == 0)
            {
                throw new SigstoreStatusException(
                    $"{parentRole} metadata has no supported hash for " +
                    $"{childName}.");
            }
        }
        catch (Exception exception)
            when (exception is JsonException
                or InvalidOperationException
                or KeyNotFoundException)
        {
            throw new SigstoreStatusException(
                $"{parentRole} metadata reference for {childName} is " +
                $"malformed: {exception.Message}");
        }
    }

    private static void CollectFingerprintEntry(
        string rootPath,
        string path,
        IDictionary<string, string> entries)
    {
        var directory = new DirectoryInfo(path);
        if (directory.LinkTarget is not null)
        {
            entries.Add(
                NormalizeRelativePath(rootPath, path),
                $"link:{directory.LinkTarget}");
            return;
        }
        if (directory.Exists)
        {
            entries.Add(
                NormalizeRelativePath(rootPath, path) + "/",
                "directory");
            foreach (var child in Directory
                .EnumerateFileSystemEntries(path)
                .Order(StringComparer.Ordinal))
            {
                CollectFingerprintEntry(rootPath, child, entries);
            }
            return;
        }

        var file = new FileInfo(path);
        if (file.LinkTarget is not null)
        {
            entries.Add(
                NormalizeRelativePath(rootPath, path),
                $"link:{file.LinkTarget}");
            return;
        }
        if (!file.Exists)
        {
            throw new FileNotFoundException(
                $"Required trust-state entry '{path}' does not exist.",
                path);
        }

        entries.Add(
            NormalizeRelativePath(rootPath, path),
            $"file:{Hash(ReadRequiredBytes(path))}");
    }

    private static string NormalizeRelativePath(
        string rootPath,
        string path) =>
        Path.GetRelativePath(rootPath, path)
            .Replace(Path.DirectorySeparatorChar, '/');

    private static string HashNamedValues(
        IEnumerable<KeyValuePair<string, string>> values)
    {
        var contents = string.Concat(
            values
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(
                    pair => $"{pair.Key}\t{pair.Value}\n"));
        return Hash(Encoding.UTF8.GetBytes(contents));
    }

    internal static bool IsRefreshableMetadataPath(string path)
    {
        const string repositoryPrefix = "repository/";
        if (!path.StartsWith(
                repositoryPrefix,
                StringComparison.Ordinal))
        {
            return false;
        }

        var fileName = path[repositoryPrefix.Length..];
        if (fileName.Contains('/', StringComparison.Ordinal))
        {
            return false;
        }
        return fileName.Equals(
                "snapshot.json",
                StringComparison.Ordinal)
            || fileName.Equals(
                "timestamp.json",
                StringComparison.Ordinal)
            || IsVersionedRole(fileName, ".snapshot.json")
            || IsVersionedRole(fileName, ".timestamp.json");

        static bool IsVersionedRole(
            string fileName,
            string suffix)
        {
            if (!fileName.EndsWith(suffix, StringComparison.Ordinal))
            {
                return false;
            }
            var version = fileName[..^suffix.Length];
            return version.Length > 0
                && version.All(char.IsAsciiDigit);
        }
    }

    private static string ReadRequiredLink(string path)
    {
        var directory = new DirectoryInfo(path);
        directory.Refresh();
        var target = directory.LinkTarget;
        if (string.IsNullOrWhiteSpace(target)
            || Path.IsPathFullyQualified(target))
        {
            throw new SigstoreStatusException(
                $"Required link '{path}' is missing or unsafe.");
        }
        return Path.TrimEndingDirectorySeparator(target);
    }

    private static byte[] ReadRequiredBytes(string path)
    {
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length is 0 or > MaximumStatusBytes * 32)
        {
            throw new SigstoreStatusException(
                $"File '{path}' has an invalid length.");
        }
        return bytes;
    }

    private static bool IsLowerHexSha256(string value) =>
        value is { Length: 64 }
        && value.All(
            character => character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static string Hash(ReadOnlySpan<byte> payload) =>
        Convert.ToHexString(SHA256.HashData(payload))
            .ToLowerInvariant();

    private static string HashSha512(ReadOnlySpan<byte> payload) =>
        Convert.ToHexString(SHA512.HashData(payload))
            .ToLowerInvariant();

    private static Uri EnsureTrailingSlash(Uri uri) =>
        uri.AbsolutePath.EndsWith(
            "/",
            StringComparison.Ordinal)
            ? uri
            : new Uri(uri.AbsoluteUri + "/", UriKind.Absolute);

    private static bool PathsEqual(string first, string second) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(first),
            Path.TrimEndingDirectorySeparator(second),
            OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal);

    private static bool IsExpectedStatusFailure(Exception exception) =>
        exception is SigstoreStatusException
            or IOException
            or UnauthorizedAccessException
            or HttpRequestException
            or TaskCanceledException
            or UriFormatException
            or InvalidDataException
            or CryptographicException
            or JsonException
            or KeyNotFoundException
            or FormatException;

    private sealed record ClientStatusResult(
        string Source,
        SigstoreClientTrustStatus? Status,
        SigstoreStatusError? Error);
}
