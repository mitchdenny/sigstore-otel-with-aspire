using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
    IReadOnlyList<SigstoreStatusError> Errors);

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
    string CtLogPublicKeySha256,
    string RekorPublicKeySha256,
    string TsaRootSha256,
    string TsaLeafSha256,
    string OidcKeyId,
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

        if (runtime.State != "Healthy")
        {
            errors.Add(
                new(
                    "resources",
                    runtime.Reason
                        ?? $"Parent resource state is {runtime.State}."));
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
            && clients.Count == registrations.Clients.Count;
        var reason = errors.Count == 0
            ? null
            : $"{errors[0].Source}: {errors[0].Message}";

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
            errors);
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
            || generationManifest.CreatedAtUtc
                != trustDomain.CreatedAtUtc
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
            || transition.PriorGeneration is not null
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
                != generationManifestHash)
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
        && first.CtLogPublicKeySha256 == second.CtLogPublicKeySha256
        && first.RekorPublicKeySha256 == second.RekorPublicKeySha256
        && first.TsaRootSha256 == second.TsaRootSha256
        && first.TsaLeafSha256 == second.TsaLeafSha256
        && first.OidcKeyId == second.OidcKeyId
        && DictionariesEqual(first.Files, second.Files);

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
            sourceFingerprint,
            "previous");
    }

    private static void ValidateTufReference(
        string path,
        PublicationReferenceStatus reference,
        string sourceFingerprint,
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
            || manifest.SourceFingerprint != sourceFingerprint)
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
            or UriFormatException;

    private sealed record ClientStatusResult(
        string Source,
        SigstoreClientTrustStatus? Status,
        SigstoreStatusError? Error);
}
