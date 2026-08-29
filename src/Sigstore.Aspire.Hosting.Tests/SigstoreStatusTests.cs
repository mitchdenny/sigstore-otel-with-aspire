using System.Security.Cryptography;
using System.Text.Json;
using Aspire.Hosting.ApplicationModel;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Xunit;

namespace Sigstore.Aspire.Hosting.Tests;

public sealed class SigstoreStatusTests
{
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        };

    [Fact]
    public void ParentHealthDegradesAndRecoversWithARequiredResource()
    {
        var names = new HashSet<string>(
            ["dotnet-client", "tuf"],
            StringComparer.Ordinal);
        var healthy = new Dictionary<string, SigstoreObservedResource>(
            StringComparer.Ordinal)
        {
            ["dotnet-client"] = new(
                KnownResourceStates.Running,
                HealthStatus.Healthy),
            ["tuf"] = new(
                KnownResourceStates.Running,
                HealthStatus.Healthy)
        };

        var initial = SigstoreParentHealthMonitor.Evaluate(
            names,
            healthy,
            wasHealthy: false);

        Assert.Equal("Healthy", initial.State);
        healthy["dotnet-client"] = new(
            KnownResourceStates.Exited,
            null);

        var degraded = SigstoreParentHealthMonitor.Evaluate(
            names,
            healthy,
            wasHealthy: true);

        Assert.Equal("Degraded", degraded.State);
        Assert.Equal(
            "dotnet-client is Exited (health Unknown).",
            degraded.Reason);
        healthy["dotnet-client"] = new(
            KnownResourceStates.Running,
            HealthStatus.Healthy);

        var recovered = SigstoreParentHealthMonitor.Evaluate(
            names,
            healthy,
            wasHealthy: true);

        Assert.Equal("Healthy", recovered.State);
        Assert.Null(recovered.Reason);
    }

    [Fact]
    public void ParentHealthPrioritizesFailureOverWaitingResource()
    {
        var names = new HashSet<string>(
            ["a-waiting", "z-failed"],
            StringComparer.Ordinal);
        var observed = new Dictionary<string, SigstoreObservedResource>(
            StringComparer.Ordinal)
        {
            ["a-waiting"] = new(
                KnownResourceStates.Waiting,
                null),
            ["z-failed"] = new(
                KnownResourceStates.FailedToStart,
                null)
        };

        var status = SigstoreParentHealthMonitor.Evaluate(
            names,
            observed,
            wasHealthy: false);

        Assert.Equal("Degraded", status.State);
        Assert.StartsWith("z-failed", status.Reason);
    }

    [Fact]
    public void HistoricalRekorWriterDoesNotDegradeActiveShardHealth()
    {
        var parent = new SigstoreResource(
            "sigstore",
            "/tmp/sigstore",
            "/tmp/source");
        var primary = new ContainerResource("rekor-server");
        var secondary = new ContainerResource("rekor-server-secondary");
        parent.RegisterRequiredResource(primary);
        parent.RegisterConditionalResource(secondary);
        parent.ActivateConditionalResource(secondary);
        parent.MarkResourceHistorical(primary);

        var registrations = parent.GetRegistrations();
        var requiredNames = registrations.RequiredResources
            .Select(resource => resource.Name)
            .Concat(
                registrations.ConditionalResources
                    .Where(
                        resource => parent.IsConditionalResourceActive(
                            resource.Name))
                    .Select(resource => resource.Name))
            .ToHashSet(StringComparer.Ordinal);
        var observed = new Dictionary<string, SigstoreObservedResource>(
            StringComparer.Ordinal)
        {
            [primary.Name] = new(
                KnownResourceStates.Exited,
                null),
            [secondary.Name] = new(
                KnownResourceStates.Running,
                HealthStatus.Healthy)
        };

        var status = SigstoreParentHealthMonitor.Evaluate(
            requiredNames,
            observed,
            wasHealthy: true);

        Assert.Equal("Healthy", status.State);
        Assert.Equal([secondary.Name], requiredNames);
        Assert.False(parent.IsConditionalResourceActive(primary.Name));
    }

    [Fact]
    public void ClientStatusParserRejectsIdentityAndHashErrors()
    {
        var resource = new ContainerResource("go-client");
        var registration = new SigstoreClientRegistration(
            "go",
            resource,
            null!);
        var status = NewClientStatus("go-client", "go");
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            status,
            JsonOptions);

        Assert.Equal(
            status,
            SigstoreStatusCommand.ParseClientStatus(
                payload,
                registration));

        var wrongIdentity = status with
        {
            Resource = "python-client"
        };
        Assert.Throws<SigstoreStatusException>(
            () => SigstoreStatusCommand.ParseClientStatus(
                JsonSerializer.SerializeToUtf8Bytes(
                    wrongIdentity,
                    JsonOptions),
                registration));

        var wrongHash = status with
        {
            TrustedRootSha256 = new string('A', 64)
        };
        Assert.Throws<SigstoreStatusException>(
            () => SigstoreStatusCommand.ParseClientStatus(
                JsonSerializer.SerializeToUtf8Bytes(
                    wrongHash,
                    JsonOptions),
                registration));
    }

    [Fact]
    public void DiskStatusReadsCommittedHashesAndVersions()
    {
        using var fixture = new TrustStatusFixture();

        var status = SigstoreStatusCommand.ReadDiskStatus(
            fixture.Path);

        Assert.Equal(1, status.Generation);
        Assert.Equal(2, status.TufRootVersion);
        Assert.Equal(3, status.TufTargetsVersion);
        Assert.Equal(
            fixture.TrustedRootSha256,
            status.TrustedRootSha256);
        Assert.Equal(
            fixture.SigningConfigSha256,
            status.SigningConfigSha256);

        File.AppendAllText(
            System.IO.Path.Combine(
                fixture.ActivePublicationPath,
                "targets",
                "signing_config.v0.2.json"),
            "changed");
        Assert.Throws<SigstoreStatusException>(
            () => SigstoreStatusCommand.ReadDiskStatus(
                fixture.Path));
    }

    [Fact]
    public void DiskStatusRejectsIncompleteCommittedLayout()
    {
        using var fixture = new TrustStatusFixture();
        File.Delete(
            System.IO.Path.Combine(
                fixture.Path,
                "tuf",
                "bootstrap",
                "root.json"));

        Assert.Throws<FileNotFoundException>(
            () => SigstoreStatusCommand.ReadDiskStatus(
                fixture.Path));
    }

    [Fact]
    public void RotationProvenanceRemainsValidAfterLaterGenerations()
    {
        var generation = JsonSerializer.Deserialize<GenerationManifestStatus>(
            JsonSerializer.SerializeToUtf8Bytes(
                new
                {
                    schemaVersion = 5,
                    generation = 7,
                    generationId = "generation-00000007",
                    trustDomainId = "sha256-" + new string('a', 64),
                    createdAtUtc = DateTimeOffset.UtcNow,
                    sourceSchemaVersion = 5,
                    fulcioRootSha256 = new string('b', 64),
                    fulcioRotationOperationId =
                        "11111111111111111111111111111111",
                    fulcioPriorGeneration = 4,
                    fulcioPriorGenerationId = "generation-00000004",
                    fulcioPriorRootSha256 = new string('c', 64),
                    ctLogPublicKeySha256 = new string('d', 64),
                    rekorPublicKeySha256 = new string('e', 64),
                    rekorRotationOperationId =
                        "22222222222222222222222222222222",
                    rekorPriorGeneration = 5,
                    rekorPriorGenerationId = "generation-00000005",
                    rekorPriorPublicKeySha256 = new string('f', 64),
                    rekorPriorShardId = "sha256-" + new string('f', 64),
                    rekorPriorBaseUrl =
                        "http://rekor-sigstore.dev.localhost:3000",
                    rekorShardId = "sha256-" + new string('e', 64),
                    rekorBaseUrl =
                        "http://rekor-secondary-sigstore.dev.localhost:3000",
                    tsaRootSha256 = new string('1', 64),
                    tsaLeafSha256 = new string('2', 64),
                    oidcKeyId = "test-oidc-key",
                    files = new SortedDictionary<string, string>(
                        StringComparer.Ordinal)
                }),
            JsonOptions)!;

        SigstoreStatusCommand.ValidateFulcioRotationMetadata(generation);
        SigstoreStatusCommand.ValidateRekorRotationMetadata(generation);

        Assert.Throws<SigstoreStatusException>(
            () => SigstoreStatusCommand.ValidateFulcioRotationMetadata(
                generation with
                {
                    FulcioPriorGeneration = generation.Generation,
                    FulcioPriorGenerationId = generation.GenerationId
                }));
        Assert.Throws<SigstoreStatusException>(
            () => SigstoreStatusCommand.ValidateRekorRotationMetadata(
                generation with
                {
                    RekorPriorGeneration = generation.Generation,
                    RekorPriorGenerationId = generation.GenerationId
                }));
    }

    [Fact]
    public void TufSnapshotReportsAllRolesAndTrustFingerprints()
    {
        using var fixture = new TrustStatusFixture();

        var snapshot = SigstoreStatusCommand.ReadTufStateSnapshot(
            fixture.Path);
        var trustFingerprint =
            SigstoreStatusCommand.ReadTrustStateFingerprint(
                fixture.Path);
        var materialFingerprint =
            SigstoreStatusCommand.ReadTrustMaterialFingerprint(
                fixture.Path);

        Assert.Equal(2, snapshot.Metadata.Root.Version);
        Assert.Equal(3, snapshot.Metadata.Targets.Version);
        Assert.Equal(4, snapshot.Metadata.Snapshot.Version);
        Assert.Equal(5, snapshot.Metadata.Timestamp.Version);
        Assert.Equal(
            fixture.TrustedRootSha256,
            snapshot.Metadata.TrustedRootSha256);
        Assert.Equal(
            fixture.SigningConfigSha256,
            snapshot.Metadata.SigningConfigSha256);
        Assert.Equal(64, snapshot.StableContentSha256.Length);
        Assert.Equal(64, trustFingerprint.Length);
        Assert.Equal(64, materialFingerprint.Length);
        Assert.NotEqual(trustFingerprint, materialFingerprint);
    }

    [Fact]
    public void RefreshableMetadataPathsExcludeOnlyRepositoryRoles()
    {
        Assert.True(
            SigstoreStatusCommand.IsRefreshableMetadataPath(
                "repository/snapshot.json"));
        Assert.True(
            SigstoreStatusCommand.IsRefreshableMetadataPath(
                "repository/2.snapshot.json"));
        Assert.True(
            SigstoreStatusCommand.IsRefreshableMetadataPath(
                "repository/timestamp.json"));
        Assert.True(
            SigstoreStatusCommand.IsRefreshableMetadataPath(
                "repository/2.timestamp.json"));
        Assert.False(
            SigstoreStatusCommand.IsRefreshableMetadataPath(
                "keys/snapshot.json"));
        Assert.False(
            SigstoreStatusCommand.IsRefreshableMetadataPath(
                "keys/timestamp.json"));
        Assert.False(
            SigstoreStatusCommand.IsRefreshableMetadataPath(
                "targets/snapshot.json"));
        Assert.False(
            SigstoreStatusCommand.IsRefreshableMetadataPath(
                "repository/nested/2.snapshot.json"));
    }

    [Fact]
    public void CommandResultPreservesStructuredFailurePayload()
    {
        var status = new SigstoreAggregateTrustStatus(
            1,
            "sigstore",
            false,
            "Degraded",
            "dotnet-client: unavailable",
            DateTimeOffset.UtcNow,
            null,
            null,
            [],
            [],
            [new("dotnet-client", "unavailable")]);

        var result = SigstoreStatusCommand.CreateResult(
            status,
            """{"ready":false}""");

        Assert.False(result.Success);
        Assert.Equal(
            CommandResultFormat.Json,
            result.Data?.Format);
        Assert.Equal(
            """{"ready":false}""",
            result.Data?.Value);
    }

    [Fact]
    public void CtStatusErrorsCoverComputeProjectionCountAndRecovery()
    {
        var shard = new SigstoreCtLogShardHealthStatus(
            "sha256-" + new string('1', 64),
            "primary",
            "active",
            SigstoreCtLogShard.PrimaryUrl,
            SigstoreCtLogShard.PrimaryOrigin,
            SigstoreCtLogShard.PrimaryResourceName,
            new string('1', 64),
            new string('1', 64),
            "state-id",
            1,
            1,
            new string('2', 64),
            new string('3', 64),
            true,
            true,
            false,
            new string('4', 64),
            1,
            [new string('5', 64)],
            false);
        var status = new SigstoreCtLogStatus(
            shard.ShardId,
            "primary",
            SigstoreCtLogShard.PrimaryOrigin,
            shard.PublicKeySha256,
            false,
            null,
            2,
            [],
            [shard],
            Guid.NewGuid().ToString("N"),
            SigstoreCtLogShard.StatusWorkerCommitted);
        var errors = new List<SigstoreStatusError>();

        SigstoreStatusCommand.AppendCtLogStatusErrors(status, errors);

        Assert.Contains(
            errors,
            error => error.Message.Contains(
                "compute resource is not healthy",
                StringComparison.Ordinal));
        Assert.Contains(
            errors,
            error => error.Message.Contains(
                "accepted-root projection",
                StringComparison.Ordinal));
        Assert.Contains(
            errors,
            error => error.Message.Contains(
                "entry count",
                StringComparison.Ordinal));
        Assert.Contains(
            errors,
            error => error.Message.Contains(
                "recovery is pending",
                StringComparison.Ordinal));
    }

    [Fact]
    public void CtFinalizationIgnoresOnlyItsBoundRecoveryMarkers()
    {
        const string operationId = "11111111111111111111111111111111";
        const string operationStatus = SigstoreCtLogShard.StatusNewShardProved;
        var secondary = new SigstoreCtLogShardHealthStatus(
            "sha256-" + new string('1', 64),
            "secondary",
            "active",
            SigstoreCtLogShard.SecondaryUrl,
            SigstoreCtLogShard.SecondaryOrigin,
            SigstoreCtLogShard.SecondaryResourceName,
            new string('1', 64),
            new string('1', 64),
            "secondary-state",
            1,
            1,
            new string('2', 64),
            new string('3', 64),
            true,
            true,
            true,
            new string('4', 64),
            1,
            [new string('5', 64)],
            true);
        var primary = secondary with
        {
            ShardId = "sha256-" + new string('6', 64),
            Slot = "primary",
            Status = "historical",
            BaseUrl = SigstoreCtLogShard.PrimaryUrl,
            Origin = SigstoreCtLogShard.PrimaryOrigin,
            Resource = SigstoreCtLogShard.PrimaryResourceName,
            PublicKeySha256 = new string('6', 64),
            LogIdSha256 = new string('6', 64),
            StateId = "primary-state"
        };
        var ctLog = new SigstoreCtLogStatus(
            secondary.ShardId,
            "secondary",
            SigstoreCtLogShard.SecondaryOrigin,
            secondary.PublicKeySha256,
            false,
            null,
            2,
            [],
            [primary, secondary],
            operationId,
            operationStatus);
        var status = new SigstoreAggregateTrustStatus(
            1,
            "sigstore",
            false,
            "Degraded",
            "ctlog: recovery pending",
            DateTimeOffset.UtcNow,
            null,
            null,
            [],
            [],
            [
                new("ctlog", "bound recovery pending"),
                new("operation", "rotation active")
            ],
            Operation: new(
                SigstoreOperationCommand.RotateCtLogShardCommand,
                "aggregate-status",
                25,
                26,
                "Finalizing CT log rotation.",
                DateTimeOffset.UtcNow),
            Recovery: new(
                SigstoreOperationCommand.RotateCtLogShardCommand,
                operationStatus,
                "Lifecycle Recovery Pending",
                "The durable journal is not finalized.",
                DateTimeOffset.UtcNow),
            CtLog: ctLog);

        Assert.True(
            SigstoreOperationExecutor.IsReadyForCtLogFinalization(
                status,
                operationId,
                operationStatus));
        Assert.False(
            SigstoreOperationExecutor.IsReadyForCtLogFinalization(
                status,
                new string('2', 32),
                operationStatus));
        Assert.False(
            SigstoreOperationExecutor.IsReadyForCtLogFinalization(
                status with
                {
                    Ready = true,
                    Errors = [],
                    Recovery = null,
                    CtLog = null
                },
                operationId,
                operationStatus));
        Assert.False(
            SigstoreOperationExecutor.IsReadyForCtLogFinalization(
                status with
                {
                    Errors = [new("operation", "rotation active")],
                    Recovery = null,
                    CtLog = null
                },
                operationId,
                operationStatus));
        Assert.False(
            SigstoreOperationExecutor.IsReadyForCtLogFinalization(
                status with
                {
                    Errors =
                    [
                        .. status.Errors,
                        new("resources", "required resource is unhealthy")
                    ]
                },
                operationId,
                operationStatus));
        Assert.False(
            SigstoreOperationExecutor.IsReadyForCtLogFinalization(
                status with
                {
                    CtLog = ctLog with
                    {
                        Shards =
                        [
                            primary,
                            secondary with
                            {
                                ComputeHealthy = false
                            }
                        ]
                    }
                },
                operationId,
                operationStatus));
    }

    private static SigstoreClientTrustStatus NewClientStatus(
        string resource,
        string language) =>
        new(
            1,
            resource,
            language,
            true,
            null,
            "sha256-" + new string('a', 64),
            1,
            "generation-00000001",
            new string('b', 64),
            2,
            3,
            new string('c', 64),
            new string('d', 64),
            DateTimeOffset.Parse("2026-08-27T00:00:00Z"));

    internal sealed class TrustStatusFixture : IDisposable
    {
        public TrustStatusFixture()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-status-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);

            const string generationId = "generation-00000001";
            const string trustDomainId =
                "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            var createdAt = DateTimeOffset.Parse(
                "2026-08-27T00:00:00Z");
            var trustDomain = new
            {
                schemaVersion = 5,
                trustDomainId,
                createdAtUtc = createdAt,
                ctLogStateId = "test-ct-state",
                rekorStateId = "test-rekor-state"
            };
            var trustDomainBytes = Serialize(trustDomain);
            File.WriteAllBytes(
                System.IO.Path.Combine(
                    Path,
                    "trust-domain.json"),
                trustDomainBytes);
            WriteFile(
                System.IO.Path.Combine(
                    Path,
                    "data",
                    "ctlog",
                    "bootstrap-state"),
                "test-ct-state"u8.ToArray());
            WriteFile(
                System.IO.Path.Combine(
                    Path,
                    "data",
                    "rekor",
                    "bootstrap-state"),
                "test-rekor-state"u8.ToArray());

            var generationPath = System.IO.Path.Combine(
                Path,
                "generations",
                generationId);
            WriteFile(
                System.IO.Path.Combine(
                    generationPath,
                    "private",
                    "test.key"),
                "private"u8.ToArray());
            WriteFile(
                System.IO.Path.Combine(
                    generationPath,
                    "public",
                    "test.pem"),
                "public"u8.ToArray());
            var generationFiles = Directory.EnumerateFiles(
                    generationPath,
                    "*",
                    SearchOption.AllDirectories)
                .ToDictionary(
                    file => System.IO.Path
                        .GetRelativePath(generationPath, file)
                        .Replace(
                            System.IO.Path.DirectorySeparatorChar,
                            '/'),
                    file => Hash(File.ReadAllBytes(file)),
                    StringComparer.Ordinal);
            var generationManifestValue = new
            {
                schemaVersion = 5,
                generation = 1,
                generationId,
                trustDomainId,
                createdAtUtc = createdAt,
                sourceSchemaVersion = 5,
                sourceManifestSha256 = (string?)null,
                fulcioRootSha256 = new string('1', 64),
                ctLogPublicKeySha256 = new string('2', 64),
                rekorPublicKeySha256 = new string('3', 64),
                tsaRootSha256 = new string('4', 64),
                tsaLeafSha256 = new string('5', 64),
                oidcKeyId = "test-oidc-key",
                files = new SortedDictionary<string, string>(
                    generationFiles,
                    StringComparer.Ordinal)
            };
            var generationManifest = Serialize(
                generationManifestValue);
            File.WriteAllBytes(
                System.IO.Path.Combine(
                    generationPath,
                    "manifest.json"),
                generationManifest);
            var generationManifestHash = Hash(generationManifest);
            Directory.CreateSymbolicLink(
                System.IO.Path.Combine(
                    Path,
                    "active-generation"),
                System.IO.Path.Combine(
                    "generations",
                    generationId));
            Directory.CreateDirectory(
                System.IO.Path.Combine(
                    Path,
                    "transition"));
            Directory.CreateDirectory(
                System.IO.Path.Combine(
                    Path,
                    "migration"));
            File.WriteAllBytes(
                System.IO.Path.Combine(
                    Path,
                    "transition",
                    "state.json"),
                Serialize(
                    new
                    {
                        schemaVersion = 1,
                        status = "committed",
                        lastCheckpoint = "transition-finalized",
                        priorGeneration = (object?)null,
                        candidate = new
                        {
                            generation = 1,
                            generationId,
                            manifestSha256 = generationManifestHash
                        },
                        trustDomainManifestSha256 =
                            Hash(trustDomainBytes),
                        trustDomain,
                        candidateManifest = generationManifestValue
                    }));

            var tufPath = System.IO.Path.Combine(Path, "tuf");
            var candidatePath = System.IO.Path.Combine(
                tufPath,
                "committed",
                "candidate");
            var repositoryPath = System.IO.Path.Combine(
                candidatePath,
                "repository");
            var targetsPath = System.IO.Path.Combine(
                candidatePath,
                "targets");
            Directory.CreateDirectory(repositoryPath);
            Directory.CreateDirectory(targetsPath);
            var rootMetadata = Serialize(
                new
                {
                    signed = new
                    {
                        _type = "root",
                        version = 2,
                        expires = "2030-08-27T00:00:00Z"
                    }
                });
            var targetsMetadata = Serialize(
                new
                {
                    signed = new
                    {
                        _type = "targets",
                        version = 3,
                        expires = "2030-08-27T00:00:00Z"
                    }
                });
            File.WriteAllBytes(
                System.IO.Path.Combine(
                    repositoryPath,
                    "root.json"),
                rootMetadata);
            File.WriteAllBytes(
                System.IO.Path.Combine(
                    repositoryPath,
                    "targets.json"),
                targetsMetadata);
            var snapshotMetadata = Serialize(
                new
                {
                    signed = new
                    {
                        _type = "snapshot",
                        version = 4,
                        expires = "2030-08-27T00:00:00Z",
                        meta = new Dictionary<string, object>
                        {
                            ["targets.json"] = new
                            {
                                version = 3,
                                length = targetsMetadata.Length,
                                hashes = new
                                {
                                    sha512 = HashSha512(targetsMetadata)
                                }
                            }
                        }
                    }
                });
            File.WriteAllBytes(
                System.IO.Path.Combine(
                    repositoryPath,
                    "snapshot.json"),
                snapshotMetadata);
            File.WriteAllBytes(
                System.IO.Path.Combine(
                    repositoryPath,
                    "timestamp.json"),
                Serialize(
                    new
                    {
                        signed = new
                        {
                            _type = "timestamp",
                            version = 5,
                            expires = "2030-08-27T00:00:00Z",
                            meta = new Dictionary<string, object>
                            {
                                ["snapshot.json"] = new
                                {
                                    version = 4,
                                    length = snapshotMetadata.Length,
                                    hashes = new
                                    {
                                        sha512 = HashSha512(snapshotMetadata)
                                    }
                                }
                            }
                        }
                    }));
            var trustedRoot = Serialize(
                new
                {
                    mediaType =
                        "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
                });
            var signingConfig = Serialize(
                new
                {
                    mediaType =
                        "application/vnd.dev.sigstore.signingconfig.v0.2+json"
                });
            TrustedRootSha256 = Hash(trustedRoot);
            SigningConfigSha256 = Hash(signingConfig);
            File.WriteAllBytes(
                System.IO.Path.Combine(
                    targetsPath,
                    "trusted_root.json"),
                trustedRoot);
            File.WriteAllBytes(
                System.IO.Path.Combine(
                    targetsPath,
                    "signing_config.v0.2.json"),
                signingConfig);
            File.WriteAllBytes(
                System.IO.Path.Combine(
                    targetsPath,
                    "trust_status.v1.json"),
                Serialize(
                    new
                    {
                        schemaVersion = 1,
                        trustDomainId,
                        generation = 1,
                        generationId,
                        generationManifestSha256 =
                            generationManifestHash,
                        tufRootVersion = 2,
                        tufTargetsVersion = 3,
                        trustedRootSha256 = TrustedRootSha256,
                        signingConfigSha256 = SigningConfigSha256
                    }));

            var files = Directory.EnumerateFiles(
                    candidatePath,
                    "*",
                    SearchOption.AllDirectories)
                .ToDictionary(
                    file => System.IO.Path
                        .GetRelativePath(
                            candidatePath,
                            file)
                        .Replace(
                            System.IO.Path.DirectorySeparatorChar,
                            '/'),
                    file => Hash(File.ReadAllBytes(file)),
                    StringComparer.Ordinal);
            var tufManifest = Serialize(
                new
                {
                    schemaVersion = 3,
                    sourceFingerprint = new string('f', 64),
                    files = new SortedDictionary<string, string>(
                        files,
                        StringComparer.Ordinal)
                });
            File.WriteAllBytes(
                System.IO.Path.Combine(
                    candidatePath,
                    "manifest.json"),
                tufManifest);
            var tufManifestHash = Hash(tufManifest);
            var publicationId = "sha256-" + tufManifestHash;
            ActivePublicationPath = System.IO.Path.Combine(
                tufPath,
                "committed",
                publicationId);
            Directory.Move(
                candidatePath,
                ActivePublicationPath);

            var bootstrapPath = System.IO.Path.Combine(
                tufPath,
                "bootstrap",
                "root.json");
            WriteFile(
                bootstrapPath,
                Serialize(
                    new
                    {
                        signed = new
                        {
                            _type = "root",
                            version = 1
                        }
                    }));
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    bootstrapPath,
                    UnixFileMode.UserRead
                        | UnixFileMode.GroupRead
                        | UnixFileMode.OtherRead);
            }
            Directory.CreateDirectory(
                System.IO.Path.Combine(tufPath, "history"));
            Directory.CreateDirectory(
                System.IO.Path.Combine(tufPath, "staging"));
            Directory.CreateDirectory(
                System.IO.Path.Combine(
                    tufPath,
                    "publication"));
            Directory.CreateSymbolicLink(
                System.IO.Path.Combine(tufPath, "active"),
                System.IO.Path.Combine(
                    "committed",
                    publicationId));
            File.WriteAllBytes(
                System.IO.Path.Combine(
                    tufPath,
                    "publication",
                    "state.json"),
                Serialize(
                    new
                    {
                        schemaVersion = 1,
                        status = "committed",
                        bootstrapRootSha256 = Hash(
                            File.ReadAllBytes(bootstrapPath)),
                        active = new
                        {
                            id = publicationId,
                            manifestSha256 = tufManifestHash
                        },
                        candidate = (object?)null,
                        previous = (object?)null
                    }));
        }

        public string Path { get; }

        public string ActivePublicationPath { get; }

        public string TrustedRootSha256 { get; }

        public string SigningConfigSha256 { get; }

        public void Dispose()
        {
            Directory.Delete(Path, recursive: true);
        }

        private static byte[] Serialize<T>(T value) =>
            JsonSerializer.SerializeToUtf8Bytes(
                value,
                JsonOptions);

        private static void WriteFile(
            string path,
            byte[] value)
        {
            Directory.CreateDirectory(
                System.IO.Path.GetDirectoryName(path)
                    ?? throw new InvalidOperationException());
            File.WriteAllBytes(path, value);
        }

        private static string Hash(ReadOnlySpan<byte> value) =>
            Convert.ToHexString(SHA256.HashData(value))
                .ToLowerInvariant();

        private static string HashSha512(ReadOnlySpan<byte> value) =>
            Convert.ToHexString(SHA512.HashData(value))
                .ToLowerInvariant();
    }
}
