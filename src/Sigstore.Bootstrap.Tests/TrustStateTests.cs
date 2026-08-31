using System.Security.Cryptography;
using System.Text.Json;
using Sigstore.Bootstrap;
using Xunit;

namespace Sigstore.Bootstrap.Tests;

public sealed class TrustStateTests
{
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    [Fact]
    public void FreshStateCreatesGenerationAwareTrustDomain()
    {
        using var state = new TemporaryDirectory();

        var result = SigstoreStateBootstrapper.EnsureInitialized(
            state.Path);

        Assert.Equal(
            BootstrapAction.Created,
            result.Action);
        Assert.Equal(
            5,
            result.TrustDomain.SchemaVersion);
        Assert.Equal(
            "generation-00000001",
            result.Generation.GenerationId);
        Assert.Equal(
            1,
            result.Generation.Generation);
        Assert.Equal(
            5,
            result.Generation.SourceSchemaVersion);
        Assert.Null(result.Generation.SourceManifestSha256);
        Assert.Equal(
            result.TrustDomain.TrustDomainId,
            result.Generation.TrustDomainId);
        Assert.False(
            Directory.Exists(
                System.IO.Path.Combine(
                    state.Path,
                    "private")));
        Assert.False(
            Directory.Exists(
                System.IO.Path.Combine(
                    state.Path,
                    "public")));
        Assert.Equal(
            System.IO.Path.Combine(
                "generations",
                "generation-00000001"),
            new DirectoryInfo(
                System.IO.Path.Combine(
                    state.Path,
                    "active-generation"))
                .LinkTarget);

        var journal = ReadJournal(state.Path);
        Assert.Equal(
            "committed",
            journal.Status);
        Assert.Equal(
            "transition-finalized",
            journal.LastCheckpoint);
        Assert.Null(journal.PriorGeneration);
    }

    [Fact]
    public void Schema4MigrationPreservesEveryTrustByteAndIdentifier()
    {
        using var fixture = CreateSchema4Fixture();
        using var state = CopyFixture(fixture);
        var legacy = ReadLegacyManifest(state.Path);
        var legacyManifestBytes = File.ReadAllBytes(
            System.IO.Path.Combine(
                state.Path,
                "bootstrap-manifest.json"));
        var trustBytes = SnapshotLegacyTrustMaterial(state.Path);
        CreateRepresentativeTufState(state.Path);
        var tufBytes = SnapshotSubtree(
            System.IO.Path.Combine(
                state.Path,
                "tuf"));

        var result = SigstoreStateBootstrapper.EnsureInitialized(
            state.Path);

        Assert.Equal(
            BootstrapAction.Migrated,
            result.Action);
        Assert.Equal(
            legacy.CreatedAtUtc,
            result.TrustDomain.CreatedAtUtc);
        Assert.Equal(
            legacy.CtLogStateId,
            result.TrustDomain.CtLogStateId);
        Assert.Equal(
            legacy.RekorStateId,
            result.TrustDomain.RekorStateId);
        Assert.Equal(
            legacy.FulcioRootSha256,
            result.Generation.FulcioRootSha256);
        Assert.Equal(
            legacy.CtLogPublicKeySha256,
            result.Generation.CtLogPublicKeySha256);
        Assert.Equal(
            legacy.RekorPublicKeySha256,
            result.Generation.RekorPublicKeySha256);
        Assert.Equal(
            legacy.TsaRootSha256,
            result.Generation.TsaRootSha256);
        Assert.Equal(
            legacy.TsaLeafSha256,
            result.Generation.TsaLeafSha256);
        Assert.Equal(
            legacy.OidcKeyId,
            result.Generation.OidcKeyId);
        Assert.Equal(
            trustBytes,
            SnapshotActiveTrustMaterial(state.Path));
        Assert.Equal(
            legacyManifestBytes,
            File.ReadAllBytes(
                System.IO.Path.Combine(
                    state.Path,
                    "migration",
                    "bootstrap-manifest.schema-4.json")));
        Assert.Equal(
            tufBytes,
            SnapshotSubtree(
                System.IO.Path.Combine(
                    state.Path,
                    "tuf")));
        Assert.False(
            File.Exists(
                System.IO.Path.Combine(
                    state.Path,
                    "bootstrap-manifest.json")));
        Assert.False(
            File.Exists(
                System.IO.Path.Combine(
                    state.Path,
                    ".bootstrap.lock")));
    }

    [Fact]
    public void MigrationAndStartupAreIdempotent()
    {
        using var fixture = CreateSchema4Fixture();
        using var state = CopyFixture(fixture);

        var migrated = SigstoreStateBootstrapper.EnsureInitialized(
            state.Path);
        var snapshot = SnapshotState(state.Path);
        var reused = SigstoreStateBootstrapper.EnsureInitialized(
            state.Path);

        Assert.Equal(
            BootstrapAction.Migrated,
            migrated.Action);
        Assert.Equal(
            BootstrapAction.Reused,
            reused.Action);
        Assert.Equal(
            snapshot,
            SnapshotState(state.Path));
        Assert.Equal(
            migrated.TrustDomain,
            reused.TrustDomain);
        Assert.Equal(
            migrated.Generation.GenerationId,
            reused.Generation.GenerationId);
        Assert.Equal(
            migrated.Generation.Files,
            reused.Generation.Files);
    }

    [Fact]
    public void CorruptedSchema4StateIsRejectedWithoutMigration()
    {
        using var fixture = CreateSchema4Fixture();
        using var state = CopyFixture(fixture);
        var path = System.IO.Path.Combine(
            state.Path,
            "public",
            "ctlog",
            "pubkey.pem");
        File.AppendAllText(
            path,
            "corruption");

        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper.EnsureInitialized(
                state.Path));
        Assert.True(
            File.Exists(
                System.IO.Path.Combine(
                    state.Path,
                    "bootstrap-manifest.json")));
        Assert.False(
            File.Exists(
                System.IO.Path.Combine(
                    state.Path,
                    "trust-domain.json")));
        Assert.False(
            Directory.Exists(
                System.IO.Path.Combine(
                    state.Path,
                    "transition")));
    }

    [Fact]
    public void UnexpectedGenerationFileOrChangedBytesAreRejected()
    {
        using var state = new TemporaryDirectory();
        var result = SigstoreStateBootstrapper.EnsureInitialized(
            state.Path);
        var activePath = System.IO.Path.Combine(
            state.Path,
            "generations",
            result.Generation.GenerationId);
        var unexpected = System.IO.Path.Combine(
            activePath,
            "public",
            "unexpected.pem");
        File.WriteAllText(
            unexpected,
            "unexpected");

        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper.EnsureInitialized(
                state.Path));

        File.Delete(unexpected);
        var keyPath = System.IO.Path.Combine(
            activePath,
            "private",
            "rekor",
            "signer.key");
        File.AppendAllText(
            keyPath,
            "corruption");
        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper.EnsureInitialized(
                state.Path));
    }

    [Fact]
    public void TransitionRejectsMismatchedCtRotationMetadata()
    {
        using var state = new TemporaryDirectory();
        _ = SigstoreStateBootstrapper.EnsureInitialized(state.Path);
        var journal = ReadJournal(state.Path);
        var path = System.IO.Path.Combine(
            state.Path,
            "transition",
            "state.json");

        File.WriteAllText(
            path,
            JsonSerializer.Serialize(
                journal with
                {
                    CandidateManifest = journal.CandidateManifest with
                    {
                        CtLogBaseUrl =
                            "http://tesseract-secondary-sigstore.dev.localhost:6963"
                    }
                },
                JsonOptions));

        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper.EnsureInitialized(state.Path));
    }

    [Fact]
    public void ActiveGenerationRejectsPartialCtRotationMetadata()
    {
        using var state = new TemporaryDirectory();
        var initial = SigstoreStateBootstrapper.EnsureInitialized(state.Path);
        var manifestPath = System.IO.Path.Combine(
            state.Path,
            "generations",
            initial.Generation.GenerationId,
            "manifest.json");
        var generation = initial.Generation with
        {
            CtLogBaseUrl =
                "http://tesseract-secondary-sigstore.dev.localhost:6963"
        };
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                manifestPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(
            generation,
            JsonOptions);
        File.WriteAllBytes(manifestPath, manifestBytes);
        var journal = ReadJournal(state.Path);
        var journalPath = System.IO.Path.Combine(
            state.Path,
            "transition",
            "state.json");
        File.WriteAllText(
            journalPath,
            JsonSerializer.Serialize(
                journal with
                {
                    Candidate = journal.Candidate with
                    {
                        ManifestSha256 = Convert.ToHexString(
                                SHA256.HashData(manifestBytes))
                            .ToLowerInvariant()
                    },
                    CandidateManifest = generation
                },
                JsonOptions));

        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper.EnsureInitialized(state.Path));
    }

    [Fact]
    public void AdditiveStandbyRekorMaterialSurvivesBootstrapReuse()
    {
        using var state = new TemporaryDirectory();
        var initial = SigstoreStateBootstrapper.EnsureInitialized(state.Path);
        var generation = PromoteAdditiveGeneration(
            state.Path,
            initial.Generation);

        var reused = SigstoreStateBootstrapper.EnsureInitialized(state.Path);

        Assert.Equal(2, reused.Generation.Generation);
        Assert.Contains(
            "public/rekor/rekor-standby.pub",
            reused.Generation.Files.Keys);

        var standbyPath = System.IO.Path.Combine(
            state.Path,
            "generations",
            generation.GenerationId,
            "public",
            "rekor",
            "rekor-standby.pub");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                standbyPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        File.AppendAllText(standbyPath, "tampered");
        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper.EnsureInitialized(state.Path));
    }

    [Fact]
    public void LockContentionIsExplicitAndReleasedOwnersDoNotBlock()
    {
        using var state = new TemporaryDirectory();
        using (StateFileLock.Acquire(
            state.Path,
            TimeSpan.FromSeconds(1),
            "test-holder"))
        {
            var exception = Assert.Throws<InvalidOperationException>(
                () => SigstoreStateBootstrapper.EnsureInitialized(
                    state.Path,
                    new TrustStateOperationOptions(
                        TimeSpan.FromMilliseconds(100))));
            Assert.Contains(
                "locked by another operation",
                exception.Message,
                StringComparison.Ordinal);
        }

        var result = SigstoreStateBootstrapper.EnsureInitialized(
            state.Path);
        Assert.Equal(
            BootstrapAction.Created,
            result.Action);
    }

    [Fact]
    public void FailedTransitionIsDurableAndRecoversForward()
    {
        using var fixture = CreateSchema4Fixture();
        using var state = CopyFixture(fixture);
        var injected = new InvalidOperationException(
            "injected transition failure");

        var exception = Assert.Throws<InvalidOperationException>(
            () => SigstoreStateBootstrapper.EnsureInitialized(
                state.Path,
                new TrustStateOperationOptions(
                    TimeSpan.FromSeconds(1),
                    checkpoint =>
                    {
                        if (checkpoint
                            == TrustTransitionCheckpoint.PrivateMaterialStaged)
                        {
                            throw injected;
                        }
                    })));
        Assert.Same(
            injected,
            exception);
        Assert.Equal(
            "failed",
            ReadJournal(state.Path).Status);

        var recovered = SigstoreStateBootstrapper.EnsureInitialized(
            state.Path);
        Assert.Equal(
            BootstrapAction.Recovered,
            recovered.Action);
        Assert.Equal(
            "recovered",
            ReadJournal(state.Path).Status);
    }

    [Fact]
    public void MigrationRecoversBetweenLegacyManifestRenameAndModeChange()
    {
        using var fixture = CreateSchema4Fixture();
        using var state = CopyFixture(fixture);
        var source = System.IO.Path.Combine(
            state.Path,
            "bootstrap-manifest.json");
        var migrationDirectory = System.IO.Path.Combine(
            state.Path,
            "migration");
        var archive = System.IO.Path.Combine(
            migrationDirectory,
            "bootstrap-manifest.schema-4.json");

        Assert.Throws<TrustTransitionInterruptedException>(
            () => SigstoreStateBootstrapper.EnsureInitialized(
                state.Path,
                new TrustStateOperationOptions(
                    TimeSpan.FromSeconds(1),
                    checkpoint =>
                    {
                        if (checkpoint
                            == TrustTransitionCheckpoint.TransitionCommitted)
                        {
                            throw new TrustTransitionInterruptedException(
                                "interrupt before legacy archive");
                        }
                    })));
        Directory.CreateDirectory(migrationDirectory);
        File.Move(
            source,
            archive);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                archive,
                UnixFileMode.UserRead
                | UnixFileMode.UserWrite
                | UnixFileMode.GroupRead
                | UnixFileMode.OtherRead);
        }

        var recovered = SigstoreStateBootstrapper.EnsureInitialized(
            state.Path);

        Assert.Equal(
            BootstrapAction.Recovered,
            recovered.Action);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(
                UnixFileMode.None,
                File.GetUnixFileMode(archive)
                & (UnixFileMode.UserWrite
                    | UnixFileMode.GroupWrite
                    | UnixFileMode.OtherWrite));
        }
    }

    [Theory]
    [MemberData(nameof(TransitionCheckpoints))]
    public void InterruptedMigrationRecoversAtEveryFilesystemCheckpoint(
        string checkpointName)
    {
        var wanted = Enum.Parse<TrustTransitionCheckpoint>(
            checkpointName);
        using var fixture = CreateSchema4Fixture();
        using var state = CopyFixture(fixture);
        var legacy = ReadLegacyManifest(state.Path);
        var trustBytes = SnapshotLegacyTrustMaterial(state.Path);

        Assert.Throws<TrustTransitionInterruptedException>(
            () => SigstoreStateBootstrapper.EnsureInitialized(
                state.Path,
                new TrustStateOperationOptions(
                    TimeSpan.FromSeconds(1),
                    checkpoint =>
                    {
                        if (checkpoint == wanted)
                        {
                            throw new TrustTransitionInterruptedException(
                                $"interrupted after {checkpoint}");
                        }
                    })));

        var resumed = SigstoreStateBootstrapper.EnsureInitialized(
            state.Path);
        Assert.Equal(
            wanted == TrustTransitionCheckpoint.TransitionFinalized
                ? BootstrapAction.Reused
                : BootstrapAction.Recovered,
            resumed.Action);
        Assert.Equal(
            trustBytes,
            SnapshotActiveTrustMaterial(state.Path));
        Assert.Equal(
            legacy.CtLogStateId,
            resumed.TrustDomain.CtLogStateId);
        Assert.Equal(
            legacy.RekorStateId,
            resumed.TrustDomain.RekorStateId);
        Assert.Equal(
            "transition-finalized",
            ReadJournal(state.Path).LastCheckpoint);
    }

    public static TheoryData<string> TransitionCheckpoints
    {
        get
        {
            var data = new TheoryData<string>();
            foreach (var checkpoint in
                Enum.GetValues<TrustTransitionCheckpoint>())
            {
                data.Add(checkpoint.ToString());
            }
            return data;
        }
    }

    private static TemporaryDirectory CreateSchema4Fixture()
    {
        var fixture = new TemporaryDirectory();
        SigstoreStateBootstrapper.CreateSchema4StateForMigrationTests(
            fixture.Path);
        File.WriteAllText(
            System.IO.Path.Combine(
                fixture.Path,
                ".bootstrap.lock"),
            "stale schema-4 owner metadata\n");
        return fixture;
    }

    private static TemporaryDirectory CopyFixture(
        TemporaryDirectory source)
    {
        var destination = new TemporaryDirectory();
        CopyDirectory(
            source.Path,
            destination.Path);
        return destination;
    }

    private static GenerationManifest PromoteAdditiveGeneration(
        string statePath,
        GenerationManifest current)
    {
        const string generationId = "generation-00000002";
        var generationsPath = System.IO.Path.Combine(
            statePath,
            "generations");
        var source = System.IO.Path.Combine(
            generationsPath,
            current.GenerationId);
        var destination = System.IO.Path.Combine(
            generationsPath,
            generationId);
        CopyDirectory(source, destination);

        var manifestPath = System.IO.Path.Combine(
            destination,
            "manifest.json");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                manifestPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        using var standby = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var standbyPath = System.IO.Path.Combine(
            destination,
            "public",
            "rekor",
            "rekor-standby.pub");
        File.WriteAllText(
            standbyPath,
            standby.ExportSubjectPublicKeyInfoPem());

        var generation = current with
        {
            Generation = 2,
            GenerationId = generationId,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            Files = SnapshotTrustMaterial(destination)
        };
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(
            generation,
            JsonOptions);
        File.WriteAllBytes(manifestPath, manifestBytes);
        foreach (var file in Directory.EnumerateFiles(
            destination,
            "*",
            SearchOption.AllDirectories))
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    file,
                    UnixFileMode.UserRead
                    | UnixFileMode.GroupRead
                    | UnixFileMode.OtherRead);
            }
        }

        var currentManifestPath = System.IO.Path.Combine(
            source,
            "manifest.json");
        var journal = ReadJournal(statePath);
        var now = DateTimeOffset.UtcNow;
        var candidateManifestSha256 = Convert.ToHexString(
                SHA256.HashData(manifestBytes))
            .ToLowerInvariant();
        var updatedJournal = journal with
        {
            TransitionId = Guid.NewGuid().ToString("N"),
            Operation = "generation-advance",
            Status = "committed",
            LastCheckpoint = "transition-finalized",
            StartedAtUtc = now,
            UpdatedAtUtc = now,
            PriorGeneration = new GenerationReference(
                current.Generation,
                current.GenerationId,
                Convert.ToHexString(
                        SHA256.HashData(
                            File.ReadAllBytes(currentManifestPath)))
                    .ToLowerInvariant()),
            Candidate = new GenerationReference(
                generation.Generation,
                generation.GenerationId,
                candidateManifestSha256),
            CandidateManifest = generation
        };
        File.WriteAllText(
            System.IO.Path.Combine(
                statePath,
                "transition",
                "state.json"),
            JsonSerializer.Serialize(updatedJournal, JsonOptions));

        var activeGeneration = System.IO.Path.Combine(
            statePath,
            "active-generation");
        Directory.Delete(activeGeneration);
        Directory.CreateSymbolicLink(
            activeGeneration,
            System.IO.Path.Combine(
                "generations",
                generationId));
        return generation;
    }

    private static void CopyDirectory(
        string source,
        string destination)
    {
        foreach (var directory in Directory.EnumerateDirectories(
            source,
            "*",
            SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(
                System.IO.Path.Combine(
                    destination,
                    System.IO.Path.GetRelativePath(
                        source,
                        directory)));
        }
        foreach (var file in Directory.EnumerateFiles(
            source,
            "*",
            SearchOption.AllDirectories))
        {
            var target = System.IO.Path.Combine(
                destination,
                System.IO.Path.GetRelativePath(
                    source,
                    file));
            Directory.CreateDirectory(
                System.IO.Path.GetDirectoryName(target)!);
            File.Copy(
                file,
                target);
        }
    }

    private static BootstrapManifest ReadLegacyManifest(
        string statePath)
        => JsonSerializer.Deserialize<BootstrapManifest>(
            File.ReadAllText(
                System.IO.Path.Combine(
                    statePath,
                    "bootstrap-manifest.json")),
            JsonOptions)
            ?? throw new InvalidDataException(
                "The schema-4 manifest is empty.");

    private static TrustTransitionJournal ReadJournal(
        string statePath)
        => JsonSerializer.Deserialize<TrustTransitionJournal>(
            File.ReadAllText(
                System.IO.Path.Combine(
                    statePath,
                    "transition",
                    "state.json")),
            JsonOptions)
            ?? throw new InvalidDataException(
                "The transition journal is empty.");

    private static SortedDictionary<string, string>
        SnapshotLegacyTrustMaterial(string statePath)
        => SnapshotTrustMaterial(
            statePath);

    private static SortedDictionary<string, string>
        SnapshotActiveTrustMaterial(string statePath)
        => SnapshotTrustMaterial(
            System.IO.Path.Combine(
                statePath,
                "active-generation"));

    private static SortedDictionary<string, string>
        SnapshotTrustMaterial(string rootPath)
    {
        var snapshot = new SortedDictionary<string, string>(
            StringComparer.Ordinal);
        foreach (var directory in new[] { "private", "public" })
        {
            foreach (var file in Directory.EnumerateFiles(
                System.IO.Path.Combine(
                    rootPath,
                    directory),
                "*",
                SearchOption.AllDirectories))
            {
                var relative = System.IO.Path.GetRelativePath(
                        rootPath,
                        file)
                    .Replace(
                        System.IO.Path.DirectorySeparatorChar,
                        '/');
                snapshot.Add(
                    relative,
                    Convert.ToHexString(
                            SHA256.HashData(
                                File.ReadAllBytes(file)))
                        .ToLowerInvariant());
            }
        }
        return snapshot;
    }

    private static SortedDictionary<string, string>
        SnapshotState(string statePath)
    {
        var snapshot = new SortedDictionary<string, string>(
            StringComparer.Ordinal);
        SnapshotDirectory(
            statePath,
            statePath,
            snapshot);
        return snapshot;
    }

    private static SortedDictionary<string, string>
        SnapshotSubtree(string path)
    {
        var snapshot = new SortedDictionary<string, string>(
            StringComparer.Ordinal);
        SnapshotDirectory(
            path,
            path,
            snapshot);
        return snapshot;
    }

    private static void CreateRepresentativeTufState(
        string statePath)
    {
        var tufPath = System.IO.Path.Combine(
            statePath,
            "tuf");
        var publicationId = "sha256-" + new string('c', 64);
        var committed = System.IO.Path.Combine(
            tufPath,
            "committed",
            publicationId);
        Directory.CreateDirectory(
            System.IO.Path.Combine(
                committed,
                "repository"));
        Directory.CreateDirectory(
            System.IO.Path.Combine(
                tufPath,
                "publication"));
        File.WriteAllText(
            System.IO.Path.Combine(
                committed,
                "repository",
                "root.json"),
            "{\"signed\":{\"version\":1}}\n");
        File.WriteAllText(
            System.IO.Path.Combine(
                tufPath,
                "publication",
                "state.json"),
            "{\"schemaVersion\":1,\"status\":\"committed\"}\n");
        Directory.CreateSymbolicLink(
            System.IO.Path.Combine(
                tufPath,
                "active"),
            System.IO.Path.Combine(
                "committed",
                publicationId));
    }

    private static void SnapshotDirectory(
        string statePath,
        string directory,
        SortedDictionary<string, string> snapshot)
    {
        foreach (var entry in Directory.EnumerateFileSystemEntries(
            directory)
            .Order(StringComparer.Ordinal))
        {
            var relative = System.IO.Path.GetRelativePath(
                    statePath,
                    entry)
                .Replace(
                    System.IO.Path.DirectorySeparatorChar,
                    '/');
            if (relative == StateFileLock.FileName)
            {
                continue;
            }

            var info = new FileInfo(entry);
            if (info.LinkTarget is not null)
            {
                snapshot.Add(
                    relative,
                    $"link:{info.LinkTarget}");
            }
            else if (Directory.Exists(entry))
            {
                SnapshotDirectory(
                    statePath,
                    entry,
                    snapshot);
            }
            else
            {
                snapshot.Add(
                    relative,
                    Convert.ToHexString(
                            SHA256.HashData(
                                File.ReadAllBytes(entry)))
                        .ToLowerInvariant());
            }
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-bootstrap-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            Directory.Delete(
                Path,
                recursive: true);
        }
    }
}
