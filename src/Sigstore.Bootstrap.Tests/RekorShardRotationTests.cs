using System.Security.Cryptography;
using Sigstore.Bootstrap;
using Xunit;

namespace Sigstore.Bootstrap.Tests;

public sealed class RekorShardRotationTests
{
    [Fact]
    public void InitializedStateHasSeparateEmptySecondaryStorage()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");

        var initial = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        var primaryPath = Path.Combine(statePath, "data", "rekor");
        var secondaryPath = Path.Combine(
            statePath,
            "data",
            "rekor-shards",
            "secondary");

        Assert.True(Directory.Exists(primaryPath));
        Assert.True(Directory.Exists(secondaryPath));
        Assert.Empty(
            Directory.EnumerateFileSystemEntries(secondaryPath));
        Assert.Equal(
            initial.TrustDomain.RekorStateId,
            File.ReadAllText(
                Path.Combine(primaryPath, "bootstrap-state")));
    }

    [Fact]
    public void CandidateIsImmutableDistinctAndLogIdBound()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");
        var initial = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        var initialPath = Path.Combine(
            statePath,
            "generations",
            initial.Generation.GenerationId);
        var operationId = Guid.NewGuid().ToString("N");
        var candidatePath = Path.Combine(
            statePath,
            "rekor-shard-rotation",
            operationId,
            "candidate");

        var candidate =
            SigstoreStateBootstrapper.EnsureRekorShardRotationCandidate(
                candidatePath);
        var replay =
            SigstoreStateBootstrapper.EnsureRekorShardRotationCandidate(
                candidatePath);

        Assert.Equal(candidate, replay);
        Assert.NotEqual(
            initial.Generation.RekorPublicKeySha256,
            candidate.PublicKeySha256);
        Assert.Equal(candidate.PublicKeySha256, candidate.LogId);
        Assert.Equal($"sha256-{candidate.LogId}", candidate.ShardId);
        Assert.Equal(
            [
                "private/rekor/signer.key",
                "public/rekor/signer.pub"
            ],
            RelativeFiles(candidatePath));

        using var publicKey = ECDsa.Create();
        publicKey.ImportFromPem(
            File.ReadAllText(
                Path.Combine(
                    candidatePath,
                    "public",
                    "rekor",
                    "signer.pub")));
        Assert.Equal(256, publicKey.KeySize);
        Assert.Equal(
            candidate.LogId,
            Convert.ToHexString(
                    SHA256.HashData(
                        publicKey.ExportSubjectPublicKeyInfo()))
                .ToLowerInvariant());

        Assert.Equal(
            initial.Generation.RekorPublicKeySha256,
            SigstoreStateBootstrapper.ValidateRekorShardMaterial(
                initialPath).PublicKeySha256);
    }

    [Fact]
    public void RuntimeProjectionContainsOnlyTheSecondaryPrivateSigner()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");
        _ = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        var candidatePath = Path.Combine(
            statePath,
            "rekor-shard-rotation",
            Guid.NewGuid().ToString("N"),
            "candidate");
        var candidate =
            SigstoreStateBootstrapper.EnsureRekorShardRotationCandidate(
                candidatePath);

        var runtime = SigstoreStateBootstrapper.StageRekorShardRuntime(
            statePath,
            candidatePath);
        var replay = SigstoreStateBootstrapper.StageRekorShardRuntime(
            statePath,
            candidatePath);
        var runtimePath = Path.Combine(
            statePath,
            "runtime",
            "rekor-secondary");

        Assert.Equal(candidate, runtime);
        Assert.Equal(runtime, replay);
        Assert.Equal(["signer.key"], RelativeFiles(runtimePath));
        Assert.False(
            File.Exists(Path.Combine(runtimePath, "signer.pub")));
    }

    [Fact]
    public void CandidateAndRuntimeTamperingAreRejected()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");
        _ = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        var candidatePath = Path.Combine(
            statePath,
            "rekor-shard-rotation",
            Guid.NewGuid().ToString("N"),
            "candidate");
        _ = SigstoreStateBootstrapper.EnsureRekorShardRotationCandidate(
            candidatePath);
        _ = SigstoreStateBootstrapper.StageRekorShardRuntime(
            statePath,
            candidatePath);

        var candidatePublicPath = Path.Combine(
            candidatePath,
            "public",
            "rekor",
            "signer.pub");
        var candidatePublic = File.ReadAllBytes(candidatePublicPath);
        File.Copy(
            Path.Combine(
                statePath,
                "active-generation",
                "public",
                "rekor",
                "signer.pub"),
            candidatePublicPath,
            overwrite: true);
        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper
                .EnsureRekorShardRotationCandidate(candidatePath));
        File.WriteAllBytes(candidatePublicPath, candidatePublic);

        File.WriteAllText(
            Path.Combine(
                statePath,
                "runtime",
                "rekor-secondary",
                "unexpected"),
            "tampered");
        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper.StageRekorShardRuntime(
                statePath,
                candidatePath));
    }

    private static string[] RelativeFiles(string path) =>
        Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
            .Select(
                file => Path.GetRelativePath(path, file)
                    .Replace(Path.DirectorySeparatorChar, '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-rekor-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
