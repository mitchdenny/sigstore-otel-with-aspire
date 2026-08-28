using Sigstore.Bootstrap;
using Xunit;

namespace Sigstore.Bootstrap.Tests;

public sealed class TimestampAuthorityRotationTests
{
    [Fact]
    public void CandidateUsesExistingProfileAndBoundsActiveSecrets()
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var initial = SigstoreStateBootstrapper.EnsureInitialized(state);
        var initialMaterial =
            SigstoreStateBootstrapper.ValidateTimestampAuthority(
                Path.Combine(
                    state,
                    "generations",
                    initial.Generation.GenerationId));
        var candidatePath = Path.Combine(
            state,
            "tsa-rotation",
            Guid.NewGuid().ToString("N"),
            "candidate");

        var candidate =
            SigstoreStateBootstrapper
                .EnsureTimestampAuthorityRotationCandidate(
                    candidatePath);
        var replay =
            SigstoreStateBootstrapper
                .EnsureTimestampAuthorityRotationCandidate(
                    candidatePath);

        Assert.Equal(candidate, replay);
        Assert.True(initialMaterial.HasRootPrivateKey);
        Assert.False(candidate.HasRootPrivateKey);
        Assert.NotEqual(
            initialMaterial.RootSha256,
            candidate.RootSha256);
        Assert.NotEqual(
            initialMaterial.LeafSha256,
            candidate.LeafSha256);
        Assert.Equal(
            [
                "private/tsa/password",
                "private/tsa/signer.key",
                "public/tsa/cert-chain.pem",
                "public/tsa/leaf.pem",
                "public/tsa/root.pem"
            ],
            Directory.EnumerateFiles(
                    candidatePath,
                    "*",
                    SearchOption.AllDirectories)
                .Select(
                    path => Path.GetRelativePath(candidatePath, path)
                        .Replace(Path.DirectorySeparatorChar, '/'))
                .Order(StringComparer.Ordinal));
        Assert.StartsWith(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            File.ReadAllText(
                Path.Combine(
                    candidatePath,
                    "private",
                    "tsa",
                    "signer.key")),
            StringComparison.Ordinal);
    }

    [Fact]
    public void CandidateTamperingIsRejectedInsteadOfRegenerated()
    {
        using var fixture = new TemporaryDirectory();
        var candidatePath = Path.Combine(
            fixture.Path,
            "candidate");
        _ = SigstoreStateBootstrapper
            .EnsureTimestampAuthorityRotationCandidate(candidatePath);
        File.Copy(
            Path.Combine(
                candidatePath,
                "public",
                "tsa",
                "root.pem"),
            Path.Combine(
                candidatePath,
                "public",
                "tsa",
                "leaf.pem"),
            overwrite: true);

        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper
                .EnsureTimestampAuthorityRotationCandidate(
                    candidatePath));
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-tsa-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}
