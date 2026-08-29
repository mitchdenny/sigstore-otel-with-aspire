using System.Security.Cryptography;
using Sigstore.Bootstrap;
using Xunit;

namespace Sigstore.Bootstrap.Tests;

/// <summary>
/// Durable-state coverage for the certificate-transparency shard rotation
/// primitives: the isolated candidate signer, the least-privilege
/// secondary runtime projection, and the staged/promoted Fulcio CT
/// selection that decides which shard a restarted Fulcio binds to.
/// </summary>
public sealed class CtLogShardRotationTests
{
    [Fact]
    public void InitializedStateHasSeparateEmptySecondaryStorage()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");

        var initial = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        var primaryPath = Path.Combine(statePath, "data", "ctlog");
        var secondaryPath = Path.Combine(
            statePath,
            "data",
            "ctlog-shards",
            "secondary");

        Assert.True(Directory.Exists(primaryPath));
        Assert.True(Directory.Exists(secondaryPath));
        Assert.Empty(Directory.EnumerateFileSystemEntries(secondaryPath));
        Assert.Equal(
            initial.TrustDomain.CtLogStateId,
            File.ReadAllText(
                Path.Combine(primaryPath, "bootstrap-state")));
        Assert.Null(initial.Generation.CtLogRotationOperationId);
        Assert.Null(initial.Generation.CtLogPriorGenerationId);
        Assert.Null(initial.Generation.CtLogShardId);
    }

    [Fact]
    public void BootstrapSelectsThePrimaryShardForFulcio()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");
        var initial = SigstoreStateBootstrapper.EnsureInitialized(statePath);

        var selection =
            SigstoreStateBootstrapper.ReadFulcioCtRuntimeProjection(
                statePath);

        Assert.Equal("primary", selection.Selector);
        Assert.Equal(
            "tesseract-sigstore.dev.localhost",
            selection.Origin);
        Assert.Equal(
            initial.Generation.CtLogPublicKeySha256,
            selection.CtLogPublicKeySha256);
        Assert.False(selection.PromotionPending);
        Assert.Null(selection.StagedCtLogPublicKeySha256);
        Assert.Equal(
            ["primary.pub", "selection"],
            RelativeFiles(
                Path.Combine(statePath, "runtime", "fulcio-ct")));
        Assert.Equal(
            "sigstore-fulcio-ct-selection/1\n"
                + "primary\n"
                + "tesseract-sigstore.dev.localhost\n"
                + "primary.pub\n",
            File.ReadAllText(
                Path.Combine(
                    statePath,
                    "runtime",
                    "fulcio-ct",
                    "selection")));
    }

    [Fact]
    public void CandidateIsImmutableDistinctAndLogIdBound()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");
        var initial = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        var candidatePath = CandidatePath(statePath);

        var candidate =
            SigstoreStateBootstrapper.EnsureCtLogShardRotationCandidate(
                candidatePath);
        var replay =
            SigstoreStateBootstrapper.EnsureCtLogShardRotationCandidate(
                candidatePath);

        Assert.Equal(candidate, replay);
        Assert.NotEqual(
            initial.Generation.CtLogPublicKeySha256,
            candidate.PublicKeySha256);
        Assert.Equal(candidate.PublicKeySha256, candidate.LogId);
        Assert.Equal($"sha256-{candidate.LogId}", candidate.ShardId);
        Assert.Equal(
            [
                "private/ctlog/privkey.pem",
                "public/ctlog/pubkey.pem"
            ],
            RelativeFiles(candidatePath));

        // The CT log ID an SCT carries is the SHA-256 of the signer's
        // SubjectPublicKeyInfo, so the derived identity must match exactly.
        using var publicKey = ECDsa.Create();
        publicKey.ImportFromPem(
            File.ReadAllText(
                Path.Combine(
                    candidatePath,
                    "public",
                    "ctlog",
                    "pubkey.pem")));
        Assert.Equal(256, publicKey.KeySize);
        Assert.Equal(
            candidate.LogId,
            Convert.ToHexString(
                    SHA256.HashData(
                        publicKey.ExportSubjectPublicKeyInfo()))
                .ToLowerInvariant());
    }

    [Fact]
    public void SecondaryRuntimeCarriesOnlyItsSignerAndTheCompleteRoots()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");
        _ = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        var candidatePath = CandidatePath(statePath);
        var candidate =
            SigstoreStateBootstrapper.EnsureCtLogShardRotationCandidate(
                candidatePath);

        var staged = SigstoreStateBootstrapper.StageCtLogShardRuntime(
            statePath,
            candidatePath);
        var replay = SigstoreStateBootstrapper.StageCtLogShardRuntime(
            statePath,
            candidatePath);
        var runtimePath = Path.Combine(
            statePath,
            "runtime",
            "tesseract-secondary");

        Assert.Equal(candidate.PublicKeySha256, staged.PublicKeySha256);
        Assert.Equal(candidate.LogId, staged.LogId);
        Assert.Equal(candidate.ShardId, staged.ShardId);
        Assert.Equal(staged.PublicKeySha256, replay.PublicKeySha256);
        Assert.Equal(
            staged.AcceptedRootsSha256,
            replay.AcceptedRootsSha256);
        Assert.Equal(
            staged.AcceptedRootFingerprints,
            replay.AcceptedRootFingerprints);

        // The staged runtime reports the identity of the complete accepted
        // Fulcio root bundle so it can be recorded durably in the catalog.
        var primaryBundle = File.ReadAllBytes(
            Path.Combine(
                statePath,
                "runtime",
                "tesseract",
                "accepted-roots.pem"));
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(primaryBundle))
                .ToLowerInvariant(),
            staged.AcceptedRootsSha256);
        Assert.NotEmpty(staged.AcceptedRootFingerprints);
        Assert.Equal(
            ["accepted-roots.pem", "privkey.pem"],
            RelativeFiles(runtimePath));
        Assert.False(
            File.Exists(Path.Combine(runtimePath, "pubkey.pem")));

        // The secondary shard must accept exactly the complete Fulcio root
        // set the historical primary shard already accepts.
        Assert.Equal(
            File.ReadAllBytes(
                Path.Combine(
                    statePath,
                    "runtime",
                    "tesseract",
                    "accepted-roots.pem")),
            File.ReadAllBytes(
                Path.Combine(runtimePath, "accepted-roots.pem")));

        // The primary shard's signer is never re-projected.
        Assert.Equal(
            File.ReadAllBytes(
                Path.Combine(
                    statePath,
                    "active-generation",
                    "private",
                    "ctlog",
                    "privkey.pem")),
            File.ReadAllBytes(
                Path.Combine(
                    statePath,
                    "runtime",
                    "tesseract",
                    "privkey.pem")));
        Assert.NotEqual(
            File.ReadAllBytes(
                Path.Combine(runtimePath, "privkey.pem")),
            File.ReadAllBytes(
                Path.Combine(
                    statePath,
                    "runtime",
                    "tesseract",
                    "privkey.pem")));

        var reused = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        Assert.Equal(BootstrapAction.Reused, reused.Action);
    }

    [Fact]
    public void StagingTheFulcioSelectionNeverChangesTheLiveSelection()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");
        var initial = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        var candidatePath = CandidatePath(statePath);
        var candidate =
            SigstoreStateBootstrapper.EnsureCtLogShardRotationCandidate(
                candidatePath);
        _ = SigstoreStateBootstrapper.StageCtLogShardRuntime(
            statePath,
            candidatePath);

        var staged =
            SigstoreStateBootstrapper.StageFulcioCtRuntimeProjection(
                statePath,
                candidatePath);
        var replay =
            SigstoreStateBootstrapper.StageFulcioCtRuntimeProjection(
                statePath,
                candidatePath);

        Assert.Equal(staged, replay);
        Assert.Equal("primary", staged.Selector);
        Assert.Equal(
            initial.Generation.CtLogPublicKeySha256,
            staged.CtLogPublicKeySha256);
        Assert.True(staged.PromotionPending);
        Assert.Equal("secondary", staged.StagedSelector);
        Assert.Equal(
            "tesseract-secondary-sigstore.dev.localhost",
            staged.StagedOrigin);
        Assert.Equal(
            candidate.PublicKeySha256,
            staged.StagedCtLogPublicKeySha256);

        // Staging is purely additive: the one selection manifest the
        // running Fulcio reads is untouched, so before the promotion flip
        // Fulcio is still wholly bound to the primary shard.
        Assert.Equal(
            "sigstore-fulcio-ct-selection/1\n"
                + "primary\n"
                + "tesseract-sigstore.dev.localhost\n"
                + "primary.pub\n",
            File.ReadAllText(
                Path.Combine(
                    statePath,
                    "runtime",
                    "fulcio-ct",
                    "selection")));
        Assert.Equal(
            ["primary.pub", "secondary.pub", "selection"],
            RelativeFiles(
                Path.Combine(statePath, "runtime", "fulcio-ct")));
    }

    [Fact]
    public void PromotionRequiresAGenerationBoundToTheOperation()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");
        var initial = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        var candidatePath = CandidatePath(statePath);
        var candidate =
            SigstoreStateBootstrapper.EnsureCtLogShardRotationCandidate(
                candidatePath);
        _ = SigstoreStateBootstrapper.StageCtLogShardRuntime(
            statePath,
            candidatePath);
        _ = SigstoreStateBootstrapper.StageFulcioCtRuntimeProjection(
            statePath,
            candidatePath);

        // No CT-rotated generation exists yet, so promotion is refused.
        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper
                .ActivateFulcioCtRuntimeProjection(
                    statePath,
                    Guid.NewGuid().ToString("N"),
                    initial.Generation.CtLogPublicKeySha256,
                    candidate.PublicKeySha256));

        // A malformed operation ID and an unchanged signer are rejected
        // before any state is inspected.
        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper
                .ActivateFulcioCtRuntimeProjection(
                    statePath,
                    "NOT-A-GUID",
                    initial.Generation.CtLogPublicKeySha256,
                    candidate.PublicKeySha256));
        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper
                .ActivateFulcioCtRuntimeProjection(
                    statePath,
                    Guid.NewGuid().ToString("N"),
                    initial.Generation.CtLogPublicKeySha256,
                    initial.Generation.CtLogPublicKeySha256));

        Assert.Equal(
            "sigstore-fulcio-ct-selection/1\n"
                + "primary\n"
                + "tesseract-sigstore.dev.localhost\n"
                + "primary.pub\n",
            File.ReadAllText(
                Path.Combine(
                    statePath,
                    "runtime",
                    "fulcio-ct",
                    "selection")));
    }

    [Fact]
    public void TamperedFulcioCtSelectionManifestsAreRejected()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");
        _ = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        var selectionPath = Path.Combine(
            statePath,
            "runtime",
            "fulcio-ct",
            "selection");
        var original = File.ReadAllBytes(selectionPath);

        // Every mixed, truncated, extended or mislabelled manifest is
        // refused: selector, origin and key file name must always agree.
        foreach (var tampered in new[]
        {
            // A selector naming a shard whose key was never staged.
            "sigstore-fulcio-ct-selection/1\nsecondary\n"
                + "tesseract-secondary-sigstore.dev.localhost\n"
                + "secondary.pub\n",
            // A mixed selector/origin pair.
            "sigstore-fulcio-ct-selection/1\nprimary\n"
                + "tesseract-secondary-sigstore.dev.localhost\n"
                + "primary.pub\n",
            // A mixed selector/key pair.
            "sigstore-fulcio-ct-selection/1\nprimary\n"
                + "tesseract-sigstore.dev.localhost\nsecondary.pub\n",
            // An unknown selector.
            "sigstore-fulcio-ct-selection/1\nthird\n"
                + "tesseract-sigstore.dev.localhost\nprimary.pub\n",
            // A wrong schema header.
            "sigstore-fulcio-ct-selection/2\nprimary\n"
                + "tesseract-sigstore.dev.localhost\nprimary.pub\n",
            // A truncated manifest.
            "sigstore-fulcio-ct-selection/1\nprimary\n",
            // An extended manifest.
            "sigstore-fulcio-ct-selection/1\nprimary\n"
                + "tesseract-sigstore.dev.localhost\nprimary.pub\nextra\n",
            // A manifest without its terminating newline.
            "sigstore-fulcio-ct-selection/1\nprimary\n"
                + "tesseract-sigstore.dev.localhost\nprimary.pub"
        })
        {
            WriteSelection(selectionPath, tampered);
            Assert.Throws<InvalidDataException>(
                () => SigstoreStateBootstrapper
                    .ReadFulcioCtRuntimeProjection(statePath));
        }

        WriteSelection(selectionPath, original);
        Assert.Equal(
            "primary",
            SigstoreStateBootstrapper
                .ReadFulcioCtRuntimeProjection(statePath)
                .Selector);
    }

    private static void WriteSelection(string path, string contents) =>
        WriteSelection(
            path,
            System.Text.Encoding.UTF8.GetBytes(contents));

    private static void WriteSelection(string path, byte[] contents)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        File.WriteAllBytes(path, contents);
    }

    [Fact]
    public void CandidateAndRuntimeTamperingAreRejected()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");
        _ = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        var candidatePath = CandidatePath(statePath);
        _ = SigstoreStateBootstrapper.EnsureCtLogShardRotationCandidate(
            candidatePath);
        _ = SigstoreStateBootstrapper.StageCtLogShardRuntime(
            statePath,
            candidatePath);

        var candidatePublicPath = Path.Combine(
            candidatePath,
            "public",
            "ctlog",
            "pubkey.pem");
        var candidatePublic = File.ReadAllBytes(candidatePublicPath);
        File.Copy(
            Path.Combine(
                statePath,
                "active-generation",
                "public",
                "ctlog",
                "pubkey.pem"),
            candidatePublicPath,
            overwrite: true);
        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper
                .EnsureCtLogShardRotationCandidate(candidatePath));
        File.WriteAllBytes(candidatePublicPath, candidatePublic);

        File.WriteAllText(
            Path.Combine(
                statePath,
                "runtime",
                "tesseract-secondary",
                "unexpected"),
            "tampered");
        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper.StageCtLogShardRuntime(
                statePath,
                candidatePath));
    }

    [Fact]
    public void ASecondaryShardWithForeignAcceptedRootsIsRejected()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, "state");
        _ = SigstoreStateBootstrapper.EnsureInitialized(statePath);
        var candidatePath = CandidatePath(statePath);
        _ = SigstoreStateBootstrapper.EnsureCtLogShardRotationCandidate(
            candidatePath);
        _ = SigstoreStateBootstrapper.StageCtLogShardRuntime(
            statePath,
            candidatePath);

        var secondaryRootsPath = Path.Combine(
            statePath,
            "runtime",
            "tesseract-secondary",
            "accepted-roots.pem");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                secondaryRootsPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        File.WriteAllText(secondaryRootsPath, "");

        Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper.EnsureInitialized(statePath));
    }

    private static string CandidatePath(string statePath) =>
        Path.Combine(
            statePath,
            "ct-log-shard-rotation",
            Guid.NewGuid().ToString("N"),
            "candidate");

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
                $"sigstore-ctlog-{Guid.NewGuid():N}");
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
