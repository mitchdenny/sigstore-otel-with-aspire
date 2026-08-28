using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Sigstore.Bootstrap;
using Xunit;

namespace Sigstore.Aspire.Hosting.Tests;

public sealed class SigstoreTimestampAuthorityTests
{
    [Fact]
    public void StatusAcceptsAdditiveTrustOnlyAfterSignerActivation()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, ".sigstore");
        var initial = SigstoreStateBootstrapper.EnsureInitialized(
            statePath);
        var initialPath = Path.Combine(
            statePath,
            "generations",
            initial.Generation.GenerationId);
        var initialMaterial =
            SigstoreStateBootstrapper.ValidateTimestampAuthority(
                initialPath);
        var rotatedPath = Path.Combine(
            statePath,
            "generations",
            "generation-00000002");
        var rotated =
            SigstoreStateBootstrapper
                .EnsureTimestampAuthorityRotationCandidate(
                    rotatedPath);
        Directory.Delete(
            Path.Combine(statePath, "active-generation"));
        Directory.CreateSymbolicLink(
            Path.Combine(statePath, "active-generation"),
            Path.Combine(
                "generations",
                "generation-00000002"));
        WriteTrustedRoot(
            statePath,
            [
                ReadPair(initialPath),
                ReadPair(rotatedPath)
            ]);

        var authorities =
            SigstoreTimestampAuthority.ReadTrustedAuthorities(
                statePath);
        var activeProbe = NewProbe(
            rotated.RootSha256,
            rotated.LeafSha256);
        var status = SigstoreTimestampAuthority.ReadStatus(
            statePath,
            activeProbe);

        Assert.Equal(2, status.TrustedAuthorities.Count);
        Assert.Equal(
            initialMaterial.LeafSha256,
            status.TrustedAuthorities[0].LeafSha256);
        Assert.Equal(
            rotated.LeafSha256,
            status.TrustedAuthorities[1].LeafSha256);
        Assert.Equal(
            rotated.LeafSha256,
            status.RunningSigner.LeafSha256);
        Assert.True(status.ActiveSignerMatches);
        var pending = SigstoreTimestampAuthority.ReadStatus(
                statePath,
                NewProbe(
                    initialMaterial.RootSha256,
                    initialMaterial.LeafSha256));
        Assert.False(pending.ActiveSignerMatches);
        Assert.Equal(2, pending.TrustedAuthorities.Count);
    }

    [Fact]
    public void TrustedRootRejectsDuplicateTimestampChains()
    {
        using var fixture = new TemporaryDirectory();
        var statePath = Path.Combine(fixture.Path, ".sigstore");
        var initial = SigstoreStateBootstrapper.EnsureInitialized(
            statePath);
        var pair = ReadPair(
            Path.Combine(
                statePath,
                "generations",
                initial.Generation.GenerationId));
        WriteTrustedRoot(statePath, [pair, pair]);

        Assert.Throws<InvalidDataException>(
            () => SigstoreTimestampAuthority.ReadTrustedAuthorities(
                statePath));
    }

    private static SigstoreTimestampAuthorityProbeEvidence NewProbe(
        string rootSha256,
        string leafSha256) =>
        new(
            rootSha256,
            leafSha256,
            "CN=Timestamp Authority",
            "CN=Timestamp Authority Root",
            new string('1', 64),
            new string('2', 64),
            new string('3', 64),
            DateTimeOffset.UtcNow);

    private static CertificatePair ReadPair(string generationPath)
    {
        using var leaf = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                Path.Combine(
                    generationPath,
                    "public",
                    "tsa",
                    "leaf.pem")));
        using var root = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                Path.Combine(
                    generationPath,
                    "public",
                    "tsa",
                    "root.pem")));
        return new CertificatePair(leaf.RawData, root.RawData);
    }

    private static void WriteTrustedRoot(
        string statePath,
        IReadOnlyList<CertificatePair> pairs)
    {
        var path = Path.Combine(
            statePath,
            "tuf",
            "active",
            "targets");
        Directory.CreateDirectory(path);
        File.WriteAllText(
            Path.Combine(path, "trusted_root.json"),
            JsonSerializer.Serialize(
                new
                {
                    timestampAuthorities = pairs.Select(
                        pair => new
                        {
                            uri = SigstoreDefaults.TimestampAuthorityUrl,
                            certChain = new
                            {
                                certificates = new[]
                                {
                                    new { rawBytes = pair.Leaf },
                                    new { rawBytes = pair.Root }
                                }
                            }
                        })
                }));
    }

    private sealed record CertificatePair(
        byte[] Leaf,
        byte[] Root);

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-hosting-tsa-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}
