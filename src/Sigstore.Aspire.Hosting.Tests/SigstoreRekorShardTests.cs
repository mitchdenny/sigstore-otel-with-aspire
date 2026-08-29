using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aspire.Hosting.ApplicationModel;
using Xunit;

namespace Sigstore.Aspire.Hosting.Tests;

public sealed class SigstoreRekorShardTests
{
    [Fact]
    public void PreflightAcceptsBoundAdditiveStandbyEntry()
    {
        var active = new string('a', 64);
        var standby = new string('b', 64);

        SigstoreOperationExecutor.ValidatePreflightTlogEntries(
            active,
            standby,
            [
                new(
                    0,
                    "http://rekor-sigstore.dev.localhost:3000",
                    active),
                new(
                    1,
                    "http://rekor-sigstore.dev.localhost:3000/standby",
                    standby)
            ]);
    }

    [Fact]
    public void PreflightRejectsUnboundAdditionalEntry()
    {
        var active = new string('a', 64);
        var standby = new string('b', 64);

        Assert.Throws<InvalidDataException>(
            () => SigstoreOperationExecutor
                .ValidatePreflightTlogEntries(
                    active,
                    standby,
                    [
                        new(
                            0,
                            "http://rekor-sigstore.dev.localhost:3000",
                            active),
                        new(
                            1,
                            "http://rekor-sigstore.dev.localhost:3000/standby",
                            new string('c', 64))
                    ]));
    }

    [Fact]
    public void ReadTlogEntriesParsesAValidSingleShardTrustedRoot()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trustedRoot = BuildTrustedRootWithTlog(
            "http://rekor-sigstore.dev.localhost:3000",
            signer);

        var entries = SigstoreRekorShard.ReadTlogEntries(trustedRoot);

        var entry = Assert.Single(entries);
        Assert.Equal(0, entry.Index);
        Assert.Equal(
            "http://rekor-sigstore.dev.localhost:3000",
            entry.BaseUrl);
        Assert.Equal(
            Convert.ToHexString(
                    SHA256.HashData(signer.ExportSubjectPublicKeyInfo()))
                .ToLowerInvariant(),
            entry.PublicKeySha256);
    }

    [Fact]
    public void ReadTlogEntriesRejectsALogIdThatDoesNotMatchThePublicKey()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var node = System.Text.Json.Nodes.JsonNode.Parse(
            BuildTrustedRootWithTlog(
                "http://rekor-sigstore.dev.localhost:3000",
                signer))!;
        node["tlogs"]![0]!["logId"]!["keyId"] =
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var tampered = Encoding.UTF8.GetBytes(node.ToJsonString());

        Assert.Throws<InvalidDataException>(
            () => SigstoreRekorShard.ReadTlogEntries(tampered));
    }

    [Fact]
    public void ReadTlogEntriesRejectsAMissingTlogsArray()
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { });

        Assert.Throws<InvalidDataException>(
            () => SigstoreRekorShard.ReadTlogEntries(bytes));
    }

    [Fact]
    public void
        ReadAndVerifyCheckpointAcceptsAZeroTreeSizeFirstCheckpoint()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string origin = "rekor-secondary-sigstore.dev.localhost";
        var checkpoint = BuildSignedCheckpoint(
            origin,
            treeSize: 0,
            rootHash: new byte[32],
            signer);

        var evidence = SigstoreRekorShard.ReadAndVerifyCheckpoint(
            checkpoint,
            origin,
            signer.ExportSubjectPublicKeyInfo());

        Assert.Equal(origin, evidence.Origin);
        Assert.Equal(0, evidence.TreeSize);
        Assert.Equal(
            Convert.ToHexString(new byte[32]).ToLowerInvariant(),
            evidence.RootHashHex);
    }

    [Fact]
    public void ReadAndVerifyCheckpointAcceptsANonZeroTreeSize()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string origin = "rekor-secondary-sigstore.dev.localhost";
        var rootHash = RandomNumberGenerator.GetBytes(32);
        var checkpoint = BuildSignedCheckpoint(
            origin,
            treeSize: 42,
            rootHash,
            signer);

        var evidence = SigstoreRekorShard.ReadAndVerifyCheckpoint(
            checkpoint,
            origin,
            signer.ExportSubjectPublicKeyInfo());

        Assert.Equal(42, evidence.TreeSize);
        Assert.Equal(
            Convert.ToHexString(rootHash).ToLowerInvariant(),
            evidence.RootHashHex);
    }

    [Fact]
    public void ReadAndVerifyCheckpointRejectsAnUnexpectedOrigin()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var checkpoint = BuildSignedCheckpoint(
            "rekor-sigstore.dev.localhost",
            treeSize: 1,
            rootHash: RandomNumberGenerator.GetBytes(32),
            signer);

        Assert.Throws<InvalidDataException>(
            () => SigstoreRekorShard.ReadAndVerifyCheckpoint(
                checkpoint,
                "rekor-secondary-sigstore.dev.localhost",
                signer.ExportSubjectPublicKeyInfo()));
    }

    [Fact]
    public void ReadAndVerifyCheckpointRejectsATamperedSignature()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string origin = "rekor-secondary-sigstore.dev.localhost";
        var checkpoint = BuildSignedCheckpoint(
            origin,
            treeSize: 1,
            rootHash: RandomNumberGenerator.GetBytes(32),
            signer);
        var lines = Encoding.UTF8.GetString(checkpoint)
            .Split('\n');
        // Retain the original signature but change the signed tree size,
        // so the note key hash still matches while the signature no
        // longer covers the (tampered) body.
        lines[1] = (long.Parse(
                lines[1],
                CultureInfo.InvariantCulture) + 1)
            .ToString(CultureInfo.InvariantCulture);
        var tampered = Encoding.UTF8.GetBytes(string.Join('\n', lines));

        Assert.Throws<InvalidDataException>(
            () => SigstoreRekorShard.ReadAndVerifyCheckpoint(
                tampered,
                origin,
                signer.ExportSubjectPublicKeyInfo()));
    }

    [Fact]
    public void ReadAndVerifyCheckpointRejectsAnUnrelatedSignerKey()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string origin = "rekor-secondary-sigstore.dev.localhost";
        var checkpoint = BuildSignedCheckpoint(
            origin,
            treeSize: 1,
            rootHash: RandomNumberGenerator.GetBytes(32),
            signer);

        Assert.Throws<InvalidDataException>(
            () => SigstoreRekorShard.ReadAndVerifyCheckpoint(
                checkpoint,
                origin,
                other.ExportSubjectPublicKeyInfo()));
    }

    [Fact]
    public void ReadArtifactTlogEntryAcceptsAFirstEntryAtIndexZero()
    {
        var logId = RandomNumberGenerator.GetBytes(32);
        var bundle = BuildBundleWithTlogEntry(
            logIndexAsString: "0",
            logId);

        var entry = SigstoreRekorShard.ReadArtifactTlogEntry(bundle);

        Assert.Equal(0, entry.LogIndex);
        Assert.Equal(
            Convert.ToHexString(logId).ToLowerInvariant(),
            entry.LogIdSha256);
    }

    [Fact]
    public void ReadArtifactTlogEntryAcceptsANumericLogIndex()
    {
        var logId = RandomNumberGenerator.GetBytes(32);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                verificationMaterial = new
                {
                    tlogEntries = new[]
                    {
                        new
                        {
                            logIndex = 7,
                            logId = new
                            {
                                keyId = Convert.ToBase64String(logId)
                            }
                        }
                    }
                }
            });

        var entry = SigstoreRekorShard.ReadArtifactTlogEntry(bytes);

        Assert.Equal(7, entry.LogIndex);
    }

    [Fact]
    public void ReadArtifactTlogEntryRejectsAMissingTlogEntriesArray()
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            new { verificationMaterial = new { } });

        Assert.Throws<InvalidDataException>(
            () => SigstoreRekorShard.ReadArtifactTlogEntry(bytes));
    }

    private static byte[] BuildTrustedRootWithTlog(
        string baseUrl,
        ECDsa signer)
    {
        var spki = signer.ExportSubjectPublicKeyInfo();
        var logId = SHA256.HashData(spki);
        return JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                tlogs = new[]
                {
                    new
                    {
                        baseUrl,
                        hashAlgorithm = "SHA2_256",
                        publicKey = new
                        {
                            rawBytes = Convert.ToBase64String(spki),
                            keyDetails = "PKIX_ECDSA_P256_SHA_256"
                        },
                        logId = new
                        {
                            keyId = Convert.ToBase64String(logId)
                        }
                    }
                }
            });
    }

    private static byte[] BuildBundleWithTlogEntry(
        string logIndexAsString,
        byte[] logId) =>
        JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                verificationMaterial = new
                {
                    tlogEntries = new[]
                    {
                        new
                        {
                            logIndex = logIndexAsString,
                            logId = new
                            {
                                keyId = Convert.ToBase64String(logId)
                            }
                        }
                    }
                }
            });

    /// <summary>
    /// Builds a C2SP/transparency-dev "signed note" checkpoint
    /// independently of <see cref="SigstoreRekorShard.ReadAndVerifyCheckpoint"/>,
    /// signing the body (through the blank line) with a standard note
    /// ECDSA key hash (the low four bytes of the SHA-256 fingerprint of the
    /// signer's SubjectPublicKeyInfo) followed by an ASN.1 DER-encoded
    /// ECDSA P-256/SHA-256 signature. The body includes its terminating
    /// newline; the unsigned second newline separates the signature block.
    /// </summary>
    private static byte[] BuildSignedCheckpoint(
        string origin,
        long treeSize,
        byte[] rootHash,
        ECDsa signer)
    {
        var body =
            $"{origin}\n" +
            $"{treeSize.ToString(CultureInfo.InvariantCulture)}\n" +
            $"{Convert.ToBase64String(rootHash)}\n";
        var signedMessage = body;
        var signature = signer.SignData(
            Encoding.UTF8.GetBytes(signedMessage),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        var keyHash = SHA256.HashData(signer.ExportSubjectPublicKeyInfo())
            .AsSpan(0, 4)
            .ToArray();
        var noteSignature = keyHash.Concat(signature).ToArray();
        var signatureLine =
            $"\u2014 {origin} " +
            $"{Convert.ToBase64String(noteSignature)}\n";
        return Encoding.UTF8.GetBytes(
            signedMessage + "\n" + signatureLine);
    }

    [Fact]
    public void TryReadShardCatalogReturnsNullWhenNoCatalogExists()
    {
        using var fixture = new TemporaryDirectory();

        Assert.Null(
            SigstoreRekorShard.TryReadShardCatalog(fixture.Path));
    }

    [Fact]
    public void ReadShardCatalogParsesAValidSingleShardCatalog()
    {
        using var fixture = new TemporaryDirectory();
        var initial = Sigstore.Bootstrap.SigstoreStateBootstrapper
            .EnsureInitialized(fixture.Path);
        var active = Sigstore.Bootstrap.SigstoreStateBootstrapper
            .ValidateRekorShardMaterial(
                Path.Combine(fixture.Path, "active-generation"));
        WriteSingleShardCatalog(
            fixture.Path,
            initial.TrustDomain.TrustDomainId,
            active.PublicKeySha256);

        var catalog = SigstoreRekorShard.ReadShardCatalog(fixture.Path);

        var shard = Assert.Single(catalog.Shards);
        Assert.Equal(1, catalog.SchemaVersion);
        Assert.Equal($"sha256-{active.PublicKeySha256}", catalog.ActiveShardId);
        Assert.Equal("primary", shard.Slot);
        Assert.Equal("active", shard.Status);
        Assert.Equal(active.PublicKeySha256, shard.PublicKeySha256);
    }

    [Fact]
    public void ReadShardCatalogRejectsAShardIdThatDoesNotMatchItsPublicKey()
    {
        using var fixture = new TemporaryDirectory();
        var initial = Sigstore.Bootstrap.SigstoreStateBootstrapper
            .EnsureInitialized(fixture.Path);
        var active = Sigstore.Bootstrap.SigstoreStateBootstrapper
            .ValidateRekorShardMaterial(
                Path.Combine(fixture.Path, "active-generation"));
        WriteSingleShardCatalog(
            fixture.Path,
            initial.TrustDomain.TrustDomainId,
            active.PublicKeySha256,
            tamperShardId: true);

        Assert.Throws<InvalidDataException>(
            () => SigstoreRekorShard.ReadShardCatalog(fixture.Path));
    }

    [Fact]
    public void ReadRotationJournalsReturnsEmptyWhenNoJournalDirectoryExists()
    {
        using var fixture = new TemporaryDirectory();

        Assert.Empty(
            SigstoreRekorShard.ReadRotationJournals(fixture.Path));
    }

    [Fact]
    public void ReadActivePublicKeySpkiMatchesTheBootstrappedRekorSigner()
    {
        using var fixture = new TemporaryDirectory();
        _ = Sigstore.Bootstrap.SigstoreStateBootstrapper.EnsureInitialized(
            fixture.Path);
        var active = Sigstore.Bootstrap.SigstoreStateBootstrapper
            .ValidateRekorShardMaterial(
                Path.Combine(fixture.Path, "active-generation"));

        var spki = SigstoreRekorShard.ReadActivePublicKeySpki(fixture.Path);

        Assert.Equal(
            active.PublicKeySha256,
            Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant());
    }

    [Fact]
    public void ReadStatusReportsReadyForABootstrappedSingleShardState()
    {
        using var fixture = new TemporaryDirectory();
        var initial = Sigstore.Bootstrap.SigstoreStateBootstrapper
            .EnsureInitialized(fixture.Path);
        var active = Sigstore.Bootstrap.SigstoreStateBootstrapper
            .ValidateRekorShardMaterial(
                Path.Combine(fixture.Path, "active-generation"));
        var spki = SigstoreRekorShard.ReadActivePublicKeySpki(fixture.Path);
        WriteTrustedRootTargets(
            fixture.Path,
            "http://rekor-sigstore.dev.localhost:3000",
            spki);
        WriteSingleShardCatalog(
            fixture.Path,
            initial.TrustDomain.TrustDomainId,
            active.PublicKeySha256);

        var status = SigstoreRekorShard.ReadStatus(fixture.Path);

        Assert.True(status.Ready, status.Reason);
        Assert.True(status.ActiveShardInTrustedRoot);
        Assert.True(status.ActiveShardMatchesCatalog);
        Assert.Equal(1, status.ShardCount);
        Assert.Null(status.IncompleteRotationOperationId);
        Assert.Null(status.SigningConfigRoutesExclusivelyToActiveShard);
        Assert.Null(status.ActiveCheckpoint);
    }

    [Fact]
    public void ReadStatusReportsSigningConfigMismatchWhenProvided()
    {
        using var fixture = new TemporaryDirectory();
        var initial = Sigstore.Bootstrap.SigstoreStateBootstrapper
            .EnsureInitialized(fixture.Path);
        var active = Sigstore.Bootstrap.SigstoreStateBootstrapper
            .ValidateRekorShardMaterial(
                Path.Combine(fixture.Path, "active-generation"));
        var spki = SigstoreRekorShard.ReadActivePublicKeySpki(fixture.Path);
        WriteTrustedRootTargets(
            fixture.Path,
            "http://rekor-sigstore.dev.localhost:3000",
            spki);
        WriteSingleShardCatalog(
            fixture.Path,
            initial.TrustDomain.TrustDomainId,
            active.PublicKeySha256);

        var status = SigstoreRekorShard.ReadStatus(
            fixture.Path,
            signingConfigRekorTlogUrls:
            [
                "http://rekor-secondary-sigstore.dev.localhost:3000"
            ]);

        Assert.False(status.Ready);
        Assert.False(status.SigningConfigRoutesExclusivelyToActiveShard);
        Assert.Equal(
            "SigningConfig does not route exclusively to the active " +
            "Rekor shard.",
            status.Reason);
    }

    private static void WriteTrustedRootTargets(
        string statePath,
        string baseUrl,
        byte[] spki)
    {
        var targetsPath = Path.Combine(
            statePath,
            "tuf",
            "active",
            "targets");
        Directory.CreateDirectory(targetsPath);
        File.WriteAllBytes(
            Path.Combine(targetsPath, "trusted_root.json"),
            BuildTrustedRootJsonWithRawKey(baseUrl, spki));
    }

    private static byte[] BuildTrustedRootJsonWithRawKey(
        string baseUrl,
        byte[] spki)
    {
        var logId = SHA256.HashData(spki);
        return JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                tlogs = new[]
                {
                    new
                    {
                        baseUrl,
                        hashAlgorithm = "SHA2_256",
                        publicKey = new
                        {
                            rawBytes = Convert.ToBase64String(spki),
                            keyDetails = "PKIX_ECDSA_P256_SHA_256"
                        },
                        logId = new
                        {
                            keyId = Convert.ToBase64String(logId)
                        }
                    }
                }
            });
    }

    private static void WriteSingleShardCatalog(
        string statePath,
        string trustDomainId,
        string publicKeySha256,
        bool tamperShardId = false)
    {
        var directory = Path.Combine(statePath, "data", "rekor-shards");
        Directory.CreateDirectory(directory);
        var now = DateTimeOffset.UtcNow;
        var shardId = tamperShardId
            ? "sha256-0000000000000000000000000000000000000000000000000000000000000000"
            : $"sha256-{publicKeySha256}";
        var catalog = new
        {
            schemaVersion = 1,
            trustDomainId,
            activeShardId = shardId,
            updatedAtUtc = now,
            shards = new[]
            {
                new
                {
                    shardId,
                    slot = "primary",
                    baseUrl = "http://rekor-sigstore.dev.localhost:3000",
                    origin = "rekor-sigstore.dev.localhost",
                    publicKeySha256,
                    logIdSha256 = publicKeySha256,
                    stateId = Guid.NewGuid().ToString(),
                    dataPath = "data/rekor",
                    resourceName = "rekor-server",
                    createdAtUtc = now,
                    activatedAtUtc = now,
                    status = "active"
                }
            }
        };
        File.WriteAllBytes(
            Path.Combine(directory, "state.json"),
            JsonSerializer.SerializeToUtf8Bytes(catalog));
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-rekor-shard-tests-{Guid.NewGuid():N}");
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
