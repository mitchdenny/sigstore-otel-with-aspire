using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aspire.Hosting.ApplicationModel;
using Xunit;

namespace Sigstore.Aspire.Hosting.Tests;

/// <summary>
/// Wire-format and durable-state coverage for the certificate-transparency
/// shard helpers the rotation command and read-only status depend on: the
/// additive <c>ctlogs</c> TrustedRoot section, the per-shard checkpoint
/// note (which binds a checkpoint to one origin and one log ID), and the
/// durable shard catalog.
/// </summary>
public sealed class SigstoreCtLogShardTests
{
    [Fact]
    public void CtlogEntriesRequireLogIdsDerivedFromTheirOwnKeys()
    {
        using var primary = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var secondary = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var entries = SigstoreCtLogShard.ReadCtlogEntries(
            TrustedRoot(
                (SigstoreCtLogShard.PrimaryUrl, primary, null),
                (SigstoreCtLogShard.SecondaryUrl, secondary, null)));

        Assert.Equal(2, entries.Count);
        Assert.Equal(SigstoreCtLogShard.PrimaryUrl, entries[0].BaseUrl);
        Assert.Equal(SigstoreCtLogShard.SecondaryUrl, entries[1].BaseUrl);
        Assert.Equal(Fingerprint(primary), entries[0].PublicKeySha256);
        Assert.Equal(Fingerprint(secondary), entries[1].PublicKeySha256);
        Assert.NotEqual(
            entries[0].PublicKeySha256,
            entries[1].PublicKeySha256);
    }

    [Fact]
    public void CtlogEntriesRejectMismatchedOrDuplicateLogIds()
    {
        using var primary = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var secondary = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        Assert.Throws<InvalidDataException>(
            () => SigstoreCtLogShard.ReadCtlogEntries(
                TrustedRoot(
                    (
                        SigstoreCtLogShard.PrimaryUrl,
                        primary,
                        SHA256.HashData(
                            secondary.ExportSubjectPublicKeyInfo())))));
        Assert.Throws<InvalidDataException>(
            () => SigstoreCtLogShard.ReadCtlogEntries(
                TrustedRoot(
                    (SigstoreCtLogShard.PrimaryUrl, primary, null),
                    (SigstoreCtLogShard.PrimaryUrl, primary, null))));
        Assert.Throws<InvalidDataException>(
            () => SigstoreCtLogShard.ReadCtlogEntries(
                Encoding.UTF8.GetBytes("""{"ctlogs":[]}""")));
    }

    [Fact]
    public void CheckpointVerificationIsBoundToOriginAndSigner()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var checkpoint = SignedCheckpoint(
            SigstoreCtLogShard.SecondaryOrigin,
            signer,
            treeSize: 7,
            timestamp: 1_700_000_000_000);

        var evidence = SigstoreCtLogShard.ReadAndVerifyCheckpoint(
            checkpoint,
            SigstoreCtLogShard.SecondaryOrigin,
            signer);

        Assert.Equal(SigstoreCtLogShard.SecondaryOrigin, evidence.Origin);
        Assert.Equal(7ul, evidence.TreeSize);
        Assert.Equal(1_700_000_000_000ul, evidence.Timestamp);
        Assert.Equal(Fingerprint(signer), evidence.LogId);

        // A checkpoint only verifies for the exact origin and signer it was
        // produced for, which is what makes "this checkpoint came from the
        // secondary shard" a real proof.
        Assert.Throws<InvalidDataException>(
            () => SigstoreCtLogShard.ReadAndVerifyCheckpoint(
                checkpoint,
                SigstoreCtLogShard.PrimaryOrigin,
                signer));
        Assert.Throws<InvalidDataException>(
            () => SigstoreCtLogShard.ReadAndVerifyCheckpoint(
                checkpoint,
                SigstoreCtLogShard.SecondaryOrigin,
                other));

        var tampered = checkpoint.ToArray();
        tampered[SigstoreCtLogShard.SecondaryOrigin.Length + 1] = (byte)'9';
        Assert.Throws<InvalidDataException>(
            () => SigstoreCtLogShard.ReadAndVerifyCheckpoint(
                tampered,
                SigstoreCtLogShard.SecondaryOrigin,
                signer));
    }

    [Fact]
    public void ShardCatalogRequiresOrderedPrimaryAndSecondarySlots()
    {
        using var directory = new TemporaryDirectory();
        var primary = Fingerprint(
            ECDsa.Create(ECCurve.NamedCurves.nistP256));
        var secondary = Fingerprint(
            ECDsa.Create(ECCurve.NamedCurves.nistP256));

        WriteCatalog(
            directory.Path,
            $$"""
            {
              "schemaVersion": 1,
              "trustDomainId": "sha256-{{new string('a', 64)}}",
              "activeShardId": "sha256-{{secondary}}",
              "updatedAtUtc": "2026-01-01T00:00:00Z",
              "shards": [
                {{Shard(primary, "primary", "historical")}},
                {{Shard(secondary, "secondary", "active")}}
              ]
            }
            """);
        var catalog = SigstoreCtLogShard.ReadShardCatalog(directory.Path);
        Assert.Equal(2, catalog.Shards.Count);
        Assert.Equal("historical", catalog.Shards[0].Status);
        Assert.Equal("active", catalog.Shards[1].Status);
        Assert.Equal($"sha256-{secondary}", catalog.ActiveShardId);

        // A secondary shard that is not actually active, or a primary that
        // was not retired, is rejected rather than reported.
        WriteCatalog(
            directory.Path,
            $$"""
            {
              "schemaVersion": 1,
              "trustDomainId": "sha256-{{new string('a', 64)}}",
              "activeShardId": "sha256-{{primary}}",
              "updatedAtUtc": "2026-01-01T00:00:00Z",
              "shards": [
                {{Shard(primary, "primary", "active")}},
                {{Shard(secondary, "secondary", "active")}}
              ]
            }
            """);
        Assert.Throws<InvalidDataException>(
            () => SigstoreCtLogShard.ReadShardCatalog(directory.Path));

        // Each shard carries the identity of the accepted Fulcio root
        // bundle it enforces, and the secondary shard must have been
        // created accepting exactly the primary shard's complete bundle.
        WriteCatalog(
            directory.Path,
            $$"""
            {
              "schemaVersion": 1,
              "trustDomainId": "sha256-{{new string('a', 64)}}",
              "activeShardId": "sha256-{{secondary}}",
              "updatedAtUtc": "2026-01-01T00:00:00Z",
              "shards": [
                {{Shard(primary, "primary", "historical")}},
                {{Shard(secondary, "secondary", "active")
                    .Replace(
                        AcceptedRootsSha256,
                        new string('4', 64),
                        StringComparison.Ordinal)}}
              ]
            }
            """);
        Assert.Throws<InvalidDataException>(
            () => SigstoreCtLogShard.ReadShardCatalog(directory.Path));

        WriteCatalog(
            directory.Path,
            $$"""
            {
              "schemaVersion": 1,
              "trustDomainId": "sha256-{{new string('a', 64)}}",
              "activeShardId": "sha256-{{secondary}}",
              "updatedAtUtc": "2026-01-01T00:00:00Z",
              "shards": [
                {{Shard(primary, "primary", "historical")}},
                {{Shard(secondary, "secondary", "active")
                    .Replace(
                        "\"acceptedRootCount\": 2",
                        "\"acceptedRootCount\": 3",
                        StringComparison.Ordinal)}}
              ]
            }
            """);
        Assert.Throws<InvalidDataException>(
            () => SigstoreCtLogShard.ReadShardCatalog(directory.Path));
    }

    [Fact]
    public void ShardCatalogIsAbsentUntilTheFirstRotation()
    {
        using var directory = new TemporaryDirectory();
        Assert.Null(
            SigstoreCtLogShard.TryReadShardCatalog(directory.Path));
        Assert.Empty(
            SigstoreCtLogShard.ReadRotationJournals(directory.Path));
    }

    // Every shard records the identity of the complete Fulcio root bundle
    // it accepts: the bundle digest plus its ordered per-root fingerprints.
    private const string AcceptedRootsSha256 =
        "1111111111111111111111111111111111111111111111111111111111111111";

    private static readonly string[] AcceptedRootFingerprints =
    [
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333"
    ];

    private static string Shard(
        string publicKey,
        string slot,
        string status)
    {
        var url = slot == "primary"
            ? SigstoreCtLogShard.PrimaryUrl
            : SigstoreCtLogShard.SecondaryUrl;
        var origin = slot == "primary"
            ? SigstoreCtLogShard.PrimaryOrigin
            : SigstoreCtLogShard.SecondaryOrigin;
        var dataPath = slot == "primary"
            ? SigstoreCtLogShard.PrimaryDataRelativePath
            : SigstoreCtLogShard.SecondaryDataRelativePath;
        var resource = slot == "primary"
            ? SigstoreCtLogShard.PrimaryResourceName
            : SigstoreCtLogShard.SecondaryResourceName;
        return $$"""
            {
                  "shardId": "sha256-{{publicKey}}",
                  "slot": "{{slot}}",
                  "baseUrl": "{{url}}",
                  "origin": "{{origin}}",
                  "publicKeySha256": "{{publicKey}}",
                  "logIdSha256": "{{publicKey}}",
                  "stateId": "{{slot}}-state",
                  "dataPath": "{{dataPath}}",
                  "resourceName": "{{resource}}",
                  "createdAtUtc": "2026-01-01T00:00:00Z",
                  "activatedAtUtc": "2026-01-01T00:00:00Z",
                  "status": "{{status}}",
                  "acceptedRootsSha256": "{{AcceptedRootsSha256}}",
                  "acceptedRootCount": 2,
                  "acceptedRootFingerprints": [
                    "{{AcceptedRootFingerprints[0]}}",
                    "{{AcceptedRootFingerprints[1]}}"
                  ]
                }
            """;
    }

    private static void WriteCatalog(string statePath, string json)
    {
        var path = SigstoreCtLogShard.ShardCatalogPath(statePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, json);
    }

    private static byte[] TrustedRoot(
        params (string BaseUrl, ECDsa Key, byte[]? LogId)[] entries)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteStartArray("ctlogs");
            foreach (var (baseUrl, key, logId) in entries)
            {
                var spki = key.ExportSubjectPublicKeyInfo();
                writer.WriteStartObject();
                writer.WriteString("baseUrl", baseUrl);
                writer.WriteString("hashAlgorithm", "SHA2_256");
                writer.WriteStartObject("publicKey");
                writer.WriteString(
                    "rawBytes",
                    Convert.ToBase64String(spki));
                writer.WriteString(
                    "keyDetails",
                    "PKIX_ECDSA_P256_SHA_256");
                writer.WriteEndObject();
                writer.WriteStartObject("logId");
                writer.WriteString(
                    "keyId",
                    Convert.ToBase64String(
                        logId ?? SHA256.HashData(spki)));
                writer.WriteEndObject();
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    /// <summary>
    /// Produces a Tesseract-shaped signed checkpoint note: origin, tree
    /// size, base64 root hash, blank line, and a signature line whose note
    /// key hash binds the signature to the origin and the signer's log ID.
    /// </summary>
    private static byte[] SignedCheckpoint(
        string origin,
        ECDsa signer,
        ulong treeSize,
        ulong timestamp)
    {
        var rootHash = SHA256.HashData(
            Encoding.UTF8.GetBytes($"{origin}:{treeSize}"));
        var signed = new byte[2 + 8 + 8 + rootHash.Length];
        signed[0] = 0;
        signed[1] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(
            signed.AsSpan(2, 8),
            timestamp);
        BinaryPrimitives.WriteUInt64BigEndian(
            signed.AsSpan(10, 8),
            treeSize);
        rootHash.CopyTo(signed, 18);
        var signature = signer.SignData(
            signed,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);

        var spki = signer.ExportSubjectPublicKeyInfo();
        var logId = SHA256.HashData(spki);
        var originBytes = Encoding.UTF8.GetBytes(origin);
        var noteKeyHashInput = new byte[originBytes.Length + 2 + logId.Length];
        originBytes.CopyTo(noteKeyHashInput, 0);
        noteKeyHashInput[originBytes.Length] = (byte)'\n';
        noteKeyHashInput[originBytes.Length + 1] = 0x05;
        logId.CopyTo(noteKeyHashInput, originBytes.Length + 2);
        var noteKeyHash = SHA256.HashData(noteKeyHashInput);

        var noteSignature = new byte[4 + 8 + 4 + signature.Length];
        noteKeyHash.AsSpan(0, 4).CopyTo(noteSignature);
        BinaryPrimitives.WriteUInt64BigEndian(
            noteSignature.AsSpan(4, 8),
            timestamp);
        noteSignature[12] = 4;
        noteSignature[13] = 3;
        BinaryPrimitives.WriteUInt16BigEndian(
            noteSignature.AsSpan(14, 2),
            checked((ushort)signature.Length));
        signature.CopyTo(noteSignature, 16);

        var text = new StringBuilder()
            .Append(origin)
            .Append('\n')
            .Append(treeSize)
            .Append('\n')
            .Append(Convert.ToBase64String(rootHash))
            .Append('\n')
            .Append('\n')
            .Append('\u2014')
            .Append(' ')
            .Append(origin)
            .Append(' ')
            .Append(Convert.ToBase64String(noteSignature))
            .Append('\n')
            .ToString();
        return Encoding.UTF8.GetBytes(text);
    }

    private static string Fingerprint(ECDsa key) =>
        Convert.ToHexString(
                SHA256.HashData(key.ExportSubjectPublicKeyInfo()))
            .ToLowerInvariant();

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-ctlog-shard-{Guid.NewGuid():N}");
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
