using System.Text.Json;
using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Xunit;

namespace Sigstore.Aspire.Hosting.Tests;

/// <summary>
/// Regression coverage for two durable-replay defects in the certificate
/// -transparency log shard rotation: <c>CtLogShardMetadataFile</c>
/// equality falling back to list-reference comparison for its fingerprint
/// collection, and <c>ValidateCtIssuanceProof</c> checking a journaled
/// issuance proof's certificate validity against the current wall clock
/// instead of the moment the proof was durably recorded.
/// </summary>
public sealed class SigstoreCtLogShardReplayTests
{
    // --- CtLogShardMetadataFile structural equality -----------------

    [Fact]
    public void MetadataWithEquivalentFingerprintsInDifferentListInstancesIsEqual()
    {
        var first = Metadata(["a", "b"], listInstance: 1);
        var second = Metadata(["a", "b"], listInstance: 2);

        Assert.NotSame(first.AcceptedRootFingerprints, second.AcceptedRootFingerprints);
        Assert.Equal(first, second);
        Assert.True(first == second);
        Assert.False(first != second);
        Assert.Equal(first.GetHashCode(), second.GetHashCode());
    }

    [Fact]
    public void MetadataWithDifferentFingerprintContentIsRejected()
    {
        var first = Metadata(["a", "b"]);
        var tamperedContent = Metadata(["a", "c"]);

        Assert.NotEqual(first, tamperedContent);
        Assert.True(first != tamperedContent);
    }

    [Fact]
    public void MetadataWithReorderedFingerprintsIsRejected()
    {
        var first = Metadata(["a", "b"]);
        var reordered = Metadata(["b", "a"]);

        Assert.NotEqual(first, reordered);
        Assert.True(first != reordered);
    }

    // --- PrepareSecondaryCtShardData replay (via the extracted helper) -

    [Fact]
    public void ReplayOfSecondaryShardMetadataWithSameValuesIsIdempotent()
    {
        using var directory = new TemporaryDirectory();
        var metadataPath = Path.Combine(directory.Path, "shard.json");
        var original = Metadata(["a", "b"], listInstance: 1);

        SigstoreOperationExecutor.ReplayOrWriteCtLogShardMetadata(
            metadataPath,
            original);
        var writtenAtFirstAttempt = File.ReadAllText(metadataPath);

        // A resumed operation recomputes the same candidate-generated
        // metadata from the journal; its fingerprint list is a brand new
        // instance built from journal fields, never the same list object
        // that was serialized the first time. Replay must accept this
        // without rewriting the durable file.
        var replay = Metadata(["a", "b"], listInstance: 2);
        SigstoreOperationExecutor.ReplayOrWriteCtLogShardMetadata(
            metadataPath,
            replay);

        Assert.Equal(writtenAtFirstAttempt, File.ReadAllText(metadataPath));
    }

    [Fact]
    public void ReplayAfterJsonRoundTripWithSameValuesIsIdempotent()
    {
        using var directory = new TemporaryDirectory();
        var metadataPath = Path.Combine(directory.Path, "shard.json");
        var original = Metadata(["a", "b"], listInstance: 1);
        File.WriteAllText(
            metadataPath,
            JsonSerializer.Serialize(original));

        // Deserializing shard.json always allocates a fresh list for
        // AcceptedRootFingerprints, so this exercises the exact shape of
        // the bug: two content-identical but reference-distinct lists.
        var recomputed = Metadata(["a", "b"], listInstance: 2);
        var exception = Record.Exception(
            () => SigstoreOperationExecutor.ReplayOrWriteCtLogShardMetadata(
                metadataPath,
                recomputed));

        Assert.Null(exception);
    }

    [Fact]
    public void ReplayWithTamperedFingerprintContentIsRejected()
    {
        using var directory = new TemporaryDirectory();
        var metadataPath = Path.Combine(directory.Path, "shard.json");
        SigstoreOperationExecutor.ReplayOrWriteCtLogShardMetadata(
            metadataPath,
            Metadata(["a", "b"]));

        Assert.Throws<InvalidDataException>(
            () => SigstoreOperationExecutor.ReplayOrWriteCtLogShardMetadata(
                metadataPath,
                Metadata(["a", "c"])));
    }

    [Fact]
    public void ReplayWithTamperedFingerprintOrderIsRejected()
    {
        using var directory = new TemporaryDirectory();
        var metadataPath = Path.Combine(directory.Path, "shard.json");
        SigstoreOperationExecutor.ReplayOrWriteCtLogShardMetadata(
            metadataPath,
            Metadata(["a", "b"]));

        Assert.Throws<InvalidDataException>(
            () => SigstoreOperationExecutor.ReplayOrWriteCtLogShardMetadata(
                metadataPath,
                Metadata(["b", "a"])));
    }

    // --- ValidateCtIssuanceProof recorded-instant validity ------------

    private static readonly DateTimeOffset CertificateIssuedAt =
        new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset CertificateExpiresAt =
        CertificateIssuedAt.AddMinutes(10);

    [Fact]
    public void FreshlyCapturedProofIsValidAtItsOwnRecordedInstant()
    {
        var proof = Proof();
        var capturedAtUtc = CertificateIssuedAt.AddMinutes(2);

        var exception = Record.Exception(
            () => SigstoreOperationExecutor.ValidateCtIssuanceProof(
                proof,
                "root-sha",
                "ct-log-id",
                capturedAtUtc,
                "test-proof"));

        Assert.Null(exception);
    }

    [Fact]
    public void JournaledProofRemainsValidLongAfterCertificateExpires()
    {
        var proof = Proof();

        // The certificate is long expired relative to "now", but the
        // proof was durably recorded while it was still valid. Durable
        // replay must not re-check validity against the current wall
        // clock, or a resumed operation would fail forever once the
        // short-lived certificate's NotAfter has passed.
        var recordedWhileValid = CertificateIssuedAt.AddMinutes(5);
        var exception = Record.Exception(
            () => SigstoreOperationExecutor.ValidateCtIssuanceProof(
                proof,
                "root-sha",
                "ct-log-id",
                recordedWhileValid,
                "test-proof"));

        Assert.Null(exception);
    }

    [Fact]
    public void MissingRecordedInstantIsRejected()
    {
        var proof = Proof();

        Assert.Throws<InvalidDataException>(
            () => SigstoreOperationExecutor.ValidateCtIssuanceProof(
                proof,
                "root-sha",
                "ct-log-id",
                provedAtUtc: null,
                "test-proof"));
    }

    [Fact]
    public void RecordedInstantBeforeCertificateValidityIsRejected()
    {
        var proof = Proof();

        Assert.Throws<InvalidDataException>(
            () => SigstoreOperationExecutor.ValidateCtIssuanceProof(
                proof,
                "root-sha",
                "ct-log-id",
                CertificateIssuedAt.AddMinutes(-1),
                "test-proof"));
    }

    [Fact]
    public void RecordedInstantAfterCertificateValidityIsRejected()
    {
        var proof = Proof();

        Assert.Throws<InvalidDataException>(
            () => SigstoreOperationExecutor.ValidateCtIssuanceProof(
                proof,
                "root-sha",
                "ct-log-id",
                CertificateExpiresAt.AddMinutes(1),
                "test-proof"));
    }

    [Fact]
    public void MismatchedRootIdentityOrLogIdStillRejectsRegardlessOfTiming()
    {
        var proof = Proof();
        var validInstant = CertificateIssuedAt.AddMinutes(1);

        Assert.Throws<InvalidDataException>(
            () => SigstoreOperationExecutor.ValidateCtIssuanceProof(
                proof,
                "different-root-sha",
                "ct-log-id",
                validInstant,
                "test-proof"));
        Assert.Throws<InvalidDataException>(
            () => SigstoreOperationExecutor.ValidateCtIssuanceProof(
                proof,
                "root-sha",
                "different-ct-log-id",
                validInstant,
                "test-proof"));
        Assert.Throws<InvalidDataException>(
            () => SigstoreOperationExecutor.ValidateCtIssuanceProof(
                proof with { Identity = "someone-else@sigstore.local" },
                "root-sha",
                "ct-log-id",
                validInstant,
                "test-proof"));
        Assert.Throws<InvalidDataException>(
            () => SigstoreOperationExecutor.ValidateCtIssuanceProof(
                proof with { SctVerified = false },
                "root-sha",
                "ct-log-id",
                validInstant,
                "test-proof"));
    }

    private static SigstoreFulcioIssuanceProof Proof() =>
        new(
            CertificateSha256: new string('a', 64),
            RootSha256: "root-sha",
            CertificateSubject: "subject",
            CertificateIssuer: "issuer",
            Identity: SigstoreDefaults.ExpectedIdentity,
            NotBeforeUtc: CertificateIssuedAt,
            NotAfterUtc: CertificateExpiresAt,
            CtLogId: "ct-log-id",
            SctTimestamp: 1_700_000_000_000,
            SctSignatureSha256: new string('b', 64),
            SctVerified: true);

    private static CtLogShardMetadataFile Metadata(
        string[] fingerprints,
        int listInstance = 0) =>
        new(
            SchemaVersion: 1,
            OperationId: "operation-id",
            TrustDomainId: "trust-domain-id",
            ShardId: "shard-id",
            Slot: "secondary",
            BaseUrl: "http://tesseract-secondary:6962",
            Origin: "tesseract-secondary-sigstore.dev.localhost",
            PublicKeySha256: "public-key-sha",
            LogIdSha256: "log-id-sha",
            StateId: "secondary-state",
            DataPath: "data/ctlog-shards/secondary",
            ResourceName: "tesseract-secondary",
            CreatedAtUtc: new DateTimeOffset(
                2026,
                1,
                1,
                0,
                0,
                0,
                TimeSpan.Zero),
            AcceptedRootsSha256: "accepted-roots-sha",
            AcceptedRootCount: fingerprints.Length,
            // The listInstance parameter has no effect on the value; it
            // only makes call sites self-documenting. Every call
            // allocates a brand-new List<string>, so two calls with the
            // same fingerprints in the same order are content-equal but
            // reference-distinct — the exact shape produced by a fresh
            // journal replay or a JSON round trip.
            AcceptedRootFingerprints: new List<string>(fingerprints));

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-ctlog-shard-replay-{Guid.NewGuid():N}");
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
