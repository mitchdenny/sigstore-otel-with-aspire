using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Sigstore.Bootstrap;

namespace Aspire.Hosting.ApplicationModel;

/// <summary>
/// A single certificate-transparency log entry as published in the
/// TrustedRoot <c>ctlogs</c> array. CT shards are represented by raw ECDSA
/// public keys, so only the base URL and the SHA-256 fingerprint of the
/// SubjectPublicKeyInfo — which doubles as the shard's CT log ID — are
/// meaningful.
/// </summary>
public sealed record SigstoreCtLogTrustEntry(
    int Index,
    string BaseUrl,
    string PublicKeySha256);

/// <summary>
/// A single shard entry in the durable CT shard catalog
/// (<c>data/ctlog-shards/state.json</c>), written and switched by the Go
/// TUF worker and only ever read here.
/// </summary>
internal sealed record CtLogShardCatalogEntry(
    string ShardId,
    string Slot,
    string BaseUrl,
    string Origin,
    string PublicKeySha256,
    string LogIdSha256,
    string StateId,
    string DataPath,
    string ResourceName,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ActivatedAtUtc,
    string Status,
    string AcceptedRootsSha256,
    int AcceptedRootCount,
    IReadOnlyList<string> AcceptedRootFingerprints);

/// <summary>
/// The durable CT shard catalog at <c>data/ctlog-shards/state.json</c>:
/// exactly one (primary-only) or two (historical primary plus activated
/// secondary) ordered shard entries. This file is owned by the Go TUF
/// worker; hosting code only ever reads and validates it.
/// </summary>
internal sealed record CtLogShardCatalog(
    int SchemaVersion,
    string TrustDomainId,
    string ActiveShardId,
    DateTimeOffset UpdatedAtUtc,
    IReadOnlyList<CtLogShardCatalogEntry> Shards);

/// <summary>
/// The identity of the complete accepted Fulcio certificate-authority
/// bundle one certificate-transparency shard enforces.
/// </summary>
internal sealed record CtLogShardAcceptedRoots(
    byte[] Bundle,
    string BundleSha256,
    IReadOnlyList<string> Fingerprints);

/// <summary>
/// Per-shard health for one certificate-transparency log shard.
/// </summary>
public sealed record SigstoreCtLogShardHealthStatus(
    string ShardId,
    string Slot,
    string Status,
    string BaseUrl,
    string Origin,
    string Resource,
    string PublicKeySha256,
    string LogIdSha256,
    string StateId,
    ulong TreeSize,
    ulong CheckpointTimestamp,
    string CheckpointRootHash,
    string CheckpointSignatureSha256,
    bool InTrustedRoot,
    bool ComputeRequired,
    bool? ComputeHealthy,
    string AcceptedRootsSha256,
    int AcceptedRootCount,
    IReadOnlyList<string> AcceptedRootFingerprints,
    bool AcceptedRootsMatchRuntime);

/// <summary>
/// Aggregate certificate-transparency status: every logical shard, the
/// shard Fulcio is currently bound to, and the CT entries the committed
/// TrustedRoot publishes.
/// </summary>
public sealed record SigstoreCtLogStatus(
    string ActiveShardId,
    string SelectedFulcioShardSlot,
    string SelectedFulcioOrigin,
    string SelectedFulcioCtLogPublicKeySha256,
    bool FulcioCtPromotionPending,
    string? StagedFulcioCtLogPublicKeySha256,
    int TrustedRootCtlogCount,
    IReadOnlyList<SigstoreCtLogTrustEntry> TrustedCtlogs,
    IReadOnlyList<SigstoreCtLogShardHealthStatus> Shards,
    string? IncompleteRotationOperationId,
    string? IncompleteRotationStatus);

/// <summary>
/// Certificate-transparency shard specific durable-state and wire-format
/// helpers used by the CT log shard rotation command and by read-only
/// status. Everything here is read-only with respect to trust material:
/// hosting code never writes the catalog or generation material — only the
/// Go TUF worker and <see cref="SigstoreStateBootstrapper"/> do.
/// </summary>
internal static class SigstoreCtLogShard
{
    /// <summary>
    /// Durable hosting-journal status values, in their natural progression
    /// order. Centralized here so both the rotation operation and any
    /// read-only status caller agree on the exact set of valid values.
    /// </summary>
    internal const string StatusRequested = "requested";
    internal const string StatusCandidateGenerated = "candidate-generated";
    internal const string StatusSecondaryPrepared = "secondary-prepared";
    internal const string StatusSecondaryStarted = "secondary-started";
    internal const string StatusSecondaryProved = "secondary-proved";
    internal const string StatusWorkerCommitted = "worker-committed";
    internal const string StatusClientsConverged = "clients-converged";
    internal const string StatusOldShardProved = "old-shard-proved";
    internal const string StatusRuntimeActivated = "runtime-activated";
    internal const string StatusFulcioRestarted = "fulcio-restarted";
    internal const string StatusNewShardProved = "new-shard-proved";
    internal const string StatusCompleted = "completed";

    internal const string PrimaryUrl =
        "http://tesseract-sigstore.dev.localhost:6962";
    internal const string SecondaryUrl =
        "http://tesseract-secondary-sigstore.dev.localhost:6963";
    internal const string PrimaryOrigin =
        "tesseract-sigstore.dev.localhost";
    internal const string SecondaryOrigin =
        "tesseract-secondary-sigstore.dev.localhost";
    internal const string PrimaryDataRelativePath = "data/ctlog";
    internal const string SecondaryDataRelativePath =
        "data/ctlog-shards/secondary";
    internal const string PrimaryResourceName = "tesseract";
    internal const string SecondaryResourceName = "tesseract-secondary";
    internal const string PrimarySlot = "primary";
    internal const string SecondarySlot = "secondary";

    private const int MaximumCheckpointBytes = 64 * 1024;

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        };

    /// <summary>
    /// The certificate-transparency binding recorded in the active
    /// generation manifest: which CT signer this generation carries and,
    /// once a shard rotation exists, which immutable generation the
    /// historical primary shard is still bound to.
    /// </summary>
    internal sealed record CtLogGenerationBinding(
        string GenerationId,
        string CtLogPublicKeySha256,
        string? CtLogRotationOperationId,
        string? CtLogPriorGenerationId,
        string? CtLogPriorPublicKeySha256,
        string? CtLogShardId,
        string? CtLogBaseUrl);

    internal static CtLogGenerationBinding ReadActiveGenerationBinding(
        string statePath)
    {
        using var document = JsonDocument.Parse(
            File.ReadAllBytes(
                Path.Combine(
                    statePath,
                    "active-generation",
                    "manifest.json")));
        var root = document.RootElement;
        return new CtLogGenerationBinding(
            RequiredString(root, "generationId"),
            RequiredString(root, "ctLogPublicKeySha256"),
            OptionalString(root, "ctLogRotationOperationId"),
            OptionalString(root, "ctLogPriorGenerationId"),
            OptionalString(root, "ctLogPriorPublicKeySha256"),
            OptionalString(root, "ctLogShardId"),
            OptionalString(root, "ctLogBaseUrl"));
    }

    /// <summary>
    /// Reports whether the active generation is bound to a completed
    /// certificate-transparency log shard rotation, which is what decides
    /// whether the primary or the secondary shard currently accepts
    /// submissions. This deliberately reads only the optional rotation
    /// marker so it stays usable on any valid generation manifest.
    /// </summary>
    internal static bool HasRotatedCtLog(string statePath)
    {
        using var document = JsonDocument.Parse(
            File.ReadAllBytes(
                Path.Combine(
                    statePath,
                    "active-generation",
                    "manifest.json")));
        return OptionalString(
            document.RootElement,
            "ctLogRotationOperationId") is not null;
    }

    private static string RequiredString(
        JsonElement element,
        string name) =>
        element.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String
            && value.GetString() is { Length: > 0 } text
                ? text
                : throw new InvalidDataException(
                    $"The active generation manifest omits '{name}'.");

    private static string? OptionalString(
        JsonElement element,
        string name) =>
        element.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;

    internal static CtLogShardMaterialInfo ReadActiveMaterial(
        string statePath) =>
        SigstoreStateBootstrapper.ValidateCtLogShardMaterial(
            Path.Combine(statePath, "active-generation"));

    internal static string ShardCatalogPath(string statePath) =>
        Path.Combine(statePath, "data", "ctlog-shards", "state.json");

    internal static string SecondaryDataPath(string statePath) =>
        Path.Combine(statePath, "data", "ctlog-shards", "secondary");

    internal static string CandidatePath(
        string statePath,
        string operationId) =>
        Path.Combine(
            statePath,
            "ct-log-shard-rotation",
            operationId,
            "candidate");

    /// <summary>
    /// Parses and validates the <c>ctlogs</c> array of a TrustedRoot
    /// document. Each entry must use SHA2_256/ECDSA-P256 and its log ID
    /// must equal the SHA-256 fingerprint of its own public key, matching
    /// the binding the Go TUF worker enforces.
    /// </summary>
    internal static IReadOnlyList<SigstoreCtLogTrustEntry> ReadCtlogEntries(
        ReadOnlySpan<byte> trustedRootBytes)
    {
        using var document = JsonDocument.Parse(trustedRootBytes.ToArray());
        if (!document.RootElement.TryGetProperty("ctlogs", out var ctlogs)
            || ctlogs.ValueKind != JsonValueKind.Array
            || ctlogs.GetArrayLength() == 0)
        {
            throw new InvalidDataException(
                "TrustedRoot does not contain a certificate-transparency log.");
        }

        var result = new List<SigstoreCtLogTrustEntry>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var index = 0;
        foreach (var entry in ctlogs.EnumerateArray())
        {
            var baseUrl = entry.GetProperty("baseUrl").GetString();
            if (string.IsNullOrWhiteSpace(baseUrl)
                || !Uri.TryCreate(baseUrl, UriKind.Absolute, out var parsed)
                || parsed.Scheme is not ("http" or "https"))
            {
                throw new InvalidDataException(
                    $"TrustedRoot ctlog {index} has an invalid base URL.");
            }
            if (entry.GetProperty("hashAlgorithm").GetString()
                != "SHA2_256")
            {
                throw new InvalidDataException(
                    $"TrustedRoot ctlog {index} uses an unsupported hash " +
                    "algorithm.");
            }
            var publicKey = entry.GetProperty("publicKey");
            if (publicKey.GetProperty("keyDetails").GetString()
                != "PKIX_ECDSA_P256_SHA_256")
            {
                throw new InvalidDataException(
                    $"TrustedRoot ctlog {index} public key is not ECDSA " +
                    "P-256.");
            }
            var rawBytes = Convert.FromBase64String(
                publicKey.GetProperty("rawBytes").GetString()
                ?? throw new InvalidDataException(
                    $"TrustedRoot ctlog {index} public key bytes are empty."));
            using (var ecdsa = ECDsa.Create())
            {
                try
                {
                    ecdsa.ImportSubjectPublicKeyInfo(rawBytes, out _);
                }
                catch (CryptographicException exception)
                {
                    throw new InvalidDataException(
                        $"TrustedRoot ctlog {index} public key is not a " +
                        "valid ECDSA key.",
                        exception);
                }
                if (ecdsa.KeySize != 256)
                {
                    throw new InvalidDataException(
                        $"TrustedRoot ctlog {index} public key must be " +
                        "256-bit.");
                }
            }
            var digest = Hash(rawBytes);
            var keyId = Convert.FromBase64String(
                entry.GetProperty("logId")
                    .GetProperty("keyId")
                    .GetString()
                ?? throw new InvalidDataException(
                    $"TrustedRoot ctlog {index} log ID is empty."));
            if (Convert.ToHexString(keyId).ToLowerInvariant() != digest)
            {
                throw new InvalidDataException(
                    $"TrustedRoot ctlog {index} log ID does not match its " +
                    "public key.");
            }
            if (!seen.Add($"{baseUrl}/{digest}"))
            {
                throw new InvalidDataException(
                    "TrustedRoot contains a duplicate certificate-transparency " +
                    "log entry.");
            }
            result.Add(new SigstoreCtLogTrustEntry(index, baseUrl, digest));
            index++;
        }
        return result;
    }

    internal static IReadOnlyList<SigstoreCtLogTrustEntry> ReadCtlogEntries(
        string statePath) =>
        ReadCtlogEntries(
            File.ReadAllBytes(
                Path.Combine(
                    statePath,
                    "tuf",
                    "active",
                    "targets",
                    "trusted_root.json")));

    /// <summary>
    /// Parses and cryptographically verifies a Tesseract checkpoint note
    /// for an explicitly supplied origin and signer, so it can be used for
    /// either shard. The note key hash binds the signature to the
    /// origin/key pair and the signature covers the CT tree head
    /// (version, timestamp, tree size, root hash).
    /// </summary>
    internal static SigstoreCtCheckpoint ReadAndVerifyCheckpoint(
        ReadOnlySpan<byte> checkpointBytes,
        string expectedOrigin,
        ECDsa signerPublicKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedOrigin);
        ArgumentNullException.ThrowIfNull(signerPublicKey);
        if (checkpointBytes.Length is 0 or > MaximumCheckpointBytes)
        {
            throw new InvalidDataException(
                "Tesseract checkpoint file has an invalid length.");
        }
        var lines = Encoding.UTF8.GetString(checkpointBytes)
            .Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .ToArray();
        if (lines.Length < 6
            || lines[0] != expectedOrigin
            || !ulong.TryParse(
                lines[1],
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var treeSize)
            || lines[3].Length != 0
            || lines.Skip(5).Any(line => line.Length != 0))
        {
            throw new InvalidDataException(
                "Tesseract checkpoint has an invalid note envelope.");
        }
        var rootHash = Convert.FromBase64String(lines[2]);
        if (rootHash.Length != 32)
        {
            throw new InvalidDataException(
                "Tesseract checkpoint root hash is not SHA-256.");
        }
        var signaturePrefix = $"\u2014 {expectedOrigin} ";
        if (!lines[4].StartsWith(
                signaturePrefix,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Tesseract checkpoint signature name is invalid.");
        }
        var noteSignature = Convert.FromBase64String(
            lines[4][signaturePrefix.Length..]);
        if (noteSignature.Length < 16)
        {
            throw new InvalidDataException(
                "Tesseract checkpoint signature is truncated.");
        }
        var spki = signerPublicKey.ExportSubjectPublicKeyInfo();
        var logId = SHA256.HashData(spki);
        var origin = Encoding.UTF8.GetBytes(expectedOrigin);
        var noteKeyHashInput = new byte[origin.Length + 2 + logId.Length];
        origin.CopyTo(noteKeyHashInput, 0);
        noteKeyHashInput[origin.Length] = (byte)'\n';
        noteKeyHashInput[origin.Length + 1] = 0x05;
        logId.CopyTo(noteKeyHashInput, origin.Length + 2);
        var expectedNoteKeyHash = SHA256.HashData(noteKeyHashInput);
        if (!CryptographicOperations.FixedTimeEquals(
                noteSignature.AsSpan(0, 4),
                expectedNoteKeyHash.AsSpan(0, 4)))
        {
            throw new InvalidDataException(
                "Tesseract checkpoint note key hash is invalid.");
        }
        var timestamp = BinaryPrimitives.ReadUInt64BigEndian(
            noteSignature.AsSpan(4, 8));
        var signature = ReadDigitallySigned(noteSignature.AsSpan(12));

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
        if (!signerPublicKey.VerifyData(
                signed,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence))
        {
            throw new InvalidDataException(
                "Tesseract checkpoint signature is invalid.");
        }

        return new SigstoreCtCheckpoint(
            expectedOrigin,
            treeSize,
            timestamp,
            Convert.ToHexString(rootHash).ToLowerInvariant(),
            Hash(signature),
            Hash(spki));
    }

    /// <summary>
    /// Reads the durable CT shard catalog if it exists, or
    /// <see langword="null"/> when no rotation has ever run (the catalog is
    /// created lazily by the Go TUF worker on first rotation).
    /// </summary>
    internal static CtLogShardCatalog? TryReadShardCatalog(
        string statePath) =>
        File.Exists(ShardCatalogPath(statePath))
            ? ReadShardCatalog(statePath)
            : null;

    /// <summary>
    /// Reads and strictly validates the durable CT shard catalog: schema,
    /// ordered primary/secondary slots, per-shard log ID binding, and
    /// activation ordering.
    /// </summary>
    internal static CtLogShardCatalog ReadShardCatalog(string statePath)
    {
        var catalog = JsonSerializer.Deserialize<CtLogShardCatalog>(
            File.ReadAllText(ShardCatalogPath(statePath)),
            JsonOptions)
            ?? throw new InvalidDataException(
                "The CT shard catalog is empty.");
        if (catalog.SchemaVersion != 1
            || string.IsNullOrWhiteSpace(catalog.TrustDomainId)
            || string.IsNullOrWhiteSpace(catalog.ActiveShardId)
            || catalog.Shards.Count is not (1 or 2))
        {
            throw new InvalidDataException(
                "The CT shard catalog has malformed durable state.");
        }
        foreach (var shard in catalog.Shards)
        {
            if (!IsLowerHexSha256(shard.PublicKeySha256)
                || shard.LogIdSha256 != shard.PublicKeySha256
                || shard.ShardId != $"sha256-{shard.PublicKeySha256}"
                || string.IsNullOrWhiteSpace(shard.StateId)
                || shard.ActivatedAtUtc < shard.CreatedAtUtc
                || shard.Status is not ("active" or "historical")
                || !IsLowerHexSha256(shard.AcceptedRootsSha256)
                || shard.AcceptedRootCount < 1
                || shard.AcceptedRootFingerprints.Count
                    != shard.AcceptedRootCount
                || shard.AcceptedRootFingerprints.Any(
                    fingerprint => !IsLowerHexSha256(fingerprint))
                || shard.AcceptedRootFingerprints
                    .Distinct(StringComparer.Ordinal)
                    .Count() != shard.AcceptedRootCount)
            {
                throw new InvalidDataException(
                    "The CT shard catalog contains a malformed shard entry.");
            }
        }
        if (catalog.Shards[0].Slot != "primary"
            || catalog.Shards[0].BaseUrl != PrimaryUrl
            || catalog.Shards[0].Origin != PrimaryOrigin
            || catalog.Shards[0].DataPath != PrimaryDataRelativePath
            || catalog.Shards[0].ResourceName != PrimaryResourceName)
        {
            throw new InvalidDataException(
                "The CT shard catalog primary entry is invalid.");
        }
        if (catalog.Shards.Count == 2
            && (catalog.Shards[1].Slot != "secondary"
                || catalog.Shards[1].BaseUrl != SecondaryUrl
                || catalog.Shards[1].Origin != SecondaryOrigin
                || catalog.Shards[1].DataPath != SecondaryDataRelativePath
                || catalog.Shards[1].ResourceName != SecondaryResourceName
                || catalog.Shards[0].Status != "historical"
                || catalog.Shards[1].Status != "active"
                || catalog.ActiveShardId != catalog.Shards[1].ShardId
                // The bounded secondary shard is created accepting exactly
                // the complete Fulcio root bundle the primary already
                // accepts, including every root a prior Fulcio CA rotation
                // added. That equality is a permanent recorded fact.
                || catalog.Shards[1].AcceptedRootsSha256
                    != catalog.Shards[0].AcceptedRootsSha256
                || catalog.Shards[1].AcceptedRootCount
                    != catalog.Shards[0].AcceptedRootCount
                || !catalog.Shards[1].AcceptedRootFingerprints.SequenceEqual(
                    catalog.Shards[0].AcceptedRootFingerprints,
                    StringComparer.Ordinal)))
        {
            throw new InvalidDataException(
                "The CT shard catalog secondary entry is invalid.");
        }
        if (catalog.Shards.Count == 1
            && (catalog.Shards[0].Status != "active"
                || catalog.ActiveShardId != catalog.Shards[0].ShardId))
        {
            throw new InvalidDataException(
                "The single-shard CT catalog is inconsistent.");
        }
        return catalog;
    }

    /// <summary>
    /// Reads and schema-validates every durable CT shard rotation hosting
    /// journal (<c>ct-log-shard-rotation/&lt;operationId&gt;/
    /// hosting-state.json</c>), in no particular order, regardless of
    /// status. Callers that need "the one in-flight operation" additionally
    /// filter and enforce uniqueness.
    /// </summary>
    internal static IReadOnlyList<CtLogShardRotationCommandJournal>
        ReadRotationJournals(string statePath)
    {
        var root = Path.Combine(statePath, "ct-log-shard-rotation");
        if (!Directory.Exists(root))
        {
            return [];
        }
        return Directory
            .EnumerateFiles(
                root,
                "hosting-state.json",
                SearchOption.AllDirectories)
            .Select(
                path =>
                {
                    var journal = JsonSerializer.Deserialize<
                        CtLogShardRotationCommandJournal>(
                            File.ReadAllText(path),
                            JsonOptions)
                        ?? throw new InvalidDataException(
                            $"CT log shard rotation journal '{path}' is " +
                            "empty.");
                    var operationId = Path.GetFileName(
                        Path.GetDirectoryName(path));
                    if (journal.SchemaVersion != 1
                        || !Guid.TryParseExact(
                            journal.OperationId,
                            "N",
                            out _)
                        || journal.OperationId.Any(char.IsUpper)
                        || operationId != journal.OperationId
                        || !IsKnownStatus(journal.Status)
                        || journal.StartingGeneration < 1
                        || journal.StartingGenerationId
                            != $"generation-{journal.StartingGeneration:D8}"
                        || journal.PriorShardId
                            != $"sha256-{journal.StartingCtLogPublicKeySha256}"
                        || journal.PriorShardUrl != PrimaryUrl
                        || journal.StartingSnapshot.Tuf.Trust.TrustDomainId
                            != journal.TrustDomainId
                        || journal.StartingSnapshot.Tuf.Trust.Generation
                            != journal.StartingGeneration
                        || journal.StartingSnapshot.Tuf.Trust.GenerationId
                            != journal.StartingGenerationId
                        || journal.Clients
                            .Select(client => client.Resource)
                            .Distinct(StringComparer.Ordinal)
                            .Count() != journal.Clients.Count
                        || journal.OldArtifactValidations
                            .Select(item => item.Resource)
                            .Distinct(StringComparer.Ordinal)
                            .Count() != journal.OldArtifactValidations.Count
                        || journal.NewArtifactValidations
                            .Select(item => item.Resource)
                            .Distinct(StringComparer.Ordinal)
                            .Count() != journal.NewArtifactValidations.Count)
                    {
                        throw new InvalidDataException(
                            $"CT log shard rotation journal '{path}' has " +
                            "invalid state.");
                    }
                    if (journal.Status != StatusRequested
                        && journal.CandidatePublicKeySha256 is null)
                    {
                        throw new InvalidDataException(
                            $"CT log shard rotation journal '{path}' omits " +
                            "its candidate.");
                    }
                    if (journal.Status is not (StatusRequested
                            or StatusCandidateGenerated)
                        && (journal.CandidateAcceptedRootsSha256 is null
                            || journal.CandidateAcceptedRootFingerprints
                                is not { Count: > 0 }))
                    {
                        throw new InvalidDataException(
                            $"CT log shard rotation journal '{path}' omits " +
                            "the accepted Fulcio root bundle its secondary " +
                            "shard was created with.");
                    }
                    if (RequiresWorkerCompletion(journal.Status)
                        && journal.WorkerCompletion is null)
                    {
                        throw new InvalidDataException(
                            $"CT log shard rotation journal '{path}' omits " +
                            "worker completion.");
                    }
                    return journal;
                })
            .ToArray();
    }

    internal static bool IsKnownStatus(string status) =>
        status is StatusRequested
            or StatusCandidateGenerated
            or StatusSecondaryPrepared
            or StatusSecondaryStarted
            or StatusSecondaryProved
            or StatusWorkerCommitted
            or StatusClientsConverged
            or StatusOldShardProved
            or StatusRuntimeActivated
            or StatusFulcioRestarted
            or StatusNewShardProved
            or StatusCompleted;

    private static bool RequiresWorkerCompletion(string status) =>
        status is StatusWorkerCommitted
            or StatusClientsConverged
            or StatusOldShardProved
            or StatusRuntimeActivated
            or StatusFulcioRestarted
            or StatusNewShardProved
            or StatusCompleted;

    /// <summary>
    /// Reads the durable identity of the complete Fulcio certificate
    /// authority bundle one certificate-transparency shard's least-privilege
    /// runtime projection accepts: the SHA-256 of the exact bundle bytes and
    /// the ordered fingerprint of every root it contains. This is what the
    /// shard catalog records, so catalog entries can be bound back to the
    /// bytes the shard actually enforces.
    /// </summary>
    internal static CtLogShardAcceptedRoots ReadRuntimeAcceptedRoots(
        string statePath,
        string slot)
    {
        var bundlePath = Path.Combine(
            statePath,
            "runtime",
            slot == SecondarySlot
                ? "tesseract-secondary"
                : "tesseract",
            "accepted-roots.pem");
        var bundle = File.ReadAllBytes(bundlePath);
        var certificates = new X509Certificate2Collection();
        certificates.ImportFromPem(Encoding.UTF8.GetString(bundle));
        if (certificates.Count == 0)
        {
            throw new InvalidDataException(
                $"Accepted Fulcio roots '{bundlePath}' contain no " +
                "certificates.");
        }
        try
        {
            return new CtLogShardAcceptedRoots(
                bundle,
                Hash(bundle),
                certificates
                    .Select(certificate => Hash(certificate.RawData))
                    .ToArray());
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    /// <summary>
    /// Proves one catalog entry's recorded accepted-root identity against
    /// the bytes the shard's runtime projection actually enforces. The
    /// historical primary shard is frozen at the cutover, so it must render
    /// exactly what the catalog records; the secondary shard was created
    /// accepting that same complete bundle, so its live bundle must still
    /// begin with it after later Fulcio CA rotations extended it.
    /// </summary>
    internal static bool AcceptedRootsMatchRuntime(
        string statePath,
        CtLogShardCatalogEntry shard)
    {
        try
        {
            var frozen = ReadRuntimeAcceptedRoots(statePath, PrimarySlot);
            if (shard.AcceptedRootsSha256 != frozen.BundleSha256
                || shard.AcceptedRootCount != frozen.Fingerprints.Count
                || !shard.AcceptedRootFingerprints.SequenceEqual(
                    frozen.Fingerprints,
                    StringComparer.Ordinal))
            {
                return false;
            }
            if (shard.Slot != SecondarySlot)
            {
                return true;
            }
            var live = ReadRuntimeAcceptedRoots(statePath, SecondarySlot);
            return live.Bundle.Length >= frozen.Bundle.Length
                && live.Bundle.AsSpan(0, frozen.Bundle.Length)
                    .SequenceEqual(frozen.Bundle);
        }
        catch (Exception exception)
            when (exception is IOException
                or InvalidDataException
                or CryptographicException
                or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Reads the ECDSA public key of a CT shard's signer from a generation
    /// or rotation-candidate tree.
    /// </summary>
    internal static ECDsa ReadPublicKey(string materialPath)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(
                File.ReadAllText(
                    Path.Combine(
                        materialPath,
                        "public",
                        "ctlog",
                        "pubkey.pem")));
        }
        catch
        {
            key.Dispose();
            throw;
        }
        return key;
    }

    /// <summary>
    /// Resolves the generation directory whose CT signer a shard slot
    /// serves. The historical primary shard is bound to the CT prior
    /// generation once a rotation exists; before that it is the active
    /// generation.
    /// </summary>
    internal static string ResolveShardGenerationPath(
        string statePath,
        string slot,
        string? ctLogPriorGenerationId)
    {
        if (slot == "secondary")
        {
            return Path.Combine(statePath, "active-generation");
        }
        return ctLogPriorGenerationId is null
            ? Path.Combine(statePath, "active-generation")
            : Path.Combine(
                statePath,
                "generations",
                ctLogPriorGenerationId);
    }

    private static byte[] ReadDigitallySigned(ReadOnlySpan<byte> value)
    {
        if (value.Length < 4
            || value[0] != 4
            || value[1] != 3)
        {
            throw new InvalidDataException(
                "CT signature must use ECDSA with SHA-256.");
        }
        var length = BinaryPrimitives.ReadUInt16BigEndian(
            value.Slice(2, 2));
        if (length == 0 || length != value.Length - 4)
        {
            throw new InvalidDataException(
                "CT signature length is invalid.");
        }
        return value[4..].ToArray();
    }

    private static bool IsLowerHexSha256(string value) =>
        value is { Length: 64 }
        && value.All(
            character => character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value))
            .ToLowerInvariant();
}
