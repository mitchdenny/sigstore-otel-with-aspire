using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sigstore.Bootstrap;

namespace Aspire.Hosting.ApplicationModel;

/// <summary>
/// A single Rekor transparency-log entry as published in the TrustedRoot
/// <c>tlogs</c> array. Rekor shards are represented by raw ECDSA public keys
/// (not X.509 certificates), so only the base URL and the SHA-256
/// fingerprint of the SubjectPublicKeyInfo — which doubles as the shard's
/// log ID — are meaningful.
/// </summary>
public sealed record SigstoreRekorTlogEntry(
    int Index,
    string BaseUrl,
    string PublicKeySha256);

/// <summary>
/// Structural and cryptographic evidence recovered from a Rekor tile-log
/// signed checkpoint (a C2SP/transparency-dev "signed note").
/// </summary>
public sealed record SigstoreRekorCheckpointEvidence(
    string Origin,
    long TreeSize,
    string RootHashHex,
    string SignerKeyHashHex);

/// <summary>
/// The transparency-log binding recovered from a single entry inside an
/// artifact signature bundle's <c>verificationMaterial.tlogEntries</c>.
/// </summary>
public sealed record SigstoreRekorArtifactLogEntry(
    long LogIndex,
    string LogIdSha256);

/// <summary>
/// A single shard entry in the durable Rekor shard catalog
/// (<c>data/rekor-shards/state.json</c>), written and switched by the Go
/// TUF worker and only ever read here.
/// </summary>
internal sealed record RekorShardCatalogEntry(
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
    string Status);

/// <summary>
/// The durable Rekor shard catalog at <c>data/rekor-shards/state.json</c>:
/// exactly one (primary-only) or two (primary + activated secondary)
/// ordered shard entries. This file is owned by the Go TUF worker; hosting
/// code only ever reads and validates it, never writes it.
/// </summary>
internal sealed record RekorShardCatalog(
    int SchemaVersion,
    string TrustDomainId,
    string ActiveShardId,
    DateTimeOffset UpdatedAtUtc,
    IReadOnlyList<RekorShardCatalogEntry> Shards);

/// <summary>
/// A read-only, disk (and optionally live-evidence) aggregate status for
/// the Rekor shard rotation, suitable for folding into
/// <c>SigstoreAggregateTrustStatus</c> from <c>SigstoreStatusCommand</c>.
/// All boolean fields are <c>true</c>/<c>false</c> when the underlying
/// evidence was available and validated, or <c>null</c> when the caller
/// did not supply the optional live evidence needed to check it.
/// </summary>
public sealed record SigstoreRekorShardStatus(
    string ActiveShardId,
    string ActiveBaseUrl,
    string ActiveOrigin,
    string ActivePublicKeySha256,
    int ShardCount,
    IReadOnlyList<SigstoreRekorTlogEntry> TrustedTlogs,
    bool ActiveShardInTrustedRoot,
    bool ActiveShardMatchesCatalog,
    bool? SigningConfigRoutesExclusivelyToActiveShard,
    SigstoreRekorCheckpointEvidence? ActiveCheckpoint,
    bool? ActiveCheckpointVerified,
    string? IncompleteRotationOperationId,
    string? IncompleteRotationStatus,
    bool Ready,
    string? Reason);

/// <summary>
/// Rekor-shard specific durable-state and wire-format helpers used by the
/// Rekor shard rotation command. These mirror the reading conventions
/// already used for the timestamp authority and Fulcio CA (see
/// <see cref="SigstoreTimestampAuthority"/> and the Fulcio equivalents) but
/// are scoped to Rekor's raw ECDSA signer material, its <c>tlogs</c>
/// TrustedRoot entries, its durable shard catalog, its rotation journal,
/// and its tile-log checkpoint note format. Everything here is read-only:
/// hosting code never writes the catalog or generation material — only
/// the Go TUF worker and <c>SigstoreStateBootstrapper</c> do.
/// </summary>
internal static class SigstoreRekorShard
{
    /// <summary>
    /// Durable hosting-journal status values, in their natural progression
    /// order. Centralized here so both the rotation operation and any
    /// read-only status caller (for example <c>SigstoreStatusCommand</c>)
    /// agree on the exact set of valid values.
    /// </summary>
    internal const string StatusRequested = "requested";
    internal const string StatusCandidateGenerated = "candidate-generated";
    internal const string StatusSecondaryPrepared = "secondary-prepared";
    internal const string StatusSecondaryStarted = "secondary-started";
    internal const string StatusSecondaryProved = "secondary-proved";
    internal const string StatusWorkerCommitted = "worker-committed";
    internal const string StatusSecondaryActivated = "secondary-activated";
    internal const string StatusClientsConverged = "clients-converged";
    internal const string StatusCompleted = "completed";

    private const int MaximumCheckpointBytes = 64 * 1024;

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        };

    internal static RekorShardMaterialInfo ReadActiveMaterial(
        string statePath) =>
        SigstoreStateBootstrapper.ValidateRekorShardMaterial(
            Path.Combine(statePath, "active-generation"));

    internal static IReadOnlyList<SigstoreRekorTlogEntry> ReadTlogEntries(
        string statePath) =>
        ReadTlogEntries(
            File.ReadAllBytes(
                Path.Combine(
                    statePath,
                    "tuf",
                    "active",
                    "targets",
                    "trusted_root.json")));

    /// <summary>
    /// Parses and validates the <c>tlogs</c> array of a TrustedRoot
    /// document. Each entry must use SHA2_256/ECDSA-P256 and its log ID
    /// must equal the SHA-256 fingerprint of its own public key, matching
    /// the binding the Go TUF worker enforces
    /// (<c>transparencyLogDigest</c>).
    /// </summary>
    internal static IReadOnlyList<SigstoreRekorTlogEntry> ReadTlogEntries(
        ReadOnlySpan<byte> trustedRootBytes)
    {
        using var document = JsonDocument.Parse(trustedRootBytes.ToArray());
        if (!document.RootElement.TryGetProperty("tlogs", out var tlogs)
            || tlogs.ValueKind != JsonValueKind.Array
            || tlogs.GetArrayLength() == 0)
        {
            throw new InvalidDataException(
                "TrustedRoot does not contain a Rekor transparency log.");
        }

        var result = new List<SigstoreRekorTlogEntry>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var index = 0;
        foreach (var entry in tlogs.EnumerateArray())
        {
            var baseUrl = entry.GetProperty("baseUrl").GetString();
            if (string.IsNullOrWhiteSpace(baseUrl)
                || !Uri.TryCreate(baseUrl, UriKind.Absolute, out var parsed)
                || parsed.Scheme is not ("http" or "https"))
            {
                throw new InvalidDataException(
                    $"TrustedRoot Rekor tlog {index} has an invalid base URL.");
            }
            if (entry.GetProperty("hashAlgorithm").GetString()
                != "SHA2_256")
            {
                throw new InvalidDataException(
                    $"TrustedRoot Rekor tlog {index} uses an unsupported " +
                    "hash algorithm.");
            }
            var publicKey = entry.GetProperty("publicKey");
            if (publicKey.GetProperty("keyDetails").GetString()
                != "PKIX_ECDSA_P256_SHA_256")
            {
                throw new InvalidDataException(
                    $"TrustedRoot Rekor tlog {index} public key is not " +
                    "ECDSA P-256.");
            }
            var rawBytes = Convert.FromBase64String(
                publicKey.GetProperty("rawBytes").GetString()
                ?? throw new InvalidDataException(
                    $"TrustedRoot Rekor tlog {index} public key bytes are " +
                    "empty."));
            using (var ecdsa = ECDsa.Create())
            {
                try
                {
                    ecdsa.ImportSubjectPublicKeyInfo(rawBytes, out _);
                }
                catch (CryptographicException exception)
                {
                    throw new InvalidDataException(
                        $"TrustedRoot Rekor tlog {index} public key is not " +
                        "a valid ECDSA key.",
                        exception);
                }
                if (ecdsa.KeySize != 256)
                {
                    throw new InvalidDataException(
                        $"TrustedRoot Rekor tlog {index} public key must " +
                        "be 256-bit.");
                }
            }
            var digest = Hash(rawBytes);
            var keyId = Convert.FromBase64String(
                entry.GetProperty("logId")
                    .GetProperty("keyId")
                    .GetString()
                ?? throw new InvalidDataException(
                    $"TrustedRoot Rekor tlog {index} log ID is empty."));
            if (Convert.ToHexString(keyId).ToLowerInvariant() != digest)
            {
                throw new InvalidDataException(
                    $"TrustedRoot Rekor tlog {index} log ID does not " +
                    "match its public key.");
            }
            if (!seen.Add($"{baseUrl}/{digest}"))
            {
                throw new InvalidDataException(
                    "TrustedRoot contains a duplicate Rekor transparency " +
                    "log entry.");
            }
            result.Add(new SigstoreRekorTlogEntry(index, baseUrl, digest));
            index++;
        }
        return result;
    }

    /// <summary>
    /// Parses and cryptographically verifies a Rekor tile-log signed
    /// checkpoint (the C2SP <c>tlog-checkpoint</c>/"signed note" format):
    /// an origin line, a decimal tree size, a base64 root hash, a blank
    /// line, and one or more <c>— name signature</c> lines. The signature
    /// covers the note body through its terminating newline, excluding the
    /// additional newline that separates the signature block; its first four
    /// bytes are the standard note key hash — the low four bytes of the
    /// SHA-256 fingerprint of the signer's SubjectPublicKeyInfo — and the
    /// remainder is an ASN.1 DER-encoded ECDSA P-256/SHA-256 signature. This
    /// binds the checkpoint to both the expected origin and the expected
    /// shard signer.
    /// </summary>
    internal static SigstoreRekorCheckpointEvidence ReadAndVerifyCheckpoint(
        ReadOnlySpan<byte> checkpointBytes,
        string expectedOrigin,
        ReadOnlySpan<byte> signerPublicKeySpki)
    {
        if (checkpointBytes.Length is 0 or > MaximumCheckpointBytes)
        {
            throw new InvalidDataException(
                "Rekor checkpoint has an invalid length.");
        }
        var text = Encoding.UTF8.GetString(checkpointBytes)
            .Replace("\r\n", "\n", StringComparison.Ordinal);
        var separatorIndex = text.IndexOf(
            "\n\n",
            StringComparison.Ordinal);
        if (separatorIndex < 0)
        {
            throw new InvalidDataException(
                "Rekor checkpoint is missing its signature block.");
        }

        var body = text[..separatorIndex];
        var signedMessage = text[..(separatorIndex + 1)];
        var bodyLines = body.Split('\n');
        if (bodyLines.Length != 3)
        {
            throw new InvalidDataException(
                "Rekor checkpoint has an invalid note envelope.");
        }
        var origin = bodyLines[0];
        if (origin != expectedOrigin)
        {
            throw new InvalidDataException(
                $"Rekor checkpoint origin '{origin}' does not match the " +
                $"expected origin '{expectedOrigin}'.");
        }
        if (!long.TryParse(
                bodyLines[1],
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var treeSize)
            || treeSize < 0)
        {
            throw new InvalidDataException(
                "Rekor checkpoint tree size is invalid.");
        }
        var rootHash = Convert.FromBase64String(bodyLines[2]);
        if (rootHash.Length != 32)
        {
            throw new InvalidDataException(
                "Rekor checkpoint root hash is not SHA-256.");
        }

        var signatureBlock = text[(separatorIndex + 2)..];
        var signaturePrefix = $"\u2014 {origin} ";
        var signatureLine = signatureBlock
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(
                line => line.StartsWith(
                    signaturePrefix,
                    StringComparison.Ordinal))
            ?? throw new InvalidDataException(
                "Rekor checkpoint has no signature line for its origin.");
        var noteSignature = Convert.FromBase64String(
            signatureLine[signaturePrefix.Length..]);
        if (noteSignature.Length < 5)
        {
            throw new InvalidDataException(
                "Rekor checkpoint signature is truncated.");
        }

        var expectedKeyHash = SHA256.HashData(signerPublicKeySpki.ToArray());
        if (!CryptographicOperations.FixedTimeEquals(
                noteSignature.AsSpan(0, 4),
                expectedKeyHash.AsSpan(0, 4)))
        {
            throw new InvalidDataException(
                "Rekor checkpoint signature key hash does not match the " +
                "expected shard signer.");
        }

        using var publicKey = ECDsa.Create();
        publicKey.ImportSubjectPublicKeyInfo(
            signerPublicKeySpki,
            out _);
        if (!publicKey.VerifyData(
                Encoding.UTF8.GetBytes(signedMessage),
                noteSignature.AsSpan(4),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence))
        {
            throw new InvalidDataException(
                "Rekor checkpoint signature is invalid.");
        }

        return new SigstoreRekorCheckpointEvidence(
            origin,
            treeSize,
            Convert.ToHexString(rootHash).ToLowerInvariant(),
            Convert.ToHexString(noteSignature.AsSpan(0, 4))
                .ToLowerInvariant());
    }

    /// <summary>
    /// Reads the first (index-zero is valid and expected — never assume a
    /// positive index) transparency-log entry from an artifact's signature
    /// bundle, returning its log index and the SHA-256 fingerprint decoded
    /// from its base64 <c>logId.keyId</c>.
    /// </summary>
    internal static SigstoreRekorArtifactLogEntry ReadArtifactTlogEntry(
        ReadOnlySpan<byte> bundleBytes)
    {
        using var document = JsonDocument.Parse(bundleBytes.ToArray());
        var material = document.RootElement.GetProperty(
            "verificationMaterial");
        if (!material.TryGetProperty("tlogEntries", out var entries)
            || entries.ValueKind != JsonValueKind.Array
            || entries.GetArrayLength() == 0)
        {
            throw new InvalidDataException(
                "Artifact bundle does not contain a Rekor transparency " +
                "log entry.");
        }
        var entry = entries[0];
        var logIndexElement = entry.GetProperty("logIndex");
        var logIndex = logIndexElement.ValueKind == JsonValueKind.String
            ? long.Parse(
                logIndexElement.GetString()!,
                System.Globalization.CultureInfo.InvariantCulture)
            : logIndexElement.GetInt64();
        if (logIndex < 0)
        {
            throw new InvalidDataException(
                "Artifact bundle Rekor log index is negative.");
        }
        var keyId = Convert.FromBase64String(
            entry.GetProperty("logId")
                .GetProperty("keyId")
                .GetString()
            ?? throw new InvalidDataException(
                "Artifact bundle Rekor log ID is empty."));
        return new SigstoreRekorArtifactLogEntry(
            logIndex,
            Convert.ToHexString(keyId).ToLowerInvariant());
    }

    /// <summary>
    /// Reads the durable Rekor shard catalog if it exists, or
    /// <see langword="null"/> when no rotation has ever run (the catalog
    /// is created lazily by the Go TUF worker on first rotation).
    /// </summary>
    internal static RekorShardCatalog? TryReadShardCatalog(
        string statePath) =>
        File.Exists(ShardCatalogPath(statePath))
            ? ReadShardCatalog(statePath)
            : null;

    /// <summary>
    /// Reads and strictly validates the durable Rekor shard catalog:
    /// schema, ordered primary/secondary slots, per-shard log ID binding,
    /// and activation ordering.
    /// </summary>
    internal static RekorShardCatalog ReadShardCatalog(string statePath)
    {
        var path = ShardCatalogPath(statePath);
        var catalog = JsonSerializer.Deserialize<RekorShardCatalog>(
            File.ReadAllText(path),
            JsonOptions)
            ?? throw new InvalidDataException(
                "The Rekor shard catalog is empty.");
        if (catalog.SchemaVersion != 1
            || string.IsNullOrWhiteSpace(catalog.TrustDomainId)
            || string.IsNullOrWhiteSpace(catalog.ActiveShardId)
            || catalog.Shards.Count is not (1 or 2))
        {
            throw new InvalidDataException(
                "The Rekor shard catalog has malformed durable state.");
        }
        foreach (var shard in catalog.Shards)
        {
            if (!IsLowerHexSha256(shard.PublicKeySha256)
                || shard.LogIdSha256 != shard.PublicKeySha256
                || shard.ShardId != $"sha256-{shard.PublicKeySha256}"
                || string.IsNullOrWhiteSpace(shard.StateId)
                || shard.ActivatedAtUtc < shard.CreatedAtUtc
                || shard.Status is not ("active" or "historical"))
            {
                throw new InvalidDataException(
                    "The Rekor shard catalog contains a malformed shard " +
                    "entry.");
            }
        }
        if (catalog.Shards[0].Slot != "primary")
        {
            throw new InvalidDataException(
                "The Rekor shard catalog primary entry is invalid.");
        }
        if (catalog.Shards.Count == 2
            && catalog.Shards[1].Slot != "secondary")
        {
            throw new InvalidDataException(
                "The Rekor shard catalog secondary entry is invalid.");
        }
        return catalog;
    }

    internal static string ShardCatalogPath(string statePath) =>
        Path.Combine(statePath, "data", "rekor-shards", "state.json");

    /// <summary>
    /// Reads and schema-validates every durable Rekor shard rotation
    /// hosting journal (<c>rekor-shard-rotation/&lt;operationId&gt;/
    /// hosting-state.json</c>), in no particular order, regardless of
    /// status. Callers that need "the one in-flight operation" (the
    /// rotation command itself) additionally filter and enforce
    /// uniqueness; read-only status callers may simply pick the most
    /// recent entry.
    /// </summary>
    internal static IReadOnlyList<RekorShardRotationCommandJournal>
        ReadRotationJournals(string statePath)
    {
        var root = Path.Combine(statePath, "rekor-shard-rotation");
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
                        RekorShardRotationCommandJournal>(
                            File.ReadAllText(path),
                            JsonOptions)
                        ?? throw new InvalidDataException(
                            $"Rekor shard rotation journal '{path}' is " +
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
                        || journal.Status is not (
                            StatusRequested
                            or StatusCandidateGenerated
                            or StatusSecondaryPrepared
                            or StatusSecondaryStarted
                            or StatusSecondaryProved
                            or StatusWorkerCommitted
                            or StatusSecondaryActivated
                            or StatusClientsConverged
                            or StatusCompleted)
                        || journal.StartingGeneration < 1
                        || journal.StartingGenerationId
                            != $"generation-{journal.StartingGeneration:D8}"
                        || journal.StartingSnapshot.Tuf.Trust.TrustDomainId
                            != journal.TrustDomainId
                        || journal.StartingSnapshot.Tuf.Trust.Generation
                            != journal.StartingGeneration
                        || journal.StartingSnapshot.Tuf.Trust.GenerationId
                            != journal.StartingGenerationId
                        || journal.Clients
                            .Select(client => client.Resource)
                            .Distinct(StringComparer.Ordinal)
                            .Count() != journal.Clients.Count)
                    {
                        throw new InvalidDataException(
                            $"Rekor shard rotation journal '{path}' has " +
                            "invalid state.");
                    }
                    return journal;
                })
            .ToArray();
    }

    /// <summary>
    /// Reads the ECDSA SubjectPublicKeyInfo DER bytes of the active
    /// generation's Rekor signer (<c>active-generation/public/rekor/
    /// signer.pub</c>).
    /// </summary>
    internal static byte[] ReadActivePublicKeySpki(string statePath) =>
        ReadPublicKeySpkiFromPem(
            Path.Combine(
                statePath,
                "active-generation",
                "public",
                "rekor",
                "signer.pub"));

    /// <summary>
    /// Reads the ECDSA SubjectPublicKeyInfo DER bytes of a Rekor rotation
    /// candidate's staged public key (<c>&lt;candidatePath&gt;/public/
    /// rekor/signer.pub</c>).
    /// </summary>
    internal static byte[] ReadCandidatePublicKeySpki(
        string candidatePath) =>
        ReadPublicKeySpkiFromPem(
            Path.Combine(candidatePath, "public", "rekor", "signer.pub"));

    private static byte[] ReadPublicKeySpkiFromPem(string pemPath)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(File.ReadAllText(pemPath));
        return ecdsa.ExportSubjectPublicKeyInfo();
    }

    /// <summary>
    /// Composes a read-only status for the Rekor shard rotation from disk
    /// state alone, optionally strengthened with live evidence the caller
    /// already fetched: the active shard's SigningConfig
    /// <c>rekorTlogUrls</c> (to confirm exclusive routing) and a freshly
    /// fetched checkpoint from the active shard's route (to confirm the
    /// gateway is actually serving a validly signed checkpoint). Neither
    /// live input is required — omit them and this reports what disk state
    /// alone can prove.
    /// </summary>
    internal static SigstoreRekorShardStatus ReadStatus(
        string statePath,
        IReadOnlyList<string>? signingConfigRekorTlogUrls = null,
        ReadOnlyMemory<byte>? liveCheckpointBytes = null)
    {
        var active = ReadActiveMaterial(statePath);
        var activeShardId = $"sha256-{active.PublicKeySha256}";
        var tlogEntries = ReadTlogEntries(statePath);
        var activeTlogEntry = tlogEntries.LastOrDefault(
            entry => entry.PublicKeySha256 == active.PublicKeySha256);

        RekorShardCatalog? catalog;
        string? catalogError = null;
        try
        {
            catalog = TryReadShardCatalog(statePath);
        }
        catch (InvalidDataException exception)
        {
            catalog = null;
            catalogError = exception.Message;
        }
        var activeCatalogEntry = catalog?.Shards.SingleOrDefault(
            shard => shard.ShardId == activeShardId
                && shard.Status == "active");
        var matchesCatalog = catalogError is null
            && activeCatalogEntry is not null
            && catalog!.ActiveShardId == activeShardId;

        bool? signingConfigExclusive = null;
        if (signingConfigRekorTlogUrls is not null)
        {
            signingConfigExclusive =
                activeTlogEntry is not null
                && signingConfigRekorTlogUrls.Count == 1
                && signingConfigRekorTlogUrls[0] == activeTlogEntry.BaseUrl;
        }

        SigstoreRekorCheckpointEvidence? checkpoint = null;
        bool? checkpointVerified = null;
        if (liveCheckpointBytes is { } bytes
            && activeCatalogEntry is not null)
        {
            try
            {
                checkpoint = ReadAndVerifyCheckpoint(
                    bytes.Span,
                    activeCatalogEntry.Origin,
                    ReadActivePublicKeySpki(statePath));
                checkpointVerified = true;
            }
            catch (InvalidDataException)
            {
                checkpointVerified = false;
            }
        }

        var incomplete = ReadRotationJournals(statePath)
            .Where(journal => journal.Status != StatusCompleted)
            .OrderByDescending(journal => journal.StartedAtUtc)
            .FirstOrDefault();

        var matchesTrustedRoot = activeTlogEntry is not null;
        var ready = catalogError is null
            && matchesTrustedRoot
            && matchesCatalog
            && signingConfigExclusive != false
            && checkpointVerified != false;
        var reason = catalogError
            ?? (!matchesTrustedRoot
                ? "TrustedRoot does not contain the active Rekor shard."
                : !matchesCatalog
                    ? "The Rekor shard catalog does not agree with the " +
                        "active generation."
                    : signingConfigExclusive == false
                        ? "SigningConfig does not route exclusively to " +
                            "the active Rekor shard."
                        : checkpointVerified == false
                            ? "The active Rekor shard checkpoint did not " +
                                "verify."
                            : null);

        return new SigstoreRekorShardStatus(
            activeShardId,
            activeCatalogEntry?.BaseUrl
                ?? activeTlogEntry?.BaseUrl
                ?? string.Empty,
            activeCatalogEntry?.Origin ?? string.Empty,
            active.PublicKeySha256,
            catalog?.Shards.Count ?? tlogEntries.Count,
            tlogEntries,
            matchesTrustedRoot,
            matchesCatalog,
            signingConfigExclusive,
            checkpoint,
            checkpointVerified,
            incomplete?.OperationId,
            incomplete?.Status,
            ready,
            reason);
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
