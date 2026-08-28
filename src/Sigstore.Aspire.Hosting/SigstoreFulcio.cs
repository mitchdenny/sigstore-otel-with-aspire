using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Sigstore.Bootstrap;

namespace Aspire.Hosting.ApplicationModel;

public sealed record SigstoreFulcioTrustEntry(
    int Index,
    string Uri,
    string RootSha256,
    string Subject,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc);

public sealed record SigstoreCtCheckpoint(
    string Origin,
    ulong TreeSize,
    ulong Timestamp,
    string RootHash,
    string SignatureSha256,
    string LogId);

public sealed record SigstoreFulcioStatus(
    string ActiveRootSha256,
    string LiveRootSha256,
    bool ActiveCertificateMatchesPrivateKey,
    bool RuntimeFulcioMatchesActive,
    bool RuntimePromotionPending,
    string? StagedRootSha256,
    bool LiveRootMatchesActive,
    IReadOnlyList<SigstoreFulcioTrustEntry> TrustedRoots,
    IReadOnlyList<string> AcceptedRootSha256,
    string AcceptedRootsSha256,
    bool TesseractAcceptedRootsMatch,
    string CtLogPublicKeySha256,
    string CtLogId,
    string CtLogStateId,
    SigstoreCtCheckpoint Checkpoint);

internal sealed record SigstoreFulcioIssuanceProof(
    string CertificateSha256,
    string RootSha256,
    string CertificateSubject,
    string CertificateIssuer,
    string Identity,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc,
    string CtLogId,
    ulong SctTimestamp,
    string SctSignatureSha256,
    bool SctVerified);

internal sealed record SigstoreEmbeddedSctProof(
    ulong Timestamp,
    string LogId,
    string SignatureSha256);

internal static class SigstoreFulcio
{
    internal const string CanonicalUri =
        "http://fulcio-sigstore.dev.localhost:5555";
    internal const string CtOrigin =
        "tesseract-sigstore.dev.localhost";

    private const string SctListOid =
        "1.3.6.1.4.1.11129.2.4.2";
    private const int MaximumPayloadBytes = 4 * 1024 * 1024;

    private static readonly Asn1Tag ExtensionsTag =
        new(TagClass.ContextSpecific, 3, isConstructed: true);

    public static async Task<SigstoreFulcioStatus> ReadStatusAsync(
        string statePath,
        Uri fulcioEndpoint,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentNullException.ThrowIfNull(fulcioEndpoint);

        var activePath = Path.Combine(statePath, "active-generation");
        var active = ReadMaterial(
            Path.Combine(activePath, "public", "fulcio", "root.pem"),
            Path.Combine(activePath, "private", "fulcio", "root.key"),
            Path.Combine(activePath, "private", "fulcio", "password"));
        var runtimePath = Path.Combine(statePath, "runtime", "fulcio");
        var runtime =
            SigstoreStateBootstrapper.ReadFulcioRuntimeProjection(
                statePath);
        using var activeCertificate = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                Path.Combine(
                    activePath,
                    "public",
                    "fulcio",
                    "root.pem")));
        using var liveCertificate = await ReadLiveRootAsync(
            fulcioEndpoint,
            cancellationToken);

        var trustedRoots = ReadTrustedRoots(statePath);
        var acceptedRootsPath = Path.Combine(
            statePath,
            "runtime",
            "tesseract",
            "accepted-roots.pem");
        var acceptedBytes = File.ReadAllBytes(acceptedRootsPath);
        var acceptedCertificates = ReadCertificateBundle(acceptedBytes);
        var acceptedFingerprints = runtime.AcceptedRootSha256;
        var trustedFingerprints = trustedRoots
            .Select(root => root.RootSha256)
            .ToArray();
        var trustedCertificates = trustedRoots
            .Select(
                entry => ReadTrustedRootCertificate(
                    statePath,
                    entry.Index))
            .ToArray();
        byte[] expectedBundle;
        try
        {
            expectedBundle = CreateAcceptedRootsBundle(
                trustedCertificates);
        }
        finally
        {
            foreach (var certificate in trustedCertificates)
            {
                certificate.Dispose();
            }
        }

        var ctPrivatePath = Path.Combine(
            statePath,
            "runtime",
            "tesseract",
            "privkey.pem");
        var ctPublicPath = Path.Combine(
            activePath,
            "public",
            "ctlog",
            "pubkey.pem");
        using var ctPrivateKey = LoadEcdsaPrivateKey(ctPrivatePath);
        using var ctPublicKey = LoadEcdsaPublicKey(ctPublicPath);
        EnsureKeysMatch(
            "Tesseract runtime and active CT log keys",
            ctPrivateKey,
            ctPublicKey);
        using var fulcioCtPublicKey = LoadEcdsaPublicKey(
            Path.Combine(runtimePath, "ctlog.pub"));
        EnsureKeysMatch(
            "Fulcio runtime and active CT log keys",
            fulcioCtPublicKey,
            ctPublicKey);
        var ctSpki = ctPublicKey.ExportSubjectPublicKeyInfo();
        var checkpoint = ReadCheckpoint(
            statePath,
            ctPublicKey);
        var ctStateId = File.ReadAllText(
            Path.Combine(
                statePath,
                "data",
                "ctlog",
                "bootstrap-state"));

        foreach (var certificate in acceptedCertificates)
        {
            certificate.Dispose();
        }

        return new SigstoreFulcioStatus(
            active.RootSha256,
            Fingerprint(liveCertificate.RawData),
            active.CertificateMatchesPrivateKey,
            runtime.ActiveRootSha256 == active.RootSha256,
            runtime.PromotionPending,
            runtime.StagedRootSha256,
            liveCertificate.RawData.SequenceEqual(activeCertificate.RawData),
            trustedRoots,
            acceptedFingerprints,
            runtime.AcceptedRootsSha256,
            acceptedBytes.AsSpan().SequenceEqual(expectedBundle)
                && acceptedFingerprints.SequenceEqual(
                    trustedFingerprints,
                    StringComparer.Ordinal),
            Fingerprint(ctSpki),
            Fingerprint(ctSpki),
            ctStateId,
            checkpoint);
    }

    internal static IReadOnlyList<SigstoreFulcioTrustEntry>
        ReadTrustedRoots(string statePath)
    {
        var targetPath = ResolveActiveTarget(
            statePath,
            "trusted_root.json");
        using var document = JsonDocument.Parse(
            File.ReadAllBytes(targetPath));
        if (!document.RootElement.TryGetProperty(
                "certificateAuthorities",
                out var authorities)
            || authorities.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                "TrustedRoot omits certificateAuthorities.");
        }

        var result = new List<SigstoreFulcioTrustEntry>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var authority in authorities.EnumerateArray())
        {
            var uri = authority.GetProperty("uri").GetString()
                ?? throw new InvalidDataException(
                    "TrustedRoot Fulcio URI is empty.");
            if (uri != CanonicalUri)
            {
                throw new InvalidDataException(
                    $"TrustedRoot Fulcio URI '{uri}' is not canonical.");
            }
            var certificates = authority
                .GetProperty("certChain")
                .GetProperty("certificates")
                .EnumerateArray()
                .ToArray();
            if (certificates.Length != 1)
            {
                throw new InvalidDataException(
                    "Each Fulcio TrustedRoot entry must contain one root.");
            }
            var raw = Convert.FromBase64String(
                certificates[0].GetProperty("rawBytes").GetString()
                ?? throw new InvalidDataException(
                    "TrustedRoot Fulcio root bytes are empty."));
            using var certificate =
                X509CertificateLoader.LoadCertificate(raw);
            ValidateRootProfile(certificate);
            var fingerprint = Fingerprint(raw);
            if (!seen.Add(fingerprint))
            {
                throw new InvalidDataException(
                    "TrustedRoot contains duplicate Fulcio roots.");
            }
            result.Add(
                new SigstoreFulcioTrustEntry(
                    result.Count,
                    uri,
                    fingerprint,
                    certificate.Subject,
                    certificate.NotBefore.ToUniversalTime(),
                    certificate.NotAfter.ToUniversalTime()));
        }
        if (result.Count == 0)
        {
            throw new InvalidDataException(
                "TrustedRoot contains no Fulcio roots.");
        }
        return result;
    }

    internal static async Task<X509Certificate2> ReadLiveRootAsync(
        Uri fulcioEndpoint,
        CancellationToken cancellationToken)
    {
        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        var endpoint = new Uri(
            EnsureTrailingSlash(fulcioEndpoint),
            "api/v1/rootCert");
        using var response = await client.GetAsync(
            endpoint,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new InvalidDataException(
                $"Fulcio root endpoint returned HTTP {(int)response.StatusCode}.");
        }
        var bytes = await response.Content.ReadAsByteArrayAsync(
            cancellationToken);
        if (bytes.Length is 0 or > MaximumPayloadBytes)
        {
            throw new InvalidDataException(
                "Fulcio root endpoint returned an invalid payload length.");
        }
        var certificate = X509Certificate2.CreateFromPem(
            Encoding.UTF8.GetString(bytes));
        ValidateRootProfile(certificate);
        return certificate;
    }

    internal static async Task<SigstoreFulcioIssuanceProof>
        ProveIssuanceAsync(
            Uri fulcioEndpoint,
            string oidcToken,
            string subject,
            X509Certificate2 expectedRoot,
            ECDsa ctPublicKey,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fulcioEndpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(oidcToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        ArgumentNullException.ThrowIfNull(expectedRoot);
        ArgumentNullException.ThrowIfNull(ctPublicKey);

        ValidateRootProfile(expectedRoot);
        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue(
                "Bearer",
                oidcToken);
        using var subjectKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var requestBody = new
        {
            publicKeyRequest = new
            {
                publicKey = new
                {
                    algorithm = "ECDSA",
                    content = subjectKey.ExportSubjectPublicKeyInfoPem()
                },
                proofOfPossession = Convert.ToBase64String(
                    subjectKey.SignData(
                        Encoding.UTF8.GetBytes(subject),
                        HashAlgorithmName.SHA256))
            }
        };
        using var response = await client.PostAsJsonAsync(
            new Uri(
                EnsureTrailingSlash(fulcioEndpoint),
                "api/v2/signingCert"),
            requestBody,
            cancellationToken);
        var responseBytes = await response.Content.ReadAsByteArrayAsync(
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidDataException(
                $"Fulcio issuance returned {(int)response.StatusCode}: " +
                Encoding.UTF8.GetString(responseBytes));
        }
        if (responseBytes.Length is 0 or > MaximumPayloadBytes)
        {
            throw new InvalidDataException(
                "Fulcio issuance returned an invalid payload length.");
        }

        using var responseJson = JsonDocument.Parse(responseBytes);
        var certificatePem = FindCertificatePem(responseJson.RootElement)
            ?? throw new InvalidDataException(
                "Fulcio response did not contain a PEM certificate.");
        using var certificate = X509Certificate2.CreateFromPem(
            certificatePem);
        ValidateIssuedCertificate(
            certificate,
            expectedRoot,
            subjectKey,
            subject);
        var sct = ValidateEmbeddedSct(
            certificate,
            expectedRoot,
            ctPublicKey);

        return new SigstoreFulcioIssuanceProof(
            Fingerprint(certificate.RawData),
            Fingerprint(expectedRoot.RawData),
            certificate.Subject,
            certificate.Issuer,
            subject,
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            sct.LogId,
            sct.Timestamp,
            sct.SignatureSha256,
            true);
    }

    internal static SigstoreCtCheckpoint ReadCheckpoint(
        string statePath,
        ECDsa ctPublicKey)
    {
        var path = Path.Combine(
            statePath,
            "data",
            "ctlog",
            "checkpoint");
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length is 0 or > MaximumPayloadBytes)
        {
            throw new InvalidDataException(
                "Tesseract checkpoint file has an invalid length.");
        }
        var lines = Encoding.UTF8.GetString(bytes)
            .Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .ToArray();
        if (lines.Length < 6
            || lines[0] != CtOrigin
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
        var rootHash = Convert.FromBase64String(
            lines[2]);
        if (rootHash.Length != 32)
        {
            throw new InvalidDataException(
                "Tesseract checkpoint root hash is not SHA-256.");
        }
        var signaturePrefix = $"\u2014 {CtOrigin} ";
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
        var spki = ctPublicKey.ExportSubjectPublicKeyInfo();
        var logId = SHA256.HashData(spki);
        var origin = Encoding.UTF8.GetBytes(CtOrigin);
        var noteKeyHashInput = new byte[
            origin.Length + 2 + logId.Length];
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
        var signature = ReadDigitallySigned(
            noteSignature.AsSpan(12));

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
        if (!ctPublicKey.VerifyData(
                signed,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence))
        {
            throw new InvalidDataException(
                "Tesseract checkpoint signature is invalid.");
        }

        return new SigstoreCtCheckpoint(
            CtOrigin,
            treeSize,
            timestamp,
            Convert.ToHexString(rootHash).ToLowerInvariant(),
            Fingerprint(signature),
            Fingerprint(spki));
    }

    internal static byte[] CreateAcceptedRootsBundle(
        IEnumerable<X509Certificate2> certificates)
    {
        var builder = new StringBuilder();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var certificate in certificates)
        {
            ValidateRootProfile(certificate);
            var fingerprint = Fingerprint(certificate.RawData);
            if (!seen.Add(fingerprint))
            {
                continue;
            }
            builder.Append(certificate.ExportCertificatePem().TrimEnd());
            builder.Append('\n');
        }
        if (seen.Count == 0)
        {
            throw new InvalidDataException(
                "An accepted-root bundle must contain at least one root.");
        }
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    internal static IReadOnlyList<X509Certificate2> ReadCertificateBundle(
        ReadOnlySpan<byte> bundle)
    {
        var certificates = new X509Certificate2Collection();
        certificates.ImportFromPem(Encoding.ASCII.GetString(bundle));
        if (certificates.Count == 0)
        {
            throw new InvalidDataException(
                "The accepted-root bundle contains no certificates.");
        }
        var result = new List<X509Certificate2>(certificates.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var certificate in certificates)
        {
            ValidateRootProfile(certificate);
            if (!seen.Add(Fingerprint(certificate.RawData)))
            {
                foreach (var item in result)
                {
                    item.Dispose();
                }
                throw new InvalidDataException(
                    "The accepted-root bundle contains duplicate roots.");
            }
            result.Add(certificate);
        }
        return result;
    }

    internal static void ValidateRootProfile(
        X509Certificate2 certificate)
    {
        using var publicKey = certificate.GetECDsaPublicKey()
            ?? throw new InvalidDataException(
                "Fulcio root does not contain an ECDSA key.");
        var constraints = certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .SingleOrDefault();
        var usage = certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .SingleOrDefault();
        if (publicKey.KeySize != 256
            || certificate.SignatureAlgorithm.Value
                != "1.2.840.10045.4.3.2"
            || constraints is null
            || !constraints.Critical
            || !constraints.CertificateAuthority
            || constraints.HasPathLengthConstraint
            || usage is null
            || !usage.Critical
            || usage.KeyUsages
                != (X509KeyUsageFlags.DigitalSignature
                    | X509KeyUsageFlags.KeyCertSign
                    | X509KeyUsageFlags.CrlSign)
            || certificate.GetNameInfo(
                    X509NameType.SimpleName,
                    forIssuer: false)
                != "Fulcio Root"
            || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow
            || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow)
        {
            throw new InvalidDataException(
                "Fulcio root does not match the required CA profile.");
        }
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(certificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        if (!chain.Build(certificate))
        {
            throw new InvalidDataException(
                "Fulcio root is not validly self-signed.");
        }
    }

    internal static string Fingerprint(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes))
            .ToLowerInvariant();

    internal static X509Certificate2 ReadRootByFingerprint(
        string statePath,
        string fingerprint)
    {
        foreach (var generation in Directory.EnumerateDirectories(
            Path.Combine(statePath, "generations"))
            .Order(StringComparer.Ordinal))
        {
            var path = Path.Combine(
                generation,
                "public",
                "fulcio",
                "root.pem");
            using var candidate = X509Certificate2.CreateFromPem(
                File.ReadAllText(path));
            if (Fingerprint(candidate.RawData) == fingerprint)
            {
                return X509Certificate2.CreateFromPem(
                    File.ReadAllText(path));
            }
        }
        throw new InvalidDataException(
            $"Fulcio root {fingerprint} is not present in immutable history.");
    }

    internal static ECDsa ReadCtPublicKey(string statePath) =>
        LoadEcdsaPublicKey(
            Path.Combine(
                statePath,
                "active-generation",
                "public",
                "ctlog",
                "pubkey.pem"));

    internal static SigstoreEmbeddedSctProof
        ValidateCertificateForRoot(
            X509Certificate2 certificate,
            X509Certificate2 expectedRoot,
            ECDsa ctPublicKey,
            string subject)
    {
        ValidateCertificateIdentityAndChain(
            certificate,
            expectedRoot,
            subject);
        return ValidateEmbeddedSct(
            certificate,
            expectedRoot,
            ctPublicKey);
    }

    internal static bool CertificateChainsToRoot(
        X509Certificate2 certificate,
        X509Certificate2 expectedRoot)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(expectedRoot);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags =
            X509VerificationFlags.IgnoreWrongUsage;
        return chain.Build(certificate)
            && chain.ChainElements.Count >= 2
            && chain.ChainElements[^1].Certificate.RawData
                .SequenceEqual(expectedRoot.RawData);
    }

    private static FulcioMaterial ReadMaterial(
        string certificatePath,
        string keyPath,
        string passwordPath)
    {
        using var certificate = X509Certificate2.CreateFromPem(
            File.ReadAllText(certificatePath));
        ValidateRootProfile(certificate);
        using var key = ECDsa.Create();
        key.ImportFromEncryptedPem(
            File.ReadAllText(keyPath),
            File.ReadAllText(passwordPath));
        using var certificateKey = certificate.GetECDsaPublicKey()
            ?? throw new InvalidDataException(
                "Fulcio root does not contain an ECDSA key.");
        var matches = CryptographicOperations.FixedTimeEquals(
            key.ExportSubjectPublicKeyInfo(),
            certificateKey.ExportSubjectPublicKeyInfo());
        if (!matches)
        {
            throw new InvalidDataException(
                "Fulcio root certificate and private key do not match.");
        }
        return new FulcioMaterial(
            Fingerprint(certificate.RawData),
            Fingerprint(key.ExportSubjectPublicKeyInfo()),
            matches);
    }

    private static X509Certificate2 ReadTrustedRootCertificate(
        string statePath,
        int index)
    {
        using var document = JsonDocument.Parse(
            File.ReadAllBytes(
                ResolveActiveTarget(
                    statePath,
                    "trusted_root.json")));
        var authority = document.RootElement
            .GetProperty("certificateAuthorities")
            .EnumerateArray()
            .ElementAt(index);
        var raw = Convert.FromBase64String(
            authority
                .GetProperty("certChain")
                .GetProperty("certificates")[0]
                .GetProperty("rawBytes")
                .GetString()
            ?? throw new InvalidDataException(
                "TrustedRoot Fulcio root bytes are empty."));
        return X509CertificateLoader.LoadCertificate(raw);
    }

    private static string ResolveActiveTarget(
        string statePath,
        string target)
    {
        var active = new DirectoryInfo(
            Path.Combine(statePath, "tuf", "active"));
        var link = active.LinkTarget
            ?? throw new InvalidDataException(
                "The active TUF publication link is missing.");
        if (Path.IsPathFullyQualified(link))
        {
            throw new InvalidDataException(
                "The active TUF publication link is unsafe.");
        }
        return Path.Combine(
            statePath,
            "tuf",
            link,
            "targets",
            target);
    }

    private static void ValidateIssuedCertificate(
        X509Certificate2 certificate,
        X509Certificate2 expectedRoot,
        ECDsa subjectKey,
        string subject)
    {
        using var certificateKey = certificate.GetECDsaPublicKey()
            ?? throw new InvalidDataException(
                "Fulcio certificate does not contain an ECDSA key.");
        if (!CryptographicOperations.FixedTimeEquals(
                certificateKey.ExportSubjectPublicKeyInfo(),
                subjectKey.ExportSubjectPublicKeyInfo()))
        {
            throw new InvalidDataException(
                "Fulcio certificate does not contain the requested public key.");
        }
        ValidateCertificateIdentityAndChain(
            certificate,
            expectedRoot,
            subject);
    }

    private static void ValidateCertificateIdentityAndChain(
        X509Certificate2 certificate,
        X509Certificate2 expectedRoot,
        string subject)
    {
        if (certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow
            || certificate.NotBefore.ToUniversalTime()
                > DateTime.UtcNow.AddMinutes(1)
            || !certificate.Extensions
                .Where(extension => extension.Oid?.Value == "2.5.29.17")
                .Any(extension => extension.Format(false)
                    .Contains(
                        subject,
                        StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidDataException(
                "Fulcio certificate lifetime or identity is invalid.");
        }
        if (!CertificateChainsToRoot(certificate, expectedRoot))
        {
            throw new InvalidDataException(
                "Fulcio certificate does not chain to the expected root.");
        }
    }

    private static SigstoreEmbeddedSctProof ValidateEmbeddedSct(
        X509Certificate2 certificate,
        X509Certificate2 issuer,
        ECDsa ctPublicKey)
    {
        var extension = certificate.Extensions
            .Cast<X509Extension>()
            .SingleOrDefault(item => item.Oid?.Value == SctListOid)
            ?? throw new InvalidDataException(
                "Fulcio certificate omits the embedded SCT list.");
        var list = UnwrapOctetString(extension.RawData);
        if (list.Length < 2)
        {
            throw new InvalidDataException(
                "Fulcio certificate SCT list is truncated.");
        }
        var declaredLength = BinaryPrimitives.ReadUInt16BigEndian(list);
        if (declaredLength != list.Length - 2)
        {
            throw new InvalidDataException(
                "Fulcio certificate SCT list length is invalid.");
        }
        var offset = 2;
        SigstoreEmbeddedSctProof? proof = null;
        while (offset < list.Length)
        {
            if (offset + 2 > list.Length)
            {
                throw new InvalidDataException(
                    "Fulcio certificate SCT entry length is truncated.");
            }
            var length = BinaryPrimitives.ReadUInt16BigEndian(
                list.AsSpan(offset, 2));
            offset += 2;
            if (length == 0 || offset + length > list.Length)
            {
                throw new InvalidDataException(
                    "Fulcio certificate SCT entry length is invalid.");
            }
            var current = ParseAndVerifySct(
                list.AsSpan(offset, length),
                certificate,
                issuer,
                ctPublicKey);
            if (proof is not null)
            {
                throw new InvalidDataException(
                    "Fulcio certificate contains more than one SCT.");
            }
            proof = current;
            offset += length;
        }
        return proof
            ?? throw new InvalidDataException(
                "Fulcio certificate SCT list is empty.");
    }

    private static SigstoreEmbeddedSctProof ParseAndVerifySct(
        ReadOnlySpan<byte> serialized,
        X509Certificate2 certificate,
        X509Certificate2 issuer,
        ECDsa ctPublicKey)
    {
        const int fixedLength = 1 + 32 + 8 + 2;
        if (serialized.Length < fixedLength + 4
            || serialized[0] != 0)
        {
            throw new InvalidDataException(
                "Fulcio certificate SCT is malformed or unsupported.");
        }
        var logId = serialized.Slice(1, 32);
        var expectedLogId = SHA256.HashData(
            ctPublicKey.ExportSubjectPublicKeyInfo());
        if (!CryptographicOperations.FixedTimeEquals(
                logId,
                expectedLogId))
        {
            throw new InvalidDataException(
                "Fulcio certificate SCT log ID is unexpected.");
        }
        var timestamp = BinaryPrimitives.ReadUInt64BigEndian(
            serialized.Slice(33, 8));
        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(
            serialized.Slice(41, 2));
        var signatureOffset = fixedLength + extensionsLength;
        if (signatureOffset + 4 > serialized.Length)
        {
            throw new InvalidDataException(
                "Fulcio certificate SCT extensions are truncated.");
        }
        var extensions = serialized.Slice(
            fixedLength,
            extensionsLength);
        var signature = ReadDigitallySigned(
            serialized[signatureOffset..].ToArray());

        var issuerKeyHash = SHA256.HashData(
            issuer.GetECDsaPublicKey()!.ExportSubjectPublicKeyInfo());
        var precertificateTbs = CreatePrecertificateTbs(certificate);
        if (precertificateTbs.Length > 0x00ff_ffff)
        {
            throw new InvalidDataException(
                "Fulcio precertificate TBS is too large.");
        }
        var signed = new byte[
            1 + 1 + 8 + 2 + 32 + 3
            + precertificateTbs.Length + 2 + extensions.Length];
        var offset = 0;
        signed[offset++] = 0;
        signed[offset++] = 0;
        BinaryPrimitives.WriteUInt64BigEndian(
            signed.AsSpan(offset, 8),
            timestamp);
        offset += 8;
        BinaryPrimitives.WriteUInt16BigEndian(
            signed.AsSpan(offset, 2),
            1);
        offset += 2;
        issuerKeyHash.CopyTo(signed, offset);
        offset += issuerKeyHash.Length;
        WriteUInt24(
            signed.AsSpan(offset, 3),
            precertificateTbs.Length);
        offset += 3;
        precertificateTbs.CopyTo(signed, offset);
        offset += precertificateTbs.Length;
        BinaryPrimitives.WriteUInt16BigEndian(
            signed.AsSpan(offset, 2),
            checked((ushort)extensions.Length));
        offset += 2;
        extensions.CopyTo(signed.AsSpan(offset));

        if (!ctPublicKey.VerifyData(
                signed,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence))
        {
            throw new InvalidDataException(
                "Fulcio embedded SCT signature is invalid.");
        }
        return new SigstoreEmbeddedSctProof(
            timestamp,
            Convert.ToHexString(logId).ToLowerInvariant(),
            Fingerprint(signature));
    }

    private static byte[] CreatePrecertificateTbs(
        X509Certificate2 certificate)
    {
        var certificateReader = new AsnReader(
            certificate.RawData,
            AsnEncodingRules.DER);
        var certificateSequence = certificateReader.ReadSequence();
        var tbs = certificateSequence.ReadEncodedValue().ToArray();
        certificateReader.ThrowIfNotEmpty();

        var tbsReader = new AsnReader(tbs, AsnEncodingRules.DER);
        var tbsSequence = tbsReader.ReadSequence();
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        var replaced = false;
        while (tbsSequence.HasData)
        {
            var tag = tbsSequence.PeekTag();
            if (!tag.HasSameClassAndValue(ExtensionsTag))
            {
                writer.WriteEncodedValue(
                    tbsSequence.ReadEncodedValue().Span);
                continue;
            }

            var wrapper = tbsSequence.ReadSequence(ExtensionsTag);
            var extensions = wrapper.ReadSequence();
            writer.PushSequence(ExtensionsTag);
            writer.PushSequence();
            while (extensions.HasData)
            {
                var encoded = extensions.ReadEncodedValue().ToArray();
                var extensionReader = new AsnReader(
                    encoded,
                    AsnEncodingRules.DER);
                var extensionSequence = extensionReader.ReadSequence();
                var oid = extensionSequence.ReadObjectIdentifier();
                if (oid != SctListOid)
                {
                    writer.WriteEncodedValue(encoded);
                    continue;
                }
                if (replaced)
                {
                    throw new InvalidDataException(
                        "Fulcio certificate contains duplicate SCT extensions.");
                }
                replaced = true;
            }
            extensions.ThrowIfNotEmpty();
            wrapper.ThrowIfNotEmpty();
            writer.PopSequence();
            writer.PopSequence(ExtensionsTag);
        }
        tbsSequence.ThrowIfNotEmpty();
        tbsReader.ThrowIfNotEmpty();
        writer.PopSequence();
        if (!replaced)
        {
            throw new InvalidDataException(
                "Fulcio certificate omits its SCT extension.");
        }
        return writer.Encode();
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

    private static byte[] UnwrapOctetString(ReadOnlySpan<byte> value)
    {
        if (value.Length == 0 || value[0] != 0x04)
        {
            return value.ToArray();
        }
        var reader = new AsnReader(
            value.ToArray(),
            AsnEncodingRules.DER);
        var result = reader.ReadOctetString();
        reader.ThrowIfNotEmpty();
        return result;
    }

    private static string? FindCertificatePem(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.String)
        {
            var value = element.GetString();
            return value?.Contains(
                "-----BEGIN CERTIFICATE-----",
                StringComparison.Ordinal) == true
                ? value
                : null;
        }
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                var result = FindCertificatePem(property.Value);
                if (result is not null)
                {
                    return result;
                }
            }
        }
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                var result = FindCertificatePem(item);
                if (result is not null)
                {
                    return result;
                }
            }
        }
        return null;
    }

    private static ECDsa LoadEcdsaPrivateKey(string path)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(path));
        return key;
    }

    private static ECDsa LoadEcdsaPublicKey(string path)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(path));
        return key;
    }

    private static void EnsureKeysMatch(
        string description,
        ECDsa first,
        ECDsa second)
    {
        if (!CryptographicOperations.FixedTimeEquals(
                first.ExportSubjectPublicKeyInfo(),
                second.ExportSubjectPublicKeyInfo()))
        {
            throw new InvalidDataException(
                $"{description} do not match.");
        }
    }

    private static void WriteUInt24(
        Span<byte> destination,
        int value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }

    private static Uri EnsureTrailingSlash(Uri uri) =>
        uri.AbsolutePath.EndsWith("/", StringComparison.Ordinal)
            ? uri
            : new Uri(uri.AbsoluteUri + "/", UriKind.Absolute);

    private sealed record FulcioMaterial(
        string RootSha256,
        string KeySha256,
        bool CertificateMatchesPrivateKey);

}
