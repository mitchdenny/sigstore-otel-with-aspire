using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sigstore.Bootstrap;

namespace Aspire.Hosting.ApplicationModel;

public sealed record SigstoreTimestampAuthorityTrustEntry(
    int Index,
    string Uri,
    string RootSha256,
    string LeafSha256,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc,
    [property: JsonIgnore] byte[] LeafCertificateDer,
    [property: JsonIgnore] byte[] RootCertificateDer,
    [property: JsonIgnore] IReadOnlyList<byte[]> IntermediateCertificateDers);

public sealed record SigstoreTimestampAuthorityProbeEvidence(
    string RootSha256,
    string LeafSha256,
    string CertificateSubject,
    string CertificateIssuer,
    string MessageHashSha256,
    string RequestSha256,
    string ResponseSha256,
    DateTimeOffset GeneratedAtUtc);

public sealed record SigstoreTimestampAuthorityStatus(
    string ActiveRootSha256,
    string ActiveLeafSha256,
    IReadOnlyList<SigstoreTimestampAuthorityTrustEntry> TrustedAuthorities,
    SigstoreTimestampAuthorityProbeEvidence RunningSigner,
    bool ActiveSignerMatches);

internal sealed record SigstoreTimestampAuthorityProbe(
    byte[] Request,
    byte[] Response,
    SigstoreTimestampAuthorityProbeEvidence Evidence);

internal static class SigstoreTimestampAuthority
{
    private const string TimestampingEkuOid = "1.3.6.1.5.5.7.3.8";

    internal static TimestampAuthorityMaterialInfo ReadActiveMaterial(
        string statePath) =>
        SigstoreStateBootstrapper.ValidateTimestampAuthority(
            Path.Combine(statePath, "active-generation"));

    internal static IReadOnlyList<SigstoreTimestampAuthorityTrustEntry>
        ReadTrustedAuthorities(string statePath) =>
        ReadTrustedAuthorities(
            File.ReadAllBytes(
                Path.Combine(
                    statePath,
                    "tuf",
                    "active",
                    "targets",
                    "trusted_root.json")));

    internal static IReadOnlyList<SigstoreTimestampAuthorityTrustEntry>
        ReadTrustedAuthorities(ReadOnlySpan<byte> trustedRootBytes)
    {
        using var document = JsonDocument.Parse(trustedRootBytes.ToArray());
        if (!document.RootElement.TryGetProperty(
                "timestampAuthorities",
                out var authorities)
            || authorities.ValueKind != JsonValueKind.Array
            || authorities.GetArrayLength() == 0)
        {
            throw new InvalidDataException(
                "TrustedRoot does not contain a timestamp authority.");
        }

        var result = new List<SigstoreTimestampAuthorityTrustEntry>();
        var identities = new HashSet<string>(StringComparer.Ordinal);
        var index = 0;
        foreach (var authority in authorities.EnumerateArray())
        {
            var uri = authority.GetProperty("uri").GetString();
            if (string.IsNullOrWhiteSpace(uri)
                || !Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri)
                || parsedUri.Scheme is not ("http" or "https"))
            {
                throw new InvalidDataException(
                    $"TrustedRoot timestamp authority {index} has an invalid URI.");
            }

            var certificates = authority
                .GetProperty("certChain")
                .GetProperty("certificates")
                .EnumerateArray()
                .Select(
                    certificate => Convert.FromBase64String(
                        certificate.GetProperty("rawBytes").GetString()
                        ?? throw new InvalidDataException(
                            "TrustedRoot TSA certificate bytes are empty.")))
                .Select(X509CertificateLoader.LoadCertificate)
                .ToArray();
            try
            {
                if (certificates.Length < 2)
                {
                    throw new InvalidDataException(
                        $"TrustedRoot timestamp authority {index} requires " +
                        "a leaf and root certificate.");
                }
                var leaf = certificates[0];
                var root = certificates[^1];
                ValidateCertificateChain(leaf, root, certificates[1..^1]);
                var rootSha256 = Hash(root.RawData);
                var leafSha256 = Hash(leaf.RawData);
                if (!identities.Add($"{rootSha256}/{leafSha256}"))
                {
                    throw new InvalidDataException(
                        "TrustedRoot contains a duplicate timestamp-authority chain.");
                }
                result.Add(
                    new SigstoreTimestampAuthorityTrustEntry(
                        index,
                        uri,
                        rootSha256,
                        leafSha256,
                        certificates
                            .Max(certificate =>
                                new DateTimeOffset(
                                    certificate.NotBefore.ToUniversalTime())),
                        certificates
                            .Min(certificate =>
                                new DateTimeOffset(
                                    certificate.NotAfter.ToUniversalTime())),
                        leaf.RawData,
                        root.RawData,
                        certificates[1..^1]
                            .Select(certificate => certificate.RawData)
                            .ToArray()));
            }
            finally
            {
                foreach (var certificate in certificates)
                {
                    certificate.Dispose();
                }
            }
            index++;
        }
        return result;
    }

    internal static async Task<SigstoreTimestampAuthorityProbe> ProbeAsync(
        Uri endpoint,
        IReadOnlyList<SigstoreTimestampAuthorityTrustEntry> trustedAuthorities,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(trustedAuthorities);
        var messageHash = SHA256.HashData(
            RandomNumberGenerator.GetBytes(64));
        var request = Rfc3161TimestampRequest.CreateFromHash(
            messageHash,
            HashAlgorithmName.SHA256,
            requestedPolicyId: null,
            nonce: RandomNumberGenerator.GetBytes(16),
            requestSignerCertificates: true,
            extensions: null);
        var requestBytes = request.Encode();

        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        using var content = new ByteArrayContent(requestBytes);
        content.Headers.ContentType =
            new MediaTypeHeaderValue("application/timestamp-query");
        using var response = await client.PostAsync(
            endpoint,
            content,
            cancellationToken);
        var responseBytes = await response.Content.ReadAsByteArrayAsync(
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidDataException(
                $"Timestamp authority returned HTTP " +
                $"{(int)response.StatusCode}: " +
                $"{System.Text.Encoding.UTF8.GetString(responseBytes)}");
        }
        if (responseBytes.Length == 0)
        {
            throw new InvalidDataException(
                "Timestamp authority returned an empty RFC3161 response.");
        }

        var evidence = ValidateResponse(
            request,
            requestBytes,
            responseBytes,
            trustedAuthorities);
        return new SigstoreTimestampAuthorityProbe(
            requestBytes,
            responseBytes,
            evidence);
    }

    internal static SigstoreTimestampAuthorityProbeEvidence
        ValidateStoredResponse(
            ReadOnlyMemory<byte> requestBytes,
            ReadOnlyMemory<byte> responseBytes,
            IReadOnlyList<SigstoreTimestampAuthorityTrustEntry>
                trustedAuthorities)
    {
        if (!Rfc3161TimestampRequest.TryDecode(
                requestBytes,
                out var request,
                out var consumed)
            || request is null
            || consumed != requestBytes.Length)
        {
            throw new InvalidDataException(
                "Stored RFC3161 timestamp request is malformed.");
        }
        return ValidateResponse(
            request,
            requestBytes.Span,
            responseBytes.Span,
            trustedAuthorities);
    }

    internal static SigstoreTimestampAuthorityStatus ReadStatus(
        string statePath,
        SigstoreTimestampAuthorityProbeEvidence runningSigner)
    {
        var active = ReadActiveMaterial(statePath);
        var trusted = ReadTrustedAuthorities(statePath);
        if (!trusted.Any(
                authority =>
                    authority.RootSha256 == active.RootSha256
                    && authority.LeafSha256 == active.LeafSha256))
        {
            throw new InvalidDataException(
                "TrustedRoot does not contain the active TSA chain.");
        }
        if (trusted.Any(
                authority => authority.Uri
                    != SigstoreDefaults.TimestampAuthorityUrl))
        {
            throw new InvalidDataException(
                "TrustedRoot timestamp-authority routing changed.");
        }
        if (trusted.Count > 1 && active.HasRootPrivateKey)
        {
            throw new InvalidDataException(
                "The rotated active TSA generation retained a root private key.");
        }
        return new SigstoreTimestampAuthorityStatus(
            active.RootSha256,
            active.LeafSha256,
            trusted,
            runningSigner,
            runningSigner.RootSha256 == active.RootSha256
                && runningSigner.LeafSha256 == active.LeafSha256);
    }

    private static SigstoreTimestampAuthorityProbeEvidence ValidateResponse(
        Rfc3161TimestampRequest request,
        ReadOnlySpan<byte> requestBytes,
        ReadOnlySpan<byte> responseBytes,
        IReadOnlyList<SigstoreTimestampAuthorityTrustEntry>
            trustedAuthorities)
    {
        Rfc3161TimestampToken token;
        try
        {
            token = request.ProcessResponse(
                responseBytes.ToArray(),
                out var consumed);
            if (consumed != responseBytes.Length)
            {
                throw new InvalidDataException(
                    "RFC3161 response contains trailing data.");
            }
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "RFC3161 response does not match its request.",
                exception);
        }

        var extraCandidates = new X509Certificate2Collection();
        try
        {
            foreach (var authority in trustedAuthorities)
            {
                extraCandidates.Add(
                    X509CertificateLoader.LoadCertificate(
                        authority.LeafCertificateDer));
                extraCandidates.Add(
                    X509CertificateLoader.LoadCertificate(
                        authority.RootCertificateDer));
                foreach (var intermediate in authority.IntermediateCertificateDers)
                {
                    extraCandidates.Add(
                        X509CertificateLoader.LoadCertificate(intermediate));
                }
            }
            if (!token.VerifySignatureForHash(
                    request.GetMessageHash().Span,
                    HashAlgorithmName.SHA256,
                    out var signerCertificate,
                    extraCandidates)
                || signerCertificate is null)
            {
                throw new InvalidDataException(
                    "RFC3161 timestamp token signature is invalid.");
            }
            using (signerCertificate)
            {
                var leafSha256 = Hash(signerCertificate.RawData);
                var authority = trustedAuthorities.SingleOrDefault(
                    item => item.LeafSha256 == leafSha256)
                    ?? throw new InvalidDataException(
                        $"RFC3161 signer {leafSha256} is not trusted.");
                using var trustedRoot =
                    X509CertificateLoader.LoadCertificate(
                        authority.RootCertificateDer);
                var intermediates = authority.IntermediateCertificateDers
                    .Select(X509CertificateLoader.LoadCertificate)
                    .ToArray();
                try
                {
                    ValidateCertificateChain(
                        signerCertificate,
                        trustedRoot,
                        intermediates);
                }
                finally
                {
                    foreach (var intermediate in intermediates)
                    {
                        intermediate.Dispose();
                    }
                }
                return new SigstoreTimestampAuthorityProbeEvidence(
                    authority.RootSha256,
                    leafSha256,
                    signerCertificate.Subject,
                    signerCertificate.Issuer,
                    Hash(request.GetMessageHash().Span),
                    Hash(requestBytes),
                    Hash(responseBytes),
                    token.TokenInfo.Timestamp);
            }
        }
        finally
        {
            foreach (var certificate in extraCandidates)
            {
                certificate.Dispose();
            }
        }
    }

    private static void ValidateCertificateChain(
        X509Certificate2 leaf,
        X509Certificate2 root,
        IReadOnlyList<X509Certificate2> intermediates)
    {
        var rootConstraints = root.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .SingleOrDefault();
        var leafConstraints = leaf.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .SingleOrDefault();
        var eku = leaf.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SingleOrDefault();
        var rootUsage = root.Extensions
            .OfType<X509KeyUsageExtension>()
            .SingleOrDefault();
        var leafUsage = leaf.Extensions
            .OfType<X509KeyUsageExtension>()
            .SingleOrDefault();
        using var rootKey = root.GetECDsaPublicKey();
        using var leafKey = leaf.GetECDsaPublicKey();
        if (rootConstraints is null
            || !rootConstraints.CertificateAuthority
            || leafConstraints is null
            || leafConstraints.CertificateAuthority
            || rootUsage is null
            || !rootUsage.Critical
            || rootUsage.KeyUsages
                != (X509KeyUsageFlags.KeyCertSign
                    | X509KeyUsageFlags.CrlSign)
            || leafUsage is null
            || !leafUsage.Critical
            || leafUsage.KeyUsages
                != X509KeyUsageFlags.DigitalSignature
            || eku is null
            || !eku.Critical
            || eku.EnhancedKeyUsages.Count != 1
            || eku.EnhancedKeyUsages[0].Value != TimestampingEkuOid
            || rootKey?.KeySize != 256
            || leafKey?.KeySize != 256
            || root.SignatureAlgorithm.Value
                != "1.2.840.10045.4.3.2"
            || leaf.SignatureAlgorithm.Value
                != "1.2.840.10045.4.3.2")
        {
            throw new InvalidDataException(
                "TrustedRoot contains an invalid TSA certificate profile.");
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        foreach (var intermediate in intermediates)
        {
            chain.ChainPolicy.ExtraStore.Add(intermediate);
        }
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(TimestampingEkuOid));
        if (!chain.Build(leaf))
        {
            throw new InvalidDataException(
                "TrustedRoot contains an invalid TSA certificate chain: " +
                string.Join(
                    ", ",
                    chain.ChainStatus.Select(
                        status => status.StatusInformation.Trim())));
        }
    }

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value))
            .ToLowerInvariant();
}
