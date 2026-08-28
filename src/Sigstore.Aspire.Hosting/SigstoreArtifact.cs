using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Aspire.Hosting.ApplicationModel;

internal sealed record SigstoreArtifactEvidence(
    long ArtifactId,
    string ArtifactSha256,
    string BundleSha256,
    string CertificateSha256,
    string FulcioRootSha256,
    string CtLogId,
    ulong SctTimestamp,
    int TransparencyLogEntryCount,
    int Rfc3161TimestampCount);

internal sealed record SigstoreClientArtifactVerification(
    int SchemaVersion,
    string Resource,
    string Language,
    bool Verified,
    long ArtifactId,
    string ArtifactSha256,
    string BundleSha256,
    int Generation,
    string GenerationId,
    string TrustedRootSha256);

internal static class SigstoreArtifact
{
    private const int MaximumPayloadBytes = 16 * 1024 * 1024;
    private const int MaximumScanCount = 512;

    internal static async Task<long> ReadHeadAsync(
        Uri artifactStoreEndpoint,
        CancellationToken cancellationToken)
    {
        using var client = CreateClient();
        var bytes = await ReadRequiredAsync(
            client,
            new Uri(
                EnsureTrailingSlash(artifactStoreEndpoint),
                "artifacts/head"),
            cancellationToken);
        using var document = JsonDocument.Parse(bytes);
        var id = document.RootElement.GetProperty("id").GetInt64();
        if (id < 0)
        {
            throw new InvalidDataException(
                "The artifact store returned a negative head.");
        }
        return id;
    }

    internal static async Task<SigstoreArtifactEvidence>
        FindLatestForRootAsync(
            Uri artifactStoreEndpoint,
            long minimumExclusiveId,
            X509Certificate2 expectedRoot,
            ECDsa ctPublicKey,
            string identity,
            CancellationToken cancellationToken)
    {
        var head = await ReadHeadAsync(
            artifactStoreEndpoint,
            cancellationToken);
        if (head <= minimumExclusiveId)
        {
            throw new InvalidDataException(
                $"Artifact head {head} has not advanced beyond " +
                $"{minimumExclusiveId}.");
        }
        var lowerBound = Math.Max(
            minimumExclusiveId + 1,
            head - MaximumScanCount + 1);
        for (var id = head; id >= lowerBound; id--)
        {
            var candidate = await TryReadAsync(
                artifactStoreEndpoint,
                id,
                cancellationToken);
            if (candidate is null)
            {
                continue;
            }
            using var certificate = ReadLeafCertificate(
                candidate.Value.Bundle);
            if (!SigstoreFulcio.CertificateChainsToRoot(
                    certificate,
                    expectedRoot))
            {
                continue;
            }
            var sct = SigstoreFulcio.ValidateCertificateForRoot(
                certificate,
                expectedRoot,
                ctPublicKey,
                identity);
            var material = ReadVerificationMaterial(
                candidate.Value.Bundle);
            if (material.TransparencyLogEntryCount < 1
                || material.Rfc3161TimestampCount < 1)
            {
                throw new InvalidDataException(
                    $"Artifact {id} does not contain Rekor and RFC3161 " +
                    "verification material.");
            }
            return new SigstoreArtifactEvidence(
                id,
                SigstoreFulcio.Fingerprint(candidate.Value.Artifact),
                SigstoreFulcio.Fingerprint(candidate.Value.Bundle),
                SigstoreFulcio.Fingerprint(certificate.RawData),
                SigstoreFulcio.Fingerprint(expectedRoot.RawData),
                sct.LogId,
                sct.Timestamp,
                material.TransparencyLogEntryCount,
                material.Rfc3161TimestampCount);
        }

        throw new InvalidDataException(
            $"No sealed artifact in ({minimumExclusiveId}, {head}] chains " +
            $"to Fulcio root {SigstoreFulcio.Fingerprint(expectedRoot.RawData)}.");
    }

    internal static async Task<SigstoreClientArtifactVerification>
        VerifyWithClientAsync(
            SigstoreClientRegistration client,
            SigstoreArtifactEvidence artifact,
            CancellationToken cancellationToken)
    {
        var endpoint = await client.Endpoint.GetValueAsync(
            cancellationToken)
            ?? throw new InvalidDataException(
                $"{client.Resource.Name} endpoint is not allocated.");
        using var httpClient = CreateClient();
        var bytes = await ReadRequiredAsync(
            httpClient,
            new Uri(
                EnsureTrailingSlash(
                    new Uri(endpoint, UriKind.Absolute)),
                $"artifacts/{artifact.ArtifactId}/verify"),
            cancellationToken);
        var evidence = JsonSerializer.Deserialize<
            SigstoreClientArtifactVerification>(
                bytes,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)
                {
                    PropertyNameCaseInsensitive = false
                })
            ?? throw new InvalidDataException(
                $"{client.Resource.Name} returned empty artifact evidence.");
        if (evidence.SchemaVersion != 1
            || evidence.Resource != client.Resource.Name
            || evidence.Language != client.Language
            || !evidence.Verified
            || evidence.ArtifactId != artifact.ArtifactId
            || evidence.ArtifactSha256 != artifact.ArtifactSha256
            || evidence.BundleSha256 != artifact.BundleSha256
            || evidence.Generation <= 0
            || string.IsNullOrWhiteSpace(evidence.GenerationId)
            || !IsLowerHexSha256(evidence.TrustedRootSha256))
        {
            throw new InvalidDataException(
                $"{client.Resource.Name} returned inconsistent artifact " +
                "verification evidence.");
        }
        return evidence;
    }

    private static async Task<(byte[] Artifact, byte[] Bundle)?>
        TryReadAsync(
            Uri artifactStoreEndpoint,
            long artifactId,
            CancellationToken cancellationToken)
    {
        using var client = CreateClient();
        var baseUri = EnsureTrailingSlash(artifactStoreEndpoint);
        var artifact = await ReadOptionalAsync(
            client,
            new Uri(baseUri, $"artifacts/{artifactId}"),
            cancellationToken);
        if (artifact is null)
        {
            return null;
        }
        var bundle = await ReadOptionalAsync(
            client,
            new Uri(
                baseUri,
                $"artifacts/{artifactId}/signature"),
            cancellationToken);
        return bundle is null
            ? null
            : (artifact, bundle);
    }

    private static X509Certificate2 ReadLeafCertificate(
        ReadOnlySpan<byte> bundleBytes)
    {
        using var document = JsonDocument.Parse(bundleBytes.ToArray());
        var material = document.RootElement.GetProperty(
            "verificationMaterial");
        JsonElement certificate;
        if (material.TryGetProperty(
                "x509CertificateChain",
                out var chain))
        {
            var certificates = chain.GetProperty("certificates");
            if (certificates.GetArrayLength() == 0)
            {
                throw new InvalidDataException(
                    "Artifact bundle certificate chain is empty.");
            }
            certificate = certificates[0];
        }
        else if (!material.TryGetProperty(
                     "certificate",
                     out certificate))
        {
            throw new InvalidDataException(
                "Artifact bundle omits its signing certificate.");
        }
        var raw = Convert.FromBase64String(
            certificate.GetProperty("rawBytes").GetString()
            ?? throw new InvalidDataException(
                "Artifact bundle certificate bytes are empty."));
        return X509CertificateLoader.LoadCertificate(raw);
    }

    private static VerificationMaterialCounts ReadVerificationMaterial(
        ReadOnlySpan<byte> bundleBytes)
    {
        using var document = JsonDocument.Parse(bundleBytes.ToArray());
        var material = document.RootElement.GetProperty(
            "verificationMaterial");
        var tlogCount = material.TryGetProperty(
                "tlogEntries",
                out var tlogEntries)
            ? tlogEntries.GetArrayLength()
            : 0;
        var timestampCount = 0;
        if (material.TryGetProperty(
                "timestampVerificationData",
                out var timestampData)
            && timestampData.TryGetProperty(
                "rfc3161Timestamps",
                out var timestamps))
        {
            timestampCount = timestamps.GetArrayLength();
        }
        return new VerificationMaterialCounts(
            tlogCount,
            timestampCount);
    }

    private static HttpClient CreateClient() =>
        new()
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

    private static async Task<byte[]> ReadRequiredAsync(
        HttpClient client,
        Uri uri,
        CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync(
            uri,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            var message = await response.Content.ReadAsStringAsync(
                cancellationToken);
            throw new InvalidDataException(
                $"{uri} returned HTTP {(int)response.StatusCode}: {message}");
        }
        return await ReadBoundedAsync(response, uri, cancellationToken);
    }

    private static async Task<byte[]?> ReadOptionalAsync(
        HttpClient client,
        Uri uri,
        CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync(
            uri,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        if (response.StatusCode is HttpStatusCode.NotFound
            || (int)response.StatusCode == 425)
        {
            return null;
        }
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new InvalidDataException(
                $"{uri} returned HTTP {(int)response.StatusCode}.");
        }
        return await ReadBoundedAsync(response, uri, cancellationToken);
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpResponseMessage response,
        Uri uri,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength > MaximumPayloadBytes)
        {
            throw new InvalidDataException(
                $"{uri} exceeded {MaximumPayloadBytes} bytes.");
        }
        var bytes = await response.Content.ReadAsByteArrayAsync(
            cancellationToken);
        if (bytes.Length is 0 or > MaximumPayloadBytes)
        {
            throw new InvalidDataException(
                $"{uri} returned an invalid payload length.");
        }
        return bytes;
    }

    private static bool IsLowerHexSha256(string value) =>
        value is { Length: 64 }
        && value.All(
            character => character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static Uri EnsureTrailingSlash(Uri uri) =>
        uri.AbsolutePath.EndsWith("/", StringComparison.Ordinal)
            ? uri
            : new Uri(uri.AbsoluteUri + "/", UriKind.Absolute);

    private sealed record VerificationMaterialCounts(
        int TransparencyLogEntryCount,
        int Rfc3161TimestampCount);
}
