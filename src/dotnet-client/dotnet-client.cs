#:sdk Microsoft.NET.Sdk.Web
#:property TargetFramework=net10.0
#:property PublishAot=false
#:property TreatWarningsAsErrors=true
#:package OpenTelemetry.Exporter.OpenTelemetryProtocol@1.17.0
#:package OpenTelemetry.Extensions.Hosting@1.17.0
#:package OpenTelemetry.Instrumentation.AspNetCore@1.17.0
#:package OpenTelemetry.Instrumentation.Http@1.17.0
#:package OpenTelemetry.Instrumentation.Runtime@1.17.0
#:package Sigstore@1.1.0-alpha.131.1.fd8696f

using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Sigstore;
using Tuf;

var options = DemoOptions.FromEnvironment();
using var artifactStoreClient = new ArtifactStoreClient(
    new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(30)
    },
    options.ArtifactStoreUrl);
using var sigstoreRuntime = new SigstoreRuntime(options);

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddOpenTelemetry(
    logging =>
    {
        logging.IncludeFormattedMessage = true;
        logging.IncludeScopes = true;
        logging.AddOtlpExporter();
    });
builder.Services
    .AddOpenTelemetry()
    .ConfigureResource(
        resource => resource.AddService("dotnet-client"))
    .WithTracing(
        tracing => tracing
            .AddSource(DemoTelemetry.ActivitySourceName)
            .AddSource("Sigstore")
            .AddSource("Tuf")
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddOtlpExporter())
    .WithMetrics(
        metrics => metrics
            .AddMeter(DemoTelemetry.MeterName)
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddRuntimeInstrumentation()
            .AddOtlpExporter());
builder.Services.AddSingleton(options);
builder.Services.AddSingleton(artifactStoreClient);
builder.Services.AddSingleton(sigstoreRuntime);
builder.Services.AddSingleton<ArtifactVerificationService>();
builder.Services.AddHostedService<TrustStatusInitializer>();
builder.Services.AddHostedService<ArtifactProducer>();
builder.Services.AddHostedService<ArtifactValidator>();

var app = builder.Build();
app.MapGet(
    "/healthz",
    (SigstoreRuntime runtime) => runtime.TrustStatus is not null
        ? Results.Text(
            """{"status":"SERVING"}""",
            "application/json")
        : Results.Text(
            """{"status":"NOT_SERVING"}""",
            "application/json",
            statusCode: StatusCodes.Status503ServiceUnavailable));
app.MapGet(
    "/trust/status",
    (SigstoreRuntime runtime) => runtime.TrustStatus is { } status
        ? Results.Json(status)
        : Results.Json(
            new
            {
                error = "trust initialization has not completed"
            },
            statusCode: StatusCodes.Status503ServiceUnavailable));
app.MapGet(
    "/artifacts/{id:long}/verify",
    async (
        long id,
        ArtifactVerificationService verifier,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(
                await verifier.VerifyAsync(
                    id,
                    cancellationToken));
        }
        catch (ArtifactNotReadyException exception)
        {
            return Results.Json(
                new { error = exception.Message },
                statusCode: 425);
        }
        catch (ArtifactMissingException exception)
        {
            return Results.NotFound(
                new { error = exception.Message });
        }
        catch (Exception exception)
            when (exception is InvalidDataException
                or InvalidOperationException
                or JsonException
                or CryptographicException
                or HttpRequestException)
        {
            return Results.UnprocessableEntity(
                new { error = exception.Message });
        }
    });

await app.RunAsync();

internal sealed class ArtifactProducer(
    DemoOptions options,
    ArtifactStoreClient artifactStore,
    SigstoreRuntime sigstore,
    ILogger<ArtifactProducer> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProduceAsync(stoppingToken);
            }
            catch (OperationCanceledException)
                when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (OperationCanceledException exception)
            {
                logger.LogError(
                    exception,
                    "Timed out while producing an artifact.");
            }
            catch (Exception exception)
                when (exception is HttpRequestException
                    or InvalidDataException
                    or InvalidOperationException
                    or IOException
                    or JsonException
                    or CryptographicException)
            {
                logger.LogError(
                    exception,
                    "Failed to produce an artifact.");
            }

            await Task.Delay(
                options.ProduceInterval,
                stoppingToken);
        }
    }

    private async Task ProduceAsync(
        CancellationToken cancellationToken)
    {
        var artifact = RandomNumberGenerator.GetBytes(
            RandomNumberGenerator.GetInt32(256, 4097));
        using var activity = DemoTelemetry.Source.StartActivity(
            "artifact.produce",
            ActivityKind.Producer);
        activity?.SetTag("artifact.size", artifact.Length);
        activity?.SetTag("client.language", "dotnet");

        await using var artifactStream = new MemoryStream(
            artifact,
            writable: false);
        var bundle = await sigstore.Signer.SignAsync(
            artifactStream,
            cancellationToken);
        var bundleJson = bundle.Serialize();

        var uploaded = await artifactStore.UploadArtifactAsync(
            artifact,
            cancellationToken);
        activity?.SetTag("artifact.id", uploaded.Id);

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await artifactStore.UploadSignatureAsync(
                    uploaded.SignatureUrl,
                    uploaded.SealToken,
                    bundleJson,
                    cancellationToken);
                break;
            }
            catch (HttpRequestException exception)
            {
                logger.LogWarning(
                    exception,
                    "Signature upload for artifact {ArtifactId} failed; retrying.",
                    uploaded.Id);
                await Task.Delay(
                    options.PollInterval,
                    cancellationToken);
            }
            catch (OperationCanceledException exception)
                when (!cancellationToken.IsCancellationRequested)
            {
                logger.LogWarning(
                    exception,
                    "Signature upload for artifact {ArtifactId} timed out; retrying.",
                    uploaded.Id);
                await Task.Delay(
                    options.PollInterval,
                    cancellationToken);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        DemoTelemetry.ArtifactsProduced.Add(
            1,
            new KeyValuePair<string, object?>(
                "client.language",
                "dotnet"));
        logger.LogInformation(
            "Produced and signed artifact {ArtifactId} ({ArtifactSize} bytes).",
            uploaded.Id,
            artifact.Length);
    }
}

internal sealed class ArtifactValidator(
    DemoOptions options,
    ArtifactStoreClient artifactStore,
    ArtifactVerificationService verifier,
    ILogger<ArtifactValidator> logger) : BackgroundService
{
    private const int MaximumPendingAttempts = 5;

    private long nextArtifactId = 1;
    private long highWatermark;
    private int pendingAttempts;

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var retryAfter = options.PollInterval;
            try
            {
                if (nextArtifactId > highWatermark)
                {
                    var observedHead =
                        await artifactStore.GetHeadAsync(
                            stoppingToken);
                    if (observedHead < highWatermark)
                    {
                        throw new InvalidDataException(
                            $"The artifact head moved backward from " +
                            $"{highWatermark} to {observedHead}.");
                    }

                    highWatermark = observedHead;
                    if (nextArtifactId > highWatermark)
                    {
                        await Task.Delay(
                            retryAfter,
                            stoppingToken);
                        continue;
                    }
                }

                if (await TryValidateNextAsync(stoppingToken))
                {
                    nextArtifactId = checked(nextArtifactId + 1);
                    pendingAttempts = 0;
                    continue;
                }
            }
            catch (ArtifactNotReadyException exception)
            {
                pendingAttempts++;
                if (pendingAttempts >= MaximumPendingAttempts)
                {
                    SkipArtifact(
                        $"The artifact remained unsealed after " +
                        $"{pendingAttempts} attempts.",
                        pendingAttempts);
                    nextArtifactId = checked(nextArtifactId + 1);
                    pendingAttempts = 0;
                    continue;
                }

                retryAfter = exception.RetryAfter;
            }
            catch (ArtifactMissingException exception)
            {
                SkipArtifact(
                    exception.Message,
                    pendingAttempts);
                nextArtifactId = checked(nextArtifactId + 1);
                pendingAttempts = 0;
                continue;
            }
            catch (OperationCanceledException)
                when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (OperationCanceledException exception)
            {
                logger.LogError(
                    exception,
                    "Timed out while validating artifact {ArtifactId}.",
                    nextArtifactId);
            }
            catch (Exception exception)
                when (exception is HttpRequestException
                    or InvalidDataException
                    or InvalidOperationException
                    or IOException
                    or JsonException
                    or CryptographicException)
            {
                logger.LogError(
                    exception,
                    "Failed to validate artifact {ArtifactId}.",
                    nextArtifactId);
            }

            await Task.Delay(
                retryAfter,
                stoppingToken);
        }
    }

    private async Task<bool> TryValidateNextAsync(
        CancellationToken cancellationToken)
    {
        using var activity = DemoTelemetry.Source.StartActivity(
            "artifact.validate",
            ActivityKind.Consumer);
        activity?.SetTag("artifact.id", nextArtifactId);
        activity?.SetTag("client.language", "dotnet");

        var evidence = await verifier.VerifyAsync(
            nextArtifactId,
            cancellationToken);
        activity?.SetTag("artifact.sha256", evidence.ArtifactSha256);
        activity?.SetTag("bundle.sha256", evidence.BundleSha256);

        DemoTelemetry.ArtifactsVerified.Add(
            1,
            new KeyValuePair<string, object?>(
                "client.language",
                "dotnet"));
        logger.LogInformation(
            "Validated artifact {ArtifactId} ({ArtifactSha256}).",
            nextArtifactId,
            evidence.ArtifactSha256);
        return true;
    }

    private void SkipArtifact(
        string reason,
        int attempts)
    {
        using var activity = DemoTelemetry.Source.StartActivity(
            "artifact.skip",
            ActivityKind.Consumer);
        activity?.SetTag(
            "artifact.id",
            nextArtifactId);
        activity?.SetTag(
            "artifact.retry_count",
            attempts);
        activity?.SetTag(
            "artifact.warning",
            reason);
        activity?.AddEvent(
            new ActivityEvent(
                "artifact.skipped"));

        DemoTelemetry.ArtifactsSkipped.Add(
            1,
            new KeyValuePair<string, object?>(
                "client.language",
                "dotnet"));
        logger.LogWarning(
            "Skipping artifact {ArtifactId}: {Reason}",
            nextArtifactId,
            reason);
    }
}

internal sealed class ArtifactVerificationService(
    ArtifactStoreClient artifactStore,
    SigstoreRuntime sigstore)
{
    public async Task<ArtifactVerificationEvidence> VerifyAsync(
        long artifactId,
        CancellationToken cancellationToken)
    {
        if (artifactId <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(artifactId),
                "Artifact ID must be positive.");
        }

        var artifact = await artifactStore.DownloadArtifactAsync(
            artifactId,
            cancellationToken)
            ?? throw new ArtifactMissingException(
                artifactId,
                "artifact content");
        var bundleJson = await artifactStore.DownloadSignatureAsync(
            artifactId,
            cancellationToken)
            ?? throw new ArtifactMissingException(
                artifactId,
                "artifact signature");
        var trust = sigstore.TrustStatus
            ?? throw new InvalidOperationException(
                "Sigstore trust has not been initialized.");

        var bundle = SigstoreBundle.Deserialize(bundleJson);
        await using var artifactStream = new MemoryStream(
            artifact,
            writable: false);
        var (success, result) =
            await sigstore.Verifier.TryVerifyStreamAsync(
                artifactStream,
                bundle,
                sigstore.VerificationPolicy,
                cancellationToken);
        if (!success)
        {
            throw new InvalidDataException(
                result?.FailureReason
                ?? "Signature verification failed without a reason.");
        }

        return new ArtifactVerificationEvidence(
            1,
            "dotnet-client",
            "dotnet",
            true,
            artifactId,
            Hash(artifact),
            Hash(Encoding.UTF8.GetBytes(bundleJson)),
            trust.Generation,
            trust.GenerationId,
            trust.TrustedRootSha256);
    }

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value))
            .ToLowerInvariant();
}

internal sealed record ArtifactVerificationEvidence(
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

internal sealed class ArtifactStoreClient(
    HttpClient httpClient,
    Uri baseUrl) : IDisposable
{
    private readonly Uri normalizedBaseUrl =
        NormalizeBaseUrl(baseUrl);

    public async Task<ArtifactUploadResponse> UploadArtifactAsync(
        byte[] artifact,
        CancellationToken cancellationToken)
    {
        using var content = new ByteArrayContent(artifact);
        content.Headers.ContentType =
            new("application/octet-stream");
        using var response = await httpClient.PostAsync(
            new Uri(normalizedBaseUrl, "artifacts"),
            content,
            cancellationToken);
        response.EnsureSuccessStatusCode();

        var upload =
            await response.Content.ReadFromJsonAsync<ArtifactUploadResponse>(
                cancellationToken)
            ?? throw new InvalidDataException(
                "The artifact store returned an empty creation response.");
        if (upload.Id <= 0)
        {
            throw new InvalidDataException(
                "The artifact store returned an invalid artifact ID.");
        }
        if (string.IsNullOrWhiteSpace(upload.SealToken))
        {
            throw new InvalidDataException(
                "The artifact store returned an empty seal token.");
        }

        EnsureStoreUrl(upload.Url);
        EnsureStoreUrl(upload.SignatureUrl);
        return upload;
    }

    public async Task<long> GetHeadAsync(
        CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(
            new Uri(
                normalizedBaseUrl,
                "artifacts/head"),
            cancellationToken);
        response.EnsureSuccessStatusCode();

        var head =
            await response.Content.ReadFromJsonAsync<ArtifactHeadResponse>(
                cancellationToken)
            ?? throw new InvalidDataException(
                "The artifact store returned an empty head response.");
        if (head.Id < 0)
        {
            throw new InvalidDataException(
                "The artifact store returned an invalid head ID.");
        }

        return head.Id;
    }

    public async Task UploadSignatureAsync(
        Uri signatureUrl,
        string sealToken,
        string bundleJson,
        CancellationToken cancellationToken)
    {
        EnsureStoreUrl(signatureUrl);
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            signatureUrl);
        request.Headers.Add(
            "X-Artifact-Seal-Token",
            sealToken);
        request.Content = new StringContent(
            bundleJson,
            Encoding.UTF8,
            "application/vnd.dev.sigstore.bundle+json");
        using var response = await httpClient.SendAsync(
            request,
            cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict)
        {
            throw new InvalidDataException(
                "The artifact already has a different signature.");
        }

        response.EnsureSuccessStatusCode();
    }

    public Task<byte[]?> DownloadArtifactAsync(
        long id,
        CancellationToken cancellationToken) =>
        DownloadBytesAsync(
            new Uri(normalizedBaseUrl, $"artifacts/{id}"),
            cancellationToken);

    public async Task<string?> DownloadSignatureAsync(
        long id,
        CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(
            new Uri(
                normalizedBaseUrl,
                $"artifacts/{id}/signature"),
            cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }
        if ((int)response.StatusCode == 425)
        {
            throw new ArtifactNotReadyException(
                GetRetryAfter(response));
        }

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(
            cancellationToken);
    }

    private async Task<byte[]?> DownloadBytesAsync(
        Uri url,
        CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(
            url,
            cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }
        if ((int)response.StatusCode == 425)
        {
            throw new ArtifactNotReadyException(
                GetRetryAfter(response));
        }

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(
            cancellationToken);
    }

    private void EnsureStoreUrl(Uri url)
    {
        if (!string.Equals(
                url.Scheme,
                normalizedBaseUrl.Scheme,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                url.Host,
                normalizedBaseUrl.Host,
                StringComparison.OrdinalIgnoreCase)
            || url.Port != normalizedBaseUrl.Port)
        {
            throw new InvalidDataException(
                $"The artifact store returned an unexpected URL: {url}");
        }
    }

    public void Dispose() => httpClient.Dispose();

    private static TimeSpan GetRetryAfter(
        HttpResponseMessage response)
    {
        var retryAfter = response.Headers.RetryAfter;
        var delay =
            retryAfter?.Delta
            ?? retryAfter?.Date - DateTimeOffset.UtcNow
            ?? TimeSpan.FromSeconds(2);

        if (delay < TimeSpan.FromMilliseconds(100))
        {
            return TimeSpan.FromMilliseconds(100);
        }
        if (delay > TimeSpan.FromSeconds(30))
        {
            return TimeSpan.FromSeconds(30);
        }

        return delay;
    }

    private static Uri NormalizeBaseUrl(Uri uri) =>
        new(uri.AbsoluteUri.TrimEnd('/') + "/");
}

internal sealed class ArtifactNotReadyException(
    TimeSpan retryAfter)
    : Exception("The artifact is reserved but not sealed.")
{
    public TimeSpan RetryAfter { get; } = retryAfter;
}

internal sealed class ArtifactMissingException(
    long id,
    string part)
    : Exception(
        $"Artifact {id} is below the sealed head but its {part} is missing.");

internal sealed class SigstoreRuntime : IDisposable
{
    private const int TrustStatusSchemaVersion = 1;
    private const string TrustStatusTargetName = "trust_status.v1.json";
    private readonly DemoOptions options;
    private readonly HttpClient fulcioHttpClient = CreateHttpClient();
    private readonly HttpClient rekorHttpClient = CreateHttpClient();
    private readonly HttpClient timestampHttpClient = CreateHttpClient();
    private readonly HttpClient oidcHttpClient = CreateHttpClient();
    private readonly FulcioHttpClient fulcio;
    private readonly RekorHttpClient rekor;
    private readonly HttpTimestampAuthority timestampAuthority;
    private readonly TufTrustRootProvider trustRootProvider;

    public SigstoreRuntime(DemoOptions options)
    {
        this.options = options;
        var bootstrapRoot = File.ReadAllBytes(
            options.TufRootPath);
        trustRootProvider = new TufTrustRootProvider(
            options.TufUrl,
            new TufTrustRootProviderOptions
            {
                CustomTrustedRoot = bootstrapRoot,
                Cache = new FileSystemTufCache(
                    options.TufCachePath)
            });
        fulcio = new FulcioHttpClient(
            fulcioHttpClient,
            options.FulcioUrl);
        rekor = new RekorHttpClient(
            rekorHttpClient,
            options.RekorUrl,
            majorApiVersion: 2);
        timestampAuthority = new HttpTimestampAuthority(
            timestampHttpClient,
            new Uri(
                NormalizeBaseUrl(options.TimestampUrl),
                "api/v1/timestamp"));
        var tokenProvider = new HttpOidcTokenProvider(
            oidcHttpClient,
            new Uri(
                NormalizeBaseUrl(options.OidcUrl),
                "token"),
            options.ExpectedIdentity,
            options.ExpectedIssuer);

        Signer = new SigstoreSigner(
            fulcio,
            rekor,
            timestampAuthority,
            tokenProvider,
            trustRootProvider);
        Verifier = new SigstoreVerifier(
            trustRootProvider);
        VerificationPolicy = new VerificationPolicy
        {
            CertificateIdentity = new CertificateIdentity
            {
                SubjectAlternativeName =
                    options.ExpectedIdentity,
                Issuer = options.ExpectedIssuer
            },
            RequireSignedTimestamps = true,
            SignedTimestampThreshold = 1
        };
    }

    public SigstoreSigner Signer { get; }

    public SigstoreVerifier Verifier { get; }

    public VerificationPolicy VerificationPolicy { get; }

    public ClientTrustStatus? TrustStatus { get; private set; }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        if (TrustStatus is not null)
        {
            throw new InvalidOperationException(
                "Sigstore trust has already been initialized.");
        }

        using var activity = DemoTelemetry.Source.StartActivity(
            "sigstore.trust.initialize",
            ActivityKind.Internal);
        activity?.SetTag("client.language", "dotnet");
        activity?.SetTag("client.resource.name", "dotnet-client");

        try
        {
            _ = await trustRootProvider.GetTrustRootAsync(
                cancellationToken);
            var bootstrapRoot = await File.ReadAllBytesAsync(
                options.TufRootPath,
                cancellationToken);
            var statusCache = new FileSystemTufCache(
                options.TufCachePath + "-status");
            using var client = new TufClient(
                new TufClientOptions
                {
                    MetadataBaseUrl = options.TufUrl,
                    TargetsBaseUrl = new Uri(
                        NormalizeBaseUrl(options.TufUrl),
                        "targets/"),
                    TrustedRoot = bootstrapRoot,
                    Cache = statusCache
                });
            var trustedRoot = await client.GetTargetAsync(
                "trusted_root.json",
                cancellationToken);
            var signingConfig = await client.GetTargetAsync(
                "signing_config.v0.2.json",
                cancellationToken);
            var published = await client.GetTargetAsync(
                TrustStatusTargetName,
                cancellationToken);
            _ = TrustedRoot.Deserialize(
                Encoding.UTF8.GetString(trustedRoot.Content.Span));
            ValidateSigningConfig(signingConfig.Content.Span);
            var rootVersion = ReadMetadataVersion(
                statusCache.LoadMetadata("root"),
                "root");
            var targetsVersion = ReadMetadataVersion(
                statusCache.LoadMetadata("targets"),
                "targets");
            var initialized = CreateClientTrustStatus(
                published.Content.Span,
                trustedRoot.Content.Span,
                signingConfig.Content.Span,
                rootVersion,
                targetsVersion,
                DateTimeOffset.UtcNow);
            TrustStatus = initialized;
            SetTrustSpanAttributes(activity, initialized);
            activity?.SetStatus(ActivityStatusCode.Ok);
        }
        catch (Exception exception)
            when (exception is IOException
                or JsonException
                or TufException
                or InvalidOperationException
                or CryptographicException
                or HttpRequestException)
        {
            activity?.AddException(exception);
            activity?.SetStatus(
                ActivityStatusCode.Error,
                exception.Message);
            throw;
        }
    }

    public void Dispose()
    {
        trustRootProvider.Dispose();
        timestampAuthority.Dispose();
        rekor.Dispose();
        fulcio.Dispose();
        oidcHttpClient.Dispose();
        timestampHttpClient.Dispose();
        rekorHttpClient.Dispose();
        fulcioHttpClient.Dispose();
    }

    private static HttpClient CreateHttpClient() =>
        new()
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

    private static Uri NormalizeBaseUrl(Uri uri) =>
        new(uri.AbsoluteUri.TrimEnd('/') + "/");

    internal static ClientTrustStatus CreateClientTrustStatus(
        ReadOnlySpan<byte> publishedStatusBytes,
        ReadOnlySpan<byte> trustedRootBytes,
        ReadOnlySpan<byte> signingConfigBytes,
        int rootVersion,
        int targetsVersion,
        DateTimeOffset initializedAtUtc)
    {
        var published =
            JsonSerializer.Deserialize<PublishedTrustStatus>(
                publishedStatusBytes,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)
                {
                    PropertyNameCaseInsensitive = false
                })
            ?? throw new InvalidDataException(
                "Published trust status is empty.");
        var trustedRootHash = Hash(trustedRootBytes);
        var signingConfigHash = Hash(signingConfigBytes);
        if (published.SchemaVersion != TrustStatusSchemaVersion
            || string.IsNullOrWhiteSpace(published.TrustDomainId)
            || published.Generation <= 0
            || string.IsNullOrWhiteSpace(published.GenerationId)
            || !IsLowerHexSha256(
                published.GenerationManifestSha256)
            || published.TufRootVersion != rootVersion
            || published.TufTargetsVersion != targetsVersion
            || published.TrustedRootSha256 != trustedRootHash
            || published.SigningConfigSha256 != signingConfigHash)
        {
            throw new InvalidDataException(
                "Published trust status does not match verified TUF material.");
        }

        return new ClientTrustStatus(
            TrustStatusSchemaVersion,
            "dotnet-client",
            "dotnet",
            true,
            null,
            published.TrustDomainId,
            published.Generation,
            published.GenerationId,
            published.GenerationManifestSha256,
            rootVersion,
            targetsVersion,
            trustedRootHash,
            signingConfigHash,
            initializedAtUtc);
    }

    private static void ValidateSigningConfig(
        ReadOnlySpan<byte> signingConfigBytes)
    {
        using var document = JsonDocument.Parse(
            signingConfigBytes.ToArray());
        var mediaType = document.RootElement
            .GetProperty("mediaType")
            .GetString();
        if (mediaType
            != "application/vnd.dev.sigstore.signingconfig.v0.2+json")
        {
            throw new InvalidDataException(
                $"Unsupported signing configuration media type '{mediaType}'.");
        }
    }

    private static int ReadMetadataVersion(
        byte[]? metadata,
        string role)
    {
        if (metadata is null)
        {
            throw new InvalidDataException(
                $"Verified TUF {role} metadata is missing.");
        }
        using var document = JsonDocument.Parse(metadata);
        var version = document.RootElement
            .GetProperty("signed")
            .GetProperty("version")
            .GetInt32();
        if (version <= 0)
        {
            throw new InvalidDataException(
                $"Verified TUF {role} metadata has invalid version {version}.");
        }
        return version;
    }

    private static void SetTrustSpanAttributes(
        Activity? activity,
        ClientTrustStatus status)
    {
        activity?.SetTag(
            "sigstore.trust.domain.id",
            status.TrustDomainId);
        activity?.SetTag(
            "sigstore.trust.generation",
            status.Generation);
        activity?.SetTag(
            "sigstore.trust.generation.id",
            status.GenerationId);
        activity?.SetTag(
            "sigstore.trust.generation.manifest.sha256",
            status.GenerationManifestSha256);
        activity?.SetTag(
            "sigstore.trust.tuf.root.version",
            status.TufRootVersion);
        activity?.SetTag(
            "sigstore.trust.tuf.targets.version",
            status.TufTargetsVersion);
        activity?.SetTag(
            "sigstore.trust.trusted_root.sha256",
            status.TrustedRootSha256);
        activity?.SetTag(
            "sigstore.trust.signing_config.sha256",
            status.SigningConfigSha256);
        activity?.SetTag(
            "sigstore.trust.initialized_at",
            status.InitializedAtUtc.ToString("O"));
    }

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value))
            .ToLowerInvariant();

    private static bool IsLowerHexSha256(string value) =>
        value is { Length: 64 }
        && value.All(
            character => character is >= '0' and <= '9'
                or >= 'a' and <= 'f');
}

internal sealed class TrustStatusInitializer(
    SigstoreRuntime runtime) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) =>
        runtime.InitializeAsync(cancellationToken);

    public Task StopAsync(CancellationToken cancellationToken) =>
        Task.CompletedTask;
}

internal sealed record PublishedTrustStatus(
    int SchemaVersion,
    string TrustDomainId,
    int Generation,
    string GenerationId,
    string GenerationManifestSha256,
    int TufRootVersion,
    int TufTargetsVersion,
    string TrustedRootSha256,
    string SigningConfigSha256);

internal sealed record ClientTrustStatus(
    int SchemaVersion,
    string Resource,
    string Language,
    bool Ready,
    string? LastError,
    string TrustDomainId,
    int Generation,
    string GenerationId,
    string GenerationManifestSha256,
    int TufRootVersion,
    int TufTargetsVersion,
    string TrustedRootSha256,
    string SigningConfigSha256,
    DateTimeOffset InitializedAtUtc);

internal sealed class HttpOidcTokenProvider(
    HttpClient httpClient,
    Uri tokenUrl,
    string expectedIdentity,
    string expectedIssuer) : IOidcTokenProvider
{
    public async Task<OidcToken> GetTokenAsync(
        CancellationToken cancellationToken = default)
    {
        var rawToken = (
            await httpClient.GetStringAsync(
                tokenUrl,
                cancellationToken)).Trim();
        var parts = rawToken.Split('.');
        if (parts.Length != 3)
        {
            throw new InvalidDataException(
                "The OIDC endpoint did not return a JWT.");
        }

        var payload = parts[1]
            .Replace('-', '+')
            .Replace('_', '/');
        if (payload.Length % 4 == 1)
        {
            throw new InvalidDataException(
                "The OIDC token has an invalid payload encoding.");
        }
        payload = payload.PadRight(
            payload.Length
                + (4 - payload.Length % 4) % 4,
            '=');

        byte[] payloadBytes;
        try
        {
            payloadBytes = Convert.FromBase64String(payload);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "The OIDC token has an invalid payload encoding.",
                exception);
        }

        using var document = JsonDocument.Parse(payloadBytes);
        var subject =
            (document.RootElement.TryGetProperty(
                    "sub",
                    out var subjectClaim)
                ? subjectClaim.GetString()
                : null)
            ?? throw new InvalidDataException(
                "The OIDC token has no subject.");
        var issuer =
            (document.RootElement.TryGetProperty(
                    "iss",
                    out var issuerClaim)
                ? issuerClaim.GetString()
                : null)
            ?? throw new InvalidDataException(
                "The OIDC token has no issuer.");
        if (!string.Equals(
                subject,
                expectedIdentity,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The OIDC token subject '{subject}' did not match '{expectedIdentity}'.");
        }
        if (!string.Equals(
                issuer,
                expectedIssuer,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The OIDC token issuer '{issuer}' did not match '{expectedIssuer}'.");
        }

        return new OidcToken
        {
            RawToken = rawToken,
            Subject = subject,
            Issuer = issuer
        };
    }
}

internal sealed record ArtifactUploadResponse(
    long Id,
    Uri Url,
    Uri SignatureUrl,
    string SealToken);

internal sealed record ArtifactHeadResponse(long Id);

internal sealed record DemoOptions(
    Uri ArtifactStoreUrl,
    Uri TufUrl,
    string TufRootPath,
    string TufCachePath,
    Uri OidcUrl,
    Uri FulcioUrl,
    Uri RekorUrl,
    Uri TimestampUrl,
    string ExpectedIdentity,
    string ExpectedIssuer,
    TimeSpan ProduceInterval,
    TimeSpan PollInterval)
{
    public static DemoOptions FromEnvironment() =>
        new(
            GetRequiredUri("SHADY_BLOB_STORE_URL"),
            GetRequiredUri("SIGSTORE_TUF_URL"),
            GetRequiredValue("SIGSTORE_TUF_ROOT_PATH"),
            GetRequiredValue("SIGSTORE_TUF_CACHE_PATH"),
            GetRequiredUri("SIGSTORE_OIDC_URL"),
            GetRequiredUri("SIGSTORE_FULCIO_URL"),
            GetRequiredUri("SIGSTORE_REKOR_URL"),
            GetRequiredUri("SIGSTORE_TIMESTAMP_URL"),
            GetRequiredValue("SIGSTORE_EXPECTED_IDENTITY"),
            GetRequiredValue("SIGSTORE_EXPECTED_ISSUER"),
            TimeSpan.FromSeconds(10),
            TimeSpan.FromSeconds(2));

    private static Uri GetRequiredUri(string name)
    {
        var value = GetRequiredValue(name);
        if (!Uri.TryCreate(
                value,
                UriKind.Absolute,
                out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp
                && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException(
                $"{name} must be an absolute HTTP(S) URL.");
        }

        return uri;
    }

    private static string GetRequiredValue(string name) =>
        Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException(
            $"{name} must be configured.");
}

internal static class DemoTelemetry
{
    public const string ActivitySourceName =
        "Sigstore.Demo.Client";
    public const string MeterName =
        "Sigstore.Demo.Client";

    public static readonly ActivitySource Source =
        new(ActivitySourceName);
    private static readonly Meter Meter =
        new(MeterName);
    public static readonly Counter<long> ArtifactsProduced =
        Meter.CreateCounter<long>(
            "sigstore.demo.artifacts.produced");
    public static readonly Counter<long> ArtifactsVerified =
        Meter.CreateCounter<long>(
            "sigstore.demo.artifacts.verified");
    public static readonly Counter<long> ArtifactsSkipped =
        Meter.CreateCounter<long>(
            "sigstore.demo.artifacts.skipped");
}
