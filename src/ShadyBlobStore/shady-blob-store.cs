#:sdk Microsoft.NET.Sdk.Web
#:property TargetFramework=net10.0
#:property PublishAot=false
#:property TreatWarningsAsErrors=true
#:package OpenTelemetry.Exporter.OpenTelemetryProtocol@1.17.0
#:package OpenTelemetry.Extensions.Hosting@1.17.0
#:package OpenTelemetry.Instrumentation.AspNetCore@1.17.0
#:package OpenTelemetry.Instrumentation.Runtime@1.17.0

using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using System.Diagnostics;
using System.Security.Cryptography;

const long maximumRequestSize = 16 * 1024 * 1024;

var builder = WebApplication.CreateBuilder(args);
var dataPath =
    Environment.GetEnvironmentVariable("SHADY_BLOB_STORE_DATA_PATH")
    ?? throw new InvalidOperationException(
        "SHADY_BLOB_STORE_DATA_PATH must identify the artifact data directory.");
var baseUrl = NormalizeBaseUrl(
    Environment.GetEnvironmentVariable("SHADY_BLOB_STORE_BASE_URL")
    ?? throw new InvalidOperationException(
        "SHADY_BLOB_STORE_BASE_URL must identify the stable artifact base URL."));

builder.WebHost.ConfigureKestrel(
    options => options.Limits.MaxRequestBodySize = maximumRequestSize);
builder.Logging.AddOpenTelemetry(
    logging => logging.AddOtlpExporter());
builder.Services
    .AddOpenTelemetry()
    .WithTracing(
        tracing => tracing
            .AddAspNetCoreInstrumentation()
            .AddOtlpExporter())
    .WithMetrics(
        metrics => metrics
            .AddAspNetCoreInstrumentation()
            .AddRuntimeInstrumentation()
            .AddOtlpExporter());
builder.Services.AddSingleton(
    new ArtifactRepository(dataPath));

var app = builder.Build();

app.MapPost(
    "/artifacts",
    async (
        HttpRequest request,
        ArtifactRepository repository,
        CancellationToken cancellationToken) =>
    {
        if (request.ContentLength == 0)
        {
            return Results.BadRequest(
                new ErrorResponse("Artifact content must not be empty."));
        }

        try
        {
            var reservation = await repository.CreateArtifactAsync(
                request.Body,
                cancellationToken);
            var artifactUrl = new Uri(
                baseUrl,
                $"artifacts/{reservation.Id}");
            var response = new ArtifactCreatedResponse(
                reservation.Id,
                artifactUrl,
                new Uri(artifactUrl.AbsoluteUri + "/signature"),
                reservation.SealToken);
            Activity.Current?.SetTag(
                "artifact.id",
                reservation.Id);

            return Results.Created(artifactUrl.AbsoluteUri, response);
        }
        catch (InvalidDataException exception)
        {
            return Results.BadRequest(
                new ErrorResponse(exception.Message));
        }
    });

app.MapGet(
    "/artifacts/head",
    (ArtifactRepository repository) =>
    {
        var head = repository.GetSealedHead();
        Activity.Current?.SetTag(
            "artifact.head",
            head);
        return Results.Ok(
            new ArtifactHeadResponse(head));
    });

app.MapGet(
    "/artifacts/{id:long}",
    (
        long id,
        HttpResponse response,
        ArtifactRepository repository) =>
    {
        var path = repository.GetArtifactPath(id);
        if (path is not null)
        {
            return Results.File(
                path,
                "application/octet-stream");
        }
        if (!repository.HasArtifact(id))
        {
            return Results.NotFound();
        }
        if (!repository.IsSealed(id))
        {
            return ArtifactPending(response);
        }

        return Results.Problem(
            "The sealed artifact content is unavailable.");
    });

app.MapPost(
    "/artifacts/{id:long}/signature",
    async (
        long id,
        HttpRequest request,
        ArtifactRepository repository,
        CancellationToken cancellationToken) =>
    {
        if (request.ContentLength == 0)
        {
            return Results.BadRequest(
                new ErrorResponse("Signature content must not be empty."));
        }

        if (!request.Headers.TryGetValue(
                ArtifactRepository.SealTokenHeaderName,
                out var sealTokenValues)
            || sealTokenValues.Count != 1
            || string.IsNullOrWhiteSpace(sealTokenValues[0]))
        {
            return Results.StatusCode(
                StatusCodes.Status403Forbidden);
        }

        try
        {
            var created = await repository.StoreSignatureAsync(
                id,
                sealTokenValues[0]!,
                request.Body,
                cancellationToken);
            Activity.Current?.SetTag("artifact.id", id);
            Activity.Current?.SetTag("artifact.sealed", true);
            var signatureUrl = new Uri(
                baseUrl,
                $"artifacts/{id}/signature");

            return created
                ? Results.Created(
                    signatureUrl.AbsoluteUri,
                    new SignatureCreatedResponse(id, signatureUrl))
                : Results.Ok(
                    new SignatureCreatedResponse(id, signatureUrl));
        }
        catch (ArtifactNotFoundException)
        {
            return Results.NotFound();
        }
        catch (SignatureConflictException)
        {
            return Results.Conflict(
                new ErrorResponse(
                    "A different signature is already stored for this artifact."));
        }
        catch (InvalidSealTokenException)
        {
            return Results.StatusCode(
                StatusCodes.Status403Forbidden);
        }
        catch (InvalidDataException exception)
        {
            return Results.BadRequest(
                new ErrorResponse(exception.Message));
        }
    });

app.MapGet(
    "/artifacts/{id:long}/signature",
    (
        long id,
        HttpResponse response,
        ArtifactRepository repository) =>
    {
        var path = repository.GetSignaturePath(id);
        if (path is not null)
        {
            return Results.File(
                path,
                "application/vnd.dev.sigstore.bundle+json");
        }
        if (!repository.HasArtifact(id))
        {
            return Results.NotFound();
        }
        if (!repository.IsSealed(id))
        {
            return ArtifactPending(response);
        }

        return Results.Problem(
            "The sealed artifact signature is unavailable.");
    });

app.MapGet(
    "/healthz",
    () => Results.Text(
        """{"status":"SERVING"}""",
        "application/json"));

app.Run();

static Uri NormalizeBaseUrl(string value)
{
    if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
        || (uri.Scheme != Uri.UriSchemeHttp
            && uri.Scheme != Uri.UriSchemeHttps))
    {
        throw new InvalidOperationException(
            "SHADY_BLOB_STORE_BASE_URL must be an absolute HTTP(S) URL.");
    }

    return new Uri(uri.AbsoluteUri.TrimEnd('/') + "/");
}

static IResult ArtifactPending(HttpResponse response)
{
    response.Headers["Retry-After"] = "2";
    return Results.Text(
        """{"error":"Artifact is reserved but not sealed."}""",
        "application/json",
        statusCode: 425);
}

internal sealed class ArtifactRepository
{
    public const string SealTokenHeaderName =
        "X-Artifact-Seal-Token";

    private const string ArtifactFileName = "artifact.bin";
    private const string SignatureFileName = "signature.json";
    private const string SealTokenHashFileName = "seal-token.sha256";
    private const string SealedFileName = "sealed";

    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly string artifactsPath;
    private long nextId;
    private long sealedHead;

    public ArtifactRepository(string dataPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataPath);

        artifactsPath = Path.Combine(
            Path.GetFullPath(dataPath),
            "artifacts");
        Directory.CreateDirectory(artifactsPath);

        nextId = checked(
            Directory
                .EnumerateDirectories(artifactsPath)
                .Select(Path.GetFileName)
                .Where(name => long.TryParse(name, out _))
                .Select(
                    name => long.Parse(
                        name!,
                        System.Globalization.CultureInfo.InvariantCulture))
                .DefaultIfEmpty(0)
                .Max() + 1);
        sealedHead = Directory
            .EnumerateDirectories(artifactsPath)
            .Where(
                path => File.Exists(
                    Path.Combine(
                        path,
                        SealedFileName)))
            .Select(Path.GetFileName)
            .Where(name => long.TryParse(name, out _))
            .Select(
                name => long.Parse(
                    name!,
                    System.Globalization.CultureInfo.InvariantCulture))
            .DefaultIfEmpty(0)
            .Max();
    }

    public async Task<ArtifactReservation> CreateArtifactAsync(
        Stream content,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);

        await gate.WaitAsync(cancellationToken);
        string? temporaryPath = null;
        try
        {
            var id = nextId;
            var artifactPath = GetArtifactDirectory(id);
            temporaryPath = Path.Combine(
                artifactsPath,
                $".upload-{Guid.NewGuid():N}");
            Directory.CreateDirectory(temporaryPath);
            var sealToken = CreateSealToken();

            await using (var file = new FileStream(
                Path.Combine(temporaryPath, ArtifactFileName),
                new FileStreamOptions
                {
                    Access = FileAccess.Write,
                    Mode = FileMode.CreateNew,
                    Options = FileOptions.Asynchronous
                        | FileOptions.WriteThrough
                }))
            {
                await content.CopyToAsync(file, cancellationToken);
                await file.FlushAsync(cancellationToken);
                if (file.Length == 0)
                {
                    throw new InvalidDataException(
                        "Artifact content must not be empty.");
                }
            }

            await File.WriteAllBytesAsync(
                Path.Combine(
                    temporaryPath,
                    SealTokenHashFileName),
                HashSealToken(sealToken),
                cancellationToken);
            Directory.Move(temporaryPath, artifactPath);
            temporaryPath = null;
            nextId = checked(id + 1);

            return new ArtifactReservation(
                id,
                sealToken);
        }
        finally
        {
            if (temporaryPath is not null)
            {
                Directory.Delete(
                    temporaryPath,
                    recursive: true);
            }
            gate.Release();
        }
    }

    public string? GetArtifactPath(long id)
    {
        var path = Path.Combine(
            GetArtifactDirectory(id),
            ArtifactFileName);
        return id > 0
            && IsSealed(id)
            && File.Exists(path)
            ? path
            : null;
    }

    public bool HasArtifact(long id) =>
        id > 0
        && File.Exists(
            Path.Combine(
                GetArtifactDirectory(id),
                ArtifactFileName));

    public long GetSealedHead() =>
        Volatile.Read(ref sealedHead);

    public string? GetSignaturePath(long id)
    {
        var path = Path.Combine(
            GetArtifactDirectory(id),
            SignatureFileName);
        return id > 0
            && IsSealed(id)
            && File.Exists(path)
            ? path
            : null;
    }

    public async Task<bool> StoreSignatureAsync(
        long id,
        string sealToken,
        Stream content,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);

        await gate.WaitAsync(cancellationToken);
        string? temporaryPath = null;
        string? temporarySealPath = null;
        try
        {
            var artifactDirectory = GetArtifactDirectory(id);
            var artifactPath = Path.Combine(
                artifactDirectory,
                ArtifactFileName);
            if (id <= 0 || !File.Exists(artifactPath))
            {
                throw new ArtifactNotFoundException(id);
            }

            var expectedSealTokenHash =
                await File.ReadAllBytesAsync(
                    Path.Combine(
                        artifactDirectory,
                        SealTokenHashFileName),
                    cancellationToken);
            if (!CryptographicOperations.FixedTimeEquals(
                    expectedSealTokenHash,
                    HashSealToken(sealToken)))
            {
                throw new InvalidSealTokenException(id);
            }

            var signaturePath = Path.Combine(
                artifactDirectory,
                SignatureFileName);
            temporaryPath = signaturePath + $".{Guid.NewGuid():N}.tmp";

            await using (var file = new FileStream(
                temporaryPath,
                new FileStreamOptions
                {
                    Access = FileAccess.Write,
                    Mode = FileMode.CreateNew,
                    Options = FileOptions.Asynchronous
                        | FileOptions.WriteThrough
                }))
            {
                await content.CopyToAsync(file, cancellationToken);
                await file.FlushAsync(cancellationToken);
                if (file.Length == 0)
                {
                    throw new InvalidDataException(
                        "Signature content must not be empty.");
                }
            }

            if (File.Exists(signaturePath))
            {
                var existing = await File.ReadAllBytesAsync(
                    signaturePath,
                    cancellationToken);
                var incoming = await File.ReadAllBytesAsync(
                    temporaryPath,
                    cancellationToken);
                if (!existing.AsSpan().SequenceEqual(incoming))
                {
                    throw new SignatureConflictException(id);
                }

                File.Delete(temporaryPath);
                temporaryPath = null;
            }
            else
            {
                File.Move(temporaryPath, signaturePath);
                temporaryPath = null;
            }

            var sealedPath = Path.Combine(
                artifactDirectory,
                SealedFileName);
            if (File.Exists(sealedPath))
            {
                if (id > sealedHead)
                {
                    Volatile.Write(
                        ref sealedHead,
                        id);
                }
                return false;
            }

            temporarySealPath =
                sealedPath + $".{Guid.NewGuid():N}.tmp";
            await File.WriteAllBytesAsync(
                temporarySealPath,
                [1],
                cancellationToken);
            File.Move(temporarySealPath, sealedPath);
            temporarySealPath = null;
            if (id > sealedHead)
            {
                Volatile.Write(
                    ref sealedHead,
                    id);
            }
            return true;
        }
        finally
        {
            if (temporaryPath is not null)
            {
                File.Delete(temporaryPath);
            }
            if (temporarySealPath is not null)
            {
                File.Delete(temporarySealPath);
            }
            gate.Release();
        }
    }

    public bool IsSealed(long id) =>
        id > 0
        && File.Exists(
            Path.Combine(
                GetArtifactDirectory(id),
                SealedFileName));

    private string GetArtifactDirectory(long id) =>
        Path.Combine(
            artifactsPath,
            id.ToString(
                System.Globalization.CultureInfo.InvariantCulture));

    private static string CreateSealToken() =>
        Convert.ToBase64String(
                RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static byte[] HashSealToken(string sealToken) =>
        SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(sealToken));
}

internal sealed class ArtifactNotFoundException(long id)
    : Exception($"Artifact {id} was not found.");

internal sealed class SignatureConflictException(long id)
    : Exception($"Artifact {id} already has a different signature.");

internal sealed class InvalidSealTokenException(long id)
    : Exception($"Artifact {id} was given an invalid seal token.");

internal sealed record ArtifactReservation(
    long Id,
    string SealToken);

internal sealed record ArtifactCreatedResponse(
    long Id,
    Uri Url,
    Uri SignatureUrl,
    string SealToken);

internal sealed record ArtifactHeadResponse(long Id);

internal sealed record SignatureCreatedResponse(
    long ArtifactId,
    Uri Url);

internal sealed record ErrorResponse(string Error);
