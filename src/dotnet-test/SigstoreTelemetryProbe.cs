#:property TargetFramework=net10.0
#:package Microsoft.Extensions.Hosting@10.0.11
#:package OpenTelemetry.Exporter.OpenTelemetryProtocol@1.18.0
#:package OpenTelemetry.Extensions.Hosting@1.18.0
#:package OpenTelemetry.Instrumentation.Http@1.18.0
#:package OpenTelemetry.Instrumentation.Runtime@1.18.0
#:package Sigstore@1.1.0-alpha.131.1.fd8696f

using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Sigstore;
using Tuf;

var builder = Host.CreateApplicationBuilder(args);
var tufCachePath =
    Environment.GetEnvironmentVariable("SIGSTORE_TUF_CACHE_PATH")
    ?? Path.Combine(Path.GetTempPath(), "sigstore-tuf-cache");

builder.Logging.AddOpenTelemetry(logging => logging
    .AddOtlpExporter());

builder.Services
    .AddOpenTelemetry()
    .WithTracing(tracing => tracing
        .AddSource(SigstoreTelemetry.ActivitySourceName)
        .AddSource(TufTelemetry.ActivitySourceName)
        .AddHttpClientInstrumentation()
        .AddOtlpExporter())
    .WithMetrics(metrics => metrics
        .AddMeter(SigstoreTelemetry.MeterName)
        .AddMeter(TufTelemetry.MeterName)
        .AddRuntimeInstrumentation()
        .AddOtlpExporter());

builder.Services.AddSingleton(new ProbeSettings(tufCachePath));
builder.Services.AddSingleton(_ => new TufTrustRootProvider(
    TufTrustRootProvider.ProductionUrl,
    new TufTrustRootProviderOptions
    {
        Cache = new FileSystemTufCache(tufCachePath)
    }));
builder.Services.AddSingleton(serviceProvider => new SigstoreVerifier(
    serviceProvider.GetRequiredService<TufTrustRootProvider>()));
builder.Services.AddHostedService<SigstoreProbeWorker>();

await builder.Build().RunAsync();

internal sealed class SigstoreProbeWorker(
    ILogger<SigstoreProbeWorker> logger,
    ProbeSettings settings,
    SigstoreVerifier verifier) : BackgroundService
{
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(15);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation(
            "Starting Sigstore telemetry probe using package version {Version} and file-system TUF cache {CachePath}.",
            typeof(SigstoreVerifier).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                .InformationalVersion,
            settings.TufCachePath);

        await RunProbeAsync(stoppingToken);

        using var timer = new PeriodicTimer(ProbeInterval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await RunProbeAsync(stoppingToken);
        }
    }

    private async Task RunProbeAsync(CancellationToken cancellationToken)
    {
        using var artifact = new MemoryStream("telemetry probe"u8.ToArray());
        var (success, result) = await verifier.TryVerifyStreamAsync(
            artifact,
            new SigstoreBundle(),
            new VerificationPolicy(),
            cancellationToken);

        if (success)
        {
            throw new InvalidOperationException(
                "The intentionally invalid Sigstore bundle was unexpectedly accepted.");
        }

        logger.LogInformation(
            "The expected invalid-bundle result produced Sigstore verification telemetry: {FailureReason}",
            result?.FailureReason ?? "No failure reason was returned.");
    }
}

internal sealed record ProbeSettings(string TufCachePath);
