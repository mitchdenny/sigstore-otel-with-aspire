#:sdk Aspire.AppHost.Sdk@13.5.2
#:property AspireUseCliBundle=true

var builder = DistributedApplication.CreateBuilder(args);

builder
    .AddContainer(
        "dotnet-test",
        "mcr.microsoft.com/dotnet/sdk",
        "10.0")
    .WithBindMount(
        "./src/dotnet-test/SigstoreTelemetryProbe.cs",
        "/workspace/SigstoreTelemetryProbe.cs",
        isReadOnly: true)
    .WithEntrypoint("dotnet")
    .WithArgs(
        "run",
        "--file",
        "/workspace/SigstoreTelemetryProbe.cs")
    .WithEnvironment("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
    .WithEnvironment("SIGSTORE_TUF_CACHE_PATH", "/tmp/sigstore-tuf-cache")
    .WithOtlpExporter(OtlpProtocol.Grpc);

builder
    .AddDockerfile("cosign-test", "./src/cosign-test")
    .WithOtlpExporter(OtlpProtocol.Grpc);

builder
    .AddDockerfile("python-test", "./src/python-test")
    .WithEnvironment("OTEL_TRACES_EXPORTER", "otlp")
    .WithEnvironment("OTEL_METRICS_EXPORTER", "none")
    .WithEnvironment("OTEL_LOGS_EXPORTER", "none")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithOtlpExporter(OtlpProtocol.Grpc);

builder
    .AddDockerfile("javascript-test", "./src/javascript-test")
    .WithEnvironment("OTEL_METRICS_EXPORTER", "none")
    .WithEnvironment("OTEL_LOGS_EXPORTER", "none")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithOtlpExporter(OtlpProtocol.Grpc);

builder
    .AddDockerfile("java-test", "./src/java-test")
    .WithEnvironment("OTEL_METRICS_EXPORTER", "none")
    .WithEnvironment("OTEL_LOGS_EXPORTER", "none")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithOtlpExporter(OtlpProtocol.Grpc);

builder
    .AddDockerfile("rust-test", "./src/rust-test")
    .WithEnvironment("OTEL_METRICS_EXPORTER", "none")
    .WithEnvironment("OTEL_LOGS_EXPORTER", "none")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithOtlpExporter(OtlpProtocol.Grpc);

builder.Build().Run();
