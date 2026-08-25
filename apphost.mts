import {
  createBuilder,
  OtlpProtocol,
} from './.aspire/modules/aspire.mjs';

const builder = await createBuilder();

await builder
  .addContainer('dotnet-test', {
    image: 'mcr.microsoft.com/dotnet/sdk',
    tag: '10.0',
  })
  .withBindMount(
    './src/dotnet-test/SigstoreTelemetryProbe.cs',
    '/workspace/SigstoreTelemetryProbe.cs',
    { isReadOnly: true },
  )
  .withEntrypoint('dotnet')
  .withArgs([
    'run',
    '--file',
    '/workspace/SigstoreTelemetryProbe.cs',
  ])
  .withEnvironment('DOTNET_CLI_TELEMETRY_OPTOUT', '1')
  .withEnvironment('SIGSTORE_TUF_CACHE_PATH', '/tmp/sigstore-tuf-cache')
  .withOtlpExporter({ protocol: OtlpProtocol.Grpc });

await builder
  .addDockerfile('cosign-test', './src/cosign-test')
  .withOtlpExporter({ protocol: OtlpProtocol.Grpc });

await builder
  .addDockerfile('python-test', './src/python-test')
  .withEnvironment('OTEL_TRACES_EXPORTER', 'otlp')
  .withEnvironment('OTEL_METRICS_EXPORTER', 'none')
  .withEnvironment('OTEL_LOGS_EXPORTER', 'none')
  .withEnvironment(
    'OTEL_EXPORTER_OTLP_CERTIFICATE',
    '/usr/lib/ssl/aspire/cert.pem',
  )
  .withOtlpExporter({ protocol: OtlpProtocol.Grpc });

await builder.build().run();
