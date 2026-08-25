import {
  createBuilder,
  OtlpProtocol,
} from './.aspire/modules/aspire.mjs';

const builder = await createBuilder();

await builder
  .addContainer('sigstore-telemetry', {
    image: 'mcr.microsoft.com/dotnet/sdk',
    tag: '10.0',
  })
  .withBindMount(
    './src/SigstoreTelemetryProbe.cs',
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
  .addDockerfile('cosign', './src/CosignTelemetryProbe')
  .withOtlpExporter({ protocol: OtlpProtocol.Grpc });

await builder.build().run();