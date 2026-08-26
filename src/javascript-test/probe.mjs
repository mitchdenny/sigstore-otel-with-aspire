import { readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { SpanStatusCode, trace } from '@opentelemetry/api';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-grpc';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { UndiciInstrumentation } from '@opentelemetry/instrumentation-undici';
import { NodeSDK } from '@opentelemetry/sdk-node';

const fixturePath = '/opt/sigstore-js-fixture/bundle.sigstore.json';
const tufCachePath = '/tmp/sigstore-js-tuf-cache';
const intervalMilliseconds = 15_000;
const stopController = new AbortController();

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => stopController.abort());
}

const sdk = new NodeSDK({
  instrumentations: [new HttpInstrumentation(), new UndiciInstrumentation()],
  serviceName: process.env.OTEL_SERVICE_NAME ?? 'javascript-test',
  traceExporter: new OTLPTraceExporter(),
});

sdk.start();

const tracer = trace.getTracer('sigstore-javascript-test', '1.0.0');
const bundle = JSON.parse(await readFile(fixturePath, 'utf8'));
const { createVerifier } = await import('sigstore');

const verifier = await tracer.startActiveSpan(
  'sigstore.verifier.initialize',
  async (span) => {
    try {
      const initializedVerifier = await createVerifier({ tufCachePath });
      span.setAttribute('sigstore.client.language', 'javascript');
      span.setStatus({ code: SpanStatusCode.OK });
      return initializedVerifier;
    } catch (error) {
      span.recordException(error);
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : String(error),
      });
      throw error;
    } finally {
      span.end();
    }
  },
);

console.log('Starting sigstore-js telemetry probe.');

try {
  while (!stopController.signal.aborted) {
    await tracer.startActiveSpan('sigstore.verify', async (span) => {
      try {
        verifier.verify(bundle);
        span.setAttribute('sigstore.bundle.media_type', bundle.mediaType);
        span.setAttribute('sigstore.client.language', 'javascript');
        span.setStatus({ code: SpanStatusCode.OK });
        console.log('sigstore-js verification emitted an OpenTelemetry trace.');
      } catch (error) {
        span.recordException(error);
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: error instanceof Error ? error.message : String(error),
        });
        throw error;
      } finally {
        span.end();
      }
    });

    try {
      await delay(intervalMilliseconds, undefined, {
        signal: stopController.signal,
      });
    } catch (error) {
      if (error?.name !== 'AbortError') {
        throw error;
      }
    }
  }
} finally {
  await sdk.shutdown();
}
