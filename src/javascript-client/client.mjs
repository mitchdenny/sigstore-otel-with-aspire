import { createHash, randomBytes, randomInt } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { SpanKind, SpanStatusCode, trace } from '@opentelemetry/api';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-grpc';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { UndiciInstrumentation } from '@opentelemetry/instrumentation-undici';
import { NodeSDK } from '@opentelemetry/sdk-node';

import {
  createClientTrustStatus,
  targetText,
  TRUST_STATUS_TARGET_NAME,
  trustSpanAttributes,
} from './trust-status.mjs';

const REQUEST_TIMEOUT_MILLISECONDS = 30_000;
const PRODUCE_INTERVAL_MILLISECONDS = 10_000;
const POLL_INTERVAL_MILLISECONDS = 2_000;
const MAXIMUM_PENDING_ATTEMPTS = 5;

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

class ArtifactProtocolError extends Error {}

class ArtifactNotReady extends Error {
  constructor(retryAfterMilliseconds) {
    super('The artifact is reserved but not sealed.');
    this.retryAfterMilliseconds = retryAfterMilliseconds;
  }
}

class ArtifactMissing extends Error {}

const config = {
  artifactStoreURL: requiredURL('SHADY_BLOB_STORE_URL'),
  tufURL: requiredURL('SIGSTORE_TUF_URL'),
  tufRootPath: requiredValue('SIGSTORE_TUF_ROOT_PATH'),
  oidcURL: requiredURL('SIGSTORE_OIDC_URL'),
  expectedIdentity: requiredValue('SIGSTORE_EXPECTED_IDENTITY'),
  expectedIssuer: requiredURL('SIGSTORE_EXPECTED_ISSUER'),
  port: Number.parseInt(process.env.JAVASCRIPT_CLIENT_PORT ?? '8080', 10),
};

const stopController = new AbortController();
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => stopController.abort());
}

const sdk = new NodeSDK({
  instrumentations: [new HttpInstrumentation(), new UndiciInstrumentation()],
  serviceName: process.env.OTEL_SERVICE_NAME ?? 'javascript-client',
  traceExporter: new OTLPTraceExporter(),
});
sdk.start();

const tracer = trace.getTracer('sigstore.demo.javascript-client', '1.0.0');
const { createServer } = await import('node:http');
const { bundleToJSON } = await import('@sigstore/bundle');
const { SigningConfig } = await import('@sigstore/protobuf-specs');
const { bundleBuilderFromSigningConfig } = await import('@sigstore/sign');
const { initTUF } = await import('@sigstore/tuf');
const { createVerifier } = await import('sigstore');

let workersHealthy = true;
let artifactStore;
let bundleBuilder;
let verifier;
let trustStatus;
let lastWorkerError = null;

async function runWorker(name, worker) {
  try {
    await worker();
  } catch (error) {
    workersHealthy = false;
    lastWorkerError = error instanceof Error ? error.message : String(error);
    console.error(`The ${name} worker stopped unexpectedly.`, error);
    stopController.abort();
    throw error;
  }
}

async function producerLoop() {
  while (!stopController.signal.aborted) {
    try {
      await produceArtifact();
    } catch (error) {
      console.error('Failed to produce an artifact.', error);
    }
    await sleep(PRODUCE_INTERVAL_MILLISECONDS);
  }
}

async function produceArtifact() {
  const artifact = randomBytes(randomInt(256, 4097));
  await inSpan(
    'artifact.produce',
    SpanKind.PRODUCER,
    {
      'artifact.size': artifact.length,
      'client.language': 'javascript',
    },
    async (span) => {
      const bundle = bundleToJSON(
        await bundleBuilder.create({ data: artifact }),
      );
      const reservation = await artifactStore.uploadArtifact(artifact);
      span.setAttribute('artifact.id', reservation.id);

      while (!stopController.signal.aborted) {
        try {
          await artifactStore.uploadSignature(
            reservation.signatureURL,
            reservation.sealToken,
            JSON.stringify(bundle),
          );
          break;
        } catch (error) {
          if (
            error instanceof ArtifactProtocolError ||
            (error instanceof HTTPResponseError && error.status < 500)
          ) {
            throw error;
          }
          console.warn(
            `Signature upload for artifact ${reservation.id} failed; retrying.`,
            error,
          );
          await sleep(POLL_INTERVAL_MILLISECONDS);
        }
      }

      if (!stopController.signal.aborted) {
        console.log(
          `Produced and signed artifact ${reservation.id} ` +
            `(${artifact.length} bytes).`,
        );
      }
    },
  );
}

async function validatorLoop() {
  let artifactID = 1;
  let highWatermark = 0;
  let pendingAttempts = 0;

  while (!stopController.signal.aborted) {
    let retryAfter = POLL_INTERVAL_MILLISECONDS;
    try {
      if (artifactID > highWatermark) {
        const observedHead = await artifactStore.getHead();
        if (observedHead < highWatermark) {
          throw new ArtifactProtocolError(
            `The artifact head moved backward from ${highWatermark} ` +
              `to ${observedHead}.`,
          );
        }
        highWatermark = observedHead;
        if (artifactID > highWatermark) {
          await sleep(retryAfter);
          continue;
        }
      }

      await validateArtifact(artifactID);
      artifactID += 1;
      pendingAttempts = 0;
      continue;
    } catch (error) {
      if (error instanceof ArtifactNotReady) {
        pendingAttempts += 1;
        if (pendingAttempts >= MAXIMUM_PENDING_ATTEMPTS) {
          await skipArtifact(
            artifactID,
            `The artifact remained unsealed after ${pendingAttempts} attempts.`,
            pendingAttempts,
          );
          artifactID += 1;
          pendingAttempts = 0;
          continue;
        }
        retryAfter = error.retryAfterMilliseconds;
      } else if (error instanceof ArtifactMissing) {
        await skipArtifact(artifactID, error.message, pendingAttempts);
        artifactID += 1;
        pendingAttempts = 0;
        continue;
      } else {
        console.error(`Failed to validate artifact ${artifactID}.`, error);
      }
    }

    await sleep(retryAfter);
  }
}

async function validateArtifact(artifactID) {
  const artifact = await artifactStore.downloadArtifact(artifactID);
  if (artifact === undefined) {
    throw new ArtifactMissing(
      `Artifact ${artifactID} is below the sealed head but its content is missing.`,
    );
  }
  const bundleJSON = await artifactStore.downloadSignature(artifactID);
  if (bundleJSON === undefined) {
    throw new ArtifactMissing(
      `Artifact ${artifactID} is below the sealed head but its signature is missing.`,
    );
  }

  await inSpan(
    'artifact.validate',
    SpanKind.CONSUMER,
    {
      'artifact.id': artifactID,
      'artifact.size': artifact.length,
      'client.language': 'javascript',
    },
    async (span) => {
      verifier.verify(JSON.parse(bundleJSON), artifact);
    },
  );
  console.log(`Validated artifact ${artifactID} (${artifact.length} bytes).`);
  return {
    schemaVersion: 1,
    resource: 'javascript-client',
    language: 'javascript',
    verified: true,
    artifactId: artifactID,
    artifactSha256: sha256Hex(artifact),
    bundleSha256: sha256Hex(Buffer.from(bundleJSON)),
    generation: trustStatus.generation,
    generationId: trustStatus.generationId,
    trustedRootSha256: trustStatus.trustedRootSha256,
  };
}

async function skipArtifact(artifactID, reason, attempts) {
  await inSpan(
    'artifact.skip',
    SpanKind.CONSUMER,
    {
      'artifact.id': artifactID,
      'artifact.retry_count': attempts,
      'artifact.warning': reason,
      'client.language': 'javascript',
    },
    async (span) => {
      span.addEvent('artifact.skipped');
      console.warn(`Skipping artifact ${artifactID}: ${reason}`);
    },
  );
}

async function getIdentityToken() {
  const response = await request(
    new URL('token', normalizeURL(config.oidcURL)),
  );
  const token = (await response.text()).trim();
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new ArtifactProtocolError('The OIDC endpoint did not return a JWT.');
  }
  const claims = JSON.parse(
    Buffer.from(parts[1], 'base64url').toString('utf8'),
  );
  if (claims.sub !== config.expectedIdentity) {
    throw new ArtifactProtocolError(
      `OIDC identity ${JSON.stringify(claims.sub)} did not match ` +
        `${JSON.stringify(config.expectedIdentity)}.`,
    );
  }
  if (claims.iss !== config.expectedIssuer) {
    throw new ArtifactProtocolError(
      `OIDC issuer ${JSON.stringify(claims.iss)} did not match ` +
        `${JSON.stringify(config.expectedIssuer)}.`,
    );
  }
  return token;
}

class ArtifactStore {
  constructor(baseURL) {
    this.baseURL = normalizeURL(baseURL);
    this.origin = new URL(this.baseURL).origin;
  }

  async uploadArtifact(artifact) {
    const response = await request(
      new URL('artifacts', this.baseURL),
      {
        body: artifact,
        headers: { 'Content-Type': 'application/octet-stream' },
        method: 'POST',
      },
    );
    const payload = await response.json();
    const id = Number(payload.id);
    const artifactURL = String(payload.url);
    const signatureURL = String(payload.signatureUrl);
    const sealToken = payload.sealToken;
    if (
      !Number.isSafeInteger(id) ||
      id <= 0 ||
      typeof sealToken !== 'string' ||
      sealToken.length === 0
    ) {
      throw new ArtifactProtocolError(
        'The artifact store returned an invalid creation response.',
      );
    }
    const expectedArtifactURL = new URL(
      `artifacts/${id}`,
      this.baseURL,
    ).href;
    if (
      artifactURL !== expectedArtifactURL ||
      signatureURL !== `${expectedArtifactURL}/signature` ||
      new URL(artifactURL).origin !== this.origin ||
      new URL(signatureURL).origin !== this.origin
    ) {
      throw new ArtifactProtocolError(
        'The artifact store returned an unexpected artifact URL.',
      );
    }
    return { artifactURL, id, sealToken, signatureURL };
  }

  async uploadSignature(signatureURL, sealToken, bundleJSON) {
    if (new URL(signatureURL).origin !== this.origin) {
      throw new ArtifactProtocolError(
        'Refusing to upload a signature outside the artifact store.',
      );
    }
    await request(signatureURL, {
      body: bundleJSON,
      headers: {
        'Content-Type': 'application/vnd.dev.sigstore.bundle+json',
        'X-Artifact-Seal-Token': sealToken,
      },
      method: 'POST',
    });
  }

  async getHead() {
    const response = await request(
      new URL('artifacts/head', this.baseURL),
    );
    const payload = await response.json();
    const id = Number(payload.id);
    if (!Number.isSafeInteger(id) || id < 0) {
      throw new ArtifactProtocolError(
        'The artifact store returned an invalid head response.',
      );
    }
    return id;
  }

  async downloadArtifact(id) {
    const response = await request(
      new URL(`artifacts/${id}`, this.baseURL),
      {},
      true,
    );
    if (response.status === 404) {
      return undefined;
    }
    if (response.status === 425) {
      throw new ArtifactNotReady(retryAfter(response));
    }
    ensureSuccess(response);
    return Buffer.from(await response.arrayBuffer());
  }

  async downloadSignature(id) {
    const response = await request(
      new URL(`artifacts/${id}/signature`, this.baseURL),
      {},
      true,
    );
    if (response.status === 404) {
      return undefined;
    }
    if (response.status === 425) {
      throw new ArtifactNotReady(retryAfter(response));
    }
    ensureSuccess(response);
    return response.text();
  }
}

class HTTPResponseError extends Error {
  constructor(response) {
    super(`HTTP ${response.status} ${response.statusText}`);
    this.status = response.status;
  }
}

async function request(url, options = {}, allowError = false) {
  const response = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MILLISECONDS),
  });
  if (!allowError) {
    ensureSuccess(response);
  }
  return response;
}

function ensureSuccess(response) {
  if (!response.ok) {
    throw new HTTPResponseError(response);
  }
}

function retryAfter(response) {
  const seconds = Number(response.headers.get('Retry-After') ?? '2');
  const bounded = Number.isFinite(seconds)
    ? Math.min(Math.max(seconds, 0.1), 30)
    : 2;
  return bounded * 1000;
}

async function inSpan(name, kind, attributes, operation) {
  return tracer.startActiveSpan(
    name,
    { attributes, kind },
    async (span) => {
      try {
        const result = await operation(span);
        span.setStatus({ code: SpanStatusCode.OK });
        return result;
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
}

async function sleep(milliseconds) {
  try {
    await delay(milliseconds, undefined, {
      signal: stopController.signal,
    });
  } catch (error) {
    if (error?.name !== 'AbortError') {
      throw error;
    }
  }
}

function requiredValue(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} must be configured.`);
  }
  return value;
}

function requiredURL(name) {
  const value = requiredValue(name);
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error(`${name} must be an absolute HTTP(S) URL.`);
  }
  return value;
}

function normalizeURL(value) {
  return value.endsWith('/') ? value : `${value}/`;
}

artifactStore = new ArtifactStore(config.artifactStoreURL);

({ bundleBuilder, verifier, trustStatus } = await inSpan(
  'sigstore.trust.initialize',
  SpanKind.INTERNAL,
  {
    'client.language': 'javascript',
    'client.resource.name': 'javascript-client',
  },
  async (span) => {
    const cachePath = '/tmp/sigstore-javascript-tuf-cache';
    // Pre-seed the TUF cache with the bootstrap root as a writable file.
    // The bind-mounted rootPath is read-only; tuf-js copies it preserving
    // permissions, which prevents overwriting during root rotation traversal.
    const mirrorCacheDir = join(cachePath, encodeURIComponent(
      new URL(config.tufURL).host));
    const cachedRoot = join(mirrorCacheDir, 'root.json');
    if (!existsSync(cachedRoot)) {
      mkdirSync(mirrorCacheDir, { recursive: true, mode: 0o755 });
      writeFileSync(cachedRoot, readFileSync(config.tufRootPath), {
        mode: 0o644,
      });
    }
    const tufOptions = {
      cachePath,
      mirrorURL: config.tufURL,
      rootPath: config.tufRootPath,
    };
    const tuf = await initTUF(tufOptions);
    const trustedRootJSON = await tuf.getTarget('trusted_root.json');
    const signingConfigJSON = await tuf.getTarget(
      'signing_config.v0.2.json',
    );
    const publishedStatusJSON = await tuf.getTarget(
      TRUST_STATUS_TARGET_NAME,
    );
    const signingConfig = SigningConfig.fromJSON(
      JSON.parse(targetText(signingConfigJSON)),
    );
    const initializedBundleBuilder = bundleBuilderFromSigningConfig({
      bundleType: 'messageSignature',
      fetchOptions: {
        retry: { retries: 2 },
        timeout: REQUEST_TIMEOUT_MILLISECONDS,
      },
      identityProvider: {
        getToken: getIdentityToken,
      },
      signingConfig,
    });
    const initializedVerifier = await createVerifier({
      certificateIdentityEmail: config.expectedIdentity,
      certificateIssuer: config.expectedIssuer,
      timeout: REQUEST_TIMEOUT_MILLISECONDS,
      tufCachePath: cachePath,
      tufMirrorURL: config.tufURL,
      tufRootPath: config.tufRootPath,
    });
    const initializedStatus = createClientTrustStatus({
      resource: 'javascript-client',
      language: 'javascript',
      publishedTarget: publishedStatusJSON,
      trustedRootTarget: trustedRootJSON,
      signingConfigTarget: signingConfigJSON,
      initializedAtUtc: new Date().toISOString(),
    });
    span.setAttributes(trustSpanAttributes(initializedStatus));
    return {
      bundleBuilder: initializedBundleBuilder,
      verifier: initializedVerifier,
      trustStatus: initializedStatus,
    };
  },
));

const server = createServer(async (request, response) => {
  const requestURL = new URL(request.url ?? '/', 'http://localhost');
  const verificationMatch =
    /^\/artifacts\/([1-9][0-9]*)\/verify$/.exec(requestURL.pathname);
  if (verificationMatch !== null) {
    if (request.method !== 'GET') {
      response.writeHead(405);
      response.end();
      return;
    }
    try {
      const evidence = await validateArtifact(
        Number.parseInt(verificationMatch[1], 10),
      );
      const body = JSON.stringify(evidence);
      response.writeHead(200, {
        'Content-Length': Buffer.byteLength(body),
        'Content-Type': 'application/json',
      });
      response.end(body);
    } catch (error) {
      const body = JSON.stringify({
        error: error instanceof Error ? error.message : String(error),
      });
      response.writeHead(
        error instanceof ArtifactMissing ? 404 : 422,
        {
          'Content-Length': Buffer.byteLength(body),
          'Content-Type': 'application/json',
        },
      );
      response.end(body);
    }
    return;
  }

  if (request.url === '/trust/status') {
    const ready = !stopController.signal.aborted && workersHealthy;
    const body = JSON.stringify({
      ...trustStatus,
      ready,
      lastError: ready
        ? null
        : (lastWorkerError ?? 'client is stopping'),
    });

    response.writeHead(ready ? 200 : 503, {
      'Content-Length': Buffer.byteLength(body),
      'Content-Type': 'application/json',
    });
    response.end(body);
    return;
  }

  const healthy =
    request.url === '/healthz' &&
    !stopController.signal.aborted &&
    workersHealthy;
  const body = JSON.stringify({
    status: healthy ? 'SERVING' : 'NOT_SERVING',
  });
  response.writeHead(healthy ? 200 : 503, {
    'Content-Length': Buffer.byteLength(body),
    'Content-Type': 'application/json',
  });
  response.end(body);
});
server.listen(config.port, '0.0.0.0');

const producer = runWorker('producer', producerLoop);
const validator = runWorker('validator', validatorLoop);
console.log('JavaScript producer and validator started.');

await new Promise((resolve) => {
  stopController.signal.addEventListener('abort', resolve, { once: true });
});

await new Promise((resolve) => server.close(resolve));
await Promise.allSettled([producer, validator]);
await sdk.shutdown();
