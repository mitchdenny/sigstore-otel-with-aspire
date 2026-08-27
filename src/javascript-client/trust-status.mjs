import { createHash } from 'node:crypto';

export const TRUST_STATUS_SCHEMA_VERSION = 1;
export const TRUST_STATUS_TARGET_NAME = 'trust_status.v1.json';

export function createClientTrustStatus({
  resource,
  language,
  publishedTarget,
  trustedRootTarget,
  signingConfigTarget,
  initializedAtUtc,
  rootVersion,
  targetsVersion,
}) {
  const published = parseJSONTarget(publishedTarget, TRUST_STATUS_TARGET_NAME);
  const trustedRootSha256 = sha256Hex(trustedRootTarget);
  const signingConfigSha256 = sha256Hex(signingConfigTarget);
  const actualRootVersion = rootVersion ?? published.tufRootVersion;
  const actualTargetsVersion = targetsVersion ?? published.tufTargetsVersion;

  if (
    published.schemaVersion !== TRUST_STATUS_SCHEMA_VERSION ||
    typeof published.trustDomainId !== 'string' ||
    published.trustDomainId.length === 0 ||
    !Number.isInteger(published.generation) ||
    published.generation <= 0 ||
    typeof published.generationId !== 'string' ||
    published.generationId.length === 0 ||
    !isLowerHexSha256(published.generationManifestSha256) ||
    published.tufRootVersion !== actualRootVersion ||
    published.tufTargetsVersion !== actualTargetsVersion ||
    published.trustedRootSha256 !== trustedRootSha256 ||
    published.signingConfigSha256 !== signingConfigSha256
  ) {
    throw new Error(
      'Published trust status does not match verified TUF material.',
    );
  }

  return {
    schemaVersion: TRUST_STATUS_SCHEMA_VERSION,
    resource,
    language,
    ready: true,
    lastError: null,
    trustDomainId: published.trustDomainId,
    generation: published.generation,
    generationId: published.generationId,
    generationManifestSha256: published.generationManifestSha256,
    tufRootVersion: actualRootVersion,
    tufTargetsVersion: actualTargetsVersion,
    trustedRootSha256,
    signingConfigSha256,
    initializedAtUtc,
  };
}

export function trustSpanAttributes(status) {
  return {
    'sigstore.trust.domain.id': status.trustDomainId,
    'sigstore.trust.generation': status.generation,
    'sigstore.trust.generation.id': status.generationId,
    'sigstore.trust.generation.manifest.sha256':
      status.generationManifestSha256,
    'sigstore.trust.tuf.root.version': status.tufRootVersion,
    'sigstore.trust.tuf.targets.version': status.tufTargetsVersion,
    'sigstore.trust.trusted_root.sha256': status.trustedRootSha256,
    'sigstore.trust.signing_config.sha256': status.signingConfigSha256,
    'sigstore.trust.initialized_at': status.initializedAtUtc,
  };
}

export function targetText(value) {
  return Buffer.from(asBytes(value)).toString('utf8');
}

function parseJSONTarget(value, description) {
  try {
    return JSON.parse(targetText(value));
  } catch (error) {
    throw new Error(`${description} is not valid JSON.`, { cause: error });
  }
}

function sha256Hex(value) {
  return createHash('sha256').update(asBytes(value)).digest('hex');
}

function asBytes(value) {
  if (typeof value === 'string') {
    return Buffer.from(value, 'utf8');
  }
  if (value instanceof Uint8Array) {
    return value;
  }
  throw new TypeError('TUF target must be a string or Uint8Array.');
}

function isLowerHexSha256(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}
