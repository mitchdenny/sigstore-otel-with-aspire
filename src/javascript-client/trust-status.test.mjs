import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  createClientTrustStatus,
  trustSpanAttributes,
} from './trust-status.mjs';

test('status hashes exact verified target bytes', () => {
  const trustedRoot = Buffer.from('{"trusted":true}\n');
  const signingConfig = Buffer.from('{"signing":true}\n');
  const published = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      trustDomainId: `sha256-${'a'.repeat(64)}`,
      generation: 1,
      generationId: 'generation-00000001',
      generationManifestSha256: 'b'.repeat(64),
      tufRootVersion: 2,
      tufTargetsVersion: 3,
      trustedRootSha256: hash(trustedRoot),
      signingConfigSha256: hash(signingConfig),
    }),
  );

  const status = createClientTrustStatus({
    resource: 'javascript-client',
    language: 'javascript',
    publishedTarget: published,
    trustedRootTarget: trustedRoot,
    signingConfigTarget: signingConfig,
    initializedAtUtc: '2026-08-27T00:00:00.000Z',
  });

  assert.equal(status.ready, true);
  assert.equal(
    trustSpanAttributes(status)['sigstore.trust.generation'],
    1,
  );

  const changedRoot = Buffer.from(trustedRoot);
  changedRoot[0] ^= 0xff;
  assert.throws(
    () =>
      createClientTrustStatus({
        resource: 'javascript-client',
        language: 'javascript',
        publishedTarget: published,
        trustedRootTarget: changedRoot,
        signingConfigTarget: signingConfig,
        initializedAtUtc: '2026-08-27T00:00:00.000Z',
      }),
    /does not match verified TUF material/,
  );
});

function hash(value) {
  return createHash('sha256').update(value).digest('hex');
}
