FROM node:24.15.0-bookworm-slim

ARG SIGSTORE_JS_FIXTURE_COMMIT=7d2900eca1c22b3f87c13987c8d4b7c9a29b733a

ENV NODE_ENV=production \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci --omit=dev

RUN SIGSTORE_JS_FIXTURE_COMMIT="${SIGSTORE_JS_FIXTURE_COMMIT}" node --input-type=module - <<'JS'
import { mkdir, writeFile } from 'node:fs/promises';

const commit = process.env.SIGSTORE_JS_FIXTURE_COMMIT;
const fixtureDirectory = '/opt/sigstore-js-fixture';
const fixtureURL =
  'https://raw.githubusercontent.com/sigstore/sigstore-js/' +
  `${commit}/tests/bundles/bundleV03-intoto.sigstore`;

const response = await fetch(fixtureURL);
if (!response.ok) {
  throw new Error(`Failed to download fixture: ${response.status}`);
}

await mkdir(fixtureDirectory, { recursive: true });
await writeFile(
  `${fixtureDirectory}/bundle.sigstore.json`,
  Buffer.from(await response.arrayBuffer()),
);
JS

COPY probe.mjs ./

USER node

ENTRYPOINT ["node", "/app/probe.mjs"]
