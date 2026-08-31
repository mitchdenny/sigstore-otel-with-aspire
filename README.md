# Sigstore OpenTelemetry with Aspire

This repository runs a self-contained Sigstore trust domain and six client
workloads, then sends their OpenTelemetry data to the local Aspire dashboard.
Aspire builds and starts the containers, configures their internal endpoints and
OTLP exporters, and provides the UI for viewing resources, logs, traces, and
metrics.

Only the .NET 10 SDK is required locally for the file-based C# AppHost. The six
client toolchains run inside containers, so Go, Python, Node.js, Java, and Rust
do not need to be installed locally.

## What gets launched

- `sigstore-bootstrap` creates and validates the private keys and public trust
  material for the isolated Sigstore stack, then exits successfully.
- `oidc` is an unauthenticated, test-only OIDC issuer at
  `https://oidc-sigstore.dev.localhost:7443`. It issues short-lived tokens for
  `demo@sigstore.local` using the bootstrap-generated RSA key.
- `tesseract` is the Certificate Transparency log used to record certificates
  issued by the local Fulcio service. It stores its append-only log under
  `.sigstore/data/ctlog` and is available at
  `http://tesseract-sigstore.dev.localhost:6962`.
- `tesseract-secondary` is an explicit-start certificate-transparency shard for
  the one bounded Step 13 rotation. It has its own signer, log ID, origin,
  storage, and canonical URL `http://tesseract-secondary-sigstore.dev.localhost:6963`,
  and is started and health-proven before any trust publication.
- `fulcio` exchanges a valid test OIDC token for a short-lived code-signing
  certificate, submits the certificate to the certificate-transparency shard it
  is currently bound to, and embeds the returned SCT. Its HTTP API is available
  at `http://fulcio-sigstore.dev.localhost:5555`. The shard it uses is a durable
  runtime selection under `.sigstore/runtime/fulcio-ct`, not a build-time
  argument, so Step 13 can move it with exactly one restart.
- `timestamp` issues RFC 3161 signed timestamps using a run-scoped local file
  signer at `http://timestamp-sigstore.dev.localhost:3004`.
- `rekor-server` sequences artifact-signature entries into the initial
  run-scoped Rekor v2 shard under `.sigstore/data/rekor`. Its immutable public
  URL remains `http://rekor-sigstore.dev.localhost:3000`.
- `rekor-server-secondary` is an explicit-start writer for the one bounded
  Step 12 rotation shard. It has its own signer and storage and is started and
  health-proven before routing changes.
- `rekor` is the stable multi-shard Rekor v2 gateway. It preserves the initial
  root URL and serves the secondary shard at
  `http://rekor-secondary-sigstore.dev.localhost:3000`.
- `tuf-bootstrap` builds the signed TUF repository, Sigstore `TrustedRoot`,
  `SigningConfig`, and combined client trust configuration.
- `tuf` serves the signed repository and public client configuration at
  `http://tuf-sigstore.dev.localhost:8080`.
- `shady-blob-store` is a file-based ASP.NET Core application running directly
  from source in a .NET 10 SDK container. It stores monotonically numbered
  artifacts and Sigstore bundles for the current AppHost run under
  `.shady-blob-store`.
- `dotnet-client` runs a file-based .NET 10 producer and validator using
  `Sigstore` `1.1.0-alpha.131.1.fd8696f`. About every 10 seconds it creates
  random bytes, gets a local OIDC token, signs through local Fulcio, TSA, and
  Rekor v2, and publishes the artifact and bundle. Its second loop consumes
  artifacts from ID 1 in order and verifies every layer against the trusted
  root fetched from the local TUF repository.
- `go-client` uses `sigstore-go` `1.3.0` for native keyless signing and
  verification, including Rekor v2 and RFC 3161 timestamps.
- `python-client` runs Python 3.12 with `sigstore-python` `4.5.0`. Like the .NET
  client, it continuously produces locally signed artifacts and validates every
  artifact in numeric order. It loads both its trusted root and signing
  configuration through the local TUF repository, and exports application
  spans, auto-instrumented HTTP spans, metrics, and logs through OTLP.
- `javascript-client` runs Node.js 24 with `sigstore-js` `5.0.0`. It loads the
  local signing configuration through TUF and uses the native Rekor v2 bundle
  builder.
- `java-client` runs Java 21 with `sigstore-java` `2.2.0` and the OpenTelemetry
  Java agent `2.31.1`. Its local signing adapter uses sigstore-java's public
  HTTP Fulcio, Rekor v2, TSA, bundle, and verification APIs.
- `rust-client` uses the modular `sigstore-rust` `0.11.0` signing and
  verification crates with explicitly instrumented TUF and artifact HTTP
  boundaries.

All six language clients follow the same pattern: produce and seal a random
artifact about every 10 seconds, then independently validate every sealed
artifact produced by every language.

All workloads are safe to run locally. Every client uploads entries only to the
isolated local Rekor log.

The `oidc` resource performs no authentication and must only be used for this
local demonstration.

## Prerequisites

Install these before starting:

1. [Docker Desktop](https://www.docker.com/products/docker-desktop/) or another
   Docker-compatible container runtime with BuildKit, with the daemon running.
2. The [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0).
3. The [Aspire CLI](https://aspire.dev/get-started/install-cli/). The
   .NET global tool installation is:

   ```bash
   dotnet tool install --global Aspire.Cli
   ```

   Confirm that it is available:

   ```bash
   aspire --version
   ```

The first launch also needs internet access to download container images,
packages, and the OpenTelemetry Java agent. The Rust client compiles AWS-LC and
its pinned client dependencies from source. That initial build can take several
minutes.

## Local Sigstore state

The one-shot `sigstore-bootstrap` resource creates the private keys and public
trust material needed by the isolated Sigstore services. It writes schema-5
generation-aware state to the gitignored `.sigstore` directory in the
repository root. Every new AppHost process deletes and recreates both
`.sigstore` and `.shady-blob-store` before bootstrap, so each `aspire run` or
`aspire start` begins with a new trust domain, empty transparency logs, and
artifact numbering starting at 1.

The AppHost process is the reset boundary. Restarting an individual service or
client resource within the same run retains that run's trust and artifact
state. Stopping the AppHost and starting it again intentionally discards that
state. A `SIGSTORE_STATE_PATH` override is accepted only when its resolved path
is a safe descendant of the AppHost directory.

The trust-domain identity is separate from its active key generation:

```text
.sigstore/
|-- state.lock
|-- trust-domain.json
|-- active-generation -> generations/generation-00000001
|-- generations/
|   `-- generation-00000001/
|       |-- private/
|       |-- public/
|       `-- manifest.json
|-- transition/
|   `-- state.json
|-- tsa-rotation/
|   `-- <operation-id>/
|       |-- command.json
|       |-- old-request.tsq
|       |-- old-response.tsr
|       `-- candidate/public/           # public chain evidence retained
|-- rotate-timestamp-authority.completed
|-- fulcio-rotation/
|   `-- <operation-id>/
|       |-- command.json
|       `-- candidate/public/fulcio/root.pem
|-- rotate-fulcio-ca.completed
|-- rekor-shard-rotation/
|   `-- <operation-id>/
|       |-- candidate/
|       |-- hosting-state.json
|       `-- command.json
|-- rotate-rekor-shard.completed
|-- ct-log-shard-rotation/
|   `-- <operation-id>/
|       |-- candidate/                  # isolated secondary CT signer
|       `-- hosting-state.json
|-- rotate-ct-log-shard.completed
|-- runtime/
|   |-- fulcio/                         # active CA material only
|   |-- fulcio-ct/                      # primary.pub/secondary.pub + selection
|   |-- tesseract/                      # primary CT key + accepted roots only
|   |-- tesseract-secondary/            # secondary CT key + accepted roots
|   `-- rekor-secondary/                # secondary Rekor signer only
|-- migration/
|   `-- bootstrap-manifest.schema-4.json  # migrated state only
|-- data/
|   |-- ctlog/                          # immutable primary CT shard data
|   |-- ctlog-shards/
|   |   |-- state.json                  # schema-1 CT shard catalog
|   |   `-- secondary/                  # independent secondary CT log
|   |-- rekor/                          # immutable primary shard identity/data
|   `-- rekor-shards/
|       |-- state.json                  # schema-1 shard catalog
|       `-- secondary/                  # independent secondary tile log
`-- tuf/
```

`trust-domain.json` is immutable identity: its ID, creation time, and the CT
and Rekor log-state IDs do not belong to a replaceable key generation. Each
numbered generation has its own immutable manifest containing the generation
reference, trust-domain ID, source-schema provenance, trust fingerprints, and
the exact SHA-256 and path of every private and public material file.
`active-generation` is a normalized relative link switched atomically only
after the candidate and immutable identity have been validated.

`transition/state.json` is a durable trust-transition journal, distinct from
TUF publication state and publication IDs. It can record `staged`, `committed`,
`failed`, and `recovered`; the active-generation link is the commit record.
Interrupted pre-commit initialization or schema-4 migration completes forward
because there is no prior generation, while an interruption after that switch
also finalizes forward. A known operation failure is recorded as `failed` and
recovered by the next bootstrap. Step 4 creates or imports generation 1 only;
it does not mutate generations during live operation. Root key rotation is
provided by the `rotate-tuf-root` command (Step 7).

Bootstrap and TUF publication both serialize through `state.lock`. The lock is
an operating-system advisory lock, so an interrupted owner cannot leave a
stale lock behind; the JSON owner record is diagnostic and is overwritten by
the next holder. Schema-4 migration validates the old state before writing a
journal, moves the existing `private` and `public` trees without rewriting
their bytes, and archives the original bootstrap manifest byte-for-byte.
Ambiguous layouts, extra generation files, changed hashes, or inconsistent
keys and certificates fail instead of regenerating or discarding state.

The TUF worker keeps `.sigstore/tuf` itself stable for the entire AppHost run.
Nginx and all clients bind-mount that parent, whose layout is:

```text
.sigstore/tuf/
|-- bootstrap/root.json
|-- active -> committed/sha256-<manifest-hash>
|-- committed/sha256-<manifest-hash>/
|   |-- keys/
|   |-- repository/
|   |-- targets/
|   `-- manifest.json
|-- history/previous/
|-- staging/
`-- publication/state.json
```

`bootstrap/root.json` is a read-only, byte-for-byte copy of the initial
version-1 root and is never replaced during refresh. `active` is switched
atomically only after a complete candidate has passed source-fingerprint and
file-hash validation. `history/previous` retains exactly the prior committed
repository; older refresh history is retired so ordinary refreshes remain
bounded. `staging` contains the candidate and, while publishing, the history
entry being retired. `publication/state.json` records either `committed` or
`preparing` plus the expected bootstrap and manifest hashes.

Recovery uses that journal and the `active` link as the commit record. A
`preparing` refresh with the old link still active rolls back and restores the
parked history. If the link already selects the fully validated candidate,
recovery completes the commit and archives the old active repository. Initial
creation always completes forward once its journal exists. Missing,
conflicting, or hash-mismatched state fails without discarding the ambiguous
files; only an unjournaled staging candidate created before the journal write
is known scratch and removed.

## Artifact protocol

The initial protocol is deliberately small:

- `POST /artifacts` atomically reserves the next numeric ID, stores the raw
  request body, and returns stable artifact/signature URLs plus an opaque seal
  token known only to that producer.
- `GET /artifacts/{id}` downloads the raw artifact only after it is sealed.
- `POST /artifacts/{id}/signature` atomically stores its Sigstore bundle.
  The producer must provide its seal token in `X-Artifact-Seal-Token`; the first
  accepted signature seals and publishes the artifact. Reposting the same bytes
  with the same token is idempotent; different bytes return `409 Conflict`.
- `GET /artifacts/{id}/signature` downloads the bundle only after sealing.
- `GET /artifacts/head` returns `{"id": n}`, where `n` is the highest sealed
  artifact ID, or `0` when no artifacts have been sealed.
- Every language client exposes
  `GET /artifacts/{id}/verify` on its own local endpoint. It runs that
  language's normal verifier and returns operation-bound artifact, bundle, trust
  generation, and TrustedRoot hashes. Rotation commands use this endpoint for
  deterministic cross-language evidence; it does not rewrite bundle bytes.

An unknown ID returns `404 Not Found`. An existing reservation that has not yet
been sealed returns `425 Too Early` with `Retry-After: 2`; validators honor that
delay without treating the pending state as a verification failure.

The six producers race independently for IDs: one language might reserve
artifact 1 while another reserves artifact 2. Each producer alone seals its own
reservation. Each validator polls `/artifacts/head` only when its local
watermark is caught up, then walks sequentially toward that sealed high
watermark. This avoids probing unknown IDs. A reserved ID that remains unsealed
after five `425` responses is skipped so it cannot block the stream forever;
the client emits a correlated `artifact.skip` warning span and log.

## Launch

Clone the repository and run Aspire:

```bash
git clone https://github.com/mitchdenny/sigstore-otel-with-aspire.git
cd sigstore-otel-with-aspire
aspire run
```

Keep that terminal open. Aspire prints the dashboard URL after startup and
normally opens it in your browser. If it does not open automatically, use the
printed URL; the configured HTTP dashboard is also available at
<http://sigstore.dev.localhost:15096>.

The first run builds the OIDC issuer, artifact store, and all six client
images, pulls Tesseract, and restores the file-based .NET applications. Wait
until `oidc`, `tesseract`,
`fulcio`, `timestamp`, `rekor-server`, `rekor`, `tuf`,
`shady-blob-store`, and the six client workloads show as **Running** and
**Healthy** on the dashboard's **Resources** page. The one-shot
`sigstore-bootstrap`, `sigstore-state-ready`, `tuf-bootstrap`, and
`tuf-state-ready` resources finish successfully and remain stopped.

## View the telemetry

Open **Traces** in the Aspire dashboard:

- Filter to `dotnet-client` to see `artifact.produce` and `artifact.validate`
  traces spanning OIDC, Fulcio, the timestamp authority, Rekor v2, local TUF,
  and `shady-blob-store`.
- Filter to `python-client` to see `sigstore.trust.initialize`,
  `artifact.produce`, and `artifact.validate` with auto-instrumented HTTP spans.
- Filter to `go-client`, `javascript-client`, `java-client`, or `rust-client`
  to see the same `artifact.produce`, `artifact.validate`, and `artifact.skip`
  lifecycle with each ecosystem's HTTP instrumentation.

All clients keep TUF cache state only in their writable container filesystem.
A newly created container refreshes from the local TUF repository. An expected
request for the next root version can return `404`, so an initialization trace
may appear as an error even though trust loading succeeds. Clients then reuse
their trusted configuration until refresh is required.

## Trust status and parent health

Every client serves a read-only `GET /trust/status` route on its existing local
HTTP endpoint. The response uses the same schema in all six languages:

```json
{
  "schemaVersion": 1,
  "resource": "go-client",
  "language": "go",
  "ready": true,
  "lastError": null,
  "trustDomainId": "sha256-...",
  "generation": 1,
  "generationId": "generation-00000001",
  "generationManifestSha256": "...",
  "tufRootVersion": 1,
  "tufTargetsVersion": 1,
  "trustedRootSha256": "...",
  "signingConfigSha256": "...",
  "initializedAtUtc": "2026-08-27T00:00:00Z"
}
```

`schemaVersion`, `generation`, `tufRootVersion`, and `tufTargetsVersion` are
JSON integers; `ready` is a boolean; `lastError` is either `null` or a string;
and all other fields are strings. Timestamps use RFC 3339 UTC. SHA-256 values
are 64 lowercase hexadecimal characters without a `sha256:` prefix, except the
trust-domain identifier, whose schema already includes `sha256-`.

The TUF repository includes `trust_status.v1.json` as a signed target. It binds
the active trust-domain and generation identity to the root and targets metadata
versions and the expected trust-target hashes. Each client hashes the exact
verified `trusted_root.json` and `signing_config.v0.2.json` bytes it initialized,
then rejects a mismatch. The Java client validates its mounted status target
against the already verified targets metadata; the other clients retrieve the
status target through their TUF updater. No client derives trust hashes from
unverified host configuration.

The typed `sigstore` parent retains a read-only status command:

```bash
aspire resource sigstore status | jq
```

The command writes its structured JSON payload to stdout and its status message
to stderr. It validates the complete schema-5 generation/journal state, the
committed TUF publication layout and manifests, the bytes served by TUF, and all
six client payloads. Missing, malformed, stale, unreachable, or inconsistent
data produces a nonzero command result with explicit entries in `errors`; it
does not return fallback values.

The aggregate payload also includes `timestampAuthority`: the active
generation's root/leaf fingerprints, every ordered TrustedRoot TSA entry, the
fingerprints from a freshly verified RFC3161 response, and
`activeSignerMatches`. During a command it includes the active operation phase;
after an interrupted mutation it includes the durable recovery phase. A
running old signer against already-published additive trust is reported
explicitly as activation pending rather than Healthy.

The `fulcio` payload validates the active root certificate/key pair, every
ordered historical Fulcio CA in TrustedRoot, the component-scoped runtime
projection, Tesseract's deterministic accepted-root bundle, the root reported
by Fulcio's read-only API, the certificate-transparency shard Fulcio is
currently bound to (selector, origin and log ID) and that shard's signed
checkpoint. The parent is not Healthy while disk, served TUF, clients,
Tesseract roots, or the live Fulcio issuer disagree.

The `ctLog` payload reports every logical certificate-transparency shard: its
shard ID, slot, status, origin, canonical URL, log ID, storage identity, and a
freshly verified checkpoint signature, tree size and root hash, the identity of
the complete accepted Fulcio root bundle it enforces (bundle SHA-256, root
count and ordered per-root fingerprints) together with whether that recorded
identity still matches the bytes its runtime projection renders, plus whether
that shard is published in TrustedRoot and whether its compute is required and
healthy. It also reports the shard Fulcio selects, whether a promotion is
staged but not yet applied, the TrustedRoot `ctlogs` count, and any incomplete
rotation operation and phase. A staged-but-unpromoted selection is reported
explicitly as a pending cutover rather than Healthy.

The parent state is event-driven and initially aggregates 14 required
long-running resources: the seven active Sigstore services,
`shady-blob-store`, and six clients. The explicit-start secondary Rekor writer
and the explicit-start secondary certificate-transparency shard are
conditional: they do not degrade initial health while no rotation has
activated them, then become required after cutover. At that same boundary the
primary writer becomes historical and no longer participates in parent health;
this bounded implementation leaves it running, but immutable primary checkpoint
and tile reads through nginx are the retention contract if it is stopped.
The historical primary certificate-transparency shard is deliberately
different: it has no separate static route, so its compute stays running and
health-required after a CT shard rotation and stopping it degrades the parent.
The parent shows **Healthy** only when every active required resource is
running and healthy and disk and served TUF metadata agree and are current.
It shows **Starting** while initial readiness is pending, and **Degraded** with
the first definitive reason when an active required resource stops or becomes
unhealthy, required TUF metadata expires or approaches its refresh boundary,
or disk and served TUF metadata diverge.

## Dashboard operations

The parent also exposes nine confirmed, progress-reporting operations in the
dashboard and through the Aspire CLI:

```bash
aspire resource sigstore refresh-tuf | jq
aspire resource sigstore restart-clients | jq
aspire resource sigstore rotate-tuf-root | jq
aspire resource sigstore publish-trusted-root | jq
aspire resource sigstore rotate-oidc-signing-key | jq
aspire resource sigstore rotate-timestamp-authority | jq
aspire resource sigstore rotate-fulcio-ca | jq
aspire resource sigstore rotate-rekor-shard | jq
aspire resource sigstore rotate-ct-log-shard | jq
```

`refresh-tuf` starts a new instance of the existing `tuf-bootstrap` one-shot
through Aspire's `ResourceCommandService`. It refreshes only signed snapshot and
timestamp metadata, waits for an exact exit code of zero, and validates the
publication journal, active manifest, one-entry history, served bytes, and the
unchanged TUF nginx container before succeeding. Its JSON result includes exact
before/after versions and SHA-256 values for root, targets, snapshot, and
timestamp metadata, plus publication and manifest IDs. Root, targets, TUF keys,
public trust targets, the active trust generation, and the immutable bootstrap
root must remain unchanged.

The parent also performs this same transactional operation automatically: once
after a five-minute startup stabilization period for an untouched version-1
repository, then whenever snapshot or timestamp metadata enters its six-hour
refresh window. It uses the normal command gate, shared `state.lock`,
operation-bound request/completion files, and one-shot worker; it never edits
served metadata directly. Another operation, durable recovery, lock contention,
unhealthy required infrastructure, or a disk/served mismatch defers the attempt
and retries. Root and targets approaching expiration are reported as maintenance, not
silently rotated. Use `rotate-tuf-root` before either expires; that command
accepts the maintenance warning while still requiring current
snapshot/timestamp metadata, coherent disk/served state, and healthy clients.
If snapshot/timestamp refresh overlaps that maintenance window, `refresh-tuf`
remains safe while root and targets are unexpired; refresh first, then rotate
the root. `restart-clients` also remains available in that window if a client
must be recovered between those operations.

`refresh-tuf` remains available when one or more clients are Exited or cannot
start because snapshot or timestamp metadata expired. Its recovery preconditions
still require coherent trusted state, current root and targets, and healthy
non-client infrastructure. After a successful refresh, use `restart-clients` or
start an individual terminal client. Other trust mutations remain fail-closed
until metadata and clients are current.

`restart-clients` uses `ResourceCommandService` to restart running clients and
start terminal clients in deterministic resource-name order. It waits for every replacement
container to become **Running** and **Healthy**, then requires a valid current
`/trust/status` response that agrees with disk and served trust state. Sigstore
services are not restarted, and the complete committed trust/TUF state must be
byte-identical before and after. After a root rotation, `restart-clients` accepts
clients whose root/targets version is behind disk along a valid retained root
chain, then verifies convergence to the current version after restart.

`rotate-tuf-root` generates a new root-role key, revokes the old key, and
publishes root version `N+1` signed by both old and new keys (satisfying both
thresholds). It uses a dedicated one-shot worker with the signal-file mechanism
(`rotate-root.request`). Postconditions verify root version advance,
snapshot/timestamp advance, unchanged bootstrap root/trust generation/trust
material, and publication journal integrity. After rotation, clients report stale
root until restarted via `restart-clients`. The immutable `bootstrap/root.json`
always remains at version 1; fresh clients follow the versioned root chain
(`1.root.json`, `2.root.json`, ...) to reach the active root.

Only one parent operation can run at a time. A competing command fails
immediately with the active command and phase. All operations use the shared
`state.lock`: client restart holds it throughout, while TUF refresh and root
rotation hand ownership from the parent preflight to the worker and back to the
parent postcondition phase without nesting the lock.

Every `sigstore.trust.initialize` span contains these attributes:

| Attribute | Type |
| --- | --- |
| `client.language` | string |
| `client.resource.name` | string |
| `sigstore.trust.domain.id` | string |
| `sigstore.trust.generation` | integer |
| `sigstore.trust.generation.id` | string |
| `sigstore.trust.generation.manifest.sha256` | string |
| `sigstore.trust.tuf.root.version` | integer |
| `sigstore.trust.tuf.targets.version` | integer |
| `sigstore.trust.trusted_root.sha256` | string |
| `sigstore.trust.signing_config.sha256` | string |
| `sigstore.trust.initialized_at` | RFC 3339 UTC string |

The status routes and `status` command remain local and read-only. These
operations do not add trusted-root rollout, OIDC rotation, or any later-step
mutation.

## Stop

Press <kbd>Ctrl</kbd>+<kbd>C</kbd> in the terminal running `aspire run`, or run
this from another terminal in the repository:

```bash
aspire stop
```

If startup fails, first confirm Docker is running, then use `aspire doctor` to
check the local Aspire environment.

## Additive Trusted-Root Rollout (Step 8)

The `publish-trusted-root` command advances the trust generation with additive
standby verification material and publishes through TUF transactionally:

```bash
aspire resource sigstore publish-trusted-root
```

The command:
1. Creates generation N+1 with a standby Rekor verification key (inactive/future-dated)
2. Publishes updated TrustedRoot/SigningConfig/ClientTrustConfig through TUF
3. Restarts all six language clients for uptake
4. Waits until every client reports the new generation and fingerprint

SigningConfig routing is unchanged — the standby key is verification-only and
does not affect live signing. All historical verification material is preserved.

Cross-generation recovery is automatic: a crash at any point between generation
advance and completion is detected on next startup and either rolled back (if
TUF still serves the prior generation) or forward-completed (if TUF already
committed the new generation's publication).

## OIDC Signing-Key Rotation (Step 9)

The `rotate-oidc-signing-key` command rotates the local OIDC issuer's signing key
while maintaining overlapping JWKS for token verification continuity:

```bash
aspire resource sigstore rotate-oidc-signing-key
```

The command:
1. Captures a pre-rotation token and durably binds it to a resumable operation
2. Dispatches the Go TUF worker, which atomically commits one immutable N+1
   generation containing the new active signer, an append-only overlapping
   JWKS, and kid-bound retained private keys
3. Transactionally republishes TUF `trust_status` and switches
   `active-generation` before restarting OIDC exactly once
4. Verifies new tokens use the new key ID and proves Fulcio accepts both the
   exact pre-switch token and a post-switch token without restarting Fulcio
5. Restarts all six clients and requires generation/status convergence before
   reporting success

Generation immutability is preserved: prior generation bytes remain unchanged.
TrustedRoot and SigningConfig are not modified (OIDC keys are operational, not
in client trust material). Fulcio discovers the new key via its JWKS endpoint
refresh — no Fulcio restart required. OIDC mounts the stable state root and
resolves `/var/lib/sigstore/active-generation/...` only when its replacement
container starts.

Every completed Step 9 rotation retains all historical OIDC public and private
keys; repeated rotations grow JWKS history rather than retiring keys. The
overlap deadline recorded in the generation is the minimum token TTL plus
clock-skew safety window, not a deletion trigger. Retirement is a separate
future policy and is not performed by this command.

## Timestamp-Authority Rotation (Step 10)

The `rotate-timestamp-authority` command replaces the local RFC3161 signer
without creating a trust gap:

```bash
aspire resource sigstore rotate-timestamp-authority
```

The confirmed, non-cancelable operation captures and durably validates a real
timestamp from the old signer, generates a new ECDSA P-256 root/leaf/signer
candidate, and dispatches the existing TUF one-shot worker. The worker creates
immutable generation N+1, appends the new TSA chain to `TrustedRoot`, preserves
every prior trust entry, and transactionally advances targets, snapshot, and
timestamp metadata. The TUF bootstrap root and `SigningConfig` bytes, including
the canonical TSA URL, remain unchanged.

Activation is intentionally asymmetric. The old timestamp container keeps
signing from its in-memory key while all six clients restart and report the
additive N+1 trust. Only after every client converges does the command restart
`timestamp` exactly once. OIDC, Fulcio, Tesseract, Rekor, TUF nginx, and the
artifact store retain their original container identities. The timestamp
container mounts the stable state root and resolves
`active-generation/private/tsa` and `active-generation/public/tsa` when its
replacement starts, so Docker cannot pin the replacement to the old
generation.

Both the worker completion and AppHost command journal are operation-bound.
Before TUF activation, replay regenerates or reuses the candidate and leaves the
old signer active. Once additive TUF trust commits, recovery completes forward:
it resumes partial client convergence, suppresses a duplicate timestamp restart
when a new-signer RFC3161 probe proves activation already occurred, revalidates
the retained old response, and writes the final journal. Hash-mismatched or
ambiguously ordered state fails instead of being guessed.

Rotated active generations contain only `private/tsa/signer.key` and its
password plus the current public chain; candidate private material is retired
after completion while its public chain remains as journal evidence. Prior
generation directories remain immutable. `status` parses every TSA entry in the
served `TrustedRoot`, probes the running signer, and reports
`TSA Activation Pending` until disk, served TUF, all clients, and the live
leaf/root identity agree.

The Step 10 validation run advanced generation `1` to `2`, retained both TSA
chains, passed all `48` command postconditions, changed the timestamp container
exactly once after all six client replacements, and left every unrelated
service container unchanged. All six language stacks verified retained
old-TSA artifact `315` and new-TSA artifact `382`; Python required a targeted
verification in its restarted container because its normal sequential worker
remained visibly blocked by the known omitted-index-zero bundle parsing issue.
Rotation does not rewrite that bundle or use a public Sigstore fallback.

## Fulcio CA Rotation (Step 11)

`rotate-fulcio-ca` replaces the local file CA without creating a verification
or CT-acceptance gap:

```bash
aspire resource sigstore rotate-fulcio-ca
```

The confirmed command is non-cancelable after its durable request is written.
It retains an old-CA artifact and CT checkpoint, generates an operation-bound
ECDSA P-256 CA candidate, and starts the existing one-shot TUF worker. The
worker commits immutable generation N+1, appends the new CA to TrustedRoot,
replaces the active `fulcio_v1.crt.pem` alias, rebuilds only the combined client
trust/status targets, and advances targets, snapshot, and timestamp through the
normal preparing/committed publication transaction. TUF root/bootstrap,
SigningConfig routes, CT/Rekor/TSA/standby entries, and every non-Fulcio
generation byte remain unchanged.

Activation is deliberately split from publication:

1. All six clients restart in sorted resource-name order and report the
   additive N+1 trust.
2. The retained old-CA artifact is verified through each language's normal
   verifier.
3. Tesseract restarts exactly once with the deterministic old-then-new accepted
   root bundle.
4. Fulcio remains on its old in-memory signer and obtains a cryptographically
   verified embedded SCT from that replacement Tesseract instance.
5. Only then is the operation-bound Fulcio runtime projection promoted and
   Fulcio restarted exactly once.
6. Real new-CA issuance must chain to the candidate and carry an SCT signed by
   the unchanged CT log key. A later artifact containing Rekor and RFC3161
   material must validate in all six languages before success.

Fulcio and Tesseract no longer mount replaceable generation subtrees or the
whole private state root. `runtime/fulcio` contains exactly the active
certificate, encrypted key, password, and CT public key.
`runtime/tesseract` contains exactly its unchanged CT private key and the
ordered accepted-root bundle. Both are stable real directories, so a child
restart reopens switched bytes without exposing unrelated private keys.

Candidate generation, immutable generation commit, TUF preparation/commit,
generation switch, each client, Tesseract restart, old-CA SCT proof, Fulcio
runtime promotion/restart, new-CA SCT proof, both six-language artifact proofs,
CT checkpoint, and final completion are durable replay boundaries. Before the
old-CA overlap proof, the active Fulcio runtime remains on the old issuer.
After promotion, recovery only proceeds forward. A mismatched operation,
generation, root, runtime projection, container identity, CT key/checkpoint,
artifact hash, or publication is rejected rather than guessed.

The known Python omitted-index-zero bundle issue remains visible and is not
normalized or masked. The targeted verification endpoint uses the same
generation-pinned Python verifier and is used only to prove the selected old
and new artifacts directly.

Focused validation passes all 63 Bootstrap tests and 32 Hosting tests, the
uncached TUF/Go suite and `go vet`, AppHost and .NET client builds, Go,
JavaScript, Python-container, Java-container, and Rust client gates, and
`git diff --check`. A non-isolated recovery run completed generation 1 to 2
with all 33 structured postconditions passing: Tesseract and Fulcio each
changed exactly once after six sorted client replacements, protected services
kept their identities, the CT log ID/origin remained unchanged while its tree
advanced, and old artifact 14 plus new artifact 70 passed all six targeted
native verifiers. Dynamic fingerprints and container IDs are run-scoped and
are reported with the validation commit rather than treated as static
configuration.

## Rekor Shard Rotation (Step 12)

`rotate-rekor-shard` creates a new logical append-only log instead of replacing
the signer of the initial log:

```bash
aspire resource sigstore rotate-rekor-shard
```

The initial shard keeps its generation-1 signer, log ID, storage, signed
checkpoint, immutable tiles, writer, and canonical root URL. The command
creates a distinct ECDSA P-256 signer in immutable generation N+1 and stages
only that private signer in `runtime/rekor-secondary`. The secondary writer
can see only its signer and `.sigstore/data/rekor-shards/secondary`; the
primary writer remains bound to generation 1 and `.sigstore/data/rekor`.
Nginx sees only the two public shard data trees and its routing configuration.

Cutover is ordered to avoid an unavailable route. The command durably creates
and validates the candidate and shard catalog, starts the explicit secondary
writer, proves its Aspire health and gateway route, and only then dispatches
the TUF worker. The worker creates generation N+1 by replacing only Rekor
signer material, appends the secondary `TransparencyLogInstance` to
`TrustedRoot`, changes the single active Rekor v2 `SigningConfig` URL to the
stable secondary hostname, and transactionally advances targets, snapshot, and
timestamp.
The TUF bootstrap root, root role, Fulcio, CT, TSA, OIDC, standby and
historical trust, and unrelated routes remain unchanged.

After the TUF commit, recovery proceeds only forward. All six clients restart
in deterministic resource-name order, fetch additive trust plus the exclusive
secondary route, and must agree on the new generation before success. New
artifacts must carry the secondary log ID, while a retained old artifact must
still verify in every language and the primary checkpoint/tile hashes must not
change except for legitimate entries accepted before cutover. Index zero is a
valid first secondary entry and is never skipped or rewritten.

The schema-1 hosting journal records candidate creation, secondary start and
container identity, gateway availability, TUF preparation/commit and
generation switch, each client convergence, first secondary entry, old/new
artifact proofs, checkpoint/data continuity, and final completion. Before the
TUF routing commit, failure leaves clients on the primary route. After commit,
replay validates every stored identity/hash and resumes forward. A second
independent rotation in the same AppHost run is explicitly rejected without
mutation; the same incomplete operation is idempotently resumed. The AppHost
reset boundary still discards the complete run-scoped trust and shard state.

The known Python omitted-index-zero bundle parser issue remains out of scope.
The operation does not seed an entry, hide artifact zero, or change bundle
serialization; when encountered, it is reported and selected old/new bundles
are proven through the existing generation-pinned targeted verifier.

## Certificate-Transparency Log Shard Rotation (Step 13)

`rotate-ct-log-shard` creates a second logical certificate-transparency log
instead of replacing the signer of the initial log:

```bash
aspire resource sigstore rotate-ct-log-shard
```

### Topology

The historical primary shard (`tesseract`) keeps its generation-1 CT signer,
log ID, origin `tesseract-sigstore.dev.localhost`, canonical URL
`http://tesseract-sigstore.dev.localhost:6962`, storage under
`.sigstore/data/ctlog`, and its signed checkpoint history. It is never
restarted or mutated by this command, before or after cutover.

The command creates a distinct ECDSA P-256 signer in immutable generation N+1
and stages only that private signer plus the complete accepted-Fulcio-root
bundle in `.sigstore/runtime/tesseract-secondary`. The secondary shard
(`tesseract-secondary`) sees only that mount and its own storage under
`.sigstore/data/ctlog-shards/secondary`, which carries its own state identity
and operation-bound `shard.json`. Its origin is
`tesseract-secondary-sigstore.dev.localhost` and its stable canonical URL is
`http://tesseract-secondary-sigstore.dev.localhost:6963`. The durable shard
catalog lives at `.sigstore/data/ctlog-shards/state.json` and is owned by the
Go TUF worker.

Fulcio's certificate-transparency binding is a durable runtime selection in the
stable read-only mount `.sigstore/runtime/fulcio-ct`. That directory holds
immutable, additive per-shard public keys (`primary.pub`, and `secondary.pub`
once a rotation stages it) beside exactly one `selection` manifest:

```text
sigstore-fulcio-ct-selection/1
secondary
tesseract-secondary-sigstore.dev.localhost
secondary.pub
```

Staging only adds `secondary.pub`; promotion replaces the single `selection`
file with one atomic rename inside the same mounted directory. Selector, origin
and key file name therefore always travel together, so a crash can never leave
a mixed configuration: before the flip Fulcio is wholly bound to the primary
shard and after it wholly to the secondary shard, and recovery is forward-only.
The Fulcio entrypoint strictly validates the manifest — versioned header,
recognized selector, and the origin and key file name that selector implies —
and refuses to start otherwise. The shard Fulcio uses only ever changes through
that explicit, journaled promotion followed by exactly one restart, which is
gated on the journaled Fulcio container identity rather than on any
disk-derived field.

Each shard entry in the catalog also records the identity of the complete
accepted Fulcio root bundle that shard enforces — the bundle SHA-256, the root
count, and the ordered per-root fingerprints. The secondary shard is created
accepting byte-for-byte exactly the roots the primary already accepts,
including every root added by prior Fulcio CA rotations.

After the cutover the historical primary shard's accepted-root bundle is
frozen: a later Fulcio CA rotation extends and restarts only the shard that is
currently accepting submissions (the secondary), and the primary keeps serving
its append-only tiles without being restarted or mutated. A Fulcio CA rotation
is refused before any mutation while a CT log shard rotation is in flight.

### Ordering

1. Generate the operation-bound candidate signer and stage the secondary
   shard's storage, runtime signer, accepted roots, and staged Fulcio
   selection.
2. Start the explicit secondary shard and prove it healthy, then prove its
   signed checkpoint verifies against its own log ID and origin. No trust is
   published and no route changes before this proof.
3. Run the dedicated TUF worker: generation N+1 replaces only the CT signer and
   preserves every Fulcio root, TSA certificate, Rekor shard signer and
   routing record, OIDC key, and TUF material byte-for-byte. `TrustedRoot`
   gains a second `ctlogs` `TransparencyLogInstance` additively while every
   existing entry is preserved. `SigningConfig` is republished byte-for-byte
   unchanged, and the TUF root role and bootstrap root are untouched.
4. Restart all six clients in deterministic resource-name order and require
   each to converge on the new generation.
5. Prove the still-running old Fulcio issues a certificate with a valid
   old-shard SCT under the new additive trust.
6. Promote the Fulcio certificate-transparency runtime selection.
7. Restart Fulcio exactly once.
8. Prove the same Fulcio CA identity now issues a certificate whose SCT comes
   from the secondary shard.
9. Verify the retained old-shard artifact and a new secondary-shard artifact in
   all six languages.

No other service is restarted: OIDC, the timestamp authority, both Rekor
writers, the Rekor gateway, the TUF nginx server, the artifact store, and the
historical primary Tesseract shard all keep their container identity, which is
checked before and after cutover.

### Recovery

The schema-1 hosting journal under
`.sigstore/ct-log-shard-rotation/<operationId>/hosting-state.json` records a
deterministic checkpoint for candidate generation, secondary preparation,
secondary start and container identity, checkpoint proof, TUF preparation,
commit and generation switch, every client convergence, the old-shard issuance
proof, the Fulcio promotion and its single restart, the new-shard issuance
proof, both artifact verifications, and completion.

Before the Fulcio promotion, a failure leaves the old route intact and
everything already published is additive, so the stack stays fully usable. From
the promotion onward recovery is forward-only: replay re-validates every stored
identity and hash and resumes from the last durable checkpoint. Ambiguous or
tampered state — multiple incomplete operations, a surviving request bound to
another candidate, a mismatched worker completion, a secondary shard that
reuses the primary's storage identity, a staged selection that is not the
candidate — is rejected without mutation. A repeated invocation after a
completed rotation is rejected without mutation, and a second independent
rotation in the same AppHost run is rejected by both the hosting command and
the TUF worker.

### Lifecycle policy

The historical primary shard's compute stays running and required for the
parent's aggregate health, and this is deliberate: unlike the Rekor gateway,
Tesseract serves its append-only tiles and signed checkpoint from its own
process, so certificates that were logged there are only auditable while it
keeps running. Stopping it degrades the Sigstore parent. The secondary shard is
a conditional resource that becomes required once it is activated.

### Limitations

The rotation is bounded to exactly one secondary shard per AppHost run.
`SigningConfig` deliberately does not change, because certificate transparency
has no `SigningConfig` selector; the shard Fulcio uses is a runtime binding.
Certificates issued before cutover keep their old-shard SCTs forever and are
verified against the preserved historical `ctlogs` entry. Bundle serialization
is unchanged. The AppHost reset boundary still discards the complete
run-scoped trust and shard state.

### Step 13 validation evidence

The non-isolated fixed-port validation on 2026-08-29 completed operation
`262eae98f56a4da58d599680d645e24b` with all 50 structured postconditions
passing. The historical shard retained log ID
`685da1abd82f1aa5b2c2321142fdf3e39a7cdd4257b9d44a2f7a0235d3eb5ef4`,
state ID `fd7e938d-d27b-4052-b1f5-d6fdab956ceb`, origin and URL, and container
`459da285160657b20086331e3ba58c88993aaaa98e0737d387a06830a7b3fcc9`.
Its tree reached 46 during the pre-cutover overlap and then stayed at 46 while
the secondary tree advanced from 159 to 169 during a 20-second observation.

The secondary shard used log ID
`4dc0999ce9c3b87c2b23506f7ec5bca870d0ac27724e674a66ab435d1f123959`,
state ID `c4137125-e592-40c7-a67c-f8d4e90da430`, and container
`011bd24e93e0917182c17cff91cabb4b8b47765220e314e94df30990ddeb1caa`.
Its empty-tree checkpoint was verified before TUF publication. TrustedRoot
grew from one to two CT entries, while SigningConfig remained
`122f209b630c472925dea330003470162392f8a42b76e1e27980321193c20a8c`
and the TUF root stayed at version 1. Fulcio changed exactly once from container
`1493a0dd8e72eb10a4de81d9b6719f1ba0878403f08f05f0ac759edad4ffbab2`
to `b14634630f8e3f4ddcb596cec82569bd1ac0b1b5f7d9664e9044433c2a0620dc`;
its CA fingerprint stayed
`71e6e18157a69703ec58dbb557d7c90f9c68a9639ec2ac4d532723d8a82ba57b`.
Old artifact 20 and new artifact 39 both verified in .NET, Go, Java,
JavaScript, Python, and Rust. The known Python omitted-index-zero issue was not
encountered in this run. A repeated rotation was rejected before mutation.

## Complete Lifecycle Validation (Step 14)

Run the lifecycle on a fresh, non-isolated AppHost. Fixed
`*.dev.localhost` ports mean only one validation AppHost may run at a time:

```bash
aspire start --non-interactive --format Json
./eng/validate-sigstore-lifecycle.sh
```

The harness waits for every concrete resource and then uses only the public
`sigstore` commands, including their operation gate, shared `state.lock`,
durable worker protocols, and normal child restarts. The supported order is:

1. `status`, then `refresh-tuf`
2. `rotate-tuf-root`, then `restart-clients`
3. `publish-trusted-root`
4. `rotate-oidc-signing-key`
5. `rotate-timestamp-authority`
6. `rotate-fulcio-ca`
7. `rotate-rekor-shard`
8. `rotate-ct-log-shard`

The root rotation intentionally leaves clients stale until
`restart-clients`; this is the only expected non-ready boundary in a
successful sequence. Every other successful operation must finish with all
six clients and all required resources ready. The full sequence advances
generation `1` to `7`, TUF root `1` to `2`, and targets/snapshot/timestamp
`1` to `8`/`9`/`9`. The harness checks every intermediate transition, starts
an overlapping `refresh-tuf` while trusted-root publication owns the command
gate, and requires a structured `contention` or `recovery-pending` rejection
with no partial mutation. It finally restarts `fulcio`,
`tesseract-secondary`, and `tuf` and proves the committed trust, routing, and
signer fingerprints are unchanged.

`status` is read-only and authoritative. `ready: false` is expected while an
operation is active, clients are stale, a signer or route activation is
pending, a required historical shard is unavailable, or recovery is
required. Mutating commands are disabled while another command owns the
in-process gate or shared OS lock. If a durable journal survives an AppHost
or child interruption, only the matching command remains enabled; invoking
it replays from its last validated checkpoint. Unrelated direct invocations
return `phase: "recovery-pending"`. Multiple, malformed, unbound, or tampered
journals fail closed as `lifecycle-recovery`; they are not guessed, deleted,
or bypassed.

Recovery rolls back only before activation, where the old signer/route is
still authoritative. Once additive trust or routing has committed, recovery
is forward-only: it validates the operation ID, trust domain, generation,
worker completion, resource identity, and stored proof before resuming
client convergence or activation. A missing or mismatched historical shard,
completion, runtime projection, or client identity requires operator
inspection; automatic recovery deliberately stops.

Successful validation writes a redacted, mode-`0600` report to
`.sigstore/lifecycle-evidence/lifecycle-<trust-domain>.json`. It contains
operation IDs, exact generation/TUF transitions, public component
fingerprints, resource lifecycle identities, preserved-history checks,
client convergence, artifact proof IDs/hashes, and errors. It never includes
JWTs, private keys, passwords, or worker tokens. The entire directory is
run-scoped and ignored by Git.

### Reset, backup, and retention

Stopping and starting a **new AppHost process** is the supported safe reset:
the AppHost deletes and recreates `.sigstore` and `.shady-blob-store`, yielding
a new trust domain, generation 1, TUF version 1 topology, and a fresh artifact
sequence. Stop the existing AppHost cleanly before starting the replacement;
never delete or edit either directory while the AppHost is running.

These directories are demonstration state, not a production backup format.
A filesystem copy is useful only for offline investigation of that run; this
AppHost intentionally discards it at the next process start and provides no
restore command. Child-resource restarts within the same AppHost preserve the
state.

Normal operations retain old Fulcio/TSA verification roots, OIDC overlap,
Rekor and CT shard catalogs, immutable generations, checkpoints, and
artifacts additively. Destructive trust retirement is intentionally not
implemented. Test retirement only on a disposable stopped run by constructing
an explicit scenario that first proves no retained artifact depends on the
material; do not infer safety from current traffic.

The cross-SDK ProtoJSON/sigstore-python omitted-index-zero incompatibility
remains visible and out of scope. Validation never seeds an entry, skips
artifact zero, rewrites a bundle, or uses public Sigstore. When it occurs,
the affected Python sequential worker reports it and the same retained bundle
is submitted only to the existing generation-pinned targeted Python verifier.
Its real success or parser failure is disclosed in the evidence.

### Unattended operation

Client retry loops tolerate clock jumps across suspend. In particular, the
Python producer catches only sigstore-python's `ExpiredCertificate` and
`ExpiredIdentity` signing-attempt failures, abandons that attempt, and obtains a
new identity token and signer on the next attempt. Signer-local certificate
caching remains enabled; bundle serialization is unchanged.

The regression was found after a 954-second host sleep crossed the Python
signer's ten-minute leaf lifetime, and again after the served timestamp expired
while the AppHost remained unattended. Deterministic tests inject both Python
expiry exceptions and prove the producer survives and succeeds on its next
attempt. Hosting tests advance a test clock through TUF expiry, prove automatic
transactional refresh and contention/recovery deferral, verify an exit-code-zero
one-shot is accepted, keep `refresh-tuf` available with an Exited client, and
restore aggregate Healthy status after refresh plus client restart.

### Complete-run evidence

The complete lifecycle passed on `2026-08-29` at implementation commit
`f3896f61ca902d71d0e127a165c87b338e577757`. The run advanced trust domain
`sha256-d532aeba3339c4c113fa53e8bf61b58bf30fd932402d0a5673f09a99efa3bd31`
from generation 1 to 7 with TUF versions `1/1/1/1` to `2/8/9/9`. All
operations completed without an unresolved journal; the deliberate
`refresh-tuf` overlap returned structured `recovery-pending`, and the owning
trusted-root publication completed without partial mutation.

The final generation retained two TSA roots, two Fulcio roots, three Rekor
entries, two CT entries, and immutable generations 1-7. Artifacts `11`, `46`,
`47`, `64`, `84`, `85`, `106`, `126`, and `148` each passed the targeted
verifier in all six languages with one artifact hash and one bundle hash per
ID. Initial artifact `1` passed .NET, Go, Java, JavaScript, and Rust; Python
returned the documented missing index-zero ProtoJSON fields without any
rewrite or fallback. The composed store continued through artifact `173`.

After `fulcio`, `tesseract-secondary`, and `tuf` were restarted, status
remained Healthy with all six clients on generation 7. A subsequent AppHost
created trust domain
`sha256-26be5e8fd5c0bb4b7d46a44a751792ac051c03368f5712e6fd2f29c2be0c8de4`,
generation 1, initial TUF versions, one generation directory, and no artifact
`173`; fresh artifact `9` then passed all six targeted verifiers. The
mode-`0600` composed report SHA-256 is
`d5710f7f8e85429cc3c808e4698c341922ac96c832c2fd3b54009e38b84e6874`.
