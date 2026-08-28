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
- `fulcio` exchanges a valid test OIDC token for a short-lived code-signing
  certificate, submits the certificate to Tesseract, and embeds the returned
  SCT. Its HTTP API is available at
  `http://fulcio-sigstore.dev.localhost:5555`.
- `timestamp` issues RFC 3161 signed timestamps using a run-scoped local file
  signer at `http://timestamp-sigstore.dev.localhost:3004`.
- `rekor-server` sequences artifact-signature entries into a run-scoped Rekor
  v2 tile log under `.sigstore/data/rekor`.
- `rekor` is the single Rekor v2 gateway for entry uploads and static tile
  reads at `http://rekor-sigstore.dev.localhost:3000`.
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
|-- runtime/
|   |-- fulcio/                         # active CA + CT public key only
|   `-- tesseract/                      # CT private key + accepted roots only
|-- migration/
|   `-- bootstrap-manifest.schema-4.json  # migrated state only
|-- data/
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
by Fulcio's read-only API, the unchanged CT key/log ID, and a signed CT
checkpoint. The parent is not Healthy while disk, served TUF, clients,
Tesseract roots, or the live Fulcio issuer disagree.

The parent state is event-driven and aggregates all 14 long-running resources:
the seven Sigstore services, `shady-blob-store`, and six clients. It shows
**Healthy** only when all 14 are running and healthy, **Starting** while initial
readiness is pending, and **Degraded** with the first definitive reason when a
required resource stops or becomes unhealthy. Starting a stopped child restores
the parent to **Healthy** without changing trust state.

## Dashboard operations

The parent also exposes seven confirmed, progress-reporting operations in the
dashboard and through the Aspire CLI:

```bash
aspire resource sigstore refresh-tuf | jq
aspire resource sigstore restart-clients | jq
aspire resource sigstore rotate-tuf-root | jq
aspire resource sigstore publish-trusted-root | jq
aspire resource sigstore rotate-oidc-signing-key | jq
aspire resource sigstore rotate-timestamp-authority | jq
aspire resource sigstore rotate-fulcio-ca | jq
```

`refresh-tuf` starts a new instance of the existing `tuf-bootstrap` one-shot
through Aspire's `ResourceCommandService`. It refreshes only signed snapshot and
timestamp metadata, waits for the worker to exit successfully, and validates the
publication journal, active manifest, one-entry history, served bytes, all client
status contracts, and the unchanged TUF nginx container before succeeding. Its
JSON result includes exact before/after versions and SHA-256 values for root,
targets, snapshot, and timestamp metadata, plus publication and manifest IDs.
Root, targets, TUF keys, public trust targets, the active trust generation, and
the immutable bootstrap root must remain unchanged.

`restart-clients` uses `ResourceCommandService` to restart the six client
containers in deterministic resource-name order. It waits for every replacement
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
