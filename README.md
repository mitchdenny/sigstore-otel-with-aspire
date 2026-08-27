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
trust material needed by the isolated Sigstore services. It writes them to the
gitignored `.sigstore` directory in the repository root. Every new AppHost
process deletes and recreates both `.sigstore` and `.shady-blob-store` before
bootstrap, so each `aspire run` or `aspire start` begins with a new trust domain,
empty transparency logs, and artifact numbering starting at 1.

The AppHost process is the reset boundary. Restarting an individual service or
client resource within the same run retains that run's trust and artifact
state. Stopping the AppHost and starting it again intentionally discards that
state. A `SIGSTORE_STATE_PATH` override is accepted only when its resolved path
is a safe descendant of the AppHost directory.

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

## Stop

Press <kbd>Ctrl</kbd>+<kbd>C</kbd> in the terminal running `aspire run`, or run
this from another terminal in the repository:

```bash
aspire stop
```

If startup fails, first confirm Docker is running, then use `aspire doctor` to
check the local Aspire environment.
