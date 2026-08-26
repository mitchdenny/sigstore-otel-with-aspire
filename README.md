# Sigstore OpenTelemetry with Aspire

This repository runs six Sigstore telemetry probes and sends their
OpenTelemetry data to the local Aspire dashboard. Aspire is the local
orchestrator: it builds and starts the containers, configures their OTLP
exporters, and provides the UI for viewing resources, logs, traces, and metrics.

You do not need .NET, Go, Python, Node.js, Java, or Rust installed locally. All
six toolchains run inside containers.

## What gets launched

- `dotnet-test` runs a file-based .NET 10 application using `Sigstore`
  `1.1.0-alpha.131.1.fd8696f`. Every 15 seconds it intentionally rejects an
  invalid bundle, producing `sigstore.verify` and TUF telemetry.
- `cosign-test` builds the experimental Go tracing implementation from
  [cosign PR #4948](https://github.com/sigstore/cosign/pull/4948), plus a pinned
  [span-correlation proof](https://github.com/mitchdenny/cosign/commit/fc12d520fe12020fa6eaf7b83c390b364a1e1ba0)
  linked to [cosign issue #4101](https://github.com/sigstore/cosign/issues/4101).
  Every 15 seconds it signs an ephemeral local blob and emits one enclosing
  `sign-blob` trace.
- `python-test` runs Python 3.12 with `model-signing[otel]` `1.1.1`, whose
  OpenTelemetry support was added by
  [model-transparency PR #503](https://github.com/sigstore/model-transparency/pull/503).
  Every 15 seconds it verifies a pinned upstream Sigstore test fixture and emits
  a `Verify` trace plus auto-instrumented HTTP spans.
- `javascript-test` runs Node.js 24 with `sigstore-js` `5.0.0`. It initializes
  a verifier once using a pinned upstream bundle, emitting
  `sigstore.verifier.initialize` with auto-instrumented TUF HTTP spans. Every
  15 seconds it reuses that verifier and emits a `sigstore.verify` trace.
- `java-test` runs Java 21 with `sigstore-java` `2.2.0` and the OpenTelemetry
  Java agent `2.31.1`. It emits one `sigstore.verifier.initialize` trace with
  auto-instrumented TUF HTTP spans, then reuses the verifier for a
  `sigstore.verify` trace every 15 seconds.
- `rust-test` runs the modular `sigstore-rust` `0.11.0` client. A local wrapper
  instruments its public TUF repository boundary, producing one
  `sigstore.verifier.initialize` trace with HTTP child spans. It then reuses the
  trusted root for a `sigstore.verify` trace every 15 seconds.

All probes are safe to run locally. The cosign key and bundle are temporary,
and no transparency-log entry is uploaded. The Python probe only downloads
public trust metadata and verifies an existing upstream fixture. The JavaScript
Java, and Rust probes likewise perform verification only.

## Prerequisites

Install these before starting:

1. [Docker Desktop](https://www.docker.com/products/docker-desktop/) or another
   Docker-compatible container runtime with BuildKit, with the daemon running.
2. [Node.js](https://nodejs.org/) 20.19+, 22.13+, or 24+, with npm.
3. The [Aspire CLI](https://aspire.dev/get-started/install-cli/). The
   cross-platform npm installation is:

   ```bash
   npm install -g @microsoft/aspire-cli
   ```

   Confirm that it is available:

   ```bash
   aspire --version
   ```

The first launch also needs internet access to download container images,
packages, the pinned Python and JavaScript verification fixtures, and the
experimental cosign branch. The Java probe also downloads a pinned fixture and
the OpenTelemetry Java agent. The Rust probe compiles AWS-LC and its pinned
client dependencies from source. That initial build can take several minutes.

## Launch

Clone the repository, install the AppHost dependencies, and run Aspire:

```bash
git clone https://github.com/mitchdenny/sigstore-otel-with-aspire.git
cd sigstore-otel-with-aspire
npm ci
aspire run
```

Keep that terminal open. Aspire prints the dashboard URL after startup and
normally opens it in your browser. If it does not open automatically, use the
printed URL; the configured HTTP dashboard is also available at
<http://localhost:15096>.

The first run builds the experimental cosign, Python, JavaScript, Java, and Rust
images and restores the .NET file-based application. Wait until `dotnet-test`,
`cosign-test`, `python-test`, `javascript-test`, `java-test`, and `rust-test`
show as **Running** and **Healthy** on the dashboard's **Resources** page.

## View the telemetry

Open **Traces** in the Aspire dashboard:

- Filter to `dotnet-test` to see `sigstore.verify`,
  `sigstore.trust_root.get`, and TUF spans.
- Filter to `cosign-test` to see `sign-blob` and instrumented TUF HTTP spans.
- Filter to `python-test` to see `Verify` and auto-instrumented urllib3 HTTP
  spans.
- Filter to `javascript-test` to see `sigstore.verifier.initialize` with TUF
  HTTP spans and the repeated `sigstore.verify` traces.
- Filter to `java-test` to see `sigstore.verifier.initialize` with
  Java-agent-instrumented TUF HTTP spans and the repeated `sigstore.verify`
  traces.
- Filter to `rust-test` to see `sigstore.verifier.initialize` with explicitly
  instrumented TUF HTTP spans and the repeated `sigstore.verify` traces.

The .NET probe stores its TUF cache in the container's writable filesystem,
without an Aspire-managed volume. A newly created container starts with an
empty cache and emits `tuf.target.get` with `tuf.target.cache_hit=false`.
The provider then reuses that trusted root for its normal 24-hour refresh
interval, so later probes in the same container do not contact the TUF
repository. Restarting the resource recreates the container and starts this
sequence again.

The JavaScript, Java, and Rust probes also use only container-local cache state.
Each initializes its verifier once per container, so TUF network activity
appears once while repeated verification traces reuse the trusted root.

## Stop

Press <kbd>Ctrl</kbd>+<kbd>C</kbd> in the terminal running `aspire run`, or run
this from another terminal in the repository:

```bash
aspire stop
```

If startup fails, first confirm Docker is running, then use `aspire doctor` to
check the local Aspire environment.
