# Sigstore OpenTelemetry with Aspire

This repository runs two Sigstore telemetry probes and sends their
OpenTelemetry data to the local Aspire dashboard. Aspire is the local
orchestrator: it builds and starts the containers, configures their OTLP
exporters, and provides the UI for viewing resources, logs, traces, and metrics.

You do not need .NET or Go installed locally. Both toolchains run inside
containers.

## What gets launched

- `sigstore-telemetry` runs a file-based .NET 10 application using `Sigstore`
  `1.1.0-alpha.131.1.fd8696f`. Every 15 seconds it intentionally rejects an
  invalid bundle, producing `sigstore.verify` and TUF telemetry.
- `cosign` builds and runs the experimental Go tracing implementation from
  [cosign PR #4948](https://github.com/sigstore/cosign/pull/4948), linked to
  [cosign issue #4101](https://github.com/sigstore/cosign/issues/4101). Every
  15 seconds it signs an ephemeral local blob and emits a `sign-blob` trace.

Both probes are safe to run locally. The cosign key and bundle are temporary,
and no transparency-log entry is uploaded.

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

The first launch also needs internet access to download container images and
packages and to build the experimental cosign branch. That initial build can
take several minutes.

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

The first run builds the experimental cosign image and restores the .NET
file-based application. Wait until both `sigstore-telemetry` and `cosign` show
as **Running** and **Healthy** on the dashboard's **Resources** page.

## View the telemetry

Open **Traces** in the Aspire dashboard:

- Filter to `sigstore-telemetry` to see `sigstore.verify`,
  `sigstore.trust_root.get`, and TUF spans.
- Filter to `cosign` to see `sign-blob` and instrumented TUF HTTP spans.

The .NET probe stores its TUF cache in the container's writable filesystem,
without an Aspire-managed volume. A newly created container starts with an
empty cache and emits `tuf.target.get` with `tuf.target.cache_hit=false`.
Later probes in the same container emit `tuf.target.cache_hit=true`. Restarting
the resource recreates the container, so this miss-then-hit sequence starts
again.

## Stop

Press <kbd>Ctrl</kbd>+<kbd>C</kbd> in the terminal running `aspire run`, or run
this from another terminal in the repository:

```bash
aspire stop
```

If startup fails, first confirm Docker is running, then use `aspire doctor` to
check the local Aspire environment.
