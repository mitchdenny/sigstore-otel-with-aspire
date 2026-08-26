# Sigstore Aspire Hosting Integration

## Goal

Create a reusable Aspire hosting integration that can add a complete, local
Sigstore trust domain to an AppHost:

```csharp
var sigstore = builder.AddSigstore("sigstore");
```

The resource is a non-compute parent that owns the state paths, endpoints,
component resources, lifecycle state, and dashboard commands for the local
Sigstore deployment. Client resources can consume it through a shared wiring
helper rather than duplicating endpoint, bind-mount, and dependency setup.

The finished integration must:

- Bootstrap itself from an empty state directory.
- Preserve and validate an existing trust domain across restarts.
- Run Fulcio, Rekor v2, Tesseract, the timestamp authority, local OIDC, and TUF.
- Expose the trust-domain services through typed endpoint references.
- Support safe TUF metadata refresh and root rotation.
- Support additive Sigstore trusted-root updates.
- Orchestrate only the child restarts required by a rotation.
- Make client trust uptake observable across all six language demos.
- Recover safely from interrupted or failed rotation operations.

## Delivery workflow

Each numbered step below is implemented in its own child session and branch.
Only one child session runs at a time. Every child must:

1. Implement only its assigned step.
2. Run the step's automated and live validation.
3. Commit its changes.
4. Report the branch, commit, validation evidence, and remaining risks.
5. Stop and wait for manual validation before the next child session is created.

Each subsequent session branches from the previously approved session branch.
This keeps the work as a reviewable, dependent stack and prevents later changes
from masking regressions in an earlier step.

## Current constraints

- The AppHost is a root-level file-based C# application in `apphost.cs`.
- Aspire is pinned to 13.5.2.
- The trust domain uses fixed canonical `.dev.localhost` ports. Validation runs
  must therefore be serialized; isolated Aspire ports do not represent the
  configured trust domain.
- `.sigstore/` contains private keys, public trust, append-only log data, and
  the TUF repository.
- `.shady-blob-store/` contains artifacts signed under the trust domain.
- Existing `.sigstore/` state must be migrated, not silently regenerated.
- Existing artifact history requires historical verification keys to remain
  trusted during normal additive rotations.
- Dashboard command callbacks should orchestrate operations. Cryptographic and
  filesystem mutations belong in separately testable libraries or one-shot
  worker resources.
- The AppHost must use public Aspire resource-command and notification APIs,
  not internal DCP APIs or direct Docker CLI calls.

## Target resource model

`SigstoreResource : Resource` is the non-compute parent. It exposes:

- The resolved host state path.
- The trust-domain identifier and active generation.
- Typed references to OIDC, Fulcio, Tesseract, Rekor, TSA, and TUF endpoints.
- Typed references to child services and one-shot operation workers.
- Current TUF root, snapshot, timestamp, and targets versions.
- Current trusted-root and signing-configuration fingerprints.
- Aggregate health and operation state.

`AddSigstore(...)` creates the parent, bootstrap resources, services, stable
mounts, health checks, endpoint references, dependencies, and commands.

`WithSigstoreReference(...)` configures a client with:

- Endpoint references.
- The immutable TUF bootstrap root.
- A writable client-specific TUF cache.
- Required canonical hostname mappings.
- Resource dependencies.
- Optional trust refresh behavior.

## Validation principles

Every implementation step uses the same validation ladder:

1. **Model validation** - inspect the Aspire resource graph, endpoints,
   parent-child relationships, dependencies, and environment references.
2. **Unit validation** - exercise state transitions and file publication in
   temporary directories without mutating the developer's trust domain.
3. **Live resource validation** - start the AppHost and wait for declared
   resources through Aspire before interacting with them.
4. **Protocol validation** - verify the served TUF metadata, Sigstore trust
   material, and operation results.
5. **Traffic validation** - ensure the artifact head advances and all six
   clients continue to produce and validate artifacts.
6. **Telemetry validation** - inspect trust initialization, production,
   validation, skip, refresh, and rotation spans.
7. **Persistence validation** - stop and restart the AppHost and confirm that
   state versions and fingerprints are preserved.
8. **Failure validation** - prove an interrupted operation either rolls back to
   the previous committed state or resumes deterministically.

Live validation uses:

```bash
aspire describe --format Json
aspire wait <resource>
aspire resource sigstore <command>
aspire otel traces <resource>
aspire otel logs <resource>
aspire export
```

After AppHost model changes:

```bash
aspire stop
aspire start --non-interactive --format Json
```

Resource readiness must use `aspire wait`; HTTP polling is not a substitute.

## Step 0: Establish the regression baseline

### Scope

- Capture the current resource graph and endpoint assignments.
- Record the current bootstrap and TUF manifest fingerprints.
- Record the sealed artifact high watermark.
- Confirm every long-running resource is healthy.
- Confirm every client produces and validates artifacts.
- Capture a telemetry export for comparison during later steps.
- Record the evidence in the baseline section of this document.

### Validation gate

- OIDC, Tesseract, Fulcio, timestamp, Rekor server, Rekor nginx, TUF nginx,
  shady blob store, and all six clients are running and healthy.
- Bootstrap and TUF one-shot resources completed successfully.
- The artifact high watermark advances during the observation window.
- Each language emits successful `artifact.produce` and `artifact.validate`
  spans.
- Existing trust and artifact state survive an AppHost restart.

### Baseline evidence

Captured at `2026-08-26T09:58:36Z` with the file-based AppHost pinned to
Aspire `13.5.2`.

- `aspire wait` confirmed all 14 long-running resources healthy on both
  launches: OIDC, Tesseract, Fulcio, timestamp, Rekor server, Rekor nginx,
  TUF nginx, shady blob store, and the six clients. `sigstore-bootstrap`,
  `sigstore-state-ready`, `tuf-bootstrap`, and `tuf-state-ready` each
  completed with exit code `0`.
- Fixed external endpoints remained OIDC `:7443`, Tesseract `:6962`, Fulcio
  HTTP/gRPC `:5555`/`:5554`, timestamp `:3004`, Rekor `:3000`, and TUF
  `:8080`. Aspire-assigned client, OIDC-internal, Rekor-server, and artifact
  store ports changed across the restart as expected; the final assignments
  were .NET `64918`, Go `64921`, Python `64915`, JavaScript `64920`, Java
  `64913`, Rust `64912`, OIDC internal `64911`, Rekor server HTTP/gRPC
  `64922`/`64919`, and shady blob store `64917`.
- Bootstrap manifest: schema `4`, created
  `2026-08-26T09:53:45.742288+00:00`, CT state
  `9258495e-a2bf-4c7a-8eea-fdf4f10418f9`, Rekor state
  `9529346a-6f4f-4698-96cf-b421ebb7ea0f`, OIDC key ID
  `BY5rH2SVqPacTnJqMsdSu1wRMgByxL5cQNjoHiBpBM4`.
- Public SHA-256 fingerprints: Fulcio root
  `5f51795e45052429865b002870f417ccd2527f721cc3ed8db77d3c10412307db`,
  CT log key
  `8c486ad3f35d0de773347b4e0beb530d750afd713e70c3f63959e002556a1180`,
  Rekor key
  `25b3bb4612b1b777eba57e05958e2a8392f9e6b9abe91958bcc8d947716b0c43`,
  TSA root
  `ec0a336a772f64975c5d607b8884fc94282460fc3e9ddb41ec9576e55327f2b9`,
  and TSA leaf
  `d8037cf6eeff363413a401160ff82bca8b0050904807f0022ad7a9b9a3dede43`.
- TUF manifest: schema `3`, source fingerprint
  `d2b1e54514653a308bfe1a237fa8dac13b8fd0e8032842db605e1c7b73cef867`.
  Target hashes were TrustedRoot
  `f83f2754502d6024dd518e8cd7be8f0920e6843686d49662cc89cf2113486f2a`,
  SigningConfig
  `7b9177fd18d33bf247e6b9209d66307327aa1e08b020ace4eb26f03906c3adbe`,
  and ClientTrustConfig
  `0bfcdb2efe549b3fea7b3b967532ba89eb4266e2c53d1085509f93da39233666`.
  Root/targets versions remained `1`/`1`; the normal restart refresh advanced
  snapshot/timestamp from `1`/`1` to `2`/`2`.
- The sealed artifact head advanced `54 -> 78`. The clean stop left sealed
  head `85` on disk; after restart the served head was already `103` and then
  advanced to `110`, proving the persisted stream resumed.
- Successful `artifact.produce` traces were observed for .NET, Go, Python,
  JavaScript, Java, and Rust. Successful `artifact.validate` traces were
  observed for every client except Python. The local-only telemetry export
  `step0-initial-telemetry.zip` was captured with SHA-256
  `d996039f0352299fa62134f72189826b6d8955aad99edc916e5486e965797540`
  and was not committed.
- Restart persistence passed: bootstrap identifiers and every public
  fingerprint above were unchanged, all resources returned to their expected
  state, and artifact production and validation resumed for the same five
  validating clients.

**Validation gate status: failed.** Go produced artifact `1` at Rekor log
index `0`. Its JSON bundle omits zero/empty `logIndex`,
`inclusionProof.logIndex`, and `inclusionProof.hashes` fields, and
sigstore-python `4.5.0` rejects the bundle during Pydantic parsing. The Python
validator remains stuck retrying artifact `1`, emits error
`artifact.validate` spans, and reports no successful validation spans even
though its resource health check stays healthy. No workaround or application
change was made in Step 0.

## Step 1: Extract `AddSigstore`

### Scope

- Add `src/Sigstore.Aspire.Hosting`.
- Reference it from the file-based AppHost.
- Add `SigstoreResource`, `SigstoreOptions`, and `SigstoreComponents`.
- Move the existing Sigstore infrastructure declarations into
  `AddSigstore(...)` without changing names, images, ports, paths, or behavior.
- Add parent relationships for the infrastructure resources.
- Keep client declarations unchanged.

### Validation gate

- The resource graph differs only by the new non-compute parent and grouping.
- Existing resource names, endpoints, waits, health checks, and persistent
  fingerprints are unchanged.
- The complete Step 0 traffic and telemetry baseline still passes.

## Step 2: Centralize client wiring

### Scope

- Add `WithSigstoreReference(...)`.
- Centralize endpoint references, trust mounts, hostname mappings, waits, and
  common environment variables.
- Preserve language-specific environment and telemetry configuration.
- Replace duplicated wiring in `apphost.cs`.

### Validation gate

- `aspire describe` shows equivalent resolved references for every client.
- All clients initialize trust from local TUF.
- Every language signs, seals, and validates artifacts from every producer.
- No client falls back to public Sigstore infrastructure.

## Step 3: Stabilize the TUF filesystem and bind mounts

### Scope

- Stop replacing the bind-mounted `.sigstore/tuf` directory itself.
- Introduce a stable TUF parent containing committed, staged, historical, and
  immutable bootstrap-root state.
- Preserve the initial bootstrap root so existing clients must follow versioned
  root metadata during later rotations.
- Mount the stable parent into nginx and clients instead of mounting replaceable
  child directories or individual files.
- Add deterministic recovery for interrupted publication.

### Validation gate

- Refresh metadata while the TUF nginx container remains running.
- The served timestamp and snapshot versions change without recreating nginx.
- The initial bootstrap root remains byte-for-byte unchanged.
- Injected publication failure leaves the prior repository served.
- Restarting the AppHost preserves the committed repository and history.

## Step 4: Introduce generation-aware trust state

### Scope

- Separate immutable trust-domain identity from active key generations.
- Add a rotation journal with staged, committed, failed, and recovered states.
- Replace single-generation manifest assumptions.
- Migrate existing schema 4 state without regenerating keys or log identities.
- Use one shared state lock for bootstrap and rotation operations.

### Validation gate

- Migration tests run against copies of existing state.
- All pre-migration fingerprints and log state identifiers remain unchanged.
- Migration and startup are idempotent.
- Unexpected file changes still fail validation.
- Interrupted staged and committed transitions recover deterministically.

## Step 5: Add trust status and client observability

### Scope

- Add a read-only parent `status` command.
- Add trust attributes to every `sigstore.trust.initialize` span.
- Expose a machine-readable client trust status surface.
- Report TUF root and targets versions, trusted-root hash,
  signing-configuration hash, generation, and initialization time.
- Aggregate child health into the parent resource state.

### Validation gate

- All six clients report the expected trust generation and fingerprints.
- The parent status agrees with committed disk state and served TUF metadata.
- Stopping a child degrades the parent state.
- Restarting the child returns the parent to healthy.
- No mutating command is added in this step.

## Step 6: Add the first dashboard operations

### Scope

- Add Aspire commands for `refresh-tuf` and `restart-clients`.
- Add confirmation, progress, state updates, and structured results.
- Use one-shot workers for mutations.
- Use `ResourceCommandService` for worker and client lifecycle.
- Serialize operations through the trust-state lock.
- Verify postconditions before reporting command success.

### Validation gate

- Both commands work from the dashboard and Aspire CLI.
- Refresh reports before and after metadata versions and hashes.
- TUF nginx is not restarted during refresh.
- Client restart waits for every client to become healthy.
- Concurrent commands are rejected clearly.
- Worker failure produces a failed command and preserves committed state.

## Step 7: Implement TUF root rotation

### Scope

- Add `rotate-tuf-root`.
- Generate root version `N+1`.
- Satisfy the old and new root signature thresholds.
- Preserve all versioned roots and the immutable bootstrap anchor.
- Publish snapshot and timestamp metadata transactionally.

### Validation gate

- Cryptographic tests validate signatures and thresholds.
- A persistent client anchored at root `N` updates through `N+1`.
- A fresh client can bootstrap and update through the full root chain.
- Rollback, freeze, skipped-version, and tampered-root cases are rejected.
- Restarting a client with the latest root is not accepted as proof of rotation.

## Step 8: Implement additive trusted-root rollout

### Scope

- Add `publish-trusted-root`.
- Publish trusted-root and signing-configuration updates through TUF.
- Refresh clients in process where supported; use explicit restart uptake where
  a library cannot safely refresh.
- Wait until every client reports the new target version and fingerprint.
- Retain historical verification material by default.

### Validation gate

- Artifacts created before publication still validate.
- Artifacts created after publication validate in every language.
- Every client reports the new trusted-root fingerprint.
- A client that has not refreshed is detectable and prevents command success.
- Removal of historical verification keys is not part of this command.

## Step 9: Implement OIDC signing-key rotation

### Scope

- Publish overlapping JWKS.
- Restart the local issuer with the new active signing key.
- Allow Fulcio to discover the new key identifier.
- Retain the prior key for the token overlap interval.

### Validation gate

- Tokens from the overlap period are accepted.
- New tokens use the new key.
- Fulcio does not require restart.
- Signing and validation traffic resumes without trust regression.

## Step 10: Implement timestamp-authority rotation

### Scope

- Generate a new TSA chain and signer.
- Publish both old and new TSA trust before switching.
- Refresh clients, restart only the timestamp authority, and activate the new
  signer.

### Validation gate

- Existing timestamped artifacts still validate.
- New artifacts use the new TSA certificate.
- All clients verify artifacts from both generations.
- Failure before activation leaves the old signer active.

## Step 11: Implement Fulcio CA rotation

### Scope

- Generate a new Fulcio CA generation.
- Publish old and new CA trust additively.
- Configure Tesseract to accept both roots and restart it first.
- Restart Fulcio with the new active CA.

### Validation gate

- Tesseract accepts certificates from the new CA.
- Fulcio issues from the new CA after activation.
- Existing artifacts rooted in the old CA still validate.
- New artifacts validate in all six clients.
- Restart order and rollback behavior are explicit and tested.

## Step 12: Implement Rekor shard rotation

### Scope

- Treat a Rekor signing-key change as a new logical log shard.
- Preserve the old append-only log and public key.
- Add the new shard to trusted root and signing configuration.
- Route new entries to the new shard.

### Validation gate

- The old log remains readable and verifiable.
- New entries use the new log identifier.
- Trusted root contains both log instances.
- All clients validate bundles from both shards.

## Step 13: Implement CT log shard rotation

### Scope

- Treat a CT signing-key change as a new Tesseract log shard.
- Preserve the old log and public key.
- Publish the new CT log trust before directing Fulcio to it.
- Restart only the affected CT and Fulcio resources.

### Validation gate

- Old SCTs remain verifiable.
- New certificates contain SCTs from the new log.
- Trusted root contains both CT log identities.
- All clients validate artifacts across the shard boundary.

## Step 14: Harden the complete lifecycle

### Scope

- Exercise concurrent command rejection and idempotency.
- Add fault-injection coverage around stage, publish, restart, and verify.
- Confirm recovery after AppHost termination during each operation phase.
- Document reset, backup, recovery, and intentionally destructive trust-retirement
  scenarios.
- Run the complete sequence against an existing populated artifact store.

### Validation gate

- Every operation has deterministic success, failure, and recovery behavior.
- No successful command leaves clients or services on an unreported generation.
- The artifact stream resumes after every supported rotation.
- Historical artifacts remain verifiable under normal additive policy.
- The complete AppHost survives stop/start with the final committed state.

## Rotation safety rules

- Publish trust before activating a new signer.
- Confirm client uptake before relying exclusively on new trust.
- Keep old verification material while historical artifacts remain in the store.
- Do not rotate Rekor or CT keys in place; create new log shards.
- Do not replace a bind-mounted directory or individual mounted file.
- Do not report success until served content and child health match committed
  state.
- Do not silently regenerate missing or inconsistent state.
- Do not permit two bootstrap or rotation operations to mutate state
  concurrently.

## Completion criteria

The integration is complete when:

- `apphost.cs` consumes a reusable `AddSigstore(...)` resource.
- Client resources use shared Sigstore wiring.
- TUF metadata and root rotations work without recreating the TUF server.
- Every client exposes the trust generation it is using.
- Dashboard commands safely orchestrate refresh and rotation workflows.
- OIDC, TSA, Fulcio, Rekor, and CT rotations preserve the expected history.
- Failed and interrupted operations recover without ambiguous state.
- The continuous cross-language artifact stream validates the entire lifecycle.
