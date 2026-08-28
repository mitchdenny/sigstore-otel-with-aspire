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

- Reset and bootstrap a new trust domain at every AppHost process start.
- Preserve and validate the active trust domain across child resource restarts
  within one AppHost run.
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
  the TUF repository for the current AppHost run.
- `.shady-blob-store/` contains artifacts signed under the trust domain.
- AppHost process startup is the intentional destructive reset boundary. It
  recreates both state directories before bootstrap; child resource restarts
  must not reset them.
- The Sigstore state root is always the AppHost-relative `.sigstore/`
  directory and is not configurable.
- Within one run, committed trust state must be validated rather than silently
  regenerated, and artifact history requires historical verification keys to
  remain trusted during normal additive rotations.
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

The Sigstore-specific `WithReference(...)` overload configures a client with:

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
7. **Run-boundary validation** - stop and restart the AppHost and confirm that
   trust identifiers change and artifact numbering restarts at 1.
8. **In-run durability validation** - restart affected child resources and
   confirm that committed state and fingerprints are preserved.
9. **Failure validation** - prove an interrupted operation either rolls back to
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
- Existing trust and artifact state survive child resource restarts within the
  active AppHost run.

### Baseline evidence

This evidence predates Step 0a and records the former cross-AppHost persistence
behavior. Step 0a intentionally supersedes that behavior.

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

## Step 0a: Make runtime state run-scoped

### Run-scoped state invariant

AppHost process startup is the only automatic reset boundary. Before adding any
resources, it deletes and recreates the resolved Sigstore state directory and
the root `.shady-blob-store` directory, then bootstraps a new trust domain.
Restarting a child service, client, or one-shot worker within that AppHost
process retains the run's state. Starting a new AppHost intentionally creates
new trust/log identities and restarts artifact numbering at 1.

### Scope

- Reset both gitignored state directories once per AppHost process.
- Keep both reset roots as non-root descendants of the AppHost directory.
- Reject overlapping state roots, non-directory entries, and symbolic links
  or reparse points.
- Keep child resource restart behavior unchanged.
- Replace cross-AppHost persistence expectations throughout this plan with
  in-run child-restart durability.

### Validation gate

- Neither state directory contains tracked files and both remain ignored.
- Each of two serialized canonical-port AppHost launches creates different
  bootstrap, CT log, Rekor log, and public trust identities.
- Each launch starts with an empty artifact store and creates artifact 1.
- All one-shot resources complete successfully and long-running resources
  become healthy.
- The known sigstore-python 4.x rejection of a Go index-zero bundle may recur;
  it is recorded but is not a failure of the reset boundary.

### Validation evidence

Captured on `2026-08-27` with two serialized, non-isolated AppHost launches.

- Git tracked no files below either state root, and `.gitignore` matched both
  anchored directories.
- Before the first launch, the prior state had artifact head `5287`, CT state
  `9258495e-a2bf-4c7a-8eea-fdf4f10418f9`, Rekor state
  `9529346a-6f4f-4698-96cf-b421ebb7ea0f`, Rekor key fingerprint
  `25b3bb4612b1b777eba57e05958e2a8392f9e6b9abe91958bcc8d947716b0c43`,
  and TUF source fingerprint
  `d2b1e54514653a308bfe1a237fa8dac13b8fd0e8032842db605e1c7b73cef867`.
- The first launch recreated artifact `1` and changed those values to CT
  `d546ebcf-dc5d-4a6e-96da-718709e1dbbd`, Rekor
  `4e6f1449-285a-45f2-9b02-4bfa22af94fc`, Rekor key
  `05ee3d9b0c491f11dd65a1018d602b814fc9330216750fc1a279ba28b4a44c7f`,
  and TUF source
  `179de21e1936db8a291fc22d1084af6ac8650587a63252a55a694639636a57e3`.
  Its artifact head was `18` at capture and `30` at clean stop.
- Restarting only the OIDC child preserved the bootstrap manifest and artifact
  `1` byte-for-byte while the artifact count advanced from `24` to `27`.
- The second AppHost launch again recreated artifact `1` and changed the
  identities to CT `5366b254-aa63-41b6-9784-a9a8902e62ee`, Rekor
  `705257e8-c8ca-4b7d-8ff4-9d1d0d120aa6`, Rekor key
  `ee1e3ef1169f59d678a8b82b03fc85fd383b5d99d2b00bee88fdd89e1172efa4`,
  and TUF source
  `55c2a2919b196345bf4c546fff1787abf304cdca251868f5a8ee9287cf9e4d7a`.
- All nine recorded bootstrap/TUF identity fields changed from the prior state
  to the first run and again from the first run to the second. Both launches
  reached 14 healthy long-running resources, and all four bootstrap/readiness
  resources exited with code `0`.
- Before Step 1 fixed the state root to AppHost-relative `.sigstore/`, an
  outside `SIGSTORE_STATE_PATH` override failed before deletion and left the
  prior manifest and artifact `1` unchanged.
- Python produced and validated artifact `1` on both launches. In the final
  run, Rust produced Rekor index-zero artifact `2` with explicit zero fields,
  and Python validated it. The known Go-index-zero/sigstore-python 4.x parser
  failure therefore did not reproduce; no interoperability change was made.

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
- Existing resource names, endpoints, waits, health checks, and run-scoped
  lifecycle behavior are unchanged.
- The complete Step 0 traffic and telemetry baseline, plus the Step 0a reset
  boundary, still passes.

### Implementation evidence

Completed on `2026-08-27` with the file-based AppHost and Aspire SDK `13.5.2`.

- Added `src/Sigstore.Aspire.Hosting` with `SigstoreResource`,
  `SigstoreOptions`, `SigstoreComponents`, and `AddSigstore(...)`. The
  non-compute `sigstore` parent starts in `Active`, is excluded from deployment
  manifests, and groups all 11 Sigstore infrastructure resources. The
  integration always resolves its state under AppHost-relative `.sigstore/`.
- The file-based AppHost references the hosting project through `#:project`;
  targeted `IsAspireProjectResource="false"` metadata keeps the class library a
  compile-time reference rather than an executable resource.
- Normalized `aspire describe --include-hidden --format Json` output for every
  pre-existing resource was identical before and after extraction. External
  image identities and all fixed canonical endpoints also matched; the only
  model additions were the parent and its grouping relationships.
- `aspire wait` confirmed the four one-shot resources completed and all 14
  long-running resources became healthy. The custom parent remained `Active`,
  Aspire's state for a resource without a runtime lifetime.
- AppHost startup changed all nine recorded trust-domain identity fields and
  recreated the artifact range from `1`. Restarting only OIDC preserved the
  bootstrap, TUF, log-state, and artifact-1 hashes while the artifact head
  advanced from `215` to `224`.
- All six clients emitted successful `artifact.produce` and
  `artifact.validate` spans. Python produced and validated the Rekor index-zero
  artifact, so the known Go/sigstore-python omitted-default edge case did not
  occur.

**Validation gate status: passed.**

## Step 2: Centralize client wiring

### Scope

- Add a Sigstore-specific `WithReference(...)` overload.
- Centralize endpoint references, trust mounts, hostname mappings, waits, and
  common environment variables.
- Preserve language-specific environment and telemetry configuration.
- Replace duplicated wiring in `apphost.cs`.

### Validation gate

- `aspire describe` shows equivalent resolved references for every client.
- All clients initialize trust from local TUF.
- Every language signs, seals, and validates artifacts from every producer.
- No client falls back to public Sigstore infrastructure.

### Implementation evidence

Completed on `2026-08-27` with the file-based AppHost and Aspire SDK `13.5.2`.

- Added a container-only `WithReference(...)` overload for
  `IResourceBuilder<SigstoreResource>` and typed `SigstoreClientOptions`.
  `AddSigstore(...)` returns that typed parent builder and retains its component
  aggregate on `SigstoreResource`. The default preserves the individual
  bootstrap-root mount and canonical host mappings, Go explicitly retains its
  TUF repository directory mount, and .NET explicitly retains its direct
  Fulcio, Rekor, and timestamp endpoint variables without host mappings.
- Normalized pre-change and post-change
  `aspire describe --include-hidden --format Json` models were identical for
  all 19 declared resources. Resolved environments, mounts, fixed endpoints,
  references, and waits matched; runtime inspection also matched the five
  canonical host mappings on each non-.NET client and none on .NET.
- `aspire wait` confirmed all 14 long-running resources healthy and the four
  bootstrap/readiness resources completed. Every client fetched TUF from
  `tuf.dev.internal`, used the local OIDC, Fulcio, Rekor, and timestamp
  endpoints, and emitted no public Sigstore endpoint references.
- OpenTelemetry spans covered all 36 producer-to-validator language pairs with
  no artifact error spans or structured error logs. The final artifact head
  advanced from `31` to `42`; Python produced and validated artifact `1`, so
  the known Go-index-zero parser edge did not occur.
- Restarting only OIDC preserved the bootstrap manifest, TUF manifest, and
  artifact `1` byte-for-byte while the head advanced from `135` to `145`.
  Starting a new AppHost emptied the artifact store, changed all nine recorded
  trust identifiers, and created a different artifact `1`.

**Validation gate status: passed.**

## Step 3: Stabilize the TUF filesystem and bind mounts

### Scope

- Stop replacing the bind-mounted `.sigstore/tuf` directory itself.
- Introduce a TUF parent that remains stable for the active AppHost run and
  contains committed, staged, historical, and immutable bootstrap-root state.
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
- Restarting TUF and client child resources within the active AppHost run
  preserves the committed repository and history.

### Implementation evidence

Completed on `2026-08-27` with the file-based AppHost and Aspire SDK `13.5.2`.

- `.sigstore/tuf` is now the stable bind-mount boundary. It contains the
  read-only `bootstrap/root.json`, an `active` relative symlink, one
  content-addressed active directory under `committed/`, an optional
  `history/previous`, the bounded `staging/` workspace, and
  `publication/state.json`. Nginx and every client mount only that parent.
- Publication stages and validates a complete repository before atomically
  replacing `active`. A `preparing` journal with the old link active rolls
  back and restores parked history; the candidate link active completes
  forward and archives the old repository. Missing, conflicting, or
  hash-mismatched state fails instead of being discarded. Ordinary refresh
  retains exactly one prior committed repository.
- Focused Go tests use temporary trust state and cover initial creation,
  metadata refresh, immutable bootstrap bytes and inode, successful
  publication, exact file-hash validation, injected pre-commit rollback, and
  recovery at every filesystem checkpoint before and after the atomic switch.
- During the non-isolated live run, TUF nginx remained container
  `51a2a0eebd726efb9f672d1b7921f8f37f94262eac7a7852c3828027919af058`.
  Served root version `1` stayed at SHA-256
  `31ba7d3cec36eb5ef6fcce8ea33a1f374b9a80937dc43bc2f0eebda30d7f0bd5`.
  Snapshot version `1`
  (`99a2333c73d0eb06cd060f3ae32cf8ca8faa147e952a13b590f1340ad65f0045`)
  advanced to version `2`
  (`0f113a723e49eaa0fce4042e2378645f3ed07ff8dedcbfb9f19911794ec1d8c1`);
  timestamp version `1`
  (`29f2d0a8732aeb0e60f7db1afd3f07ff7c328f809d8807d12c6669c28570ba9e`)
  advanced to version `2`
  (`8b224176ae9d97bd78db30194c207b862f10443c259148e8172915bbbef54094`).
  The bootstrap root stayed byte-for-byte identical.
- The active manifest changed from
  `cc609b9909e06eb72f5175e88f6b8f428d22efc613c7f1a4825060e8fb9f0181`
  to
  `e292aa64c2f9e1a37e47e0fbbe706fdce284cac2cc6084726989d482eedb7063`;
  both hashes matched their publication journal entries, and the first
  manifest became `history/previous` unchanged.
- Resolved Aspire models and Docker inspection showed nginx and all six
  clients read-only mounting the same host `.sigstore/tuf` directory at
  `/var/lib/sigstore/tuf`. Every client used
  `/var/lib/sigstore/tuf/bootstrap/root.json` and the local
  `http://tuf.dev.internal:8080` repository. No public Sigstore endpoint
  appeared in client configuration or logs.
- Restarting only TUF and the Go client changed their container identities to
  `5c860500fc5f67e884a76841d793e994bdd5e3298509dc7a9774463dc9b97c3b`
  and
  `fe283783bb88a40fae9552c65d03206855bdf5f7950da1debbcc02e172f49315`
  while every TUF state file, active link, served metadata byte, bootstrap
  root, and history entry remained unchanged. The restarted Go client
  initialized trust and resumed producing and validating.
- A replacement AppHost removed sentinels from both run-scoped state trees,
  removed the prior TUF history, reset snapshot and timestamp to version `1`,
  and changed the bootstrap-manifest hash from
  `941e5b2ec25e9ac9e6b0cfefa13ef81f4c4c6bfc1e8dcae98142a4219871040f`
  to
  `c20432fbf4969f352732127720f9c15f0716cd47dbe5f283154fb49a0b68f7e4`.
  The bootstrap-root hash likewise changed from
  `31ba7d3cec36eb5ef6fcce8ea33a1f374b9a80937dc43bc2f0eebda30d7f0bd5`
  to
  `87e630fc8cee0e6aec3b01040dd7046bde9267d23d8c83a5cc6c5ca7b51600f6`.
  The reset walker treats child symlinks as non-traversed leaf entries while
  continuing to reject a symlinked state root or ancestor.
- All four one-shot resources completed and all 14 long-running resources
  became healthy. The artifact head advanced from `19` before refresh to `31`
  after refresh and `84` after child restarts. All six languages produced.
  Five languages validated the shared stream; Python encountered the known
  out-of-scope index-zero interoperability issue on artifact `1`
  (`logIndex` and `inclusionProof.logIndex`). No Go or Python bundle
  serialization was changed or masked in this step.

**Validation gate status: passed for the Step 3 filesystem, publication,
recovery, and bind-mount invariants; the full six-language validation sweep
retains the documented index-zero Python interoperability exception.**

## Step 4: Introduce generation-aware trust state

### Scope

- Separate immutable trust-domain identity from active key generations.
- Add a rotation journal with staged, committed, failed, and recovered states.
- Replace single-generation manifest assumptions.
- Migrate schema 4 state supplied to migration tests or present in the active
  run without regenerating keys or log identities.
- Use one shared state lock for bootstrap and rotation operations.

### Validation gate

- Migration tests run against copies of existing state.
- All pre-migration fingerprints and log state identifiers remain unchanged.
- Migration and startup are idempotent.
- Unexpected file changes still fail validation.
- Interrupted staged and committed transitions recover deterministically.

### Implementation evidence

Completed on `2026-08-27` with the file-based AppHost and Aspire SDK `13.5.2`.

- Schema 5 stores immutable identity in `trust-domain.json`, key material and
  exact file hashes in
  `generations/generation-00000001/manifest.json`, and a separate normalized
  `active-generation` link. Step 4 creates or imports generation 1 only; no
  rotation command or live generation mutation was added.
- `transition/state.json` is independent of TUF publication IDs and represents
  `staged`, `committed`, `failed`, and `recovered`. The active-generation link
  is its commit record. Initialization and schema-4 migration complete forward
  because no prior generation exists, including recovery after the link switch.
- Schema-4 migration validates the original keys, certificates, JWKS, log
  markers, and exact private/public file set before journaling. It moves the
  material directories without rewriting them and archives the original
  manifest byte-for-byte. Twenty-one temporary-directory .NET tests cover
  fresh state, copied schema-4 state, idempotence, pre- and post-migration
  corruption, contention and released-owner recovery, durable failure, all 13
  filesystem checkpoints, and the archive rename/mode crash window. Every
  pre/post material hash, trust fingerprint, CT state ID, and Rekor state ID
  matched.
- Bootstrap and TUF publication use the same root `state.lock` and kernel
  `flock`; process exit releases the lock while owner JSON remains diagnostic.
  Ten Go tests retain Step 3 publication/recovery coverage and additionally
  prove lock contention/recovery, generation file corruption rejection, and
  identical TUF source fingerprints before and after a schema-4 projection.
- The `.sigstore/tuf` bind-mount parent, immutable bootstrap root, atomic
  publication link, exact publication manifests, and one-entry history remain
  unchanged. In the live run, TUF nginx stayed container
  `df43c76008917b6985558eeda759697a356e8c00a33756ec1599fccee4c21c23`
  while snapshot and timestamp advanced from version `1` to `2`. The bootstrap
  root retained SHA-256
  `b3f94869cd2409af0d34b34d76c250938abee66f525182712b42b4eac7f525aa`
  and inode `57371418`; source fingerprint
  `22761cb5b9d6c30d68ea4b47cfafb1f19f38f10e39ee21cf2555bd0b6d1f13c5`
  was unchanged, and the prior manifest became `history/previous`.
- Both serialized non-isolated AppHosts completed all four one-shots with exit
  code `0` and made all 14 application resources healthy. Resolved service
  mounts use `active-generation/private` and `active-generation/public`; nginx
  and all six typed clients still mount the stable TUF parent and resolve only
  local endpoints. Every language produced, and five validated the shared
  stream in the first run. Python encountered the documented out-of-scope
  index-zero bundle omission on artifact `1`; no Go or Python serialization was
  changed. In the replacement run all six produced and validated.
- A replacement AppHost removed sentinels from both run-scoped state trees,
  changed the trust-domain ID from
  `sha256-177f160ae2bf3b6627659d5bcc84cdc72900e71eb6ec8d9f029df251c0689751`
  to
  `sha256-31c484c6199589ebe040b57efdec95b5fdaf0b031baaa591261e2f6b73111cc2`,
  changed the generation-manifest and bootstrap-root hashes, reset TUF
  snapshot/timestamp to version `1` with empty history, and replaced artifact
  `1`. The final AppHost remains running at
  `https://sigstore.dev.localhost:17249` (fixed HTTP dashboard route
  `http://sigstore.dev.localhost:15096`).

**Validation gate status: passed; the first live run retained the documented
index-zero Python interoperability exception.**

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

### Implementation evidence

Completed on `2026-08-27` with the file-based AppHost and Aspire SDK `13.5.2`.

- All six clients expose `GET /trust/status` on their existing local health
  servers. Schema 1 reports the resource and language, readiness and last error,
  trust-domain ID, integer generation and TUF root/targets versions,
  generation ID and manifest SHA-256, exact trusted-root and signing-config
  SHA-256 values, and RFC 3339 UTC initialization time. Hashes are lowercase
  hexadecimal SHA-256 over the exact verified target bytes.
- `trust_status.v1.json` is a signed TUF target that binds the active schema-5
  generation to root/targets versions and target hashes. Clients retrieve it
  through their native verified TUF path, except Java, which validates the
  mounted target bytes against its verified targets metadata. The status path
  does not weaken or replace native trust validation.
- Every `sigstore.trust.initialize` span has `client.language`,
  `client.resource.name`, `sigstore.trust.domain.id`,
  `sigstore.trust.generation`, `sigstore.trust.generation.id`,
  `sigstore.trust.generation.manifest.sha256`,
  `sigstore.trust.tuf.root.version`,
  `sigstore.trust.tuf.targets.version`,
  `sigstore.trust.trusted_root.sha256`,
  `sigstore.trust.signing_config.sha256`, and
  `sigstore.trust.initialized_at`. The generation and metadata versions are
  integer attributes; the remaining trust attributes are strings.
- The typed parent `status` command returns JSON on stdout and never mutates
  resources or files. It validates the complete generation manifest and file
  set, transition journal and trust-domain identity, committed TUF publication
  state/layout/manifests, served metadata and target bytes, all client
  contracts, and current resource health. Explicit structured errors and a
  failed command result replace success-shaped fallbacks.
- The parent watches Aspire resource notifications for the seven long-running
  Sigstore services, `shady-blob-store`, and six clients. All 14 healthy
  resources produce parent state `Healthy`. Stopping `rust-client` produced
  `Degraded`, reason `rust-client is Exited (health Unknown)`, and `13/14`;
  the status command failed with exit code `16`. Starting it and waiting for
  health restored `Healthy`, `14/14`, and a successful status command. A
  byte-for-byte trust/TUF snapshot was unchanged across the transition.
- The final non-isolated AppHost completed all four one-shots with exit code
  `0` and made all 14 long-running resources healthy. Disk, served TUF, all six
  clients, and seven initialization spans (including the restarted Rust client)
  agreed on trust domain
  `sha256-962071e3bf592cf52a4cb72543e198dd2246ceeb2f091f6895206b002bc7ea75`,
  generation `1`, root/targets versions `1`/`1`, generation-manifest SHA-256
  `2916f706eb0898caf091344044afc23688b882f698a70a4d742cd7350d5a50c2`,
  trusted-root SHA-256
  `494724872e5d07a3f3fa93ab0d0946f8b2defa28cb16ffa37d14df01664c695e`,
  and signing-config SHA-256
  `c72af3c3de5ff1446f480d27fe3793e91a7e830843108098cb02cd5bd4d430fc`.
  All seven spans contained every required attribute.
- A replacement AppHost removed sentinels from both run-scoped trees, changed
  the trust-domain ID, bootstrap-root hash, and artifact `1`, and reset the
  artifact head from `64` to a new stream. In the final run the head advanced
  from `38` to `44`; all six clients produced and validated with no error spans.
  Python validated artifact `1`, so the known index-zero exception did not occur
  in this run. No public Sigstore fallback appeared.
- Focused validation passed 6 hosting status/aggregation tests, 21 schema-5
  bootstrap tests, 10 TUF publication tests, and per-language status tests for
  Go, JavaScript, Python, Java, and Rust. The AppHost, hosting library, and .NET
  client built successfully; all changed client container images built; and
  `git diff --check` passed.
- The final AppHost remains running at
  `https://sigstore.dev.localhost:17249` (fixed HTTP dashboard route
  `http://sigstore.dev.localhost:15096`).

**Validation gate status: passed.**

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

### Implementation evidence

Completed on `2026-08-27` with the file-based AppHost and Aspire SDK `13.5.2`.

- The typed `sigstore` parent now has exactly three commands: the preserved
  read-only `status`, plus mutating `refresh-tuf` and `restart-clients`.
  Both mutations have dashboard descriptions, explicit confirmation text,
  non-cancelable progress dialogs, structured JSON success/failure results, and
  dynamic command state. While an operation runs, the parent reports its command,
  phase, ordinal progress, and underlying `14`-resource health; afterward it
  returns to the latest aggregate `Healthy` or `Degraded` state.
- The implementation uses only public Aspire command and notification surfaces.
  Installed `13.5.2` symbols and source confirmed that
  `ResourceCommandService` can start a terminal one-shot and restart a running
  container, but returns before completion or application health. The parent
  therefore requires a changed container identity/start time and waits for a
  terminal worker exit or `Running`/`Healthy` client state before validating
  postconditions.
- Both commands take an atomic in-process operation gate and the schema-5 shared
  `state.lock`. `restart-clients` holds the OS lock for the complete operation.
  `refresh-tuf` captures preconditions under the lock, starts the worker while
  still holding it, releases after Aspire creates the new worker instance, lets
  the worker acquire the same lock for its transaction, then reacquires it for
  postconditions. This parent-to-worker-to-parent handoff avoids nested-lock
  deadlock and closes the preflight/start race.
- A live `refresh-tuf` replaced worker container
  `b6eb610b2e20f2f9aa2b62bdb731289ad5fcaf3d802afc93695857d1279a035a`
  with
  `d4d4a26b8e32b61614667e3210bbbf1780880cddba5cdaa4c239ad64e8950695`,
  which exited `0`. Snapshot advanced from version `1`, SHA-256
  `8eb52086e1877111bc0909ae8db4b0e5161d31d4379ad6121310aabb89c543ca`,
  to version `2`, SHA-256
  `4f510f57b0f0714ab896aeb5cb707b6b0527a28587758020d3b761ed5bddbc1a`.
  Timestamp advanced from version `1`, SHA-256
  `6a9dcd123a618499b7efe62a20a956f4104a5c99667ea0bcb6f84d1f1114d906`,
  to version `2`, SHA-256
  `4db7d5c28dbe85553b3b24e4d21e7bdb701fa27f5abd9d2b3eac8738653b3c97`.
- Root remained version `1` at SHA-256
  `078f0df42b95c2326380142bd2a083d45b1d410647fd1f7f5b7715c63ace4d86`;
  targets remained version `1` at SHA-256
  `086f19efc2e0f854792e3424b052fa83236b12930f19b98ea87fb4f93325a12e`.
  TrustedRoot and SigningConfig stayed at
  `a3218adce7c47a930ed323419bd1220e69324ee78f6e89c293b62e3fcae1be99`
  and
  `54e5a25d36f164840b68c550c60081d1495afb9d1debf98dadc42460dc49a2c9`.
  The stable-content and trust-material fingerprints were unchanged.
- TUF nginx remained container
  `3154d4a3e31ac936ac590884a5a1ec60e21f6b6276add4bf965947cab40906f8`
  with the same start timestamp. The immutable bootstrap root retained inode
  `57546872` and SHA-256
  `078f0df42b95c2326380142bd2a083d45b1d410647fd1f7f5b7715c63ace4d86`.
  Active publication
  `sha256-60af2e4a912ffebb031e0565052b8f9145ea1bb96e97c7981a4b6ad367e914e6`
  advanced to
  `sha256-264fb2dcb06a20975e22dc3cbdf00f1d391791f7de41b06874cabda535479d3f`;
  the prior manifest moved unchanged to `history/previous`, and disk and served
  role bytes matched exactly.
- A live `restart-clients` replaced every client container in sorted order:
  .NET `6b0e6c905b01...` to `203dedd4deee...`, Go `4ef50458c36f...`
  to `d2705506b24d...`, Java `d23ddd663520...` to `50277e3dc336...`,
  JavaScript `e6249891e985...` to `a691d9dae585...`, Python
  `5fde55918741...` to `b4d9cbd90a33...`, and Rust
  `98106e8dad56...` to `c117678e044c...`. All six reached
  `Running`/`Healthy`, returned valid current status, and agreed with disk and
  served trust. An independent trust/TUF file manifest was byte-identical before
  and after at SHA-256
  `d86bb31b3c04f876f1c129df6b08bc6e0e6205ca7b080eaea1f0742360206738`.
- During another live client restart, the parent showed
  `Restarting Clients`, phase `restart-client`, progress `3/9`, and underlying
  health `13/14`. Mutation actions were unavailable while `status` remained
  enabled. A simultaneous `refresh-tuf` failed immediately with phase
  `contention` and identified `restart-clients` as the active operation; the
  parent returned to `Healthy`, `14/14`, with both mutations enabled afterward.
- Seventeen focused hosting tests cover registration/confirmation/progress,
  operation-state recovery, gate and OS-lock contention, locked lifecycle
  sequencing, new-instance waits, worker exit failure with preserved committed
  state, nginx identity, metadata postcondition failures, deterministic
  all-client health/status waits, structured results, and trust immutability.
  The 21 schema-5 bootstrap tests and 10 Go publication tests also passed,
  including injected pre-commit rollback and shared-lock recovery.
- Both operations and the preserved `status` command succeeded through
  `aspire resource`. All four startup one-shots exited `0`; all 14 long-running
  resources became healthy. Artifact head advanced from `35` before refresh to
  `54` afterward and beyond `197` after restarts. Every language emitted
  successful production, validation, and trust-initialization spans with the
  complete Step 5 attribute set. The known Python index-zero exception did not
  occur, and no public Sigstore fallback appeared in client logs.
- A replacement AppHost still resets both run-scoped state trees. The final
  non-isolated AppHost remains available at
  `https://sigstore.dev.localhost:17249` (fixed HTTP dashboard route
  `http://sigstore.dev.localhost:15096`).

**Validation gate status: passed.**

## Step 7: Implement TUF root rotation

**Status: ✅ Implemented**

### Scope

- Add `rotate-tuf-root`.
- Generate root version `N+1`.
- Satisfy the old and new root signature thresholds.
- Preserve all versioned roots and the immutable bootstrap anchor.
- Publish snapshot and timestamp metadata transactionally.

### Implementation

- **Go TUF worker** (`src/Sigstore.Tuf/main.go`, `repository.go`): On
  `rotate-root.request` signal file, `rotateTUFRoot()` generates a new root key,
  revokes the old key, and `rotateRootPublication()` publishes transactionally
  using the candidate/commit/switch pattern. go-tuf signs with both old and new
  keys satisfying both thresholds.
- **C# dashboard command** (`SigstoreOperationCommand.cs`): `rotate-tuf-root`
  uses the proven Step 6 one-shot worker pattern (signal file → start worker →
  wait → validate postconditions). Structured output includes before/after root
  versions, key rotation evidence, snapshot/timestamp advance, and bootstrap
  preservation.
- **Restart-clients integration**: After rotation, clients report stale root
  version (v1 vs disk v2). `restart-clients` accepts this specific valid
  stale-client state (root/targets version behind disk along a valid retained
  root chain) while still rejecting unsafe mismatches (wrong trust domain,
  generation, trusted-root, signing-config). After restart, clients follow the
  immutable bootstrap root v1 → `2.root.json` → v2 chain.
- **Bootstrap root remains v1**: The immutable `bootstrap/root.json` is never
  modified. Fresh clients always start from v1 and follow the versioned root
  chain (`1.root.json`, `2.root.json`, ...) to reach the current active root.

### Validation gate

- Cryptographic tests validate signatures and thresholds.
- A persistent client anchored at root `N` updates through `N+1`.
- A fresh client can bootstrap and update through the full root chain.
- Rollback, freeze, skipped-version, and tampered-root cases are rejected.
- Restarting a client with the latest root is not accepted as proof of rotation.

### Evidence

- 16/16 Go tests pass (6 rotation-specific: advance, second rotation,
  dual-threshold signatures, injected failure rollback, rotation-then-refresh,
  signal file consumption).
- 22/22 C# hosting tests pass (3 rotation + 2 restart-stale-root + existing).
- 21/21 Bootstrap tests pass.
- Live: `rotate-tuf-root` succeeds v1→v2 with all 24 postconditions passing.
- Live: `restart-clients` preflight accepts stale root; 5/6 clients converge to
  v2 (javascript-client has pre-existing startup flakiness unrelated to
  rotation).
- Nginx TUF server identity unchanged across rotation.
- Bootstrap root hash preserved at original value.

## Step 8: Implement additive trusted-root rollout

### Scope

- Add `publish-trusted-root`.
- Publish trusted-root and signing-configuration updates through TUF.
- Refresh clients in process where supported; use explicit restart uptake where
  a library cannot safely refresh.
- Wait until every client reports the new target version and fingerprint.
- Retain historical verification material by default.

### Implementation

**Command**: `publish-trusted-root` via `aspire resource sigstore publish-trusted-root`.
Uses `ResourceCommandService` with explicit confirmation, contention rejection,
non-cancelable progress, and structured schema-versioned results.

**Additive material**: An ECDSA P-256 standby Rekor verification key
(`public/rekor/rekor-standby.pub`) is added to TrustedRoot.Tlogs with a future
`ValidFor.Start` (+1 year) and `/standby` base URL. SigningConfig remains
unchanged — no routing to the standby key. The material is genuine cryptographic
content suitable for demonstrating an additive update without activating a signer
or preempting Steps 9-13.

**Transaction ordering**:
1. `advanceTrustGeneration` creates generation N+1 directory with standby key +
   manifest. NO symlink or journal change.
2. `publishNewTargets` builds targets from gen N+1, performs TUF
   prepare→commit→active-switch→finalize using gen N+1's fingerprint and gen N's
   fingerprint for the prior publication.
3. `switchActiveGeneration` updates the transition journal (with PriorGeneration
   reference) and atomically switches the active-generation symlink, only after
   step 2 fully succeeds.

**Cross-generation recovery** (automatic, deterministic):
- Crash after step 1 only (orphaned gen dir, TUF committed with gen N):
  Cleaned up on next `ensureTUFRepository` in the committed validation path.
- Crash during step 2 (before TUF active switch): `recoverPreparingPublication`
  rolls back the candidate (without fingerprint validation on cross-gen
  candidate) and restores committed state. Orphaned gen dir cleaned up.
- Crash during step 2 (after TUF active switch to candidate, before finalize):
  `recoverPreparingPublication` detects active→candidate, loads gen N+1's
  fingerprint, calls `finalizePublishPublication` with both fingerprints, then
  completes the generation switch.
- Crash between steps 2 and 3 (TUF committed with gen N+1, symlink still gen N):
  `tryForwardCompleteGeneration` detects the orphaned gen N+1 directory, computes
  its fingerprint, validates the active TUF publication matches, and completes
  `switchActiveGeneration`.
- No manual intervention required for any checkpoint. Repeated invocations are
  idempotent and converge to one coherent generation.

**Request/replay protocol**: The C# command writes a schema-versioned JSON
request file containing a unique `operationId` (GUID). The Go worker uses
`dispatchPublishRequest` which:
1. Checks a durable `publishCompletion` journal for same-ID (crash-after-success).
2. Calls `recoverTUFState` (recovery-only — no refresh or new publication).
3. Detects recovery-forward-completed state vs genuinely new second request.
4. Writes completion journal BEFORE removing request (crash-safe ordering).

**Repeated invocation contract**: `publish-trusted-root` is explicitly one-shot
per trust domain. A second invocation (different operation ID after a prior
completion) is rejected pre-mutation with a clear error. This prevents silent
removal of prior standby verification material and upholds "retain historical
verification material by default." Accumulating multiple standby keys with
stable unique identities is deferred to Steps 9-13 which introduce real
rotating keys.

**Client uptake**: All six language clients (Go cosign, Python sigstore, Rust
sigstore, Java sigstore, TypeScript sigstore, .NET sigstore) require
restart-based uptake via `ResourceCommandService`. None support in-process TUF
trust refresh. The command restarts all clients, waits for Running/Healthy
status, and validates `/trust/status` reports the new generation, targets
version, and TrustedRoot fingerprint.

**Stale-client detection**: The command polls every client's `/trust/status`
endpoint and will not report success until all clients agree with the committed
disk state. A stale client is identified by target-version/fingerprint mismatch
and prevents the command from completing.

### Validation gate

- Artifacts created before publication still validate.
- Artifacts created after publication validate in every language.
- Every client reports the new trusted-root fingerprint.
- A client that has not refreshed is detectable and prevents command success.
- Removal of historical verification keys is not part of this command.

### Evidence

- All Go tests pass (33 tests including 5 dispatch-path, 3 cross-gen recovery, 2 tampered-domain tests).
- All C# hosting tests pass (22 tests including command registration).
- `git diff --check` clean from base commit.
- Live validation: generation 1→2, all 6 clients converged, 14/14 healthy.
- Cross-generation recovery tested at every boundary: orphaned dir cleanup,
  preparing rollback, preparing forward-complete, committed forward-complete.

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

### Implementation (Step 9)

Step 9 uses a **single-stage atomic switch**. It intentionally does not
pre-publish a separate overlap-only generation. Fulcio refreshes discovery/JWKS
when it encounters the new `kid`, so one generation advance and one OIDC
replacement preserve continuity while the exact old token remains available
for proof.

The AppHost command owns orchestration and protected control files only. Under
`state.lock`, it creates a schema-versioned operation journal and a CreateNew
worker request bound to operation ID, trust domain, starting generation, and
starting `kid`. The journal stores the exact pre-switch JWT with mode `0600`
until proof succeeds. The Go worker owns all durable trust mutations under the
same lock:

1. Build generation N+1 in an operation-bound staging directory.
2. Validate the exact manifest, every JWKS entry, active RSA
   signer/public/JWK equality, every kid-bound retained private key, and
   unchanged non-OIDC material.
3. Atomically rename the complete generation into `generations/`.
4. Transactionally publish TUF `trust_status` for N+1.
5. Switch `active-generation` with the transition journal.
6. Atomically write the operation-bound completion and consume the request.

The command validates completion/publication/manifests, restarts OIDC exactly
once, validates the new JWT claims, and proves real Fulcio certificate issuance
using the exact old JWT and the new JWT with proof-of-possession. Fulcio's
container ID and start timestamp must remain unchanged. All six clients are
then restarted and every status contract must report N+1 before success. The
completed journal retains token metadata and certificate hashes but removes the
JWT.

OIDC bind-mounts the stable state root read-only at `/var/lib/sigstore`; signer
and JWKS paths use `/var/lib/sigstore/active-generation/...`. A replacement
container therefore resolves the committed generation without mounting
replaceable symlink descendants.

Generation N+1 contains:

- `private/oidc/signer.key` — new active private key.
- `public/oidc/signer.pub` — matching new active public key.
- `public/oidc/jwks.json` — new key plus every historical public key.
- `private/oidc/retained/signer-<kid>.key` — one key for every historical
  non-active JWK.
- `manifest.json` — exact hashes and operation/prior-generation/overlap
  metadata.

Repeated rotations are append-only in Step 9: JWKS grows 1→2→3 and all
historical private keys remain available. The recorded overlap expiration is
the configured 30-minute token lifetime plus clock skew and is a minimum safety
boundary, not an automatic retirement time. Key retirement is outside this
command.

Recovery always completes forward once generation/TUF commit has occurred. A
replay validates the exact operation binding and live publication before
reusing N+1; it never treats an arbitrary higher generation or broad completion
match as success. If OIDC already restarted, the new signer probe suppresses a
second restart. If proof was interrupted, the protected pre-switch JWT is
reused and no new generation is created.

TrustedRoot, SigningConfig, Fulcio/Rekor/CT/TSA identities, and prior generation
bytes must remain unchanged. Any missing endpoint, token, certificate,
container identity, completion binding, client convergence result, or aggregate
health condition fails the parent command.

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
- Confirm recovery after operation-worker or affected-child termination during
  each operation phase without ending the AppHost run.
- Document reset, backup, recovery, and intentionally destructive trust-retirement
  scenarios.
- Run the complete sequence against a populated artifact store within one
  AppHost run.

### Validation gate

- Every operation has deterministic success, failure, and recovery behavior.
- No successful command leaves clients or services on an unreported generation.
- The artifact stream resumes after every supported rotation.
- Historical artifacts remain verifiable under normal additive policy.
- Every supported child-resource restart preserves the final committed
  run-scoped state.
- A subsequent AppHost process starts a new trust domain and empty artifact
  store as specified by Step 0a.

## Rotation safety rules

- Publish trust before activating a new signer.
- Confirm client uptake before relying exclusively on new trust.
- Keep old verification material while historical artifacts remain in the store.
- Do not rotate Rekor or CT keys in place; create new log shards.
- Do not replace a bind-mounted directory or individual mounted file.
- Do not report success until served content and child health match committed
  state.
- Do not silently regenerate missing or inconsistent state within an active
  AppHost run.
- Do not permit two bootstrap or rotation operations to mutate state
  concurrently.

## Completion criteria

The integration is complete when:

- `apphost.cs` consumes a reusable `AddSigstore(...)` resource.
- Client resources use shared Sigstore wiring.
- Every AppHost process resets and bootstraps fresh run-scoped trust and
  artifact state.
- TUF metadata and root rotations work without recreating the TUF server.
- Every client exposes the trust generation it is using.
- Dashboard commands safely orchestrate refresh and rotation workflows.
- OIDC, TSA, Fulcio, Rekor, and CT rotations preserve the expected history.
- Failed and interrupted operations recover without ambiguous state across
  supported child-resource restarts within the run.
- The continuous cross-language artifact stream validates the entire lifecycle.
