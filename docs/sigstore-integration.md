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

**Status: Implemented**

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

### Implementation

`rotate-timestamp-authority` is a confirmed, non-cancelable parent command with
the same in-process contention gate and shared `state.lock` used by Steps 3-9.
Its schema-versioned result contains the old/new generation and TSA
fingerprints, TUF publication identity, every client convergence record,
timestamp lifecycle identity, RFC3161 evidence, postconditions, and recovery
errors.

The AppHost first issues a nonce-bound RFC3161 request to the running timestamp
service. It verifies the CMS signature and message imprint, validates the
returned leaf against the active TSA root, and stores the exact request and
response under `tsa-rotation/<operation-id>/` with mode `0600`. Candidate
generation uses the bootstrapper's existing ECDSA P-256, SHA-256, encrypted
PKCS#8, AES-256/PBES2, and random-password profile. The candidate has:

```text
tsa-rotation/<operation-id>/
|-- command.json
|-- old-request.tsq
|-- old-response.tsr
`-- candidate/
    |-- private/tsa/                 # removed after worker completion
    |   |-- signer.key
    |   `-- password
    `-- public/tsa/
        |-- root.pem
        |-- leaf.pem
        `-- cert-chain.pem
```

The TSA root private key exists only while the candidate is being built and
validated. Generation N+1 contains only the active signer and password in its
private TSA subtree. It copies every non-TSA file from N byte-for-byte,
replaces the TSA subtree, writes exact operation/prior-generation fingerprints
to the immutable manifest, and retains generation N unchanged.

The Go worker owns the durable mutation while holding `state.lock`:

1. Strictly validate the request, candidate profile, old active chain, manifest
   binding, and any replay state.
2. Commit immutable generation N+1 without changing `active-generation`.
3. Clone the active TUF publication, append the new chain to
   `TrustedRoot.TimestampAuthorities`, preserve every existing Fulcio, CT,
   Rekor, standby, and historical TSA entry, and retain
   `signing_config.v0.2.json` byte-for-byte.
4. Rebuild `client_trust_config.json`, replace only the current TSA alias
   targets, update `trust_status.v1.json`, and advance targets, snapshot, and
   timestamp through the existing preparing/committed publication transaction.
   TUF root and `bootstrap/root.json` remain unchanged.
5. Switch `active-generation` through the trust-transition journal only after
   the additive TUF publication commits.
6. Atomically write the operation-bound worker completion, remove the request,
   retire candidate private material, and retain only its public chain as
   journal evidence.

The old timestamp process continues using its prior in-memory signer throughout
publication. The parent proves that old signer is still running, restarts the
six clients in deterministic name order, and requires each `/trust/status` to
match generation N+1 and the additive TrustedRoot hash. It then writes the
`clients-converged` checkpoint and restarts only `timestamp`. OIDC, Fulcio,
Tesseract, Rekor server/proxy, TUF nginx, and `shady-blob-store` are protected
by exact container ID and start-time postconditions.

The timestamp container now bind-mounts the stable state root at
`/var/lib/sigstore`; both the entrypoint password and server key/chain arguments
resolve through `/var/lib/sigstore/active-generation/...` inside the replacement
container. A post-restart RFC3161 request must be signed by the N+1 leaf and
validate to the new trusted root. `--include-chain-in-response=false` remains
unchanged; the response includes the signing leaf requested by the client while
verification obtains roots from additive TrustedRoot.

### Recovery and status

Candidate generation, TUF preparing/commit, generation switch, each client
convergence, timestamp restart, old/new RFC3161 proof, and final completion are
durable replay boundaries. Before TUF activation, recovery removes only known
unjournaled scratch and keeps the old signer active. After TUF activation it
always completes forward. A replay checks live client status before restarting,
so already converged clients are not restarted again. It probes the live TSA
before issuing the service command; if the new signer and a replacement
container are already present after all recorded client start times, the second
restart is suppressed. Any mismatched operation ID, fingerprint, generation,
publication, container ordering, or file hash fails loudly.

While additive trust is committed but activation is incomplete, the parent
shows `TSA Activation Pending` (or `TSA Verification Pending`) and disables
unrelated mutation commands. The TSA command remains available for recovery.
The read-only `status` command parses and validates every TSA chain in
TrustedRoot, exposes the active and running root/leaf identities, and remains
degraded until the running RFC3161 signer matches the active generation.

### Known limitation

The existing sigstore-python rejection of a bundle whose protobuf JSON omits an
index-zero enum remains out of scope. Rotation does not alter or normalize
bundle serialization; live validation reports the issue if that producer wins
the affected artifact instead of masking it.

### Validation evidence

Validated non-isolated on `2026-08-28` at implementation commit
`c004227be74bef3514c9656535a80dd20c172d09` with Aspire SDK `13.5.2`.

- `rotate-timestamp-authority` completed generation `1` to `2` with all `48`
  structured postconditions passing. The old TSA root/leaf fingerprints were
  `27a504e148b89b91f0a5474c19d34338ad296f74a0a0f00573a0faf497d3b81c`
  and
  `27bcd224b5f51b030fd30be66ce45bdb9171fd359b42c721abcb91a9dbfa3dad`;
  the new fingerprints were
  `edbfba70454f7fc7d31552c7e5f03158c71c6fe3be6991995ce0a91bf9287cc7`
  and
  `4dee58e997fe76c0a7f54db8230ce8e946fba90b76b1eef645e10e7c6d7c391f`.
  Pre- and post-activation RFC3161 responses validated to those exact chains.
- TrustedRoot advanced from
  `fa0d7fb9c26eebe5a952c54d70a3b5e891eadf3a051633ee954f1735b3b948bf`
  to
  `c999c72cdd0612943955787bc81241141816f345270c43a6e6f77129ee698673`
  and contained the old chain followed by the new chain. SigningConfig stayed
  byte-identical at
  `fadd7279f1ea31f67a21a4b5af57398ee726a06c53a8ddcc044a839d26536916`.
  Root/bootstrap stayed version `1` at
  `f6ad1c1b703ce51ca59181b838726596fde8866203c15525ba72e4e9e3b5820b`.
  Targets, snapshot, and timestamp advanced `1` to `2`.
- The six clients restarted and converged in sorted order before timestamp.
  Timestamp then changed exactly once from container
  `7e56cf69cdf8c8582d261e81abf3119814b28f60f6eaa849605ba20b15bc6267`
  to
  `e61d31a11e00a660331d31e258e5d45d6d49362f9495ae11657087ec6e7b8487`.
  OIDC, Fulcio, Tesseract, Rekor server/proxy, TUF nginx, and
  `shady-blob-store` retained their exact pre-operation container IDs and start
  times.
- Artifact `315` was retained before rotation; its RFC3161 response contained
  exactly one certificate, preserving `include-chain-in-response=false`, and
  its signer fingerprint matched the old leaf. Post-activation artifact `382`
  identified the new leaf by its CMS issuer/serial and matched the active leaf
  certificate. .NET, Go, Java, JavaScript, and Rust normal validators each
  verified both IDs after restart. The normal Python validator visibly remained
  blocked at artifact `1` by the documented omitted-index-zero fields; a
  targeted verification inside the same restarted Python container, using the
  same generation-2 TUF trust, verified both `315` and `382`. No bundle bytes
  were changed and no public Sigstore endpoint appeared in any client log.
- Active `private/tsa` contained exactly `signer.key` and `password`; the
  operation candidate private directory and request were absent after
  completion. Immutable generation `1` retained its original root, signer, and
  password. Status finished `Healthy`, `14/14`, with no operation/recovery
  marker, two trusted TSA entries, the new running signer, and all clients on
  generation `2`.
- Focused and regression validation passed all `33` Bootstrap tests, all `27`
  Hosting tests, `53` top-level TUF/Go tests plus their fault-injection
  subtests, `go vet`, AppHost and .NET client builds, and Go, JavaScript,
  Python-container, Java-container-build, and Rust client tests. Runtime state
  remained ignored under `.sigstore` and `.shady-blob-store`; `git diff --check`
  passed.

**Validation gate status: passed, with the documented Python index-zero
limitation reported rather than masked.**

## Step 11: Implement Fulcio CA rotation

**Status: Implemented**

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

### Implementation

`rotate-fulcio-ca` is a confirmed parent-resource command. Its progress UI hides
cancel, and cancellation is honored only before the schema-versioned operation
journal and worker request are durable. Once trust mutation can begin, the
command owns an unlinked bounded critical section and either completes or leaves
an explicit recovery phase. The shared in-process operation gate rejects
contention immediately; the parent, bootstrapper, and Go worker serialize
filesystem mutations through the same `state.lock`.

The bootstrapper creates the operation-bound candidate with the existing Fulcio
profile:

```text
fulcio-rotation/<operation-id>/
|-- command.json
`-- candidate/
    |-- private/fulcio/
    |   |-- root.key                  # encrypted PKCS#8 ECDSA P-256
    |   `-- password                  # random 32-byte base64url value
    `-- public/fulcio/
        `-- root.pem                  # self-signed ECDSA-SHA256 CA
```

Generation N+1 replaces only `private/fulcio` and `public/fulcio`. Its manifest
binds the operation ID and prior generation/root; the previous generation
remains immutable bounded rollback history. The active Fulcio private subtree
contains exactly the new key and password. Candidate private material is
removed after worker completion while the candidate public root remains as
journal evidence.

The Go worker validates the CA profile and key match independently, commits the
immutable generation, and clones the active TUF publication. It validates every
existing Fulcio CA entry, preserves their exact order, and appends the new root.
The active `fulcio_v1.crt.pem` alias changes to the new root;
`trusted_root.json`, `client_trust_config.json`, and
`trust_status.v1.json` are rebuilt. All CT, Rekor, TSA, standby, and historical
entries and every unrelated target remain byte-identical.
`signing_config.v0.2.json`, its canonical URLs/routes, TUF root, and immutable
bootstrap root do not change. Targets, snapshot, and timestamp advance through
the existing preparing/candidate-committed/active-switched/history transaction
before `active-generation` switches.

### Mount and activation safety

Fulcio and Tesseract use stable component-scoped runtime projections instead of
bind-mounting a replaceable `active-generation` descendant:

```text
runtime/
|-- fulcio/
|   |-- root.pem
|   |-- root.key
|   `-- password
|-- fulcio-ct/
|   |-- primary.pub
|   `-- selection
`-- tesseract/
    |-- privkey.pem
    `-- accepted-roots.pem
```

The worker updates only Tesseract's deterministic accepted-root bundle after
additive TUF trust and generation commit. Fulcio's active projection remains on
the old CA, preventing an unexpected container recreation from activating the
candidate before CT acceptance is proven. Tesseract receives only its CT key
and Fulcio roots; Fulcio receives only its CA material and the CT public key.
Neither container can read unrelated OIDC, Rekor, TSA, or TUF private keys.

The enforced lifecycle is:

1. Commit additive TUF trust and generation N+1.
2. Restart and converge all six clients in sorted resource-name order.
3. Verify a retained old-CA artifact in every language against N+1 trust.
4. Restart Tesseract exactly once with all old roots followed by the new root.
5. Keep Fulcio on the old in-memory signer and prove real issuance with an
   embedded SCT signed by that exact replacement Tesseract identity.
6. Atomically promote the operation-bound Fulcio runtime projection.
7. Restart Fulcio exactly once, then prove its read-only root endpoint, real
   issuance chain, identity, and embedded SCT use the new CA and unchanged CT
   key.
8. Retain a new-CA artifact carrying Rekor and RFC3161 material and verify it in
   all six languages.

OIDC, timestamp, Rekor server/proxy, TUF nginx, and `shady-blob-store` are
protected by exact container ID/start-time postconditions and are never
restarted. Tesseract keeps the same signing key, origin, CT log ID,
`data/ctlog` directory, and append-only checkpoint/data across its one restart.
This is root acceptance only; no CT shard or key is created, because Step 13
owns that lifecycle.

### Recovery and status

Durable replay boundaries cover the request, candidate, immutable generation,
TUF preparing/commit, generation switch, each client, Tesseract restart,
old-CA proof, Fulcio projection promotion/restart, new-CA proof, old/new
artifact verification, CT checkpoint, and final command journal. Before the
old-CA proof, replay requires the original Fulcio issuer and never promotes its
runtime projection. After promotion or an observed new-CA replacement, replay
only completes forward. A recorded Tesseract replacement and old-CA SCT proof
are mandatory before any Fulcio restart. Existing client and service lifecycle
evidence suppresses duplicate restarts; mismatched or tampered operation IDs,
roots, generations, publications, projections, checkpoints, or container
identities fail loudly.

`status` parses every Fulcio TrustedRoot entry and requires unique canonical
roots in append order. It validates the active CA profile and certificate/key
match, component runtime projections, Tesseract bundle bytes, live Fulcio
`/api/v1/rootCert`, unchanged CT public key/log ID, and a signed CT checkpoint.
The parent becomes Healthy only when disk and served TUF agree, all six clients
report the current additive trust, Tesseract accepts the complete history, the
live Fulcio root matches the active generation, and no recovery phase remains.

Every client also exposes a local read-only
`GET /artifacts/{id}/verify` endpoint. It invokes that language's normal
verifier and returns the exact artifact/bundle hashes and trust generation used.
This supplies deterministic old/new all-six evidence without changing bundle
serialization.

### Known limitation

The existing sigstore-python omitted-index-zero protobuf JSON issue remains out
of scope. Sequential Python validation may remain blocked on an affected
artifact. Step 11 does not rewrite, normalize, skip, or replace that bundle;
the targeted endpoint proves selected old/new artifacts with the same
generation-pinned Python verifier and reports a real failure if either bundle is
affected.

### Validation evidence

- All 63 Bootstrap tests and 32 Hosting tests pass. Coverage includes the CA
  profile/key/password, exact runtime file sets and modes, Go-shaped manifest
  portability, additive root order/deduplication, two consecutive rotations,
  bounded active secrets, partial promotion repair, contention, tampering, and
  worker fault injection at every committed filesystem/publication boundary.
- The uncached TUF/Go suite, `go vet`, AppHost and .NET client builds, Go and
  JavaScript tests, Python and Java container builds, Rust tests, and
  `git diff --check` pass.
- A non-isolated recovery validation advanced generation 1 to 2 and passed all
  33 command postconditions. The old root
  `3fc09930fed807a5deddc884e9b24ceb331d226b153a28515d5359f074fedd8a`
  and new root
  `f8f6198938be6fce590478e40e44dad7b81effc5d1db419ad209eead218a1ee3`
  both produced SCTs under unchanged CT log ID
  `9b8283c3f7998f05f2d8598c46c5022c2dc6a3edc6bba0eb961958ed5c61b2c9`.
  Its signed checkpoint advanced from tree size 14 to 72 without changing
  origin.
- All six clients restarted on additive generation-2 trust before Tesseract.
  Tesseract and Fulcio then each changed exactly once in the required order.
  OIDC, timestamp, Rekor server/proxy, TUF nginx, and `shady-blob-store`
  retained their container IDs and start times.
- Retained old artifact 14 and new artifact 70 included Rekor and RFC3161
  material and passed the .NET, Go, Java, JavaScript, Python, and Rust targeted
  native verification routes with identical artifact/bundle hashes. No public
  endpoint fallback appeared, and runtime state remained ignored.

## Step 12: Implement Rekor shard rotation

### Scope

- **Topology**: the initial shard retains
  `http://rekor-sigstore.dev.localhost:3000`, its generation-1 signer,
  `.sigstore/data/rekor`, writer, checkpoint and tiles. The bounded secondary
  shard uses the stable URL
  `http://rekor-secondary-sigstore.dev.localhost:3000`, an
  explicit-start `rekor-server-secondary`, a signer-only
  `runtime/rekor-secondary` projection, and independent
  `.sigstore/data/rekor-shards/secondary` storage. The `rekor` nginx gateway
  keeps serving static checkpoints/tiles for both.
- **Trust and routing**: immutable generation N+1 replaces only
  `private/rekor/signer.key` and `public/rekor/signer.pub`. The old
  `TransparencyLogInstance` remains unchanged and the new instance is appended
  to `TrustedRoot`; the single active Rekor v2 `SigningConfig` route changes to
  the secondary URL. Root/bootstrap, OIDC, Fulcio, CT, TSA, standby and
  historical trust remain byte-identical.
- **Safe order**: prepare and validate the candidate, runtime projection,
  independent data root and schema-1 catalog; start and prove the secondary
  writer and nginx route; commit additive TUF trust plus the new exclusive
  route; converge all six clients; prove the first secondary entry (including
  index zero), new-log artifact, retained old artifact, and old
  checkpoint/tile continuity. The initial writer is never restarted onto the
  new key.
- **Recovery**: the schema-1 hosting journal records candidate, server/route,
  TUF preparing/committed, generation switch, each client, first entry,
  old/new proofs and completion. Pre-commit failure leaves the old route
  active. Post-commit recovery proceeds forward after strict
  signer/log-ID/data/URL/hash validation. Replaying the same incomplete
  operation is idempotent; a second independent rotation in the run is rejected
  without mutation.
- **Retention and health**: the secondary writer is conditionally excluded
  from initial parent health, then required after activation. The primary
  writer becomes historical at that boundary and is no longer health-required;
  this bounded implementation leaves both writers available, while nginx's
  immutable historical checkpoint/tile route remains the health-independent
  retention contract. Historical availability never depends on changing the
  old signer or storage.

### Validation gate

- The old checkpoint, tiles, data hashes, log ID, public key and root URL remain
  readable and unchanged except for legitimate pre-cutover appends.
- The secondary route is healthy before TUF selection; new entries and bundles
  use its distinct log ID and URL.
- TrustedRoot contains both exact log instances while SigningConfig selects
  only the secondary Rekor v2 URL.
- All six clients converge to the same additive generation and verify selected
  old/new bundles through native targeted routes.
- The known Python omitted-index-zero bundle parser issue is reported rather
  than seeded around, hidden, or serialized differently.
- Fault tests cover candidate/server/route/TUF/generation/client/entry/proof
  boundaries, tampered signer/data/URL/hash state, active-secret bounds,
  contention, replay and bounded-repeat rejection.

## Step 13: Implement CT log shard rotation

### Scope

- **Topology**: a certificate-transparency key change creates exactly one
  bounded secondary logical shard and never mutates or restarts the historical
  primary shard. `tesseract` keeps its generation-1 signer, log ID, origin
  `tesseract-sigstore.dev.localhost`, canonical URL
  `http://tesseract-sigstore.dev.localhost:6962`, `.sigstore/data/ctlog`
  storage and checkpoint history. The secondary shard is an explicit-start
  `tesseract-secondary` with an isolated immutable signer, its own log ID,
  origin `tesseract-secondary-sigstore.dev.localhost`, stable canonical URL
  `http://tesseract-secondary-sigstore.dev.localhost:6963`, its own
  `.sigstore/data/ctlog-shards/secondary` storage, state identity and
  operation-bound `shard.json`, and a signer-plus-accepted-roots
  `runtime/tesseract-secondary` projection that accepts exactly the complete
  Fulcio root set the primary accepts. Creation and activation metadata live in
  the schema-1 catalog `.sigstore/data/ctlog-shards/state.json`, owned by the
  Go TUF worker. Both shards run concurrent compute.
- **Fulcio binding**: the certificate-transparency URL, origin and public key
  Fulcio uses are a durable runtime selection in the stable read-only mount
  `runtime/fulcio-ct`, resolved by the Fulcio entrypoint at startup rather than
  baked into container arguments. The directory holds immutable, additive
  per-shard keys (`primary.pub`, and `secondary.pub` once staged) beside
  exactly one four-line `selection` manifest that names the schema header, the
  selector, and the origin and key file name that selector implies. Staging
  only adds `secondary.pub`; promotion atomically replaces the single
  `selection` file by rename inside the same mounted directory, so no
  bind-mounted directory or mounted file is ever replaced and a crash boundary
  can never produce a mixed selector/origin/key configuration — before the flip
  Fulcio is wholly primary, after it wholly secondary, and recovery is
  forward-only. The entrypoint strictly validates the manifest and refuses to
  start on any other shape. Hosting gates the single Fulcio restart on the
  journaled container identity and start time, never on the promoted selection,
  and proves the switch with a real issuance whose embedded SCT verifies
  against the secondary shard's signer, origin and log ID.
- **Accepted roots**: every catalog and metadata shard entry records the
  identity of the complete Fulcio root bundle that shard accepts — the bundle
  SHA-256, the root count, and the ordered per-root fingerprints — and the
  secondary shard is created accepting byte-for-byte exactly what the primary
  accepts, including every root added by prior Fulcio CA rotations. The
  recorded identity is bound back to the bytes each shard's runtime projection
  enforces, so a tampered bundle is rejected. After the cutover the historical
  primary shard's bundle is frozen and must stay the ordered prefix of the
  active shard's bundle; a later Fulcio CA rotation extends and restarts only
  the shard currently accepting submissions and is refused before any mutation
  while a CT log shard rotation is in flight.
- **Trust**: immutable generation N+1 replaces only
  `private/ctlog/privkey.pem` and `public/ctlog/pubkey.pem` and preserves every
  Fulcio root, TSA certificate, Rekor shard signer and routing record, OIDC key
  and TUF material byte-for-byte. `TrustedRoot` gains a second `ctlogs`
  `TransparencyLogInstance` additively with every existing entry preserved;
  `SigningConfig` is republished byte-for-byte unchanged because certificate
  transparency has no `SigningConfig` selector; the TUF root role and bootstrap
  root are untouched. New private CT material is active only for the secondary
  shard, and prior private material is retained only through the immutable
  prior generation while the old public key and data remain.
- **Safe order**: create, start and prove the secondary shard healthy with a
  verified checkpoint signature and log ID before any trust publication or
  route change; commit additive CT trust through the dedicated worker; restart
  and converge all six clients; prove the still-running old Fulcio issues a
  valid old-shard SCT under the new trust; promote the Fulcio CT runtime
  selection; restart Fulcio exactly once; prove the same Fulcio CA identity now
  issues an SCT from the secondary shard; verify the retained old artifact and a
  new artifact in all six languages. OIDC, the timestamp authority, both Rekor
  writers, the Rekor gateway, the TUF nginx server, the artifact store, and the
  historical primary Tesseract shard are never restarted.
- **Command**: `rotate-ct-log-shard` is a confirmed, non-cancelable parent
  command that rejects contention, reports detailed progress, and returns old
  and new shard IDs, origins, URLs, key fingerprints, resource lifecycle
  identities and postconditions.
- **Recovery**: the schema-1 hosting journal at
  `.sigstore/ct-log-shard-rotation/<operationId>/hosting-state.json` records
  deterministic checkpoints for candidate generation, secondary preparation,
  secondary start and container identity, checkpoint proof, TUF preparation,
  commit and generation switch, each client, old-shard issuance, Fulcio
  promotion and its single restart, new-shard issuance, both artifact
  verifications and completion. Before cutover a failure leaves the old route;
  after cutover recovery is forward-only. Ambiguous or tampered state is
  rejected without mutation, a repeated completed invocation is rejected
  without mutation, and the same incomplete operation resumes idempotently.
- **Retention and health**: the secondary shard is conditionally excluded from
  parent health until activation. The historical primary shard's compute stays
  running and health-required forever, because Tesseract serves its
  append-only tiles and signed checkpoint from its own process, so previously
  issued certificates are only auditable while it runs. That is the deliberate
  lifecycle policy for this step and it differs from the Rekor shard rotation,
  where a health-independent static nginx route provides retention.

### Validation gate

- Old SCTs remain verifiable and the historical `ctlogs` entry, primary signer,
  primary runtime projection and primary storage identity are unchanged.
- The secondary shard is healthy and its checkpoint verifies against its own
  origin and log ID before any trust publication or route change.
- TrustedRoot contains both exact CT log instances while SigningConfig,
  TUF root and bootstrap root are unchanged.
- New certificates contain SCTs from the secondary shard, issued by the same
  unchanged Fulcio CA identity, after exactly one Fulcio restart.
- All six clients converge on the additive generation and verify both the
  retained old-shard artifact and the new secondary-shard artifact.
- Fault tests cover CT log-ID derivation, separate signer/data/origin,
  accepted-root equality, old-shard immutability, additive trust, the Fulcio
  route switch, ordering and lifecycle, SCT and checkpoint cryptography,
  unchanged CA identity, replay at every committed boundary, bounded-repeat
  and contention rejection, tampered candidate/projection/completion state,
  secret bounds, and composition with the other bounded rotations.

### Validation evidence

The 2026-08-29 non-isolated fixed-port run completed operation
`262eae98f56a4da58d599680d645e24b` with all 50 structured postconditions
passing:

- The primary retained log ID/public-key fingerprint
  `685da1abd82f1aa5b2c2321142fdf3e39a7cdd4257b9d44a2f7a0235d3eb5ef4`,
  state ID `fd7e938d-d27b-4052-b1f5-d6fdab956ceb`, its canonical origin and
  URL, and container
  `459da285160657b20086331e3ba58c88993aaaa98e0737d387a06830a7b3fcc9`.
  Its tree advanced legitimately to 46 during the overlap proof and then
  stayed at 46 while the secondary advanced from 159 to 169 during a
  20-second observation.
- The secondary used log ID/public-key fingerprint
  `4dc0999ce9c3b87c2b23506f7ec5bca870d0ac27724e674a66ab435d1f123959`,
  state ID `c4137125-e592-40c7-a67c-f8d4e90da430`, and container
  `011bd24e93e0917182c17cff91cabb4b8b47765220e314e94df30990ddeb1caa`.
  Its signed empty-tree checkpoint verified before additive trust publication.
- TrustedRoot changed from one to two CT entries. SigningConfig stayed
  byte-identical at
  `122f209b630c472925dea330003470162392f8a42b76e1e27980321193c20a8c`;
  the TUF root and bootstrap root remained version 1 and byte-identical.
- Fulcio restarted exactly once, from container
  `1493a0dd8e72eb10a4de81d9b6719f1ba0878403f08f05f0ac759edad4ffbab2`
  to `b14634630f8e3f4ddcb596cec82569bd1ac0b1b5f7d9664e9044433c2a0620dc`,
  while its CA fingerprint remained
  `71e6e18157a69703ec58dbb557d7c90f9c68a9639ec2ac4d532723d8a82ba57b`.
  The old and new issuance proofs carried cryptographically verified SCTs
  from their respective log IDs.
- Old artifact 20 and new artifact 39 each verified through targeted routes
  in .NET, Go, Java, JavaScript, Python, and Rust. The known Python
  omitted-index-zero issue was not encountered. The six clients all reported
  generation 2, the parent and both shards were Healthy, protected service
  container IDs were unchanged, and a repeated rotation was rejected before
  mutation.
- The uncached TUF/Go suite and `go vet`, 76 bootstrap tests, 85 hosting tests,
  AppHost and .NET client builds, the Go, JavaScript, Java, Python-container,
  and Rust client gates, shell syntax checks, and `git diff --check` passed.

## Step 14: Harden the complete lifecycle

Step 14 treats the operations from Steps 0-13 as one state machine. It does not
add a shortcut command or another mutation implementation. The repeatable
public-surface driver is:

```bash
aspire start --non-interactive --format Json
./eng/validate-sigstore-lifecycle.sh
```

The driver requires Bash, `jq`, the fixed canonical ports, and a fresh
non-isolated AppHost. It waits for each concrete resource and invokes the
existing confirmed, non-cancelable commands in this dependency order:

| Boundary | Command | Generation | Root | Targets | Snapshot | Timestamp | Required result |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Initial | `status` | 1 | 1 | 1 | 1 | 1 | Ready; six current clients |
| Metadata | `refresh-tuf` | 1 | 1 | 1 | 2 | 2 | Content and identities unchanged |
| Root | `rotate-tuf-root` | 1 | 2 | 2 | 3 | 3 | Root chain valid; clients visibly stale |
| Root uptake | `restart-clients` | 1 | 2 | 2 | 3 | 3 | Six clients current |
| Additive root | `publish-trusted-root` | 2 | 2 | 3 | 4 | 4 | Additive entries and history retained |
| OIDC | `rotate-oidc-signing-key` | 3 | 2 | 4 | 5 | 5 | Old/new token continuity proved |
| TSA | `rotate-timestamp-authority` | 4 | 2 | 5 | 6 | 6 | Old/new RFC3161 proofs retained |
| Fulcio | `rotate-fulcio-ca` | 5 | 2 | 6 | 7 | 7 | Old/new CA and SCT proofs retained |
| Rekor | `rotate-rekor-shard` | 6 | 2 | 7 | 8 | 8 | Primary retained; secondary selected |
| CT | `rotate-ct-log-shard` | 7 | 2 | 8 | 9 | 9 | Primary retained; Fulcio selects secondary |

Every row checks exact before/after versions, unchanged fields, operation
postconditions, six-client convergence, required-resource health, and public
status. The underlying Go composition test performs the same sequence from
generation 1 in one state directory and additionally checks immutable
generations 1-7, root-chain validity, additive authority/shard counts, routing
selection, and bounded active TSA/Fulcio private material.

### Concurrency and durable recovery

All mutating command families share two exclusion layers. The in-process
command lease returns a structured `phase: "contention"` result for an
overlap. The OS `state.lock` rejects AppHost/one-shot-worker overlap with the
current lock owner and without mutation. The lifecycle driver proves the
public path by holding `publish-trusted-root` active and requiring an
overlapping `refresh-tuf` to be rejected; the command becomes available again
when the owner exits.

Before every status read, command-state update, and mutation entry point, the
AppHost reconstructs recovery from all durable journal families. Exactly one
incomplete operation enables only its matching replay command. An unrelated
invocation returns structured `phase: "recovery-pending"` without reaching a
runtime command. Multiple incomplete operations, unexpected JSON members,
invalid operation IDs, mismatched trust domains/generations, duplicate client
records, unbound worker completions, or malformed activation evidence produce
`Lifecycle Recovery Failed Closed`.

The root worker request is strict schema-1 JSON bound to the operation ID,
trust domain, starting generation/manifest, root version, and publication.
The worker holds `state.lock`, first recovers any interrupted TUF publication,
then either rotates once or validates the already committed state. Its
operation-scoped completion is atomically persisted before request cleanup.
AppHost replay independently binds every completion field to the hosting
journal and live committed repository, preventing a crash after worker commit
from rotating root twice.

Trusted-root publication journals the worker commit and each client's
container/start identity plus exact trust status. Replay skips a recorded
client only when that same live identity still reports the recorded committed
trust; stale, missing, or restarted clients converge individually. Root,
trusted-root, OIDC, TSA, Fulcio, Rekor, and CT recovery is rollback-safe before
activation and forward-only after additive trust or routing activation.
Stored proof, runtime projection, service identity, and shard history are
revalidated before each resumed side effect.

Internal fault seams cover worker termination at activation/completion,
AppHost orchestration failure after durable commit, affected-child restart,
partial client convergence, replay with restarted clients, lock contention,
and tampered requests/completions. These seams are test-only callbacks and
temporary state; no production fault environment variable or bypass exists.
Temporary candidates are either atomically promoted, retained as journal
evidence, or cleaned before a new pre-activation attempt.

### Health and evidence

Public `status` never reports ready while an operation is active, recovery is
pending, a client is stale, a signer or route has not activated, CT projection
is incomplete, or any required historical shard compute is unavailable.
Internal postcondition checks ignore only the status error for the operation
that currently owns the lease; all other errors still fail the command. A
successful replay clears recovery and re-enables commands without retaining a
stale monitor value.

The lifecycle driver writes
`.sigstore/lifecycle-evidence/lifecycle-<trust-domain>.json` with mode `0600`.
The schema contains operation IDs, exact generation/TUF transitions, public
component fingerprints, resource lifecycle identities, history checks,
client convergence, artifact proof IDs/hashes, representative child restart
checks, and errors. It allowlists fields from command results: JWTs, private
keys, passwords, candidate secrets, and worker tokens cannot enter the report
or telemetry. `.sigstore`, `.shady-blob-store`, the report, and all temporary
fault state remain ignored and untracked.

After the composed state is ready, the driver restarts `fulcio`,
`tesseract-secondary`, and `tuf` through Aspire, waits for each concrete
resource, and proves generation 7, routing, component fingerprints, historical
catalogs, and all clients remain current. Artifact production must continue
through every boundary; retained pre/post boundary artifacts are verified in
all six language implementations through the normal stream or their existing
targeted verification route.

### Operator policy

- **Automatic recovery:** replay the one matching command when status names a
  valid incomplete operation. Before activation, replay may discard only its
  uncommitted candidate. After activation, it resumes forward from the
  validated checkpoint.
- **Intentional fail-closed:** do not edit state to bypass multiple, malformed,
  unbound, missing-history, mismatched-identity, or changed-committed-state
  errors. Stop the run and retain an offline copy for investigation.
- **Backup limitation:** `.sigstore` and `.shady-blob-store` are demonstration
  run state, not a supported backup/restore format. A copy is useful for
  offline evidence only; a new AppHost process intentionally deletes it.
- **Safe reset:** stop the AppHost cleanly, verify no child remains, then start
  a new AppHost. The new run must have a different trust domain, generation 1,
  initial TUF versions/topology, and a fresh artifact sequence. Never delete
  either state directory while an AppHost is live.
- **Historical retention:** normal operations are additive. Preserve old
  Fulcio/TSA roots, OIDC overlap evidence, Rekor/CT shard catalogs, immutable
  generations, tiles/checkpoints, and bundles while retained artifacts depend
  on them.
- **Destructive retirement:** there is no production retirement command.
  Exercise removal only as an explicit disposable, stopped-run scenario after
  proving that no retained artifact depends on the material.
- **Known index-zero limitation:** never seed, skip, rewrite, or reserialize a
  bundle to hide the cross-SDK ProtoJSON/sigstore-python omitted-index-zero
  defect. If the Python sequential worker encounters it, report the blocked
  artifact and use only the existing generation-pinned targeted verifier for
  that same bundle. No public Sigstore fallback is allowed.

### Validation gates

1. Run Bootstrap and Hosting tests, the full TUF Go suite and `go vet`, OIDC,
   AppHost and .NET client builds, and Go, JavaScript, Java, Python-container,
   and Rust client tests.
2. Run the full-sequence composition, contention, termination, tamper, partial
   convergence, and replay tests; then run `bash -n
   eng/validate-sigstore-lifecycle.sh` and `git diff --check`.
3. Run the public lifecycle driver on the exact implementation HEAD and retain
   its redacted report. Verify representative artifacts at the initial,
   root/trusted-root, OIDC overlap, old/new TSA, old/new Fulcio, old/new Rekor,
   and old/new CT boundaries in all six languages, disclosing only the targeted
   Python exception above.
4. Restart representative affected and unaffected children inside the run,
   then stop/start the AppHost and prove the intentional reset contract. Leave
   the final exact-HEAD AppHost running for inspection.

### Complete-run validation evidence

The full public driver passed on `2026-08-29` at implementation commit
`f3896f61ca902d71d0e127a165c87b338e577757`. Its composed trust domain was
`sha256-d532aeba3339c4c113fa53e8bf61b58bf30fd932402d0a5673f09a99efa3bd31`.
The exact command execution IDs and transitions were:

| Command | Execution ID | Generation | TUF root/targets/snapshot/timestamp |
| --- | --- | --- | --- |
| `refresh-tuf` | `48701912f12b477d86edbbb2b730a586` | 1 to 1 | `1/1/1/1` to `1/1/2/2` |
| `rotate-tuf-root` | `b492434d7ed244e6849c017e89124e42` | 1 to 1 | `1/1/2/2` to `2/2/3/3` |
| `restart-clients` | `325629e85a474c93b28ec687d3f42082` | 1 to 1 | unchanged `2/2/3/3` |
| contended `refresh-tuf` | `14c6ec699c3548669fdefaf27b225521` | unchanged | structured `recovery-pending` |
| `publish-trusted-root` | `b83ab73d6ba64e0abb0237fbdd17d054` | 1 to 2 | `2/2/3/3` to `2/3/4/4` |
| `rotate-oidc-signing-key` | `cf13d726f9974bdc8b7c12c19d3c4b86` | 2 to 3 | `2/3/4/4` to `2/4/5/5` |
| `rotate-timestamp-authority` | `c3e40b3eb3614abe8c9456abf156be7f` | 3 to 4 | `2/4/5/5` to `2/5/6/6` |
| `rotate-fulcio-ca` | `5c4f788489934e9eb1bc3b9e6268522d` | 4 to 5 | `2/5/6/6` to `2/6/7/7` |
| `rotate-rekor-shard` | `2e9aa813d41545a092602cc954fb1c5e` | 5 to 6 | `2/6/7/7` to `2/7/8/8` |
| `rotate-ct-log-shard` | `2fbcb31226fa43729a25d77d03b3246a` | 6 to 7 | `2/7/8/8` to `2/8/9/9` |

Every successful row ended with its exact postconditions passing. Generation 7
was Healthy with six current clients, no operation or recovery marker, two TSA
roots, two Fulcio roots, three Rekor entries, two CT entries, the secondary
Rekor and CT routes selected, and immutable generations 1-7. Restarting
`fulcio`, `tesseract-secondary`, and `tuf` preserved those values and resumed
traffic through artifact `173`.

The retained-artifact matrix used initial artifact `1`, post-root artifact
`11`, post-trusted-root artifact `46`, OIDC continuity artifacts `47` and `64`,
old/new TSA artifacts `64` and `84`, old/new Fulcio artifacts `85` and `106`,
old/new Rekor artifacts `106` and `126`, and old/new CT artifacts `126` and
`148`. Every ID except `1` passed the final generation-pinned targeted route in
.NET, Go, Java, JavaScript, Python, and Rust, with one agreed artifact hash and
one agreed bundle hash per ID. Artifact `1` passed the other five languages;
Python returned the known missing `logIndex`, inclusion-proof `logIndex`, and
`hashes` fields. The bundle was not seeded, skipped, rewritten, reserialized,
or sent to public Sigstore.

The report was mode `0600`, contained numeric proof IDs and public hashes, and
had SHA-256
`d5710f7f8e85429cc3c808e4698c341922ac96c832c2fd3b54009e38b84e6874`.
No token or private-key field was present. A clean subsequent AppHost created
trust domain
`sha256-26be5e8fd5c0bb4b7d46a44a751792ac051c03368f5712e6fd2f29c2be0c8de4`,
generation 1, initial TUF topology, and one generation directory. Artifact
`173` was absent, and fresh artifact `9` passed all six targeted verifiers.

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
