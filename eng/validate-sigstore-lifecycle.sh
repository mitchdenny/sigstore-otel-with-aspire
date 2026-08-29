#!/usr/bin/env bash
set -euo pipefail

command -v aspire >/dev/null
command -v jq >/dev/null

state_dir="${SIGSTORE_STATE_PATH:-.sigstore}"
evidence_dir="${state_dir}/lifecycle-evidence"
mkdir -p "${evidence_dir}"
work_dir="$(mktemp -d "${state_dir}/.lifecycle-validation.XXXXXX")"
operations_file="${work_dir}/operations.jsonl"
started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
trap 'rm -rf "${work_dir}"' EXIT

required_resources=(
  oidc
  tesseract
  fulcio
  timestamp
  rekor-server
  rekor
  tuf
  shady-blob-store
  dotnet-client
  go-client
  python-client
  javascript-client
  java-client
  rust-client
)

completed_resources=(
  sigstore-bootstrap
  sigstore-state-ready
  tuf-bootstrap
  tuf-state-ready
)

for resource in "${completed_resources[@]}"; do
  aspire wait "${resource}" --status down --non-interactive >/dev/null
done

for resource in "${required_resources[@]}"; do
  aspire wait "${resource}" --non-interactive >/dev/null
done

status() {
  local output="$1"
  aspire resource sigstore status --non-interactive >"${output}" || true
  jq -e '.schemaVersion == 1' "${output}" >/dev/null
}

assert_status() {
  local output="$1"
  local generation="$2"
  local root_version="$3"
  local targets_version="$4"
  local ready="$5"
  jq -e \
    --argjson generation "${generation}" \
    --argjson root_version "${root_version}" \
    --argjson targets_version "${targets_version}" \
    --argjson ready "${ready}" \
    '
      .disk.generation == $generation
      and .disk.tufRootVersion == $root_version
      and .disk.tufTargetsVersion == $targets_version
      and (.clients | length) == 6
      and .ready == $ready
      and (
        if $ready then
          (.errors | length) == 0
          and all(.clients[]; .ready)
          and all(
            .requiredResources[];
            .state == "Running" and .health == "Healthy"
          )
        else
          (.errors | length) > 0
        end
      )
    ' "${output}" >/dev/null
}

record_operation() {
  local input="$1"
  jq -c '
    {
      command,
      operationId,
      success,
      phase,
      startedAtUtc,
      completedAtUtc,
      before: (
        .before
        | if . == null then null else {
            trustDomainId: .tuf.trust.trustDomainId,
            generation: .tuf.trust.generation,
            generationId: .tuf.trust.generationId,
            generationManifestSha256:
              .tuf.trust.generationManifestSha256,
            rootVersion: .tuf.metadata.root.version,
            targetsVersion: .tuf.metadata.targets.version,
            snapshotVersion: .tuf.metadata.snapshot.version,
            timestampVersion: .tuf.metadata.timestamp.version,
            trustedRootSha256: .tuf.trust.trustedRootSha256,
            signingConfigSha256: .tuf.trust.signingConfigSha256,
            publicationId: .tuf.trust.publicationId
          } end
      ),
      after: (
        .after
        | if . == null then null else {
            trustDomainId: .tuf.trust.trustDomainId,
            generation: .tuf.trust.generation,
            generationId: .tuf.trust.generationId,
            generationManifestSha256:
              .tuf.trust.generationManifestSha256,
            rootVersion: .tuf.metadata.root.version,
            targetsVersion: .tuf.metadata.targets.version,
            snapshotVersion: .tuf.metadata.snapshot.version,
            timestampVersion: .tuf.metadata.timestamp.version,
            trustedRootSha256: .tuf.trust.trustedRootSha256,
            signingConfigSha256: .tuf.trust.signingConfigSha256,
            publicationId: .tuf.trust.publicationId
          } end
      ),
      resourceLifecycleIdentities: [
        .resources[]? | {
          resource,
          beforeContainerId,
          afterContainerId,
          beforeStartTimeUtc,
          afterStartTimeUtc
        }
      ],
      preservedHistoryChecks: [
        .postconditions[]?
        | select(
            .passed
            and (
              .name
              | test("histor|additive|unchanged|preserv|retained")
            )
          )
        | .name
      ],
      artifactProofIds: [
        ..
        | objects
        | to_entries[]
        | select(.key | test("artifactId$"; "i"))
        | .value
        | strings
      ] | unique,
      proofHashes: [
        ..
        | objects
        | to_entries[]
        | select(.key | test("(artifact|checkpoint).*sha256$"; "i"))
        | .value
        | strings
      ] | unique,
      errors
    }
  ' "${input}" >>"${operations_file}"
}

run_operation() {
  local command_name="$1"
  local output="${work_dir}/${command_name}.json"
  aspire resource sigstore "${command_name}" --non-interactive >"${output}" || true
  jq -e --arg command_name "${command_name}" \
    '.command == $command_name and .success and .phase == "complete"' \
    "${output}" >/dev/null
  record_operation "${output}"
}

assert_transition() {
  local command_name="$1"
  local before_generation="$2"
  local before_root="$3"
  local before_targets="$4"
  local before_snapshot="$5"
  local before_timestamp="$6"
  local after_generation="$7"
  local after_root="$8"
  local after_targets="$9"
  local after_snapshot="${10}"
  local after_timestamp="${11}"
  jq -e \
    --argjson bg "${before_generation}" \
    --argjson br "${before_root}" \
    --argjson bt "${before_targets}" \
    --argjson bs "${before_snapshot}" \
    --argjson btime "${before_timestamp}" \
    --argjson ag "${after_generation}" \
    --argjson ar "${after_root}" \
    --argjson at "${after_targets}" \
    --argjson as "${after_snapshot}" \
    --argjson atime "${after_timestamp}" \
    '
      .success
      and .before.tuf.trust.generation == $bg
      and .before.tuf.metadata.root.version == $br
      and .before.tuf.metadata.targets.version == $bt
      and .before.tuf.metadata.snapshot.version == $bs
      and .before.tuf.metadata.timestamp.version == $btime
      and .after.tuf.trust.generation == $ag
      and .after.tuf.metadata.root.version == $ar
      and .after.tuf.metadata.targets.version == $at
      and .after.tuf.metadata.snapshot.version == $as
      and .after.tuf.metadata.timestamp.version == $atime
      and .before.tuf.trust.trustDomainId
        == .after.tuf.trust.trustDomainId
      and (.errors | length) == 0
      and all(.postconditions[]; .passed)
    ' "${work_dir}/${command_name}.json" >/dev/null
}

run_publish_with_contention() {
  local publish_output="${work_dir}/publish-trusted-root.json"
  local contention_output="${work_dir}/contention.json"
  aspire resource sigstore publish-trusted-root --non-interactive \
    >"${publish_output}" &
  local publish_pid=$!
  local observed=false
  for _ in $(seq 1 120); do
    local current="${work_dir}/contention-status.json"
    status "${current}"
    if jq -e \
      '.operation.command == "publish-trusted-root"' \
      "${current}" >/dev/null; then
      observed=true
      break
    fi
    sleep 0.25
  done
  if [[ "${observed}" != true ]]; then
    wait "${publish_pid}" || true
    echo "did not observe publish-trusted-root as active" >&2
    return 1
  fi
  aspire resource sigstore refresh-tuf --non-interactive \
    >"${contention_output}" || true
  jq -e '
    .success == false
    and (
      .phase == "contention"
      or .phase == "recovery-pending"
    )
    and (.errors | length) == 1
  ' "${contention_output}" >/dev/null
  wait "${publish_pid}" || true
  jq -e '
    .command == "publish-trusted-root"
    and .success
    and .phase == "complete"
  ' "${publish_output}" >/dev/null
  record_operation "${contention_output}"
  record_operation "${publish_output}"
}

initial_status="${work_dir}/initial-status.json"
status "${initial_status}"
assert_status "${initial_status}" 1 1 1 true
trust_domain="$(jq -r '.disk.trustDomainId' "${initial_status}")"

run_operation refresh-tuf
assert_transition refresh-tuf 1 1 1 1 1 1 1 1 2 2
assert_status_file="${work_dir}/status-after-refresh.json"
status "${assert_status_file}"
assert_status "${assert_status_file}" 1 1 1 true

run_operation rotate-tuf-root
assert_transition rotate-tuf-root 1 1 1 2 2 1 2 2 3 3
assert_status_file="${work_dir}/status-after-root.json"
status "${assert_status_file}"
assert_status "${assert_status_file}" 1 2 2 false

run_operation restart-clients
assert_transition restart-clients 1 2 2 3 3 1 2 2 3 3
assert_status_file="${work_dir}/status-after-client-restart.json"
status "${assert_status_file}"
assert_status "${assert_status_file}" 1 2 2 true

run_publish_with_contention
assert_transition publish-trusted-root 1 2 2 3 3 2 2 3 4 4
assert_status_file="${work_dir}/status-after-trusted-root.json"
status "${assert_status_file}"
assert_status "${assert_status_file}" 2 2 3 true

run_operation rotate-oidc-signing-key
assert_transition rotate-oidc-signing-key 2 2 3 4 4 3 2 4 5 5
assert_status_file="${work_dir}/status-after-oidc.json"
status "${assert_status_file}"
assert_status "${assert_status_file}" 3 2 4 true

run_operation rotate-timestamp-authority
assert_transition rotate-timestamp-authority 3 2 4 5 5 4 2 5 6 6
assert_status_file="${work_dir}/status-after-tsa.json"
status "${assert_status_file}"
assert_status "${assert_status_file}" 4 2 5 true

run_operation rotate-fulcio-ca
assert_transition rotate-fulcio-ca 4 2 5 6 6 5 2 6 7 7
assert_status_file="${work_dir}/status-after-fulcio.json"
status "${assert_status_file}"
assert_status "${assert_status_file}" 5 2 6 true

run_operation rotate-rekor-shard
assert_transition rotate-rekor-shard 5 2 6 7 7 6 2 7 8 8
assert_status_file="${work_dir}/status-after-rekor.json"
status "${assert_status_file}"
assert_status "${assert_status_file}" 6 2 7 true

run_operation rotate-ct-log-shard
assert_transition rotate-ct-log-shard 6 2 7 8 8 7 2 8 9 9

composed_status="${work_dir}/composed-status.json"
status "${composed_status}"
assert_status "${composed_status}" 7 2 8 true

child_restarts="${work_dir}/child-restarts.jsonl"
for resource in fulcio tesseract-secondary tuf; do
  aspire resource "${resource}" restart \
    --include-hidden \
    --non-interactive >/dev/null
  aspire wait "${resource}" --non-interactive >/dev/null
  restart_status="${work_dir}/status-after-${resource}-restart.json"
  status "${restart_status}"
  assert_status "${restart_status}" 7 2 8 true
  jq -cn \
    --arg resource "${resource}" \
    --arg completed_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{resource: $resource, command: "restart", success: true,
      completedAtUtc: $completed_at}' >>"${child_restarts}"
done

final_status="${work_dir}/final-status.json"
status "${final_status}"
assert_status "${final_status}" 7 2 8 true
jq -e --arg trust_domain "${trust_domain}" '
  .disk.trustDomainId == $trust_domain
  and (.timestampAuthority.trustedAuthorities | length) == 2
  and (.fulcio.trustedRoots | length) == 2
  and .rekor.trustedRootTlogCount == 3
  and .ctLog.trustedRootCtlogCount == 2
  and (.recovery == null)
  and (.operation == null)
' "${final_status}" >/dev/null
jq -e --slurpfile composed "${composed_status}" '
  .disk == $composed[0].disk
  and .timestampAuthority.activeRootSha256
    == $composed[0].timestampAuthority.activeRootSha256
  and .timestampAuthority.activeLeafSha256
    == $composed[0].timestampAuthority.activeLeafSha256
  and .fulcio.activeRootSha256
    == $composed[0].fulcio.activeRootSha256
  and .rekor.activeShardId == $composed[0].rekor.activeShardId
  and .ctLog.activeShardId == $composed[0].ctLog.activeShardId
' "${final_status}" >/dev/null

report="${evidence_dir}/lifecycle-${trust_domain}.json"
jq -n \
  --arg started_at "${started_at}" \
  --arg completed_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg trust_domain "${trust_domain}" \
  --slurpfile initial "${initial_status}" \
  --slurpfile final "${final_status}" \
  --slurpfile operations "${operations_file}" \
  --slurpfile child_restarts "${child_restarts}" \
  '
    {
      schemaVersion: 1,
      startedAtUtc: $started_at,
      completedAtUtc: $completed_at,
      trustDomainId: $trust_domain,
      initial: $initial[0],
      operations: $operations,
      childRestartChecks: $child_restarts,
      final: $final[0],
      clientConvergence: {
        expected: 6,
        observed: ($final[0].clients | length),
        allCurrent: all($final[0].clients[]; .ready)
      },
      componentFingerprints: {
        timestampAuthority: $final[0].timestampAuthority,
        fulcio: $final[0].fulcio,
        rekor: $final[0].rekor,
        ctLog: $final[0].ctLog
      },
      errors: [
        $operations[]
        | select(.success == false and .phase != "contention")
        | .errors[]
      ]
    }
  ' >"${report}"
chmod 600 "${report}"
printf '%s\n' "${report}"
