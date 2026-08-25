#!/bin/sh
set -eu

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT INT TERM

artifact="$work_dir/artifact.txt"
key_prefix="$work_dir/cosign"
bundle="$work_dir/artifact.sigstore.json"
signing_config="$work_dir/signing-config.json"

printf 'cosign telemetry probe\n' > "$artifact"
export COSIGN_PASSWORD=

cosign generate-key-pair \
    --output-key-prefix "$key_prefix" \
    >/dev/null

cosign signing-config create \
    --no-default-fulcio \
    --no-default-oidc \
    --no-default-rekor \
    --no-default-tsa \
    --out "$signing_config"

while true; do
    cosign \
        --tracing-enabled \
        --tracing-insecure=false \
        sign-blob \
        --bundle "$bundle" \
        --key "$key_prefix.key" \
        --signing-config "$signing_config" \
        "$artifact" \
        >/dev/null

    echo "Cosign sign-blob emitted an OpenTelemetry trace."
    sleep 15
done
