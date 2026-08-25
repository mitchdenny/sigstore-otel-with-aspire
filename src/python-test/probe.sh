#!/bin/sh
set -eu

fixture_dir=/opt/model-signing-fixture
interval_seconds=${MODEL_SIGNING_PROBE_INTERVAL_SECONDS:-15}
identity=stefanb@us.ibm.com
identity_provider=https://sigstore.verify.ibm.com/oauth2

echo "Starting model-signing telemetry probe."

while true; do
    model_signing \
        --log-level info \
        verify sigstore \
        --identity "$identity" \
        --identity_provider "$identity_provider" \
        --ignore-paths "$fixture_dir/ignore-me" \
        --signature "$fixture_dir/model.sig" \
        "$fixture_dir" \
        >/dev/null

    echo "model-signing verification emitted an OpenTelemetry trace."
    sleep "$interval_seconds"
done
