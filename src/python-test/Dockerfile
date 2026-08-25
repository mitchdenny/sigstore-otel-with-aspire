FROM python:3.12-slim-bookworm

ARG MODEL_SIGNING_VERSION=1.1.1
ARG MODEL_SIGNING_FIXTURE_COMMIT=49285522a7dfe1ae6ae51f9db2b183029727325a
ARG OPENTELEMETRY_VERSION=1.44.0
ARG OPENTELEMETRY_INSTRUMENTATION_VERSION=0.65b0
ARG SIGSTORE_VERSION=4.5.0

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN python -m pip install \
    "model-signing[otel]==${MODEL_SIGNING_VERSION}" \
    "opentelemetry-distro==${OPENTELEMETRY_INSTRUMENTATION_VERSION}" \
    "opentelemetry-exporter-otlp==${OPENTELEMETRY_VERSION}" \
    "opentelemetry-instrumentation-urllib3==${OPENTELEMETRY_INSTRUMENTATION_VERSION}" \
    "sigstore==${SIGSTORE_VERSION}"

RUN MODEL_SIGNING_FIXTURE_COMMIT="${MODEL_SIGNING_FIXTURE_COMMIT}" python - <<'PY'
import os
import pathlib
import urllib.request

commit = os.environ["MODEL_SIGNING_FIXTURE_COMMIT"]
fixture_dir = pathlib.Path("/opt/model-signing-fixture")
fixture_dir.mkdir(parents=True)

base_url = (
    "https://raw.githubusercontent.com/sigstore/model-transparency/"
    f"{commit}/scripts/tests/v1.1.0-sigstore"
)

for name in ("ignore-me", "model.sig", "signme-1", "signme-2"):
    with urllib.request.urlopen(f"{base_url}/{name}", timeout=30) as response:
        fixture_dir.joinpath(name).write_bytes(response.read())
PY

RUN useradd --create-home --uid 10001 probe

COPY probe.sh /usr/local/bin/model-signing-telemetry-probe

USER probe

ENTRYPOINT ["/bin/sh", "/usr/local/bin/model-signing-telemetry-probe"]
