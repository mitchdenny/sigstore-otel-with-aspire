FROM python:3.12-slim-bookworm

ARG OPENTELEMETRY_VERSION=1.44.0
ARG OPENTELEMETRY_INSTRUMENTATION_VERSION=0.65b0
ARG SIGSTORE_VERSION=4.5.0

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN python -m pip install \
    "opentelemetry-distro==${OPENTELEMETRY_INSTRUMENTATION_VERSION}" \
    "opentelemetry-exporter-otlp==${OPENTELEMETRY_VERSION}" \
    "opentelemetry-instrumentation-requests==${OPENTELEMETRY_INSTRUMENTATION_VERSION}" \
    "opentelemetry-instrumentation-urllib3==${OPENTELEMETRY_INSTRUMENTATION_VERSION}" \
    "sigstore==${SIGSTORE_VERSION}"

RUN useradd --create-home --uid 10001 client

WORKDIR /app
COPY client.py test_client.py ./

USER client

EXPOSE 8080
ENTRYPOINT ["python", "/app/client.py"]
