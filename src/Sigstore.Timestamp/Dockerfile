FROM ghcr.io/sigstore/timestamp-server:v2.1.3@sha256:21b32b43cf51e4f1bcb76518727ddaecd58b16a7cab57bbd7e7bedea5696933b AS timestamp

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=timestamp /ko-app/timestamp-server /usr/local/bin/timestamp-server
COPY entrypoint.sh /usr/local/bin/timestamp-entrypoint.sh

ENTRYPOINT ["/bin/sh", "/usr/local/bin/timestamp-entrypoint.sh"]
