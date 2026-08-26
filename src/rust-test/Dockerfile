FROM rust:1.90-bookworm AS build

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release \
    && cp target/release/sigstore-rust-telemetry-probe /out

FROM debian:bookworm-slim

ARG SIGSTORE_RUST_FIXTURE_COMMIT=ef17cacdbd357befea4c1c768ef02ed9bf52672c
ARG SIGSTORE_RUST_FIXTURE_BASE=https://raw.githubusercontent.com/sigstore/sigstore-rust

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/pki/tls/certs \
    && useradd --create-home --uid 10001 probe

COPY --from=build /out /usr/local/bin/sigstore-rust-telemetry-probe

ADD --checksum=sha256:e194b99df6639501325c5f44da79fe3a8efae6f239bd79443a19787e06fb1764 \
    ${SIGSTORE_RUST_FIXTURE_BASE}/${SIGSTORE_RUST_FIXTURE_COMMIT}/crates/sigstore-verify/test_data/bundles/cosign-v3-blob.txt \
    /opt/sigstore-rust-fixture/artifact.txt
ADD --checksum=sha256:f7afd1c87706839b6ac19974ce23e47c4988c22807791e8257734202308923ec \
    ${SIGSTORE_RUST_FIXTURE_BASE}/${SIGSTORE_RUST_FIXTURE_COMMIT}/crates/sigstore-verify/test_data/bundles/cosign-v3-blob.sigstore.json \
    /opt/sigstore-rust-fixture/bundle.sigstore.json

RUN chmod 0444 \
    /opt/sigstore-rust-fixture/artifact.txt \
    /opt/sigstore-rust-fixture/bundle.sigstore.json

USER probe

ENTRYPOINT ["/usr/local/bin/sigstore-rust-telemetry-probe"]
