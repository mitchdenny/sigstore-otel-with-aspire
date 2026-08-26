FROM rust:1.90-bookworm AS build

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release \
    && cp target/release/sigstore-rust-client /out

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/pki/tls/certs \
    && useradd --create-home --uid 10001 probe

COPY --from=build /out /usr/local/bin/sigstore-rust-client

USER probe

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sigstore-rust-client"]
