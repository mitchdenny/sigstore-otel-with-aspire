FROM golang:1.26.3-bookworm AS build

ARG COSIGN_REPOSITORY=https://github.com/miyunari/cosign.git
ARG COSIGN_COMMIT=cae7f0565c02b9c4274e77fc633f9c45e25466c8

WORKDIR /src

RUN git clone --filter=blob:none "${COSIGN_REPOSITORY}" cosign \
    && cd cosign \
    && git checkout "${COSIGN_COMMIT}"

WORKDIR /src/cosign

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/cosign ./cmd/cosign

FROM golang:1.26.3-bookworm

COPY --from=build /out/cosign /usr/local/bin/cosign
COPY probe.sh /usr/local/bin/cosign-telemetry-probe

ENTRYPOINT ["/bin/sh", "/usr/local/bin/cosign-telemetry-probe"]
