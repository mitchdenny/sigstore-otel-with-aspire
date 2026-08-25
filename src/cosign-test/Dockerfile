FROM golang:1.26.3-bookworm AS build

ARG COSIGN_REPOSITORY=https://github.com/mitchdenny/cosign.git
ARG COSIGN_COMMIT=fc12d520fe12020fa6eaf7b83c390b364a1e1ba0

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
