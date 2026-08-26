FROM ghcr.io/sigstore/fulcio:v1.8.8@sha256:ef72cf56c64b7455ceda5268d1cc801b92992e7ce36b744b40b7761684d60753 AS fulcio

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=fulcio /ko-app/fulcio /usr/local/bin/fulcio
COPY entrypoint.sh /usr/local/bin/fulcio-entrypoint.sh

ENTRYPOINT ["/bin/sh", "/usr/local/bin/fulcio-entrypoint.sh"]
