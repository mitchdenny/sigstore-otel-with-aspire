#!/bin/sh
set -eu

password=$(cat /var/lib/sigstore/private/tsa/password)

exec /usr/local/bin/timestamp-server "$@" --file-signer-passwd "$password"
