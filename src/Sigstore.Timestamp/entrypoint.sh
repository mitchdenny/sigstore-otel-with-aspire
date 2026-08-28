#!/bin/sh
set -eu

password=$(cat /var/lib/sigstore/active-generation/private/tsa/password)

exec /usr/local/bin/timestamp-server "$@" --file-signer-passwd "$password"
