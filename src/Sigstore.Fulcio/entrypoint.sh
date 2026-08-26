#!/bin/sh
set -eu

password=$(cat /var/lib/sigstore/private/fulcio/password)

exec /usr/local/bin/fulcio "$@" --fileca-key-passwd "$password"
