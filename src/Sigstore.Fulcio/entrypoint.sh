#!/bin/sh
set -eu

password=$(cat /var/lib/sigstore/fulcio/password)


ct_config_dir=/var/lib/sigstore/fulcio-ct

# The certificate-transparency shard Fulcio binds to is a durable runtime
# selection, not a build-time argument. The selection is exactly one
# atomically replaced manifest that lives beside immutable, additive
# per-shard public keys in this stable read-only mount, so a rotation can
# never present a mixed selector/origin/key configuration: this process
# either boots wholly on the historical primary shard or wholly on the
# secondary shard, and exactly one restart moves it between them.
#
# The manifest is strictly validated: a versioned header, a recognized
# selector, and the origin and key file name that selector implies. Any
# other shape, and any selector whose origin or key name does not match,
# is refused before Fulcio starts.
ct_selection="$ct_config_dir/selection"
ct_header=""
ct_selector=""
ct_origin=""
ct_key_name=""
ct_extra=""
{
    IFS= read -r ct_header || ct_header=""
    IFS= read -r ct_selector || ct_selector=""
    IFS= read -r ct_origin || ct_origin=""
    IFS= read -r ct_key_name || ct_key_name=""
    if IFS= read -r ct_extra || [ -n "$ct_extra" ]; then
        ct_extra="unexpected"
    fi
} < "$ct_selection"

if [ "$ct_header" != "sigstore-fulcio-ct-selection/1" ] || [ -n "$ct_extra" ]; then
    echo "Certificate-transparency selection manifest is malformed." >&2
    exit 1
fi

case "$ct_selector" in
    primary)
        ct_expected_origin="tesseract-sigstore.dev.localhost"
        ct_expected_key="primary.pub"
        ct_url="${SIGSTORE_CT_LOG_URL_PRIMARY:-}"
        ;;
    secondary)
        ct_expected_origin="tesseract-secondary-sigstore.dev.localhost"
        ct_expected_key="secondary.pub"
        ct_url="${SIGSTORE_CT_LOG_URL_SECONDARY:-}"
        ;;
    *)
        echo "Unsupported certificate-transparency selector '$ct_selector'." >&2
        exit 1
        ;;
esac

if [ "$ct_origin" != "$ct_expected_origin" ] || [ "$ct_key_name" != "$ct_expected_key" ]; then
    echo "Certificate-transparency selection does not match selector '$ct_selector'." >&2
    exit 1
fi

if [ -z "$ct_url" ]; then
    echo "No certificate-transparency URL for selector '$ct_selector'." >&2
    exit 1
fi

ct_key_path="$ct_config_dir/$ct_key_name"
if [ ! -s "$ct_key_path" ]; then
    echo "Certificate-transparency key '$ct_key_path' is missing or empty." >&2
    exit 1
fi

exec /usr/local/bin/fulcio "$@" \
    --fileca-key-passwd "$password" \
    --ct-log-url "$ct_url" \
    --ct-log-origin "$ct_origin" \
    --ct-log-public-key-path "$ct_key_path"
