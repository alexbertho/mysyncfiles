#!/bin/sh
# Run from a configured checkout; building and starting are separate operations.
set -eu
cd "$(dirname "$0")/.."
server_name=${MYSYNC_SERVER_NAME:-}
if [ -z "$server_name" ]; then
    [ -t 0 ] || { printf '%s\n' 'Set MYSYNC_SERVER_NAME or run this installer in a terminal.' >&2; exit 1; }
    printf 'Server display name: '
    IFS= read -r server_name
fi
[ -n "$server_name" ] || { printf '%s\n' 'A server name is required.' >&2; exit 1; }
make install
docker compose --env-file deploy/.env -f deploy/compose.yaml run --rm --no-deps server init --data-dir /data --name "$server_name"
printf '%s\n' 'Server initialized. Configure the HTTPS origin and manufacturer EK roots, then run make start.'
