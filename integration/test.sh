#!/bin/sh
set -eu
server_dir=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
client_dir=$(CDPATH='' cd -- "$server_dir/../mysyncfiles-client" && pwd)
if [ "${MYSYNC_INTEGRATION_WORKTREE:-0}" != 1 ]; then
    expected=$(cat "$server_dir/integration/client-revision")
    actual=$(git -C "$client_dir" rev-parse HEAD)
    [ "$actual" = "$expected" ] || { printf '%s\n' "Check out client revision $expected in $client_dir (or explicitly set MYSYNC_INTEGRATION_WORKTREE=1 for development)." >&2; exit 1; }
    protocol_revision=$(cargo metadata --locked --no-deps --format-version 1 --manifest-path "$client_dir/Cargo.toml" | python3 -c '
import json, re, sys, urllib.parse
package = next(p for p in json.load(sys.stdin)["packages"] if p["name"] == "mysyncfiles-client")
source = next(d["source"] for d in package["dependencies"] if d["name"] == "mysync-protocol")
revision = urllib.parse.parse_qs(urllib.parse.urlsplit(source).query)["rev"][0]
if not re.fullmatch(r"[0-9a-f]{40}", revision):
    raise SystemExit("The client must pin a full protocol Git revision.")
print(revision)
    ')
    git -C "$server_dir" diff --quiet "$protocol_revision" -- crates/protocol || {
        printf '%s\n' 'The protocol differs from the pinned client dependency. Update and validate the client pin, or explicitly use MYSYNC_INTEGRATION_WORKTREE=1 during coordinated development.' >&2
        exit 1
    }
fi
cd "$server_dir"
if pkg-config --atleast-version=2.4.6 tss2-sys; then
    export MYSYNC_CLIENT_SOURCE="$client_dir"
    cargo fmt --manifest-path integration/Cargo.toml --all -- --check
    if [ "${1:-}" = --bench ]; then
        shift
        cargo build --locked --manifest-path integration/Cargo.toml --release --bin mysync
        exec cargo bench --locked --manifest-path integration/Cargo.toml --bench performance -- "$@"
    fi
    exec cargo test --locked --manifest-path integration/Cargo.toml --jobs "${MYSYNC_CARGO_JOBS:-1}"
fi
docker build -t mysyncfiles-tpm-dev -f deploy/Dockerfile.tpm-dev .
command=test
if [ "${1:-}" = --bench ]; then command=bench; shift; fi
docker run --rm --memory 3g --memory-swap 3g --cpus 2 \
    --user "$(id -u):$(id -g)" \
    --volume "$server_dir:/workspace/mysyncfiles" \
    --volume "$client_dir:/workspace/mysyncfiles-client" \
    --volume "$HOME/.cargo/registry:/tmp/cargo/registry" \
    --volume "$HOME/.cargo/git:/tmp/cargo/git" \
    --env CARGO_HOME=/tmp/cargo --env CARGO_TARGET_DIR=/workspace/mysyncfiles/target/integration \
    --env MYSYNC_CLIENT_SOURCE=/workspace/mysyncfiles-client \
    --workdir /workspace/mysyncfiles \
    mysyncfiles-tpm-dev sh -c '
        cargo fmt --manifest-path integration/Cargo.toml --all -- --check || exit
        action=$1; shift
        if [ "$action" = bench ]; then
            cargo build --locked --manifest-path integration/Cargo.toml --release --bin mysync &&
            cargo bench --locked --manifest-path integration/Cargo.toml --bench performance -- --binary /workspace/mysyncfiles/target/integration/release/mysync "$@"
        else
            cargo test --locked --manifest-path integration/Cargo.toml --jobs 1
        fi' sh "$command" "$@"
