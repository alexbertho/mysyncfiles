#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_binary=${1:-"$project_dir/target/release/mysync"}
config_dir="$HOME/.config"
config_path="$config_dir/mysync/config.json"
destination_dir="$HOME/.local/bin"
unit_dir="$config_dir/systemd/user"
account=$(id -un)

if [[ ! -f "$config_path" ]]; then
    printf 'Configure a synchronization folder before installing the background service: %s\n' "$config_path" >&2
    exit 1
fi
if [[ ! -f "$source_binary" || ! -x "$source_binary" ]]; then
    printf 'Client binary is missing or not executable: %s\n' "$source_binary" >&2
    exit 1
fi
"$source_binary" --version >/dev/null

install -d -m 755 "$destination_dir"
install -d -m 755 "$unit_dir"
temporary_binary="$destination_dir/.mysync-install-$$"
trap 'rm -f "$temporary_binary"' EXIT
install -m 755 "$source_binary" "$temporary_binary"
mv -f "$temporary_binary" "$destination_dir/mysync"
install -m 644 "$project_dir/deploy/mysync.service" "$unit_dir/mysync.service"

if [[ $(loginctl show-user "$account" --property=Linger --value) != yes ]]; then
    sudo loginctl enable-linger "$account"
fi
systemctl --user daemon-reload
systemctl --user enable --now mysync.service
systemctl --user restart mysync.service
printf 'Installed %s; service enabled at boot for %s.\n' "$("$destination_dir/mysync" --version)" "$account"
