#!/bin/sh
# Served by MySyncFiles as /install.sh. The server fills the three placeholders
# from its configured HTTPS origin, compiled release key and systemd unit.
set -eu

SERVER_URL=@MYSYNC_SERVER_URL@
PUBLIC_KEY_HEX=@MYSYNC_PUBLIC_KEY@

if [ -t 1 ] && [ -z "${NO_COLOR+x}" ] && [ "${TERM:-dumb}" != dumb ]; then
    blue=$(printf '\033[34m')
    green=$(printf '\033[32m')
    yellow=$(printf '\033[33m')
    red=$(printf '\033[31m')
    reset=$(printf '\033[0m')
else
    blue= green= yellow= red= reset=
fi

say() { printf '%s\n' "$*"; }
step() { printf '\n%s[%s]%s %s\n' "$blue" "$1" "$reset" "$2"; }
ok() { printf '%s[ok]%s %s\n' "$green" "$reset" "$*"; }
warn() { printf '%s[!]%s %s\n' "$yellow" "$reset" "$*" >&2; }
die() { printf '%s[error]%s %s\n' "$red" "$reset" "$*" >&2; exit 1; }

say '  /\/\  MySyncFiles'
say ' /_/\_\ Client setup'
say
say 'The installer verifies a signed release before running it.'

case "$SERVER_URL" in
    https://*) ;;
    *) die 'The server must have a configured HTTPS public URL.' ;;
esac
[ "$(uname -s)" = Linux ] || die 'This installer supports Linux only.'
case "$(uname -m)" in
    x86_64) target=linux-x86_64 ;;
    aarch64|arm64) target=linux-aarch64 ;;
    *) die 'Unsupported CPU architecture; use Linux x86-64 or AArch64.' ;;
esac
[ -n "${HOME:-}" ] || die 'HOME is not set.'
command -v curl >/dev/null 2>&1 || die 'curl is required to download the client.'

distribution=other
if [ -r /etc/os-release ]; then
    # os-release is a root-owned shell-compatible file on supported systems.
    . /etc/os-release
    case "${ID:-}:${VERSION_ID:-}:${ID_LIKE:-}" in
        debian:13:*) distribution=debian ;;
        arch:*:*|*:arch|*:arch\ *) distribution=arch ;;
        *) case " ${ID_LIKE:-} " in *' arch '*) distribution=arch ;; esac ;;
    esac
fi
step 1 "Checking $target on ${PRETTY_NAME:-Linux}"
say 'The client will probe the TPM before installation.'

offer_packages() {
    packages=$1
    [ -r /dev/tty ] || die "Install $packages with your package manager, then retry in a terminal."
    command -v sudo >/dev/null 2>&1 || die "sudo is unavailable; install $packages manually."
    printf 'Install system packages with sudo (%s)? [y/N] ' "$packages" >/dev/tty
    answer=
    IFS= read -r answer </dev/tty || true
    case "$answer" in
        y|Y|yes|YES) ;;
        *) die 'No system packages were changed. Install the missing packages and retry.' ;;
    esac
    case "$distribution" in
        debian)
            sudo apt-get update
            # The package list is fixed by this script, never obtained from a download.
            sudo apt-get install -y --no-install-recommends $packages
            ;;
        arch) sudo pacman -S --needed $packages ;;
    esac
}

missing=
for tool in python3 openssl; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
    warn "Missing tools:$missing"
    case "$distribution" in
        debian) packages='python3 openssl' ;;
        arch) packages='python openssl' ;;
        *) die 'Install Python 3 and OpenSSL 3 using your distribution package manager, then retry.' ;;
    esac
    offer_packages "$packages"
fi
for tool in python3 openssl; do
    command -v "$tool" >/dev/null 2>&1 || die "Still missing $tool after dependency setup."
done

tmp=$(mktemp -d "${TMPDIR:-/tmp}/mysync-install.XXXXXXXX") || die 'Cannot create a private temporary directory.'
staged=
cleanup() {
    [ -z "$staged" ] || rm -f -- "$staged"
    rm -rf -- "$tmp"
}
trap cleanup EXIT HUP INT TERM
chmod 700 "$tmp"

fetch() {
    address=$1 destination=$2 limit=$3 timeout=$4
    status=$(curl --fail --silent --show-error --proto '=https' --max-redirs 0 \
        --connect-timeout 10 --max-time "$timeout" --max-filesize "$limit" \
        --output "$destination" --write-out '%{http_code}' "$address") || die "Download failed: $address"
    [ "$status" = 200 ] || die "Server returned HTTP $status for $address (redirects are not allowed)."
}

step 2 'Downloading signed release metadata'
base="$SERVER_URL/v1/updates/$target"
fetch "$base/latest.json" "$tmp/latest.json" 16384 30
fetch "$base/latest.sig" "$tmp/latest.sig" 256 30

if ! python3 - "$tmp" "$PUBLIC_KEY_HEX" "$target" <<'PY'
import json, pathlib, re, sys

directory, key, target = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
manifest_bytes = (directory / 'latest.json').read_bytes()
signature = (directory / 'latest.sig').read_text(encoding='ascii').strip()
if len(manifest_bytes) > 16384 or not re.fullmatch(r'[0-9a-fA-F]{128}', signature):
    raise SystemExit('Invalid release metadata or signature format.')
if not re.fullmatch(r'[0-9a-fA-F]{64}', key):
    raise SystemExit('Invalid embedded release public key.')
(directory / 'signed-payload').write_bytes(b'MySyncFiles release manifest v1\n' + manifest_bytes)
(directory / 'signature.bin').write_bytes(bytes.fromhex(signature))
(directory / 'public.der').write_bytes(bytes.fromhex('302a300506032b6570032100' + key))
PY
then
    die 'Cannot prepare release signature verification.'
fi
openssl pkeyutl -verify -pubin -keyform DER -inkey "$tmp/public.der" \
    -rawin -in "$tmp/signed-payload" -sigfile "$tmp/signature.bin" \
    >/dev/null 2>&1 || die 'Release signature is invalid; nothing was installed.'
ok 'Release signature verified.'

if ! python3 - "$tmp" "$target" <<'PY'
import json, pathlib, re, sys

directory, target = pathlib.Path(sys.argv[1]), sys.argv[2]
manifest = json.loads((directory / 'latest.json').read_bytes())
version = manifest.get('version')
artifact = manifest.get('artifact')
size = manifest.get('size')
digest = manifest.get('sha256')
if (manifest.get('target') != target
        or not isinstance(version, str)
        or not re.fullmatch(r'[0-9A-Za-z][0-9A-Za-z.+-]{0,80}', version)
        or not isinstance(artifact, str)
        or artifact != f'mysync-{version}-{target}'
        or not re.fullmatch(r'[0-9A-Za-z._-]{1,128}', artifact)
        or type(size) is not int or not 0 < size <= 64 * 1024 * 1024
        or not isinstance(digest, str)
        or not re.fullmatch(r'[0-9a-fA-F]{64}', digest)):
    raise SystemExit('Signed manifest has an invalid target, name, size or hash.')
(directory / 'fields').write_text(f'{version}\n{artifact}\n{size}\n{digest.lower()}\n')
PY
then
    die 'Signed release metadata is invalid.'
fi
version=$(sed -n '1p' "$tmp/fields")
artifact=$(sed -n '2p' "$tmp/fields")
size=$(sed -n '3p' "$tmp/fields")
digest=$(sed -n '4p' "$tmp/fields")

step 3 "Downloading MySyncFiles $version"
fetch "$base/$artifact" "$tmp/mysync" 67108864 900
if ! python3 - "$tmp/mysync" "$size" "$digest" <<'PY'
import hashlib, pathlib, sys

path, size, digest = pathlib.Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
if path.stat().st_size != size:
    raise SystemExit('Client size does not match the signed manifest.')
hasher = hashlib.sha256()
with path.open('rb') as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b''):
        hasher.update(chunk)
if hasher.hexdigest() != digest:
    raise SystemExit('Client SHA-256 does not match the signed manifest.')
PY
then
    die 'Client integrity check failed; nothing was installed.'
fi
chmod 700 "$tmp/mysync"
if ! reported=$("$tmp/mysync" --version 2>"$tmp/probe-error"); then
    if command -v ldd >/dev/null 2>&1 && ldd "$tmp/mysync" 2>/dev/null | grep -q 'not found'; then
        case "$distribution" in
            debian) offer_packages 'tpm2-tools' ;;
            arch) offer_packages 'tpm2-tss' ;;
            *) die 'Signed client needs native TPM/OpenSSL libraries; install them using your distribution package manager, then retry.' ;;
        esac
        reported=$("$tmp/mysync" --version) || die 'Signed client still cannot run after installing native libraries.'
    else
        die 'Signed client cannot run here. Check native library and glibc compatibility.'
    fi
fi
[ "$reported" = "mysync $version" ] || die 'Signed client reports a different version.'
ok 'Binary integrity and compatibility verified.'

step 4 'Checking TPM 2.0 and EK certificate'
if [ -n "${MYSYNC_EK_CERT:-}" ]; then
    [ -r "$MYSYNC_EK_CERT" ] || die 'MYSYNC_EK_CERT is not readable by this user.'
    "$tmp/mysync" doctor --ek-cert "$MYSYNC_EK_CERT" || die 'TPM preflight failed; the supplied EK certificate must match this TPM.'
else
    "$tmp/mysync" doctor || die 'TPM preflight failed; if the EK certificate is absent from TPM NV, obtain its DER certificate from the manufacturer and retry with MYSYNC_EK_CERT=/path/to/ek.der.'
fi

step 5 'Installing client and background service'
destination_dir="$HOME/.local/bin"
unit_dir="$HOME/.config/systemd/user"
for directory in "$destination_dir" "$unit_dir"; do
    [ ! -L "$directory" ] || die "Refusing symbolic-link installation directory: $directory"
    if [ ! -e "$directory" ]; then
        install -d -m 755 "$directory" || die "Cannot create $directory"
    fi
    python3 - "$directory" <<'PY' || exit 1
import os, pathlib, stat, sys
directory = pathlib.Path(sys.argv[1])
info = directory.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
    raise SystemExit(f'Unsafe installation directory: {directory}')
PY
done
destination="$destination_dir/mysync"
setup_available=0
if [ -L "$destination" ]; then
    die "Refusing symbolic-link client binary: $destination"
fi
if [ -e "$destination" ]; then
    [ -f "$destination" ] && [ -x "$destination" ] || die "Existing client is not a regular executable: $destination"
    warn "An existing client was left untouched: $destination"
    say 'Use mysync update for signed upgrades; this bootstrap installer never downgrades a client.'
    if cmp -s "$tmp/mysync" "$destination"; then
        setup_available=1
    fi
else
    staged="$destination_dir/.mysync-install-$$"
    [ ! -e "$staged" ] && [ ! -L "$staged" ] || die 'Temporary installation path already exists.'
    install -m 755 "$tmp/mysync" "$staged"
    ln "$staged" "$destination" || die 'The client appeared during installation; it was not replaced.'
    rm -f -- "$staged"
    staged=
    ok "Installed $destination"
    setup_available=1
fi

cat > "$tmp/mysync.service" <<'MYSYNC_UNIT'
@MYSYNC_UNIT@
MYSYNC_UNIT
unit="$unit_dir/mysync.service"
service_ready=1
if [ -L "$unit" ]; then
    die "Refusing symbolic-link service file: $unit"
fi
if [ -e "$unit" ]; then
    if ! cmp -s "$tmp/mysync.service" "$unit"; then
        warn "Existing service file was left untouched: $unit"
        service_ready=0
    fi
else
    install -m 644 "$tmp/mysync.service" "$unit"
    ok 'Installed systemd user service (not started yet).'
fi
say
if [ "$setup_available" = 1 ] && [ -t 1 ] && [ -r /dev/tty ]; then
    step 6 'Pairing this client with the server'
    printf 'Folder to synchronize [%s/Sync]: ' "$HOME" >/dev/tty
    mirror_dir=
    IFS= read -r mirror_dir </dev/tty || die 'Cannot read the folder from the terminal.'
    [ -n "$mirror_dir" ] || mirror_dir="$HOME/Sync"
    set -- setup --server "$SERVER_URL" --dir "$mirror_dir"
    [ -z "${MYSYNC_EK_CERT:-}" ] || set -- "$@" --ek-cert "$MYSYNC_EK_CERT"
    if [ -n "${MYSYNC_EK_CHAIN:-}" ]; then
        [ -r "$MYSYNC_EK_CHAIN" ] || die 'MYSYNC_EK_CHAIN is not readable by this user.'
        set -- "$@" --ek-chain "$MYSYNC_EK_CHAIN"
    fi
    "$destination" "$@" || die 'Pairing or first synchronization is incomplete. Rerun this installer or mysync setup to resume; the service remains stopped.'
    if [ "$service_ready" = 1 ]; then
        systemctl --user daemon-reload || die 'Synchronization succeeded, but the user service manager could not reload.'
        systemctl --user enable --now mysync.service || die 'Synchronization succeeded, but the user service could not start. Check systemctl --user status mysync.service.'
        ok 'Client paired, files checked and user service started.'
    else
        warn 'Pairing succeeded, but the existing service file differs; review it before starting the service.'
    fi
    say 'For startup without login: sudo loginctl enable-linger "$(id -un)"'
else
    say "Next: run $destination setup --server $SERVER_URL --dir \"\$HOME/Sync\" in a terminal."
    if [ "$setup_available" = 0 ]; then
        say 'Update the existing client with mysync update before using the new setup command.'
    fi
    say 'The user service remains stopped until setup succeeds.'
fi
