#!/usr/bin/env bash
set -euo pipefail

if [[ -r /etc/debian_version ]]; then
    sudo apt-get update
    sudo apt-get install -y tpm2-tools
elif [[ -r /etc/arch-release ]]; then
    sudo pacman -S --needed tpm2-tss tpm2-tools openssl
else
    printf 'Install the TPM2 TSS runtime and tpm2-tools using your distribution packages.\n' >&2
    exit 1
fi

if [[ ! -e /dev/tpmrm0 ]]; then
    printf 'No TPM 2.0 resource manager found at /dev/tpmrm0; enable TPM in firmware.\n' >&2
    exit 1
fi
if [[ ! -r /dev/tpmrm0 || ! -w /dev/tpmrm0 ]]; then
    if getent group tss >/dev/null; then
        sudo usermod -aG tss "$(id -un)"
        printf 'TPM access group enabled; reboot before enrollment.\n'
    else
        printf 'Configure access to /dev/tpmrm0 according to your distribution.\n' >&2
        exit 1
    fi
fi
printf 'TPM runtime installed. A verifiable manufacturer EK certificate is also required.\n'
