#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -ne 3 ]]; then
  echo "usage: tools/vsix-sign.sh <input-vsix> <output-vsix> <key-id>" >&2
  exit 64
fi

input="$1"
output="$2"
key_id="$3"
secret_key="${LOCKET_MINISIGN_SECRET_KEY:-${MINISIGN_SECRET_KEY:-}}"
trusted_comment="${LOCKET_MINISIGN_TRUSTED_COMMENT:-locket VSIX release ${key_id}}"
public_key="${repo_root}/dist/keys/${key_id}.pub"

if [[ ! -f "${input}" ]]; then
  echo "input VSIX not found: ${input}" >&2
  exit 66
fi

if [[ ! "${key_id}" =~ ^locket-release-[0-9a-f]{16}$ ]]; then
  echo "key id must look like locket-release-<16 lowercase hex>: ${key_id}" >&2
  exit 64
fi

if [[ ! -f "${public_key}" ]]; then
  echo "release public key not found: ${public_key}" >&2
  exit 66
fi

if [[ -z "${secret_key}" ]]; then
  echo "LOCKET_MINISIGN_SECRET_KEY is required on the offline signing host" >&2
  exit 64
fi

if [[ ! -f "${secret_key}" ]]; then
  echo "minisign secret key not found: ${secret_key}" >&2
  exit 66
fi

if ! command -v minisign >/dev/null 2>&1; then
  echo "minisign is required for VSIX signing" >&2
  exit 127
fi

mkdir -p "$(dirname "${output}")"
cp "${input}" "${output}"
minisign -S -s "${secret_key}" -m "${output}" -x "${output}.sig" -t "${trusted_comment}"
minisign -V -p "${public_key}" -m "${output}" -x "${output}.sig"

echo "signed VSIX: ${output}"
echo "signature: ${output}.sig"
