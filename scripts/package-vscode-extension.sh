#!/usr/bin/env bash
set -euo pipefail

# Packages the Locket VS Code extension as a VSIX.
#
# Usage:
#   scripts/package-vscode-extension.sh                  # unsigned VSIX
#   scripts/package-vscode-extension.sh --sign <key-id>  # signed VSIX
#
# In --sign mode the script invokes the ceremony signing hook
# (tools/vsix-sign.sh by default, override with LOCKET_VSIX_SIGN_TOOL) on
# the produced VSIX. The signing tool itself is provisioned only on the
# air-gapped signing host; this flag exists so the same script drives both
# the CI-built unsigned artifact and the offline ceremony output.
#
# See dist/vscode-vsix-signing.md for the full signing flow and
# dist/release-key-offline.md for the release-key infrastructure.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pnpm_bin="${PNPM:-pnpm}"
node_bin="${NODE:-node}"
out_dir="${VSIX_OUT_DIR:-${repo_root}/target/package/vscode}"

sign_mode=0
sign_key=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sign)
      sign_mode=1
      if [[ $# -lt 2 ]]; then
        echo "--sign requires a <key-id> argument" >&2
        exit 64
      fi
      sign_key="$2"
      shift 2
      ;;
    --sign=*)
      sign_mode=1
      sign_key="${1#--sign=}"
      shift
      ;;
    -h|--help)
      sed -n '3,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 64
      ;;
  esac
done

if [[ $sign_mode -eq 1 && -z "${sign_key}" ]]; then
  echo "--sign requires a non-empty <key-id>" >&2
  exit 64
fi

if ! command -v "${pnpm_bin}" >/dev/null 2>&1; then
  echo "pnpm is required to package the VS Code extension" >&2
  exit 127
fi

if ! command -v "${node_bin}" >/dev/null 2>&1; then
  echo "node is required to package the VS Code extension" >&2
  exit 127
fi

package_name="$("${node_bin}" -e 'const p = require(process.argv[1]); process.stdout.write(p.name);' "${repo_root}/extensions/vscode/package.json")"
package_version="$("${node_bin}" -e 'const p = require(process.argv[1]); process.stdout.write(p.version);' "${repo_root}/extensions/vscode/package.json")"

# Output naming: unsigned -> locket-<version>.vsix
#                signed   -> locket-<version>.signed.vsix
artifact_basename="locket-${package_version}"
if [[ $sign_mode -eq 1 ]]; then
  vsix_path="${out_dir}/${artifact_basename}.signed.vsix"
  signature_path="${vsix_path}.sig"
else
  vsix_path="${out_dir}/${artifact_basename}.vsix"
  signature_path=""
fi
digest_path="${vsix_path}.sha256"

# vsce always produces an unsigned VSIX first; in --sign mode we sign in place.
build_vsix_path="${out_dir}/${artifact_basename}.vsix.tmp"

mkdir -p "${out_dir}"
rm -f "${vsix_path}" "${digest_path}" "${build_vsix_path}"
[[ -n "${signature_path}" ]] && rm -f "${signature_path}"

"${pnpm_bin}" --dir "${repo_root}/extensions/vscode" install --frozen-lockfile
"${pnpm_bin}" --dir "${repo_root}/extensions/vscode" run build
"${pnpm_bin}" --dir "${repo_root}/extensions/vscode" exec vsce package --no-dependencies --out "${build_vsix_path}"

if [[ $sign_mode -eq 1 ]]; then
  sign_tool="${LOCKET_VSIX_SIGN_TOOL:-${repo_root}/tools/vsix-sign.sh}"
  if [[ ! -x "${sign_tool}" ]]; then
    echo "signing tool not found or not executable: ${sign_tool}" >&2
    echo "the signing tool is provisioned on the air-gapped signing host;" >&2
    echo "see dist/vscode-vsix-signing.md and dist/release-key-offline.md" >&2
    exit 127
  fi
  # Contract: <input-vsix> <output-vsix> <key-id>; emits a detached <output>.sig
  "${sign_tool}" "${build_vsix_path}" "${vsix_path}" "${sign_key}"
  if [[ ! -f "${signature_path}" ]]; then
    echo "signing tool did not produce ${signature_path}" >&2
    exit 1
  fi
  rm -f "${build_vsix_path}"
else
  mv "${build_vsix_path}" "${vsix_path}"
fi

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "${vsix_path}" > "${digest_path}"
elif command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${vsix_path}" > "${digest_path}"
else
  echo "shasum or sha256sum is required to write the VSIX digest" >&2
  exit 127
fi

echo "VSIX: ${vsix_path}"
echo "SHA256: ${digest_path}"
if [[ -n "${signature_path}" ]]; then
  echo "SIGNATURE: ${signature_path}"
fi
