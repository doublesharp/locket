#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pnpm_bin="${PNPM:-pnpm}"
node_bin="${NODE:-node}"
out_dir="${VSIX_OUT_DIR:-${repo_root}/target/package/vscode}"

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
vsix_path="${out_dir}/${package_name}-${package_version}.vsix"
digest_path="${vsix_path}.sha256"

mkdir -p "${out_dir}"
rm -f "${vsix_path}" "${digest_path}"

"${pnpm_bin}" --dir "${repo_root}/extensions/vscode" install --frozen-lockfile
"${pnpm_bin}" --dir "${repo_root}/extensions/vscode" run build
"${pnpm_bin}" --dir "${repo_root}/extensions/vscode" exec vsce package --no-dependencies --out "${vsix_path}"

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
