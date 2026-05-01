#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${CARGO:-cargo}"
jobs="${CARGO_JOBS:-12}"
offline="${OFFLINE:-1}"

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

"${cargo_bin}" test -p locket-scan --test leak_canary "${offline_args[@]}" -j "${jobs}"
"${cargo_bin}" test -p locket-cli cli_canary "${offline_args[@]}" -j "${jobs}"
"${cargo_bin}" test -p locket-agent canary "${offline_args[@]}" -j "${jobs}"
"${cargo_bin}" test -p locket-docker canary "${offline_args[@]}" -j "${jobs}"
"${cargo_bin}" test -p locket-app canary "${offline_args[@]}" -j "${jobs}"

if command -v pnpm >/dev/null 2>&1 && [[ -d crates/locket-app/ui/node_modules ]]; then
  (
    cd crates/locket-app/ui
    pnpm run test:smoke
  )
else
  echo "Desktop UI canary skipped; pnpm or crates/locket-app/ui/node_modules unavailable"
fi

if command -v pnpm >/dev/null 2>&1 && [[ -d extensions/vscode/node_modules ]]; then
  (
    cd extensions/vscode
    pnpm run build
    node --test --test-name-pattern canary out/*.test.js
  )
else
  echo "VS Code canary skipped; pnpm or extensions/vscode/node_modules unavailable"
fi
echo "leak canary passed"
