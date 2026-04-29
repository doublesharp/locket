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
echo "leak canary passed"
