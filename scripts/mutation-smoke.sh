#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${CARGO:-cargo}"
jobs="${CARGO_JOBS:-12}"
offline="${OFFLINE:-1}"
strict="${STRICT:-0}"

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

if command -v cargo-mutants >/dev/null 2>&1; then
  exec cargo mutants --package locket-core --timeout 60 --jobs "${jobs}" --no-shuffle
fi

if [[ "${strict}" == "1" ]]; then
  echo "cargo-mutants is required for strict mutation gates" >&2
  exit 127
fi

echo "cargo-mutants is not installed; running focused policy/env/error tests as a local smoke fallback" >&2
exec "${cargo_bin}" test -p locket-core "${offline_args[@]}" -j "${jobs}"
