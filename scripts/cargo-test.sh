#!/usr/bin/env bash
set -euo pipefail

mode="${1:-cargo}"
cargo_bin="${CARGO:-cargo}"
jobs="${CARGO_JOBS:-12}"
offline="${OFFLINE:-1}"

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

if [[ "${mode}" == "nextest" ]]; then
  if "${cargo_bin}" nextest --version >/dev/null 2>&1; then
    exec "${cargo_bin}" nextest run --workspace --all-features "${offline_args[@]}" -j "${jobs}"
  fi

  if [[ "${STRICT:-0}" == "1" ]]; then
    echo "cargo-nextest is required for strict nextest runs" >&2
    exit 127
  fi

  echo "cargo-nextest is not installed; falling back to cargo test" >&2
fi

exec "${cargo_bin}" test --workspace --all-targets --all-features "${offline_args[@]}" -j "${jobs}"
