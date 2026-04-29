#!/usr/bin/env bash
set -euo pipefail

mode="${1:-line}"
cargo_bin="${CARGO:-cargo}"
llvm_cov="${CARGO_LLVM_COV:-cargo llvm-cov}"
jobs="${CARGO_JOBS:-12}"
offline="${OFFLINE:-1}"
strict="${STRICT:-0}"

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

if ! ${llvm_cov} --version >/dev/null 2>&1; then
  if [[ "${strict}" == "1" ]]; then
    echo "cargo-llvm-cov is required for strict coverage gates" >&2
    exit 127
  fi

  echo "cargo-llvm-cov is not installed; running tests without coverage" >&2
  exec "${cargo_bin}" test --workspace --all-targets --all-features "${offline_args[@]}" -j "${jobs}"
fi

mkdir -p coverage

case "${mode}" in
  line)
    exec ${llvm_cov} --workspace --all-features "${offline_args[@]}" --fail-under-lines 90 --lcov --output-path coverage/lcov.info
    ;;
  html)
    exec ${llvm_cov} --workspace --all-features "${offline_args[@]}" --fail-under-lines 90 --html --output-dir coverage/html
    ;;
  branch)
    exec ${llvm_cov} --workspace --all-features "${offline_args[@]}" --branch --fail-under-lines 90 --fail-under-branches 90 --lcov --output-path coverage/branch.lcov.info
    ;;
  *)
    echo "unknown coverage mode: ${mode}" >&2
    exit 2
    ;;
esac
