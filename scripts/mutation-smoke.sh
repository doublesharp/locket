#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${CARGO:-cargo}"
cargo_mutants="${CARGO_MUTANTS:-cargo mutants}"
jobs="${CARGO_JOBS:-12}"
offline="${OFFLINE:-1}"
strict="${STRICT:-0}"
mutation_packages="${MUTATION_PACKAGES:-locket-core locket-store locket-agent locket-exec locket-platform}"
fallback_packages="${MUTATION_FALLBACK_PACKAGES:-${mutation_packages}}"
mutation_timeout="${MUTATION_TIMEOUT:-60}"

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

if ${cargo_mutants} --version >/dev/null 2>&1; then
  for package in ${mutation_packages}; do
    ${cargo_mutants} --package "${package}" --timeout "${mutation_timeout}" --jobs "${jobs}" --no-shuffle
  done
  exit 0
fi

if [[ "${strict}" == "1" ]]; then
  echo "cargo-mutants is required for strict mutation gates" >&2
  exit 127
fi

echo "cargo-mutants is not installed; running focused package tests as a local smoke fallback" >&2
for package in ${fallback_packages}; do
  "${cargo_bin}" test -p "${package}" "${offline_args[@]}" -j "${jobs}"
done
