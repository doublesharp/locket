#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${CARGO:-cargo}"
jobs="${CARGO_JOBS:-12}"
offline="${OFFLINE:-1}"
samples="${PERF_PASSPHRASE_SAMPLES:-50}"
warmups="${PERF_PASSPHRASE_WARMUPS:-5}"
budget_ms="${PERF_PASSPHRASE_BUDGET_MS:-300}"
report="${PERF_PASSPHRASE_REPORT:-target/quality/perf-passphrase-unlock.md}"
build_profile="${PERF_PASSPHRASE_BUILD_PROFILE:-release}"

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

profile_args=()
if [[ "${build_profile}" == "release" ]]; then
  profile_args=(--release)
elif [[ "${build_profile}" != "debug" ]]; then
  echo "PERF_PASSPHRASE_BUILD_PROFILE must be release or debug" >&2
  exit 2
fi

"${cargo_bin}" run -p locket-crypto --example perf_passphrase_unlock \
  "${offline_args[@]}" \
  "${profile_args[@]}" \
  -j "${jobs}" \
  -- \
  --samples "${samples}" \
  --warmups "${warmups}" \
  --budget-ms "${budget_ms}" \
  --report "${report}"
