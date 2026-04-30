#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${CARGO:-cargo}"
jobs="${CARGO_JOBS:-12}"
offline="${OFFLINE:-1}"
build_profile="${PERF_RECOVERY_BUILD_PROFILE:-release}"
samples="${PERF_RECOVERY_SAMPLES:-50}"
warmups="${PERF_RECOVERY_WARMUPS:-5}"
budget_ms="${PERF_RECOVERY_BUDGET_MS:-2000}"
report="${PERF_RECOVERY_REPORT:-target/quality/perf-recovery-envelope-unlock.md}"

cargo_profile_args=()
if [[ "${build_profile}" == "release" ]]; then
  cargo_profile_args=(--release)
elif [[ "${build_profile}" != "debug" ]]; then
  echo "unsupported PERF_RECOVERY_BUILD_PROFILE=${build_profile}" >&2
  exit 2
fi

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

"${cargo_bin}" run \
  -p locket-crypto \
  --example perf_recovery_envelope_unlock \
  "${cargo_profile_args[@]}" \
  "${offline_args[@]}" \
  -j "${jobs}" \
  -- \
  --samples "${samples}" \
  --warmups "${warmups}" \
  --budget-ms "${budget_ms}" \
  --report "${report}" \
  --build-profile "${build_profile}" \
  --cargo-jobs "${jobs}" \
  --offline "${offline}"
