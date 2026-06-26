#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
quality_dir="${repo_root}/target/quality"
output="${LOCKET_REFERENCE_RUNNER_FINGERPRINT:-${quality_dir}/reference-runner-setup.json}"
steps_file="${LOCKET_REFERENCE_RUNNER_STEPS_FILE:-}"

mkdir -p "${quality_dir}"

"${repo_root}/scripts/reference-runners/write-fingerprint.mjs" "${output}" "${steps_file}"

echo "wrote ${output}"
