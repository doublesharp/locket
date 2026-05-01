#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(git -C "${script_dir}" rev-parse --show-toplevel)"
apply="${LOCKET_REFERENCE_RUNNER_APPLY:-0}"
allow_mismatch="${LOCKET_REFERENCE_ALLOW_MISMATCH:-0}"
steps_file="$(mktemp)"
trap 'rm -f "${steps_file}"' EXIT

record_step() {
  local name="$1"
  local status="$2"
  local detail="$3"
  printf '%s\t%s\t%s\n' "${name}" "${status}" "${detail}" >> "${steps_file}"
}

run_or_plan() {
  local name="$1"
  shift
  if [[ "${apply}" == "1" ]]; then
    if "$@"; then
      record_step "${name}" applied "$*"
    else
      record_step "${name}" failed "$*"
      return 1
    fi
  else
    record_step "${name}" planned "$*"
  fi
}

host_os="$(uname -s)"
host_arch="$(uname -m)"
if [[ "${host_os}" != "Darwin" || "${host_arch}" != "arm64" ]]; then
  record_step host_class skipped "expected Darwin/arm64, got ${host_os}/${host_arch}"
  if [[ "${allow_mismatch}" != "1" ]]; then
    echo "not an arm64 macOS reference runner; set LOCKET_REFERENCE_ALLOW_MISMATCH=1 to fingerprint anyway" >&2
    exit 2
  fi
else
  record_step host_class verified "${host_os}/${host_arch}"
fi

if command -v pmset >/dev/null 2>&1; then
  run_or_plan disable_low_power_mode sudo pmset -a lowpowermode 0
  run_or_plan disable_sleep sudo pmset -a sleep 0 disksleep 0 displaysleep 0
  record_step thermal_state observed "$(pmset -g therm 2>/dev/null | tr '\n' ';' || true)"
fi

if command -v defaults >/dev/null 2>&1; then
  run_or_plan disable_app_nap defaults write NSGlobalDomain NSAppSleepDisabled -bool YES
fi

if command -v mdutil >/dev/null 2>&1; then
  run_or_plan disable_spotlight_indexing sudo mdutil -a -i off
fi

LOCKET_REFERENCE_RUNNER_CLASS="locket-ref-arm64-mac" \
LOCKET_REFERENCE_RUNNER_SCRIPT="${BASH_SOURCE[0]}" \
LOCKET_REFERENCE_RUNNER_APPLY="${apply}" \
LOCKET_REFERENCE_RUNNER_STEPS_FILE="${steps_file}" \
  "${script_dir}/write-fingerprint.sh"

echo "reference runner setup complete for locket-ref-arm64-mac in ${repo_root}"
