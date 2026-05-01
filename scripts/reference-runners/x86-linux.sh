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
if [[ "${host_os}" != "Linux" || "${host_arch}" != "x86_64" ]]; then
  record_step host_class skipped "expected Linux/x86_64, got ${host_os}/${host_arch}"
  if [[ "${allow_mismatch}" != "1" ]]; then
    echo "not an x86_64 Linux reference runner; set LOCKET_REFERENCE_ALLOW_MISMATCH=1 to fingerprint anyway" >&2
    exit 2
  fi
else
  record_step host_class verified "${host_os}/${host_arch}"
fi

if command -v cpupower >/dev/null 2>&1; then
  run_or_plan set_cpu_governor sudo cpupower frequency-set -g performance
  record_step cpu_governor observed "$(cpupower frequency-info 2>/dev/null | grep -i 'current policy\|governor' | tr '\n' ';' || true)"
else
  record_step cpu_governor skipped "cpupower not found"
fi

if command -v findmnt >/dev/null 2>&1; then
  record_step root_filesystem observed "$(findmnt / 2>/dev/null | tr '\n' ';' || true)"
fi

if command -v systemctl >/dev/null 2>&1; then
  run_or_plan stop_unattended_upgrades sudo systemctl stop unattended-upgrades
fi

LOCKET_REFERENCE_RUNNER_CLASS="locket-ref-x86-linux" \
LOCKET_REFERENCE_RUNNER_SCRIPT="${BASH_SOURCE[0]}" \
LOCKET_REFERENCE_RUNNER_APPLY="${apply}" \
LOCKET_REFERENCE_RUNNER_STEPS_FILE="${steps_file}" \
  "${script_dir}/write-fingerprint.sh"

echo "reference runner setup complete for locket-ref-x86-linux in ${repo_root}"
