#!/usr/bin/env bash
set -euo pipefail

mode="${1:-local}"
strict="${STRICT:-0}"
cargo_machete="${CARGO_MACHETE:-cargo machete}"
cargo_udeps="${CARGO_UDEPS:-cargo +nightly udeps}"
quality_dir="target/quality"
report="${quality_dir}/dependency-hygiene.md"

mkdir -p "${quality_dir}"

declare -a report_lines=(
  "# Dependency Hygiene"
  ""
  "| Check | Status | Detail |"
  "| --- | --- | --- |"
)

append_report() {
  local check="$1"
  local status="$2"
  local detail="$3"

  detail="${detail//$'\n'/ }"
  detail="${detail//|/\\|}"
  report_lines+=("| ${check} | ${status} | ${detail} |")
}

write_report() {
  printf '%s\n' "${report_lines[@]}" > "${report}"
}

require_optional_tool() {
  local check="$1"
  local binary="$2"

  if command -v "${binary}" >/dev/null 2>&1; then
    return 0
  fi

  append_report "${check}" "skipped" "${binary} is not installed"
  if [[ "${strict}" == "1" ]]; then
    write_report
    echo "${binary} is required for strict dependency hygiene checks" >&2
    exit 127
  fi
  echo "${binary} is not installed; skipping ${check}" >&2
  return 1
}

run_command() {
  local check="$1"
  shift

  local output
  local status
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e

  if [[ "${status}" -eq 0 ]]; then
    append_report "${check}" "passed" "no unused dependencies reported"
    [[ -n "${output}" ]] && printf '%s\n' "${output}"
    return 0
  fi

  append_report "${check}" "failed" "${output}"
  printf '%s\n' "${output}" >&2
  write_report
  exit "${status}"
}

run_machete() {
  require_optional_tool "cargo machete" "cargo-machete" || return 0
  read -r -a command_parts <<< "${cargo_machete}"
  run_command "cargo machete" "${command_parts[@]}"
}

run_udeps() {
  require_optional_tool "cargo udeps" "cargo-udeps" || return 0
  read -r -a command_parts <<< "${cargo_udeps}"
  run_command "cargo udeps" "${command_parts[@]}" --workspace --all-targets --all-features
}

case "${mode}" in
  local)
    run_machete
    run_udeps
    ;;
  machete)
    run_machete
    ;;
  udeps)
    run_udeps
    ;;
  *)
    echo "unknown dependency hygiene mode: ${mode}" >&2
    exit 2
    ;;
esac

write_report
echo "wrote ${report}"
