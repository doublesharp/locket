#!/usr/bin/env bash
set -euo pipefail

# coverage.sh - drive cargo-llvm-cov for line, html, and branch coverage.
#
# docs/specs/testing.md:48 names `cargo llvm-cov` as the canonical line and
# branch coverage tool. HTML mode renders through
# `npx -y @0xdoublesharp/doublcov` by default for richer reports under
# coverage/report/; `cargo llvm-cov --html` is retained as the legacy
# renderer and is also used as an automatic fallback when npx is unavailable.
#
# Set COVERAGE_HTML_TOOL=llvm-cov (or pass --use-llvm-cov as the second
# argument) to force the legacy renderer.

mode="${1:-line}"
html_tool_flag="${2:-}"
cargo_bin="${CARGO:-cargo}"
llvm_cov="${CARGO_LLVM_COV:-cargo llvm-cov}"
jobs="${CARGO_JOBS:-12}"
offline="${OFFLINE:-1}"
strict="${STRICT:-0}"
html_tool="${COVERAGE_HTML_TOOL:-doublcov}"
doublcov_version="${DOUBLCOV_VERSION:-0.4.3}"
doublcov_pkg="@0xdoublesharp/doublcov@${doublcov_version}"
line_floor="${COVERAGE_MIN_LINES:-89}"
branch_floor="${COVERAGE_MIN_BRANCHES:-68}"

if [[ "${html_tool_flag}" == "--use-doublcov" ]]; then
  html_tool="doublcov"
elif [[ "${html_tool_flag}" == "--use-llvm-cov" ]]; then
  html_tool="llvm-cov"
fi

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

doublcov_open_args=()
if [[ -n "${CI:-}" ]]; then
  doublcov_open_args=(--no-open)
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
    exec ${llvm_cov} --workspace --all-features "${offline_args[@]}" --fail-under-lines "${line_floor}" --lcov --output-path coverage/lcov.info
    ;;
  html)
    if [[ "${html_tool}" == "llvm-cov" ]]; then
      # Legacy path: cargo llvm-cov --html. No Node, no network.
      exec ${llvm_cov} --workspace --all-features "${offline_args[@]}" --fail-under-lines "${line_floor}" --html --output-dir coverage/html
    fi

    if ! command -v npx >/dev/null 2>&1; then
      if [[ "${strict}" == "1" ]]; then
        echo "npx (Node.js) is required for the doublcov html report" >&2
        exit 127
      fi

      echo "npx not found; falling back to cargo llvm-cov --html" >&2
      exec ${llvm_cov} --workspace --all-features "${offline_args[@]}" --fail-under-lines "${line_floor}" --html --output-dir coverage/html
    fi

    ${llvm_cov} --workspace --all-features "${offline_args[@]}" --fail-under-lines "${line_floor}" --lcov --output-path coverage/lcov.info
    exec npx -y "${doublcov_pkg}" build \
      --lcov coverage/lcov.info \
      --sources crates \
      --extensions rs \
      --out coverage/report \
      "${doublcov_open_args[@]}"
    ;;
  branch)
    branch_llvm_cov="${CARGO_LLVM_COV:-cargo +nightly llvm-cov}"
    if ! ${branch_llvm_cov} --version >/dev/null 2>&1; then
      echo "cargo-llvm-cov branch coverage requires a nightly toolchain; set CARGO_LLVM_COV or install nightly" >&2
      exit 127
    fi
    ${branch_llvm_cov} --workspace --all-features "${offline_args[@]}" --branch --fail-under-lines "${line_floor}" --lcov --output-path coverage/branch.lcov.info
    branch_percent="$(
      awk -F: '
        /^BRF:/ { total += $2 }
        /^BRH:/ { hit += $2 }
        END {
          if (total == 0) {
            exit 2
          }
          printf "%.2f", (hit * 100) / total
        }
      ' coverage/branch.lcov.info
    )" || {
      echo "branch coverage data missing from coverage/branch.lcov.info" >&2
      exit 1
    }
    awk -v actual="${branch_percent}" -v floor="${branch_floor}" 'BEGIN { exit !(actual + 0 >= floor + 0) }' || {
      echo "branch coverage ${branch_percent}% is below ${branch_floor}%" >&2
      exit 1
    }
    echo "branch coverage ${branch_percent}% meets ${branch_floor}%"
    ;;
  *)
    echo "unknown coverage mode: ${mode}" >&2
    exit 2
    ;;
esac
