#!/usr/bin/env bash
set -euo pipefail

mode="${1:-smoke}"
cargo_fuzz="${CARGO_FUZZ:-cargo +nightly fuzz}"
strict="${STRICT:-0}"
seconds="${FUZZ_TIME:-60}"
max_len="${FUZZ_MAX_LEN:-65536}"
timeout_seconds="${FUZZ_TIMEOUT:-30}"
rss_limit_mb="${FUZZ_RSS_LIMIT_MB:-2048}"
sanitizer="${FUZZ_SANITIZER:-}"
required_targets=(
  fuzz_dotenv_import
  fuzz_locket_toml
  fuzz_lk_uri
  fuzz_policy_toml
  fuzz_agent_protocol
  fuzz_bundle_container
  fuzz_recovery_envelope
  fuzz_audit_row
  fuzz_redactor
  fuzz_scanner_tokenization
  fuzz_env_merge
  fuzz_device_descriptor
)
default_targets="${required_targets[*]} fuzz_secret_name"
targets="${FUZZ_TARGETS:-${default_targets}}"

case "${mode}" in
  list | smoke | run | nightly) ;;
  *)
    echo "usage: $0 [list|smoke|run|nightly]" >&2
    exit 2
    ;;
esac

# docs/specs/fuzzing.md:43 - sanitizer-supported jobs should use
# AddressSanitizer/UBSan where available. Default the smoke job to
# `address` on Linux and macOS (libFuzzer + ASan are well supported),
# while keeping the nightly default unchanged. Set FUZZ_SANITIZER=none
# to opt out (useful when sanitizer-instrumented builds break a target).
host_os="$(uname -s 2>/dev/null || echo unknown)"
case "${mode}" in
  smoke | run)
    if [[ -z "${sanitizer}" ]]; then
      case "${host_os}" in
        Linux | Darwin)
          sanitizer="address"
          ;;
      esac
    fi
    ;;
esac

if [[ "${mode}" == "nightly" ]]; then
  strict=1
  seconds="${FUZZ_TIME:-900}"
  sanitizer="${sanitizer:-address}"
fi

# Allow callers to disable the sanitizer with FUZZ_SANITIZER=none.
if [[ "${sanitizer}" == "none" ]]; then
  sanitizer=""
fi

if [[ "${strict}" == "1" && "${seconds}" -lt 60 ]]; then
  echo "strict fuzz gates require FUZZ_TIME >= 60 seconds per target" >&2
  exit 2
fi

if ! available_targets="$(${cargo_fuzz} list 2>/dev/null)"; then
  if [[ "${strict}" == "1" ]]; then
    echo "cargo-fuzz on nightly is required for strict fuzz gates" >&2
    exit 127
  fi

  echo "cargo-fuzz on nightly is not available; skipping local fuzz smoke" >&2
  exit 0
fi

if [[ "${mode}" == "list" ]]; then
  printf '%s\n' "${available_targets}"
  exit 0
fi

for required in "${required_targets[@]}"; do
  if ! grep -qx "${required}" <<<"${available_targets}"; then
    echo "required fuzz target missing: ${required}" >&2
    exit 1
  fi
done

run_args=(
  "-max_total_time=${seconds}"
  "-max_len=${max_len}"
  "-timeout=${timeout_seconds}"
  "-rss_limit_mb=${rss_limit_mb}"
  "-print_final_stats=1"
)

sanitizer_args=()
if [[ -n "${sanitizer}" ]]; then
  sanitizer_args=(-s "${sanitizer}")
fi

for target in ${targets}; do
  if ! grep -qx "${target}" <<<"${available_targets}"; then
    echo "selected fuzz target missing: ${target}" >&2
    exit 1
  fi
  echo "fuzz smoke: ${target} (${seconds}s)"
  echo "fuzz artifacts: fuzz/artifacts/${target}/"
  ${cargo_fuzz} run "${sanitizer_args[@]}" "${target}" -- "${run_args[@]}"
done
