#!/usr/bin/env bash
set -euo pipefail

cargo_fuzz="${CARGO_FUZZ:-cargo +nightly fuzz}"
strict="${STRICT:-0}"
seconds="${FUZZ_TIME:-60}"
targets="${FUZZ_TARGETS:-fuzz_secret_name fuzz_env_merge fuzz_locket_toml fuzz_scanner_tokenization fuzz_redactor}"

if ! ${cargo_fuzz} list >/dev/null 2>&1; then
  if [[ "${strict}" == "1" ]]; then
    echo "cargo-fuzz on nightly is required for strict fuzz gates" >&2
    exit 127
  fi

  echo "cargo-fuzz on nightly is not available; skipping local fuzz smoke" >&2
  exit 0
fi

for target in ${targets}; do
  echo "fuzz smoke: ${target} (${seconds}s)"
  ${cargo_fuzz} run "${target}" -- -max_total_time="${seconds}"
done
