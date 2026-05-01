#!/usr/bin/env bash
# bench-regression.sh — gate a criterion microbench against a fixed budget.
#
# Wraps `cargo bench` for the `locket-crypto` `key_derivation` bench with the
# bencher output format, parses the warm-call ns/op figure, and exits non-zero
# when the measurement exceeds the configured budget by more than 20%.
#
# ----- Budget reference -----
#
# `LOCKET_KEY_DERIVATION_WARM_NS` is the warm-call ns/op budget. The default
# (15000 ns ≈ 15 µs) is a deliberately liberal placeholder. HKDF-SHA256
# expansion of a 32-byte key is well under 1 µs on the docs/specs/performance.md
# reference runner, so the gate purposefully has slack until a named reference
# runner publishes a measured baseline.
#
# How to update:
#
#   1. Run `cargo bench -p locket-crypto --bench key_derivation -- \
#         --output-format bencher` on the named reference runner with the
#      release profile and AC power per docs/specs/performance.md.
#   2. Take the warm_repeat_call ns/iter median and round up to a stable
#      ceiling (typical 2x headroom).
#   3. Update the default `LOCKET_KEY_DERIVATION_WARM_NS` value in this script
#      and note the runner + commit SHA in the commit message.
#
# CI override:
#
#   LOCKET_KEY_DERIVATION_WARM_NS=<ns>            # base budget
#   LOCKET_BENCH_REGRESSION_TOLERANCE_PCT=<pct>   # default 20
#
# ----- Output -----
#
# Pass: prints `bench-regression: pass key_derivation/warm_repeat_call <ns> ns/iter (budget <budget> +<tolerance>%)`
# Fail: prints `bench-regression: fail …` and exits 1.
# Skip: when the bench produces no warm_repeat_call line, exits 2 with a
# `bench-regression: skip` reason; CI must treat this as a hard error.

set -euo pipefail

cargo_bin="${CARGO:-cargo}"
package="${LOCKET_BENCH_REGRESSION_PACKAGE:-locket-crypto}"
bench_name="${LOCKET_BENCH_REGRESSION_BENCH:-key_derivation}"
case_name="${LOCKET_BENCH_REGRESSION_CASE:-key_derivation/warm_repeat_call}"
budget_ns="${LOCKET_KEY_DERIVATION_WARM_NS:-15000}"
tolerance_pct="${LOCKET_BENCH_REGRESSION_TOLERANCE_PCT:-20}"
warmup_seconds="${LOCKET_BENCH_REGRESSION_WARMUP_SECS:-1}"
measurement_seconds="${LOCKET_BENCH_REGRESSION_MEASUREMENT_SECS:-3}"
output_dir="${LOCKET_BENCH_REGRESSION_OUTPUT_DIR:-target/perf}"

mkdir -p "${output_dir}"
output_file="${output_dir}/bench-regression-${bench_name}.txt"

if ! [[ "${budget_ns}" =~ ^[0-9]+$ ]]; then
  echo "bench-regression: invalid LOCKET_KEY_DERIVATION_WARM_NS=${budget_ns}" >&2
  exit 2
fi

if ! [[ "${tolerance_pct}" =~ ^[0-9]+$ ]]; then
  echo "bench-regression: invalid LOCKET_BENCH_REGRESSION_TOLERANCE_PCT=${tolerance_pct}" >&2
  exit 2
fi

# Run the bench in release mode with bencher output. `tee` so we keep the raw
# log under target/perf/ for inspection on regressions.
set +e
"${cargo_bin}" bench -p "${package}" --bench "${bench_name}" -- \
  --warm-up-time "${warmup_seconds}" \
  --measurement-time "${measurement_seconds}" \
  --output-format bencher \
  | tee "${output_file}"
status="${PIPESTATUS[0]}"
set -e

if [[ "${status}" -ne 0 ]]; then
  echo "bench-regression: cargo bench failed with status ${status}" >&2
  exit "${status}"
fi

# bencher output format example:
#   test key_derivation/warm_repeat_call ... bench:        612 ns/iter (+/- 18)
measurement_ns="$(awk -v target="${case_name}" '
  $1 == "test" && $2 == target && $4 == "bench:" {
    # Reconstruct the median value, stripping commas for thousands grouping.
    value = $5
    gsub(",", "", value)
    print value
    exit
  }
' "${output_file}")"

if [[ -z "${measurement_ns}" ]]; then
  echo "bench-regression: skip — no '${case_name}' line in bencher output" >&2
  exit 2
fi

# Compute ceiling = budget * (100 + tolerance_pct) / 100, rounded up to the
# nearest integer ns. Using awk so we do not need bash float math.
ceiling_ns="$(awk -v b="${budget_ns}" -v t="${tolerance_pct}" 'BEGIN {
  ceil = b * (100 + t) / 100
  printf "%d", (ceil == int(ceil) ? ceil : int(ceil) + 1)
}')"

if (( measurement_ns > ceiling_ns )); then
  printf 'bench-regression: fail %s %s ns/iter exceeds %s ns ceiling (budget %s ns +%s%%)\n' \
    "${case_name}" "${measurement_ns}" "${ceiling_ns}" "${budget_ns}" "${tolerance_pct}"
  exit 1
fi

printf 'bench-regression: pass %s %s ns/iter (budget %s ns +%s%%, ceiling %s ns)\n' \
  "${case_name}" "${measurement_ns}" "${budget_ns}" "${tolerance_pct}" "${ceiling_ns}"
