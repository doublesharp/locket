#!/usr/bin/env bash
set -euo pipefail

mode="${1:-ci}"
cargo_bin="${CARGO:-cargo}"
jobs="${CARGO_JOBS:-12}"
offline="${OFFLINE:-1}"
quality_dir="target/quality"
jsonl="${quality_dir}/bench-smoke.jsonl"
report="${quality_dir}/bench-report.md"

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

mkdir -p "${quality_dir}"

now_seconds() {
  perl -MTime::HiRes=time -e 'printf "%.6f\n", time'
}

elapsed_ms() {
  local start="$1"
  local end="$2"
  awk -v start="${start}" -v end="${end}" 'BEGIN { printf "%.3f", (end - start) * 1000 }'
}

percentile_95() {
  awk '
    { values[NR] = $1 }
    END {
      if (NR == 0) {
        print "0.000";
        exit;
      }
      for (i = 1; i <= NR; i++) {
        for (j = i + 1; j <= NR; j++) {
          if (values[i] > values[j]) {
            tmp = values[i];
            values[i] = values[j];
            values[j] = tmp;
          }
        }
      }
      idx = int(0.95 * NR);
      if (0.95 * NR > idx) {
        idx++;
      }
      if (idx < 1) {
        idx = 1;
      }
      printf "%.3f\n", values[idx];
    }
  '
}

run_sample() {
  local name="$1"
  shift
  local start end elapsed
  start="$(now_seconds)"
  "$@" >/dev/null
  end="$(now_seconds)"
  elapsed="$(elapsed_ms "${start}" "${end}")"
  printf '%s\n' "${elapsed}" >> "${quality_dir}/${name}.samples"
  printf '{"name":"%s","elapsed_ms":%s}\n' "${name}" "${elapsed}" >> "${jsonl}"
}

write_report() {
  local cli_p95
  cli_p95="$(percentile_95 < "${quality_dir}/cli_help.samples")"
  {
    echo "# Locket Benchmark Smoke Report"
    echo
    echo "- mode: ${mode}"
    echo "- cargo_jobs: ${jobs}"
    echo "- offline: ${offline}"
    echo "- cli_help_samples: $(wc -l < "${quality_dir}/cli_help.samples" | tr -d ' ')"
    echo "- cli_help_p95_ms: ${cli_p95}"
    echo
    echo "This smoke report checks that the benchmark harness works. Full release"
    echo "budget enforcement is tracked in docs/specs/performance.md."
  } > "${report}"
  cat "${report}"
}

if [[ "${mode}" == "report" ]]; then
  if [[ ! -f "${report}" ]]; then
    echo "no benchmark report found; run make bench-ci first" >&2
    exit 2
  fi
  cat "${report}"
  exit 0
fi

: > "${jsonl}"
: > "${quality_dir}/cli_help.samples"

"${cargo_bin}" build -p locket-cli "${offline_args[@]}" -j "${jobs}" >/dev/null

samples="${BENCH_SAMPLES:-10}"
if [[ "${mode}" == "full" ]]; then
  samples="${BENCH_SAMPLES:-50}"
fi

for _ in $(seq 1 "${samples}"); do
  run_sample cli_help target/debug/locket --help
done

write_report
