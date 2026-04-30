#!/usr/bin/env bash
set -euo pipefail

mode="${1:-ci}"
cargo_bin="${CARGO:-cargo}"
jobs="${CARGO_JOBS:-12}"
offline="${OFFLINE:-1}"
quality_dir="target/quality"
jsonl="${quality_dir}/bench-smoke.jsonl"
summary="${quality_dir}/bench-summary.json"
report="${quality_dir}/bench-report.md"
min_warmups="${BENCH_WARMUPS:-5}"
min_samples="${BENCH_SAMPLES:-50}"
build_profile="${BENCH_BUILD_PROFILE:-debug}"
policy_mode="${BENCH_POLICY_MODE:-}"
baseline_summary="${BENCH_BASELINE_SUMMARY:-}"
accepted_regression_note="${BENCH_ACCEPTED_REGRESSION_NOTE:-}"

if [[ "${mode}" == "full" ]]; then
  build_profile="${BENCH_BUILD_PROFILE:-release}"
fi

if [[ -z "${policy_mode}" ]]; then
  if [[ "${mode}" == "full" ]]; then
    policy_mode="release"
  else
    policy_mode="pr"
  fi
fi

cargo_profile_args=()
binary="target/debug/locket"
if [[ "${build_profile}" == "release" ]]; then
  cargo_profile_args=(--release)
  binary="target/release/locket"
fi

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

mkdir -p "${quality_dir}"

metadata_value() {
  local command="$1"
  shift
  "$command" "$@" 2>/dev/null | head -n 1 || printf 'unknown\n'
}

cpu_model() {
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n machdep.cpu.brand_string 2>/dev/null && return
  fi
  if [[ -r /proc/cpuinfo ]]; then
    awk -F: '/model name/ { sub(/^ /, "", $2); print $2; exit }' /proc/cpuinfo && return
  fi
  printf 'unknown\n'
}

memory_bytes() {
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.memsize 2>/dev/null && return
  fi
  if [[ -r /proc/meminfo ]]; then
    awk '/MemTotal/ { print $2 * 1024; exit }' /proc/meminfo && return
  fi
  printf 'unknown\n'
}

filesystem_type() {
  local device
  device="$(df . 2>/dev/null | awk 'NR == 2 { print $1 }')"
  if [[ -n "${device}" ]] && mount >/dev/null 2>&1; then
    mount | awk -v device="${device}" '
      $1 == device {
        sub(/^.*\(/, "", $0);
        sub(/[,)].*$/, "", $0);
        print $0;
        found = 1;
        exit;
      }
      END { if (!found) exit 1 }
    ' && return
  fi
  if stat -f %T . >/dev/null 2>&1; then
    stat -f %T .
    return
  fi
  if df -T . >/dev/null 2>&1; then
    df -T . | awk 'NR == 2 { print $2 }'
    return
  fi
  printf 'unknown\n'
}

power_mode() {
  if command -v pmset >/dev/null 2>&1; then
    pmset -g batt 2>/dev/null | awk 'NR == 1 { print $0; exit }' && return
  fi
  printf 'unknown\n'
}

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
  local cli_p95 sample_count p95_index processed_bytes elapsed_seconds throughput
  cli_p95="$(percentile_95 < "${quality_dir}/cli_help.samples")"
  sample_count="$(wc -l < "${quality_dir}/cli_help.samples" | tr -d ' ')"
  p95_index="$(awk -v n="${sample_count}" 'BEGIN { idx = int(0.95 * n); if (0.95 * n > idx) idx++; if (idx < 1) idx = 1; print idx }')"
  processed_bytes="0"
  elapsed_seconds="0"
  throughput="not-measured"
  {
    echo "# Locket Benchmark Smoke Report"
    echo
    echo "- mode: ${mode}"
    echo "- policy_mode: ${policy_mode}"
    echo "- reference_runner: local-smoke"
    echo "- cpu_model: $(cpu_model)"
    echo "- core_count: $(metadata_value getconf _NPROCESSORS_ONLN)"
    echo "- memory_bytes: $(memory_bytes)"
    echo "- os: $(uname -srmo 2>/dev/null || uname -srm)"
    echo "- filesystem_type: $(filesystem_type)"
    echo "- power_mode: $(power_mode)"
    echo "- commit_sha: $(git rev-parse HEAD)"
    echo "- build_profile: ${build_profile}"
    echo "- rust_version: $(rustc -V)"
    echo "- agent_running_unlocked: no"
    echo "- cargo_jobs: ${jobs}"
    echo "- offline: ${offline}"
    echo "- warmup_iterations: ${min_warmups}"
    echo "- cli_help_samples: ${sample_count}"
    echo "- cli_help_p95_ms: ${cli_p95}"
    echo "- cli_help_budget_ms: 100"
    echo "- p95_index_formula: ceil(0.95 * n) - 1 zero-based / report index ${p95_index} one-based"
    echo "- throughput_processed_bytes: ${processed_bytes}"
    echo "- throughput_elapsed_seconds: ${elapsed_seconds}"
    echo "- throughput_bytes_per_second: ${throughput}"
    echo
    echo "This report records the reference-runner fields and sampling rules required"
    echo "by docs/specs/performance.md. Expanded fixtures remain tracked by the"
    echo "broader performance-gates item."
  } > "${report}"
  perl -MJSON::PP -e '
    my ($path, $mode, $policy_mode, $profile, $samples, $p95) = @ARGV;
    open my $fh, ">", $path or die "open $path: $!";
    print {$fh} JSON::PP->new->canonical->pretty->encode({
      mode => $mode,
      policy_mode => $policy_mode,
      build_profile => $profile,
      benchmarks => [
        {
          name => "cli_help",
          kind => "latency_ms",
          budget_ms => 100,
          samples => 0 + $samples,
          p95_ms => 0 + $p95,
        },
      ],
    });
  ' "${summary}" "${mode}" "${policy_mode}" "${build_profile}" "${sample_count}" "${cli_p95}"
}

if [[ "${mode}" == "report" ]]; then
  if [[ ! -f "${report}" ]]; then
    echo "no benchmark report found; run make bench-ci first" >&2
    exit 2
  fi
  cat "${report}"
  if [[ -f "${quality_dir}/bench-policy.md" ]]; then
    echo
    cat "${quality_dir}/bench-policy.md"
  fi
  exit 0
fi

: > "${jsonl}"
: > "${quality_dir}/cli_help.samples"

"${cargo_bin}" build -p locket-cli "${offline_args[@]}" "${cargo_profile_args[@]}" -j "${jobs}" >/dev/null

for _ in $(seq 1 "${min_warmups}"); do
  "${binary}" --help >/dev/null
done

for _ in $(seq 1 "${min_samples}"); do
  run_sample cli_help "${binary}" --help
done

write_report
policy_args=(--current "${summary}" --mode "${policy_mode}" --report "${quality_dir}/bench-policy.md")
if [[ -n "${baseline_summary}" ]]; then
  policy_args+=(--baseline "${baseline_summary}")
fi
if [[ -n "${accepted_regression_note}" ]]; then
  policy_args+=(--accepted-regression-note "${accepted_regression_note}")
fi
scripts/bench-policy.pl "${policy_args[@]}"
cat "${report}"
