#!/usr/bin/env bash
set -euo pipefail

cargo_fuzz="${CARGO_FUZZ:-cargo +nightly fuzz}"
target="${FUZZ_TARGET:-}"
artifact="${FUZZ_ARTIFACT:-}"
max_len="${FUZZ_MAX_LEN:-65536}"
timeout_seconds="${FUZZ_TIMEOUT:-30}"
rss_limit_mb="${FUZZ_RSS_LIMIT_MB:-2048}"
sanitizer="${FUZZ_SANITIZER:-address}"

if [[ -z "${target}" || -z "${artifact}" ]]; then
  echo "Set FUZZ_TARGET=<target> and FUZZ_ARTIFACT=<path-to-crash>" >&2
  exit 2
fi

if [[ ! -f "${artifact}" ]]; then
  echo "fuzz artifact not found: ${artifact}" >&2
  exit 2
fi

if ! ${cargo_fuzz} list | grep -qx "${target}"; then
  echo "selected fuzz target missing: ${target}" >&2
  exit 1
fi

corpus_dir="fuzz/corpus/${target}"
mkdir -p "${corpus_dir}"
basename="$(basename "${artifact}")"
reproducer="${FUZZ_REPRODUCER:-${corpus_dir}/repro-${basename}}"
cp "${artifact}" "${reproducer}"

echo "minimizing ${artifact} for ${target}"
${cargo_fuzz} tmin -s "${sanitizer}" "${target}" "${reproducer}" -- \
  "-max_len=${max_len}" \
  "-timeout=${timeout_seconds}" \
  "-rss_limit_mb=${rss_limit_mb}"

echo "verifying minimized reproducer: ${reproducer}"
${cargo_fuzz} run -s "${sanitizer}" "${target}" "${reproducer}" -- \
  "-runs=1" \
  "-max_len=${max_len}" \
  "-timeout=${timeout_seconds}" \
  "-rss_limit_mb=${rss_limit_mb}"

echo "add a focused regression test with the same fix before committing ${reproducer}"
