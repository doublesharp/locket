#!/usr/bin/env bash
set -euo pipefail

# mutation-smoke.sh - run cargo-mutants over the security-critical *areas*
# called out in docs/specs/testing.md:43 and docs/specs/engineering.md:34.
#
# The spec requires mutation coverage on policy evaluation, env merge, typed
# error mapping, and authorization boundaries before public release. Running
# `cargo mutants --package <crate>` over whole crates dilutes mutant density
# and skips locket-cli env-merge / error-mapping code that lives outside the
# security-critical libraries.
#
# Instead this script drives cargo-mutants per *area* using --file glob
# filters. Each area is a logical concern that may span multiple crates:
#
#   policy_evaluation  - crates/locket-core/src/policy/**.rs
#                        crates/locket-agent/src/policies.rs
#   env_merge          - crates/locket-cli/src/commands/exec/run.rs
#                        crates/locket-agent/src/prepare_exec.rs
#   typed_error_map    - crates/locket-core/src/error.rs
#                        crates/locket-cli/src/main.rs (error -> exit code)
#   authz_boundaries   - crates/locket-agent/src/auth.rs (peer creds)
#                        crates/locket-store/src/grants.rs
#
# The fallback path (cargo-mutants not installed) still runs `cargo test` per
# package so contributors without cargo-mutants get a meaningful smoke. The
# fallback packages include locket-cli (which owns env-merge + error mapping)
# in addition to the previous library set.

cargo_bin="${CARGO:-cargo}"
cargo_mutants="${CARGO_MUTANTS:-cargo mutants}"
jobs="${CARGO_JOBS:-12}"
offline="${OFFLINE:-1}"
strict="${STRICT:-0}"
mutation_timeout="${MUTATION_TIMEOUT:-60}"

# Areas mapped to --file glob filters. Globs are interpreted by cargo-mutants.
mutation_areas=(
  "policy_evaluation:crates/locket-core/src/policy/**/*.rs,crates/locket-agent/src/policies.rs"
  "env_merge:crates/locket-cli/src/commands/exec/run.rs,crates/locket-agent/src/prepare_exec.rs"
  "typed_error_map:crates/locket-core/src/error.rs,crates/locket-cli/src/main.rs"
  "authz_boundaries:crates/locket-agent/src/auth.rs,crates/locket-store/src/grants.rs"
)

# Fallback package set (cargo-mutants not installed). locket-cli is included
# so env-merge / error mapping coverage isn't silently skipped.
fallback_packages="${MUTATION_FALLBACK_PACKAGES:-locket-core locket-store locket-agent locket-exec locket-platform locket-cli}"

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

if ${cargo_mutants} --version >/dev/null 2>&1; then
  for entry in "${mutation_areas[@]}"; do
    area="${entry%%:*}"
    globs="${entry#*:}"
    file_args=()
    IFS=',' read -r -a file_list <<<"${globs}"
    for path in "${file_list[@]}"; do
      file_args+=(--file "${path}")
    done
    echo "mutation area: ${area} (${globs})"
    ${cargo_mutants} \
      "${file_args[@]}" \
      --timeout "${mutation_timeout}" \
      --jobs "${jobs}" \
      --no-shuffle
  done
  exit 0
fi

if [[ "${strict}" == "1" ]]; then
  echo "cargo-mutants is required for strict mutation gates" >&2
  exit 127
fi

echo "cargo-mutants is not installed; running focused package tests as a local smoke fallback" >&2
for package in ${fallback_packages}; do
  "${cargo_bin}" test -p "${package}" "${offline_args[@]}" -j "${jobs}"
done
