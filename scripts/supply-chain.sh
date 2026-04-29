#!/usr/bin/env bash
set -euo pipefail

mode="${1:-local}"
cargo_bin="${CARGO:-cargo}"
cargo_deny="${CARGO_DENY:-cargo deny}"
cargo_audit="${CARGO_AUDIT:-cargo audit}"
strict="${STRICT:-0}"
quality_dir="target/quality"

mkdir -p "${quality_dir}"

require_tool() {
  local name="$1"
  local command="$2"

  if ${command} --version >/dev/null 2>&1; then
    return 0
  fi

  if [[ "${strict}" == "1" ]]; then
    echo "${name} is required for strict supply-chain checks" >&2
    exit 127
  fi

  echo "${name} is not installed; skipping ${name} check" >&2
  return 1
}

metadata() {
  "${cargo_bin}" metadata --offline --locked --format-version=1 > "${quality_dir}/cargo-metadata.json"
}

deny_local() {
  if require_tool "cargo-deny" "${cargo_deny}"; then
    ${cargo_deny} check licenses bans sources
  fi
}

deny_strict() {
  if require_tool "cargo-deny" "${cargo_deny}"; then
    ${cargo_deny} check
  fi
}

audit_local() {
  if ! require_tool "cargo-audit" "${cargo_audit}"; then
    return 0
  fi

  if ${cargo_audit} --help 2>/dev/null | grep -q -- '--no-fetch'; then
    ${cargo_audit} --no-fetch --stale
    return 0
  fi

  if [[ "${strict}" == "1" ]]; then
    echo "cargo-audit does not support --no-fetch; refusing strict offline audit" >&2
    exit 127
  fi

  echo "cargo-audit lacks --no-fetch; skipping to avoid network access" >&2
}

audit_strict() {
  if require_tool "cargo-audit" "${cargo_audit}"; then
    ${cargo_audit}
  fi
}

unsafe_inventory() {
  if command -v cargo-geiger >/dev/null 2>&1; then
    cargo geiger --all-features --output-format GitHubMarkdown > "${quality_dir}/unsafe-inventory.md"
    echo "wrote ${quality_dir}/unsafe-inventory.md"
    return 0
  fi

  if [[ "${strict}" == "1" ]]; then
    echo "cargo-geiger is required for strict unsafe inventory" >&2
    exit 127
  fi

  echo "cargo-geiger is not installed; skipping unsafe inventory" >&2
}

sbom() {
  if command -v cargo-cyclonedx >/dev/null 2>&1; then
    cargo cyclonedx --format json --output-cdx --output-prefix "${quality_dir}/locket"
    return 0
  fi

  if [[ "${strict}" == "1" ]]; then
    echo "cargo-cyclonedx is required for strict SBOM generation" >&2
    exit 127
  fi

  echo "cargo-cyclonedx is not installed; writing metadata fallback only" >&2
  metadata
}

case "${mode}" in
  local)
    metadata
    deny_local
    audit_local
    ;;
  deny)
    metadata
    if [[ "${strict}" == "1" ]]; then
      deny_strict
    else
      deny_local
    fi
    ;;
  audit)
    if [[ "${strict}" == "1" ]]; then
      audit_strict
    else
      audit_local
    fi
    ;;
  unsafe)
    unsafe_inventory
    ;;
  sbom)
    sbom
    ;;
  strict)
    metadata
    deny_strict
    audit_strict
    unsafe_inventory
    sbom
    ;;
  *)
    echo "unknown supply-chain mode: ${mode}" >&2
    exit 2
    ;;
esac
