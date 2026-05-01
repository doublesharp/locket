#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO:-cargo}"
target="auto"
dry_run=0
require_fido2=0

usage() {
  sed -n '1,120p' <<'USAGE'
Usage:
  scripts/validate-local-user-auth-real-host.sh [--target auto|linux-secret-service|windows-hello] [--require-fido2] [--dry-run]

Runs the LocalUserVerifier against real host OS user-presence APIs.

Targets:
  linux-secret-service  Exercises the Linux Secret Service/keyring prompt.
  windows-hello         Exercises Windows Hello UserConsentVerifier.
  auto                  Selects a target from uname.

--require-fido2 verifies that a Linux FIDO2 token is visible to the host and
prints the exact manual follow-up. The libfido2 ceremony is intentionally not
marked complete until the production fallback is wired and touched on hardware.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      target="${2:-}"
      shift 2
      ;;
    --require-fido2)
      require_fido2=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

detect_target() {
  case "$(uname -s)" in
    Linux*) echo "linux-secret-service" ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT) echo "windows-hello" ;;
    *)
      echo "unsupported"
      ;;
  esac
}

require_tool() {
  local tool="$1"
  if command -v "${tool}" >/dev/null 2>&1; then
    return 0
  fi
  echo "required tool not found: ${tool}" >&2
  exit 127
}

write_harness() {
  local harness_dir="$1"
  mkdir -p "${harness_dir}/src"
  cat > "${harness_dir}/Cargo.toml" <<EOF
[package]
name = "locket-local-auth-real-host"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
locket-platform = { path = "${repo_root}/crates/locket-platform" }
EOF
  cat > "${harness_dir}/src/main.rs" <<'EOF'
use locket_platform::{LocalUserVerificationRequest, default_local_user_verifier};

fn main() {
    let verifier = default_local_user_verifier();
    let request = LocalUserVerificationRequest::new(
        "real_host_validation",
        "Validate Locket local user verification",
    );

    match verifier.verify_user(&request) {
        Ok(result) => {
            println!(
                "local user verification succeeded: method={:?} platform={}",
                result.method, result.platform
            );
        }
        Err(error) => {
            eprintln!("local user verification failed: {error}");
            std::process::exit(1);
        }
    }
}
EOF
}

run_harness() {
  local harness_dir
  harness_dir="$(mktemp -d "${TMPDIR:-/tmp}/locket-local-auth.XXXXXX")"
  trap 'rm -rf "${harness_dir}"' EXIT
  write_harness "${harness_dir}"
  "${cargo_bin}" run --manifest-path "${harness_dir}/Cargo.toml" --locked
}

validate_linux_prereqs() {
  if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
    echo "DBUS_SESSION_BUS_ADDRESS is unset; run from an unlocked graphical Linux user session" >&2
    exit 65
  fi
  if [[ "${require_fido2}" == "1" ]]; then
    require_tool fido2-token
    fido2-token -L
    cat <<'EOF'
manual follow-up [ ]: after the libfido2-sys fallback is wired, rerun this
script on this host with --require-fido2 and touch the physical security key
when Locket prompts for user presence.
EOF
  fi
}

if [[ "${target}" == "auto" ]]; then
  target="$(detect_target)"
fi

case "${target}" in
  linux-secret-service|windows-hello)
    ;;
  unsupported)
    if [[ "${dry_run}" == "1" ]]; then
      echo "dry-run: current host has no real-host local-auth target"
      exit 0
    fi
    echo "unsupported host for real local-auth validation: $(uname -s)" >&2
    exit 64
    ;;
  *)
    echo "unknown target: ${target}" >&2
    usage >&2
    exit 64
    ;;
esac

if [[ "${dry_run}" == "1" ]]; then
  echo "dry-run: would run ${target} LocalUserVerifier harness via ${cargo_bin}"
  if [[ "${require_fido2}" == "1" ]]; then
    echo "dry-run: would require fido2-token -L before the Linux FIDO2 manual touch"
  fi
  exit 0
fi

require_tool "${cargo_bin}"
cd "${repo_root}"

case "${target}" in
  linux-secret-service)
    validate_linux_prereqs
    run_harness
    ;;
  windows-hello)
    run_harness
    ;;
esac
