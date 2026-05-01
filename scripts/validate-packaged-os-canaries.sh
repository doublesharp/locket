#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${LOCKET_PACKAGE_ARTIFACT_ROOT:-${repo_root}/target/package}"
dry_run=0
install_smoke=0
vsix_path="${LOCKET_VSIX_PATH:-}"

usage() {
  sed -n '1,120p' <<'USAGE'
Usage:
  scripts/validate-packaged-os-canaries.sh [--artifact-root PATH] [--vsix PATH] [--install-smoke] [--dry-run]

Validates packaged OS canary surfaces that normal CI cannot fully exercise:
signed desktop installer artifacts, packaged VSIX execution, and artifact
scanning for known canary markers.

--install-smoke runs host-specific installer/extension smoke commands when the
required tools and artifacts are available.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-root)
      artifact_root="${2:-}"
      shift 2
      ;;
    --vsix)
      vsix_path="${2:-}"
      shift 2
      ;;
    --install-smoke)
      install_smoke=1
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

require_tool() {
  local tool="$1"
  if command -v "${tool}" >/dev/null 2>&1; then
    return 0
  fi
  echo "required tool not found: ${tool}" >&2
  exit 127
}

scan_artifacts_for_canaries() {
  if [[ ! -d "${artifact_root}" ]]; then
    echo "artifact root not found: ${artifact_root}" >&2
    exit 66
  fi
  if rg -a -n "lk-canary|LOCKET_CANARY|DATABASE_URL_CANARY" "${artifact_root}"; then
    echo "known canary marker leaked into packaged artifacts" >&2
    exit 1
  fi
  echo "artifact scan passed: no known canary markers under ${artifact_root}"
}

validate_host_package() {
  case "$(uname -s)" in
    Darwin*)
      local pkg
      pkg="$(find "${artifact_root}" -name '*.pkg' -type f | sort | head -n 1 || true)"
      [[ -n "${pkg}" ]] || { echo "no macOS pkg under ${artifact_root}" >&2; exit 66; }
      require_tool pkgutil
      require_tool spctl
      pkgutil --check-signature "${pkg}"
      spctl -a -vv -t install "${pkg}"
      ;;
    Linux*)
      local deb rpm
      deb="$(find "${artifact_root}" -name '*.deb' -type f | sort | head -n 1 || true)"
      rpm="$(find "${artifact_root}" -name '*.rpm' -type f | sort | head -n 1 || true)"
      if [[ -n "${deb}" ]]; then
        require_tool dpkg-deb
        dpkg-deb --info "${deb}" >/dev/null
      fi
      if [[ -n "${rpm}" ]]; then
        require_tool rpm
        rpm --checksig "${rpm}"
      fi
      if [[ -z "${deb}${rpm}" ]]; then
        echo "no Linux deb/rpm under ${artifact_root}" >&2
        exit 66
      fi
      ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      local msi
      msi="$(find "${artifact_root}" -name '*.msi' -type f | sort | head -n 1 || true)"
      [[ -n "${msi}" ]] || { echo "no Windows MSI under ${artifact_root}" >&2; exit 66; }
      require_tool signtool
      signtool verify /pa /v "${msi}"
      ;;
    *)
      echo "unsupported host for package install smoke: $(uname -s)" >&2
      exit 64
      ;;
  esac
}

validate_vsix() {
  if [[ -z "${vsix_path}" ]]; then
    vsix_path="$(find "${artifact_root}" -name '*.vsix' -type f | sort | head -n 1 || true)"
  fi
  [[ -n "${vsix_path}" ]] || { echo "no VSIX artifact found" >&2; exit 66; }
  require_tool code
  code --install-extension "${vsix_path}" --force
  code --list-extensions | rg '^locket\.locket$|^doublesharp\.locket$' >/dev/null
}

if [[ "${dry_run}" == "1" ]]; then
  echo "dry-run: would scan packaged artifacts under ${artifact_root}"
  if [[ "${install_smoke}" == "1" ]]; then
    echo "dry-run: would run host installer and VSIX smoke checks when artifacts exist"
  fi
  exit 0
fi

require_tool rg
scan_artifacts_for_canaries

if [[ "${install_smoke}" == "1" ]]; then
  validate_host_package
  validate_vsix
fi
