#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tauri_dir="${repo_root}/crates/locket-app/src-tauri"
ui_dir="${repo_root}/crates/locket-app/ui"
out_root="${NATIVE_INSTALLER_OUT_DIR:-${repo_root}/target/package/installers}"
target="all"
dry_run=0

usage() {
  sed -n '1,120p' <<'USAGE'
Usage:
  scripts/package-native-installers.sh --target <all|macos-pkg|windows-msi|linux-deb|linux-rpm> [--dry-run]

Builds and signs native desktop installers. --dry-run validates repository
manifests, command shape, and signing inputs without requiring credentials.

Required signing environment:
  macos-pkg:   APPLE_DEVELOPER_ID_INSTALLER, APPLE_ID,
               APPLE_APP_SPECIFIC_PASSWORD, APPLE_TEAM_ID
  windows-msi: WINDOWS_EV_CERT_SHA1, WINDOWS_TIMESTAMP_URL
  linux-deb:   LOCKET_DEB_GPG_KEY
  linux-rpm:   LOCKET_RPM_GPG_NAME
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      target="${2:-}"
      shift 2
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
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: missing optional tool ${tool}"
    return 0
  fi
  echo "required tool not found: ${tool}" >&2
  exit 127
}

require_env() {
  local name="$1"
  if [[ -n "${!name:-}" ]]; then
    return 0
  fi
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: required signing env ${name} is unset"
    return 0
  fi
  echo "required signing env is unset: ${name}" >&2
  exit 64
}

version() {
  node -e 'const fs=require("fs"); const t=fs.readFileSync(process.argv[1],"utf8"); const m=t.match(/\[workspace\.package\][\s\S]*?\nversion\s*=\s*"([^"]+)"/); if(!m) process.exit(1); process.stdout.write(m[1]);' "${repo_root}/Cargo.toml"
}

build_tauri_bundle() {
  local bundles="$1"
  require_tool pnpm
  require_tool cargo
  if ! command -v cargo-tauri >/dev/null 2>&1 && ! cargo tauri --version >/dev/null 2>&1; then
    if [[ "${dry_run}" == "1" ]]; then
      echo "dry-run: missing cargo-tauri"
      return 0
    fi
    echo "cargo-tauri is required; install with: cargo install tauri-cli --locked" >&2
    exit 127
  fi
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: would build Tauri bundles: ${bundles}"
    return 0
  fi
  pnpm --dir "${ui_dir}" install --frozen-lockfile
  pnpm --dir "${ui_dir}" build
  (cd "${tauri_dir}" && cargo tauri build --bundles "${bundles}")
}

copy_first_match() {
  local pattern="$1"
  local destination="$2"
  local match=""
  match="$(find "${repo_root}/target/release/bundle" -path "${pattern}" -type f | sort | head -n 1 || true)"
  if [[ -z "${match}" ]]; then
    echo "expected bundle output not found: ${pattern}" >&2
    exit 1
  fi
  mkdir -p "$(dirname "${destination}")"
  cp "${match}" "${destination}"
}

macos_pkg() {
  require_tool node
  require_tool pkgbuild
  require_tool productbuild
  require_tool xcrun
  require_env APPLE_DEVELOPER_ID_INSTALLER
  require_env APPLE_ID
  require_env APPLE_APP_SPECIFIC_PASSWORD
  require_env APPLE_TEAM_ID
  build_tauri_bundle app
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: would pkgbuild/productbuild/sign/notarize macOS pkg"
    return 0
  fi
  local v component distribution pkg app_bundle
  v="$(version)"
  app_bundle="${repo_root}/target/release/bundle/macos/Locket.app"
  component="${out_root}/macos/locket-component.pkg"
  distribution="${out_root}/macos/distribution.xml"
  pkg="${out_root}/macos/Locket-${v}-$(uname -m).pkg"
  mkdir -p "${out_root}/macos"
  sed "s#__LOCKET_VERSION__#${v}#g" "${repo_root}/dist/installers/macos/distribution.xml" > "${distribution}"
  pkgbuild --component "${app_bundle}" --install-location /Applications --sign "${APPLE_DEVELOPER_ID_INSTALLER}" "${component}"
  productbuild --distribution "${distribution}" --package-path "${out_root}/macos" --sign "${APPLE_DEVELOPER_ID_INSTALLER}" "${pkg}"
  xcrun notarytool submit "${pkg}" --apple-id "${APPLE_ID}" --password "${APPLE_APP_SPECIFIC_PASSWORD}" --team-id "${APPLE_TEAM_ID}" --wait
  xcrun stapler staple "${pkg}"
  pkgutil --check-signature "${pkg}"
  xcrun stapler validate "${pkg}"
  echo "macOS pkg: ${pkg}"
}

windows_msi() {
  require_tool node
  require_tool signtool
  require_env WINDOWS_EV_CERT_SHA1
  require_env WINDOWS_TIMESTAMP_URL
  build_tauri_bundle msi
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: would signtool sign and verify MSI"
    return 0
  fi
  local v out
  v="$(version)"
  out="${out_root}/windows/Locket-${v}-${PROCESSOR_ARCHITECTURE:-x64}.msi"
  copy_first_match "*/msi/*.msi" "${out}"
  signtool sign /fd SHA256 /tr "${WINDOWS_TIMESTAMP_URL}" /td SHA256 /sha1 "${WINDOWS_EV_CERT_SHA1}" "${out}"
  signtool verify /pa /v "${out}"
  echo "Windows MSI: ${out}"
}

linux_deb() {
  require_tool node
  require_tool debsign
  require_env LOCKET_DEB_GPG_KEY
  build_tauri_bundle deb
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: would debsign generated deb"
    return 0
  fi
  local v out
  v="$(version)"
  out="${out_root}/linux/locket_${v}_$(uname -m).deb"
  copy_first_match "*/deb/*.deb" "${out}"
  debsign -k"${LOCKET_DEB_GPG_KEY}" "${out}"
  echo "Linux deb: ${out}"
}

linux_rpm() {
  require_tool node
  require_tool rpmsign
  require_env LOCKET_RPM_GPG_NAME
  build_tauri_bundle rpm
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: would rpmsign generated rpm"
    return 0
  fi
  local v out
  v="$(version)"
  out="${out_root}/linux/locket-${v}-1.$(uname -m).rpm"
  copy_first_match "*/rpm/*.rpm" "${out}"
  rpmsign --define "_gpg_name ${LOCKET_RPM_GPG_NAME}" --addsign "${out}"
  rpm --checksig "${out}"
  echo "Linux rpm: ${out}"
}

run_target() {
  case "$1" in
    macos-pkg) macos_pkg ;;
    windows-msi) windows_msi ;;
    linux-deb) linux_deb ;;
    linux-rpm) linux_rpm ;;
    all)
      macos_pkg
      windows_msi
      linux_deb
      linux_rpm
      ;;
    *)
      echo "unknown target: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
}

run_target "${target}"
