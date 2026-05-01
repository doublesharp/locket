#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
template="${repo_root}/dist/homebrew/locket.rb.in"
out="${HOMEBREW_FORMULA_OUT:-${repo_root}/target/package/homebrew/locket.rb}"
version=""
url=""
sha256=""

usage() {
  sed -n '1,80p' <<'USAGE'
Usage:
  scripts/render-homebrew-formula.sh --version <version> --url <signed-tarball-url> --sha256 <hex> [--out <path>]

Renders a publishable Homebrew formula from dist/homebrew/locket.rb.in.
The URL and SHA256 must come from the signed release source tarball.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --url)
      url="${2:-}"
      shift 2
      ;;
    --sha256)
      sha256="${2:-}"
      shift 2
      ;;
    --out)
      out="${2:-}"
      shift 2
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

if [[ -z "${version}" || -z "${url}" || -z "${sha256}" ]]; then
  echo "--version, --url, and --sha256 are required" >&2
  usage >&2
  exit 64
fi

if [[ ! "${version}" =~ ^[0-9]+[.][0-9]+[.][0-9]+([-.+][A-Za-z0-9.-]+)?$ ]]; then
  echo "version must be a semver-like string without a leading v: ${version}" >&2
  exit 64
fi

if [[ ! "${url}" =~ ^https:// ]]; then
  echo "formula url must be https: ${url}" >&2
  exit 64
fi

if [[ ! "${sha256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "sha256 must be 64 lowercase hex characters" >&2
  exit 64
fi

mkdir -p "$(dirname "${out}")"
sed \
  -e "s#__LOCKET_VERSION__#${version}#g" \
  -e "s#__LOCKET_SOURCE_TARBALL_URL__#${url}#g" \
  -e "s#__LOCKET_SOURCE_TARBALL_SHA256__#${sha256}#g" \
  "${template}" > "${out}"

if command -v ruby >/dev/null 2>&1; then
  ruby -c "${out}" >/dev/null
fi

if [[ "${LOCKET_HOMEBREW_AUDIT:-0}" == "1" ]] && command -v brew >/dev/null 2>&1; then
  brew audit --strict --new-formula "${out}"
fi

echo "Homebrew formula: ${out}"
