#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
strict="${EDITOR_SMOKE_STRICT:-0}"
ran=0

run_or_skip() {
  local name="$1"
  local dir="$2"
  shift 2

  if ! command -v pnpm >/dev/null 2>&1; then
    if [[ "${strict}" == "1" ]]; then
      echo "${name} smoke failed: pnpm is unavailable" >&2
      return 1
    fi
    echo "${name} smoke skipped; pnpm unavailable"
    return 0
  fi
  if [[ ! -d "${dir}/node_modules" ]]; then
    if [[ "${strict}" == "1" ]]; then
      echo "${name} smoke failed: ${dir}/node_modules is unavailable" >&2
      return 1
    fi
    echo "${name} smoke skipped; ${dir}/node_modules unavailable"
    return 0
  fi

  (
    cd "${dir}"
    "$@"
  )
  ran=1
}

run_or_skip "desktop editor" "${repo_root}/crates/locket-app/ui" pnpm run test:smoke
run_or_skip "VS Code editor" "${repo_root}/extensions/vscode" pnpm run test:smoke

if [[ "${ran}" == "1" ]]; then
  echo "editor smoke passed"
else
  echo "editor smoke skipped; no JS workspace dependencies installed"
fi
