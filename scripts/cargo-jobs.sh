#!/usr/bin/env bash

cargo_jobs() {
  if [[ -n "${CARGO_JOBS:-}" ]]; then
    printf '%s\n' "${CARGO_JOBS}"
    return
  fi
  getconf _NPROCESSORS_ONLN 2>/dev/null && return
  sysctl -n hw.logicalcpu 2>/dev/null && return
  nproc 2>/dev/null && return
  printf '1\n'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  cargo_jobs
fi
