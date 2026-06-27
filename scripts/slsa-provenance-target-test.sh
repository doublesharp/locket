#!/usr/bin/env bash
set -euo pipefail

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/locket-slsa-target-test.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

stdout="${tmpdir}/stdout"
stderr="${tmpdir}/stderr"

set +e
make slsa-provenance STRICT=1 >"${stdout}" 2>"${stderr}"
status=$?
set -e

if [[ "${status}" -eq 0 ]]; then
  echo "strict SLSA provenance target should fail when required inputs are missing" >&2
  cat "${stdout}" >&2
  cat "${stderr}" >&2
  exit 1
fi

if ! grep -Fq "SLSA provenance verification requires" "${stderr}"; then
  echo "strict SLSA provenance target should explain which inputs are required" >&2
  cat "${stderr}" >&2
  exit 1
fi

set +e
make slsa-provenance >"${stdout}" 2>"${stderr}"
status=$?
set -e

if [[ "${status}" -ne 0 ]]; then
  echo "local SLSA provenance target should skip when required inputs are missing" >&2
  cat "${stdout}" >&2
  cat "${stderr}" >&2
  exit 1
fi

grep -Fq "skip: set SLSA_ARTIFACT" "${stdout}"
