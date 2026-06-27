#!/usr/bin/env bash
set -euo pipefail

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/locket-rustsec-policy-test.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

audit="${tmpdir}/cargo-audit.json"
metadata="${tmpdir}/cargo-metadata.json"
ledger="${tmpdir}/supply-chain-exceptions.json"
report="${tmpdir}/rustsec-policy.md"

cat >"${audit}" <<'JSON'
{
  "vulnerabilities": {
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2099-0001",
          "package": "dev-vulnerable",
          "title": "dev-only medium fixture",
          "severity": "medium"
        },
        "package": {
          "name": "dev-vulnerable",
          "version": "1.2.3"
        }
      }
    ]
  }
}
JSON

cat >"${metadata}" <<'JSON'
{
  "packages": [
    {
      "name": "locket-tests",
      "version": "0.1.0",
      "id": "path+file:///repo#locket-tests@0.1.0",
      "source": null
    },
    {
      "name": "dev-vulnerable",
      "version": "1.2.3",
      "id": "registry+https://github.com/rust-lang/crates.io-index#dev-vulnerable@1.2.3",
      "source": "registry+https://github.com/rust-lang/crates.io-index"
    }
  ],
  "workspace_members": [
    "path+file:///repo#locket-tests@0.1.0"
  ],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#locket-tests@0.1.0",
        "deps": [
          {
            "pkg": "registry+https://github.com/rust-lang/crates.io-index#dev-vulnerable@1.2.3",
            "dep_kinds": [
              { "kind": "dev", "target": null }
            ]
          }
        ]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#dev-vulnerable@1.2.3",
        "deps": []
      }
    ]
  }
}
JSON

cat >"${ledger}" <<'JSON'
{
  "exceptions": []
}
JSON

set +e
scripts/rustsec-policy.mjs "${audit}" "${metadata}" "${ledger}" "${report}" >"${tmpdir}/stdout" 2>"${tmpdir}/stderr"
status=$?
set -e

if [[ "${status}" -eq 0 ]]; then
  echo "medium dev-only RustSec advisory should fail without a matching supply-chain exception" >&2
  cat "${tmpdir}/stdout" >&2
  cat "${tmpdir}/stderr" >&2
  exit 1
fi

grep -Fq "missing dev-only exception" "${report}"

cat >"${ledger}" <<'JSON'
{
  "exceptions": [
    {
      "package": "dev-vulnerable",
      "version": "1.2.3",
      "advisory": "RUSTSEC-2099-0001",
      "reason": "dev-only fixture advisory is not reachable from runtime builds",
      "compensating_controls": [
        "dev dependency is not part of distributed artifacts"
      ],
      "owner": "release",
      "expires_at": "2099-12-31"
    }
  ]
}
JSON

scripts/rustsec-policy.mjs "${audit}" "${metadata}" "${ledger}" "${report}" >/dev/null
grep -Fq "dev-only exception accepted" "${report}"
