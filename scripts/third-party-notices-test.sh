#!/usr/bin/env bash
set -euo pipefail

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/locket-notices-test.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

metadata="${tmpdir}/cargo-metadata.json"
report="${tmpdir}/THIRD_PARTY_NOTICES.md"

cat >"${metadata}" <<'JSON'
{
  "packages": [
    {
      "name": "cssparser",
      "version": "0.36.0",
      "id": "registry+https://github.com/rust-lang/crates.io-index#cssparser@0.36.0",
      "license": "MPL-2.0",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "repository": "https://github.com/servo/rust-cssparser"
    },
    {
      "name": "serde",
      "version": "1.0.228",
      "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
      "license": "MIT OR Apache-2.0",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "repository": "https://github.com/serde-rs/serde"
    },
    {
      "name": "locket-core",
      "version": "0.1.0",
      "id": "path+file:///repo/crates/locket-core#0.1.0",
      "license": "MIT",
      "source": null,
      "repository": null
    }
  ]
}
JSON

scripts/third-party-notices.mjs "${metadata}" "${report}"

grep -Fq "# Third-party Notices" "${report}"
grep -Fq "cssparser 0.36.0" "${report}"
grep -Fq "License: MPL-2.0" "${report}"
grep -Fq "https://crates.io/crates/cssparser/0.36.0" "${report}"
grep -Fq "This distribution includes unmodified MPL-2.0 covered third-party crates" "${report}"

if grep -Fq "serde 1.0.228" "${report}"; then
  echo "permissive non-MPL dependency should not be listed in the MPL notice section" >&2
  exit 1
fi
