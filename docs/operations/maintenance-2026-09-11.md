# Dependency and correctness maintenance

## Toolchain and dependencies

The build now pins Rust 1.98.1 with a declared Rust 1.98 minimum. This is a
deliberate pre-1.0 toolchain update. Rust 1.98.1 includes a vtable-generation
compiler fix; see the [release notes](https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/).
Clippy adaptations retain existing behavior and do not add lint suppressions.

Both Cargo lockfiles were refreshed within the existing dependency version
requirements. Examples include Tauri 2.11.5, Tokio 1.53.1, serde 1.0.229,
serde_json 1.0.151, regex 1.13.1, ignore 0.4.33, and zeroize 1.9.0.
Major upgrades outside those requirements, including the crypto and SQLite
dependency families, are not part of this update.

The config fuzzer now uses TOML 1, matching the app. Previously it tested
TOML 0.8 while production used TOML 1.

## Correctness fixes

- Redaction covers the union of overlapping matches, including self-overlaps
  and overlaps between known secrets and provider rules. Known-secret markers
  take priority. Counts describe emitted replacements.
- `ai-safe` replaces an unterminated line that reaches 64 KiB with
  `lk_redacted_BUFFER_LIMIT`, discards continuation bytes until newline, and
  resumes normal redaction. Previously a flush could split a complete known
  secret and output both unrecognized pieces. The old boundary test covered
  only an incomplete secret wholly retained in the suffix.
- Partial Tauri listener setup now cleans up acquired listeners and returns a
  typed error. Unsubscribe is idempotent.
- Vue scope disposal cleans up subscriptions that finish asynchronously.
  Late callbacks and refresh completions cannot update disposed state.
- Initial heartbeat events populate the status after a webview remount.
  Subsequent heartbeats preserve status identity. Older refresh results cannot
  overwrite newer stream events or later refreshes.
- Reveal scrubbing clears retained state objects before replacing them.
  Replacement, dismissal, and unmount all drop the old value. JavaScript
  strings cannot be securely erased from memory. Invalid and infinite TTLs
  use the default timeout.

Tests now assert exact redacted output and retained-state behavior, and exercise
failed registration, delayed setup, disposal, out-of-order completion, and
heartbeat-only startup. The redaction fuzzer checks overlapping secret removal
in addition to its former output-length bound.

CI now executes the Rust tests it previously only compiled, and has a desktop
UI job. `make app-ui-check` installs locked dependencies and runs lint, type
checking, and tests.

## Redaction performance

Release measurements on this Mac used Rust 1.98.1 for both implementations.
Each result is the median of seven calls, with output checked after every call.
These measurements describe the supplied fixtures, not overall app latency.

| Fixture | Original | Final |
| --- | ---: | ---: |
| 1,000 matches / 17 KB | 4.79 ms | 0.239 ms |
| 5,000 matches / 85 KB | 115.65 ms | 0.806 ms |
| 10,000 matches / 170 KB | 460.27 ms | 1.557 ms |

The original redactor rescanned all preceding text for every match to calculate
unused line and column positions. Redaction now stores only byte spans. The
overlap matcher uses KMP prefix state to avoid restarting searches for long
repetitive values. A 10,000-byte repetitive secret in 30,000 bytes takes
0.511 ms; the intermediate restart-search implementation took 3.9 seconds.

Reproduce the benchmark with:

```sh
cargo run -p locket-scan --example redaction_bench --release --locked
```

## Validation and remaining limits

Builds use `RUSTC_WRAPPER=/opt/homebrew/bin/sccache`,
`CARGO_INCREMENTAL=0`, `CARGO_TARGET_DIR=/Volumes/Scratch/locket/target`,
and `TMPDIR=/Volumes/Scratch/locket/tmp` on the validation host. The shared
sccache configuration resolves to `/Volumes/Scratch/sccache`. These machine
paths are not imposed on other developers or CI. Logs are under
`/Volumes/Scratch/locket/reports`.

Verification commands:

```sh
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
make app-ui-check
pnpm --dir crates/locket-app/ui build
actionlint .github/workflows/ci.yml
```

The final Rust workspace run passed 1,343 tests across 22 targets with no
failures or ignored tests. The final desktop UI check passed lint, typecheck,
and 131 Vitest tests. Strict Clippy passed with `-D warnings`.

All fuzz targets compile. The redaction target also completed a bounded smoke
run with explicit Unicode and repetitive-value seeds. That run used a stable
build without coverage instrumentation; it is not a coverage-guided fuzz
campaign.

The refreshed RustSec audit has zero entries in `vulnerabilities` and eight
warnings. Seven concern unmaintained transitive crates. The remaining warning,
RUSTSEC-2024-0429, concerns GLib 0.18.5 in the Linux desktop dependency chain;
the patched GLib 0.20 line requires an upstream dependency migration. No
advisories were suppressed. `proc-macro-error2` also emits a future compiler
compatibility notice.

Validation ran on macOS. The changed GitHub jobs and native Linux/Windows
runtime behavior have not been exercised by this local pass.

## Outstanding-work follow-up

Integrated the pending local coverage commit `393f71a0` after reviewing its
request conversions and tests. Desktop requests now resolve a default path
only when no explicit path was supplied. The imported conversions evaluated
the fallback eagerly, which could reject an explicit path when default
directory lookup failed. The regression test failed with that implementation
and passes with lazy lookup. Existing eager config and policy conversions
use the same corrected helper.

The integration adds version filtering, privacy, grace-boundary, command
validation, client-key replacement/deletion, and desktop request tests.
Secret-forwarding assertions cover both creation and rotation. Removed a
verifier test that asserted only an Arc reference count, and isolated the
missing-store fixture under a temporary directory. Independent review found
no blocking issues.

The VS Code extension's command fixture now imports its module in the async
test setup hook, preserving the VS Code stub while satisfying ESLint.
Extension lint, TypeScript compilation, and all 87 tests passed.

The integrated workspace passed 1,361 Rust tests across 22 targets with no
failures or ignored tests. After strengthening the desktop assertions, all
33 desktop tests passed again. Final workspace Clippy passed with warnings
denied, and formatting and documentation checks passed.

Additional checks completed:

- Cargo deny license, ban, and source checks; RustSec policy; exception ledger;
  and regenerated third-party notices.
- Cargo machete, installed under `/Volumes/Scratch/locket/tools`, found no
  unused dependencies.
- Notice, RustSec-policy, and provenance-policy fixture tests.
- Distribution validation including Cargo package file lists, VSIX file
  selection, workflow lint, and installer dry runs.
- Local-auth and packaged-canary host harness dry runs.

The local `target` symlink routes scripts with fixed output paths to
`/Volumes/Scratch/locket/target`; Git ignores either a target directory or
symlink. Follow-up logs use the `outstanding-` prefix in the Scratch reports
directory. No remote publication or installer signing was performed. Signed
installer tests, Linux/Windows runtime validation, and physical FIDO2 checks
still require their release hosts and credentials. The upstream dependency
warnings documented above remain.
