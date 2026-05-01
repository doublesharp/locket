# Per-Budget Bench Task List (performance.md)

Audit date: 2026-04-30. Source spec: `docs/specs/performance.md` (lines 9-17).

This is the planning slice for closing the performance budget table. Each row
in the spec table is mapped to either an **existing** bench/perf script, or a
new criterion bench task that gates via a budget env var consumed by a
to-be-added `bench-regression` Make target. No benches are written here.

The reference runner that eventually validates these budgets is documented in
`docs/specs/performance-reference-runner.md`. Until those runners are online,
the budget values are placeholder defaults from `performance.md` and the
existing harness scripts.

## Existing coverage (no new bench task; verify only)

These budgets already have a runnable harness today; they need no new
criterion bench, only periodic verification on the reference runners:

- Metadata-only CLI commands p95 < 100 ms — covered by `scripts/bench-smoke.sh`
  (`cli_help`, `agent_status` samples; budgets hard-coded to 100 ms; spec ref:
  `docs/specs/performance.md:9`). **Gap:** `profile list` and
  `project list-roots` are not yet sampled — see task `bench-metadata-list-profiles`
  and `bench-metadata-list-roots` below.
- `locket scan --staged` p95 < 500 ms — covered by `scripts/bench-smoke.sh`
  (`scan_staged` samples; budget hard-coded to 500 ms; spec ref:
  `docs/specs/performance.md:12`).
- Argon2id passphrase fallback p95 < 300 ms — covered by
  `scripts/perf-passphrase-unlock.sh` (`PERF_PASSPHRASE_BUDGET_MS=300`; spec
  ref: `docs/specs/performance.md:15`).
- Recovery-envelope Argon2 unlock p95 < 2 s — covered by
  `scripts/perf-recovery-envelope-unlock.sh` (`PERF_RECOVERY_BUDGET_MS=2000`;
  spec ref: `docs/specs/performance.md:15`).
- Agent idle memory < 50 MB — covered by
  `scripts/perf-agent-idle-memory.sh` (`PERF_AGENT_IDLE_BUDGET_MB=50`; spec
  ref: `docs/specs/performance.md:16`).

## Unmet budgets (new bench tasks)

Each task below is gated through a budget env var. The convention
`LOCKET_<NAME>_NS=<budget>` (or `_MS`, `_MBPS` as appropriate) is consumed by
the future `bench-regression.sh` harness referenced in
`docs/specs/performance-reference-runner.md`. The harness target name and
crate location are concrete; the budget number is taken verbatim from the
spec line and is **not** invented.

- [ ] **bench-metadata-list-profiles**: criterion bench at
  `crates/locket-cli/benches/metadata_commands.rs` measuring p95 wall-clock
  latency of `locket profile list` against the metadata fixture (3 profiles,
  150 secret rows); gate via `bench-regression.sh` with
  `LOCKET_METADATA_PROFILE_LIST_MS=100`. Spec ref:
  `docs/specs/performance.md:9`.

- [ ] **bench-metadata-list-roots**: criterion bench at
  `crates/locket-cli/benches/metadata_commands.rs` measuring p95 wall-clock
  latency of `locket project list-roots` against the metadata fixture (5
  trusted roots); gate via `bench-regression.sh` with
  `LOCKET_METADATA_LIST_ROOTS_MS=100`. Spec ref:
  `docs/specs/performance.md:9`.

- [ ] **bench-run-prep-overhead**: criterion bench at
  `crates/locket-cli/benches/run_prep.rs` measuring p95 of `locket run
  <policy>` process-preparation overhead (start of CLI invocation through
  immediately-before-child-spawn) against the runtime fixture (50 active
  secrets, one policy injecting all 50); must isolate child-spawn time from
  the measurement window. Gate via `bench-regression.sh` with
  `LOCKET_RUN_PREP_OVERHEAD_MS=150`. Spec ref:
  `docs/specs/performance.md:10`.

- [ ] **bench-lk-reference-resolution**: criterion bench at
  `crates/locket-agent/benches/reference_resolution.rs` measuring p95
  per-reference latency for `lk://` resolution through the agent IPC after
  grant validation, against the reference-resolution fixture (>= 500
  references mixed across current / pinned-current / deprecated-in-grace /
  expired / missing / unauthorized). Bench must hold the agent unlocked
  across iterations to match the spec preconditions. Gate via
  `bench-regression.sh` with `LOCKET_LK_RESOLVE_PER_REF_MS=25`. Spec ref:
  `docs/specs/performance.md:11`.

- [ ] **bench-full-repo-scan-throughput**: criterion bench at
  `crates/locket-scan/benches/full_repo_scan.rs` measuring sustained
  throughput (bytes / wall-clock seconds, decryption time excluded) of
  `locket scan` against the deterministic >= 250 MB full-scan fixture; the
  PR-tier fixture is acceptable for the bench, the >= 1 GB release fixture
  is reserved for release runs. Gate via `bench-regression.sh` with
  `LOCKET_FULL_SCAN_MIN_MBPS=25`. Spec ref:
  `docs/specs/performance.md:13`.

- [ ] **bench-locked-pattern-scan-throughput**: criterion bench at
  `crates/locket-scan/benches/locked_pattern_scan.rs` measuring throughput of
  the locked-vault pattern + entropy + provider-token + `.env` scan modes
  (no decryption path) against the same >= 250 MB full-scan fixture; the
  bench must assert no key-unwrap or decrypt code path is reached. Gate via
  `bench-regression.sh` with `LOCKET_LOCKED_SCAN_MIN_MBPS=25`. Spec ref:
  `docs/specs/performance.md:14`.

- [ ] **bench-no-argon2-on-hot-path**: criterion bench at
  `crates/locket-agent/benches/hot_path_argon2_audit.rs` that asserts via
  a counting hook (e.g. a `#[cfg(bench_audit)]` Argon2 invocation counter in
  `locket-crypto`) that zero Argon2 executions occur during a representative
  steady-state agent workload (resolve 100 `lk://` refs against an unlocked
  agent). This is an invariant, not a latency budget; gate via
  `bench-regression.sh` with `LOCKET_HOT_PATH_ARGON2_MAX=0`. Spec ref:
  `docs/specs/performance.md:17`.

## Cross-cutting follow-ups

- [ ] **bench-regression-harness-skeleton**: introduce
  `scripts/bench-regression.sh` and a `bench-regression` Make target that
  reads each `LOCKET_*` budget env var listed above, runs the corresponding
  criterion bench under `--release`, and emits a pass/fail JSON line per
  budget. The doc `docs/specs/performance-reference-runner.md` already
  references this script; the script itself is added with the first
  criterion bench that lands.
- [ ] **bench-regression-cli-cold-start-skeleton**: introduce
  `scripts/perf-cli-cold-start.sh` (referenced by the reference-runner doc)
  to record cold-process p95 for each metadata CLI command from a fresh
  process invocation, with the agent already running and unlocked. This
  complements the warm-process numbers in `bench-smoke.sh` and is required
  before the metadata-CLI budget can be considered fully validated for
  release.
- [ ] **bench-criterion-key-derivation-template**: add the workspace's first
  criterion bench at `crates/locket-crypto/benches/key_derivation.rs` to
  serve as the template referenced by all the bench tasks above (criterion
  setup, `[[bench]]` block in the crate `Cargo.toml`, `--bench` target name,
  budget-gating pattern). This is a setup task, not a budget task; once it
  lands, every per-budget task above can be expanded into a real bench
  without re-deciding harness conventions.

## Summary

- **Budgets in spec table:** 9 distinct rows (`performance.md:9-17`).
- **Already covered:** 5 rows (metadata-CLI partial, staged scan, passphrase
  unlock, recovery-envelope unlock, agent idle memory).
- **Unmet (new bench task each):** 7 tasks above — 2 to fill the metadata-CLI
  gap (`profile list`, `project list-roots`), plus `run` prep overhead,
  `lk://` resolution, full-scan throughput, locked-pattern-scan throughput,
  and the no-Argon2-on-hot-path invariant.
- **Cross-cutting setup:** 3 follow-ups (`bench-regression.sh` skeleton,
  `perf-cli-cold-start.sh` skeleton, criterion key-derivation template).
