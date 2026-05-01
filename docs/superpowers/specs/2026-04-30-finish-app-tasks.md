# Finish-the-App Task List

Generated 2026-04-30. Single working file for closing the gap between
the current `crates/` tree and full coverage of the 21 spec files in
`docs/specs/`: 20 implementation-bearing specs plus `product.md`
positioning. Replaces the legacy `docs/agents/progress.md` and
`docs/agents/completed.md` workflow. Pick a section, ship items,
delete bullets when done.

Sources:
- Open items pulled forward from the legacy `docs/agents/progress.md`
  (the multi-agent claim/integrator workflow it described is being
  retired; the *work* it tracked is not).
- Net-new gaps from a fresh spec-vs-code audit (20-spec audit pass
  on 2026-04-30; positioning-only `product.md` excluded).

## Conventions

- `[ ]` = open. Delete when shipped.
- **Spec ref** points at the section that defines the requirement.
  Re-read it before starting work; specs are canonical.
- **Pre-req** lists upstream items in this same file. Don't start
  until those are checked.
- Subtasks are nested bullets under their parent.

## Definition of Done

Every shipped slice satisfies these:

1. **Spec match.** Each linked-spec bullet implemented or carried
   forward as a `[ ]` follow-up in this file.
2. **Typed errors.** Failures return a `LocketError` in the right
   exit-code band; new variants land in
   `crates/locket-core/src/error.rs`.
3. **Audit rows.** Spec-defined success/denial/failure events write
   via `crates/locket-store/src/audit.rs` in the same SQLite tx as
   the data change. `metadata_json` is metadata-only.
4. **Convenience columns.** When `secret_name`/`command` are
   populated, echo them inside `metadata_json`. Never write `null`.
5. **Locked vault.** Locked-safe commands succeed metadata-only;
   key-requiring commands fail with `UnlockRequired` before any work.
6. **Privacy mode.** Output respects `privacy.redact_names` via
   `*_label` helpers wherever the spec permits aliases.
7. **Typed confirmations.** Destructive flows read the spec literal
   through `RuntimeContext::confirmation_reader`; `--force` only
   where the spec calls for it.
8. **Permissions.** New non-SQLite files are 0600 (or equivalent
   ACL) via `set_user_only_file_permissions`.
9. **Tests.** Golden path, locked-vault (when applicable), every new
   typed error, audit-row shape.
10. **Leak canary.** `make leak-canary` clean; new artifact paths
    reachable from the canary scanner.

## Critical Path

Updated 2026-04-30 after wave 7 integration. Two remaining items
unblock the most fan-out.

| # | Task | Unblocks |
| - | --- | --- |
| 1 | bundle-apply-and-conflicts | bundle roundtrip e2e, full team sync, parity test with `team accept` |
| 2 | LocalUserVerifier Windows + Linux backends | `--verify-user` works without a memory-only stub on Windows / Linux hosts (macOS shipped) |

## P0 — Correctness / Security Drift (audit findings)

These are spec contracts the code currently violates or silently
ignores. Ship before any "v1 ready" claim.

### `PrepareExec` should return the issued grant id
`crates/locket-agent/src/prepare_exec.rs` issues a
`GrantAction::PrepareExec` grant on success but does not return the
grant id on the wire. The doctor and runtime paths today issue a
separate `RequestGrant(ResolveReference)` instead of reusing the
prepare-exec grant.

- [ ] **prepare-exec-grant-return**: extend `PrepareExecResponse`
  with `grant_id: String` and rewire the CLI doctor + runtime paths
  to consume it, removing the redundant `RequestGrant` call. There
  is already a `// TODO(prepare-exec-grant-return):` marker in
  `prepare_exec.rs`. Note: a previous attempt was reverted because
  it was branched off pre-prepare-exec-impl; redo against the
  current handler.

## Runtime / DX

### Local agent daemon
Spec ref: `docs/specs/agent.md`. Socket server, unlock cache, grant
table, reveal/copy, scan-known-values, list-secrets/versions,
`ResolveReference`, `PrepareExec`, `SetSecret`, `SetActiveProfile`,
`Unlock` (agent-owned unwrap), `RegisterIdeEnvSession`, and
`IdeEnvSession` dispatch are all implemented.

(No remaining daemon stubs at the dispatch level. New gaps go here
as they are discovered.)

### `locket run` spec coverage
Spec ref: `docs/specs/runtime.md:5-122`. Argv policy execution
exists with full env-mode parsing, env precedence, secret
precedence, and zeroize-on-drop. A 2026-04-30 deep audit found
three remaining gaps:

- [ ] **runtime-merge-passthrough-e2e**: Add e2e test coverage for
  `env_mode = "merge"` and `env_mode = "passthrough"` policy
  execution paths. Spec: `docs/specs/runtime.md:23-24`. Touches:
  `crates/locket-cli/src/tests/e2e_policy_run.rs`.
- [ ] **runtime-audit-policy-rejection**: Emit metadata-only audit
  rows when policy execution is rejected before spawn (missing
  required secrets, policy resolution failure, etc.). Spec:
  `docs/specs/runtime.md:28-29`. Touches:
  `crates/locket-cli/src/commands/exec/run.rs`.
- [ ] **runtime-audit-external-source-names**: Include external
  environment source names in `RUN_POLICY` audit metadata. Spec:
  `docs/specs/runtime.md:119`. Touches:
  `crates/locket-cli/src/main.rs:2418`.

### Policy command surface
Spec ref: `docs/specs/policy.md:5-35`. `policy add`, `policy allow`,
`policy require`, `policy edit`, `policy delete`, and the
agent-backed `policy doctor` (with real `lk://` resolution +
env-mode expansion via `PrepareExec` + `ResolveReference`) all
exist. No remaining gaps in this surface — but see
`agent-policy-snapshot-pump` above; without it `policy doctor`
returns `PolicyNotFound` against a running agent that hasn't been
told about the policies yet.

### `lk://` reference resolution
Spec ref: `docs/specs/runtime.md:123-155`. Agent-side
`ResolveReference` implements parsing, grant checks, policy auth,
pinned-version grace handling, expired-version rejection, and
`RESOLVE_REFERENCE` audit. Reopen concrete subtasks here only if the
runtime spec audit finds CLI integration gaps.

### Policy TOML
Spec ref: `docs/specs/policy.md`. Remaining bullets — re-read the
spec and enumerate specific TOML keys/shapes that aren't yet
parsed by `crates/locket-core/src/policy/`.

- [ ] Audit `docs/specs/policy.md` against
  `crates/locket-core/src/policy/` and enumerate unmet TOML
  features as nested subtasks here.

## Security / Recovery / Team

### Sealed bundle
Spec ref: `docs/specs/team-sync-recovery.md:111-224`.
`bundle-container-format`, `device-private-key-storage`, and
`bundle-import-decrypt` shipped. The remaining apply chain is more
entangled than the original task breakdown implied; a 2026-04-30
attempt found three structural blockers that need separate slices
before the apply chain can ship cleanly:

All three preconditions shipped — see "Recently shipped" above.
The apply chain below is the one remaining slice in this section
(round-trip same-store test requires identical-arm conflict
resolution in the same commit, so apply + conflicts + rotate are
inseparable):

- [ ] **bundle-apply-and-conflicts**: insert decrypted profile keys
  (via `bundle-profile-key-rewrap-helper`), command policies,
  secret metadata, secret_versions, and blobs in one SQLite tx,
  including the full conflict matrix in the same commit (identical
  / newer-incoming / divergent / deleted-vs-active with
  `--accept-incoming` / `--accept-local` / `interactive-required`)
  and the rotate-with-no-grace lifecycle for the newer-incoming
  arm against active local versions. Round-trip same-store tests
  require identical-arm resolution at apply time, which is why
  these three originally-separate tasks have to ship together.
  Audit: extend the existing `BACKUP_IMPORT` row's `metadata_json`
  with applied counts and `conflict_counts`.
  Pre-req: `bundle-profile-key-rewrap-helper`.
- [ ] **bundle-include-audit-import**: append imported audit rows
  to `imported_audit_chains` with HMAC structural verification.
  Pre-req: `bundle-payload-include-audit-rows`,
  `bundle-apply-and-conflicts`.
- [ ] **bundle-team-accept-parity-test**: integration test
  asserting `team accept` and `import-bundle` produce identical
  store state for newer-incoming. Pre-req:
  `team-accept-row-apply-path`, `bundle-apply-and-conflicts`.

### Team command surfaces
Spec ref: `docs/specs/team-sync-recovery.md:5-110`.
`team-store-schema`, `team-init-command`, `team-members-list`,
`team-invite-create`, `team-invite-accept`, invite revoke, member
remove, and device revoke are implemented. Re-read the spec and
enumerate remaining bullets here.

- [ ] Audit team-sync-recovery.md:5-110 and enumerate other unmet
  team commands here.

### Passkey support
Spec ref: `docs/specs/crypto.md:192-218`.

- [ ] **passkey-platform-register**: platform-authenticator
  registration flow.
- [ ] **passkey-prf-wrap**: PRF-based optional key wrapping.

### Device descriptors
Spec ref: `docs/specs/team-sync-recovery.md:50-58`.
`lkdev1_` descriptor encode/decode and v1 fingerprint hashing are
implemented. Safety words currently use a small local word list, not a
license-vetted PGP word list.

- [ ] **device-safety-words**: PGP-word-list safety-word
  derivation replacing the temporary 16-word local mapping. Note:
  previously blocked on a license-compatible PGP word list source —
  resolve before reclaiming.
(Device-key lifecycle now complete: `device init --force`,
`device remove`, and `team revoke-device` clean up wrapped
envelopes; `device_private_key_storage` doctor check reports
storage health.)

### Invite issuer/recipient trust ceremony
Spec ref: `docs/specs/team-sync-recovery.md:56-69`.
`invite-codec`, `invite-replay-protect`, `invite-clock-skew`,
signed invite creation, trust-summary display, issuer fingerprint
confirmation, accept denial rows, and revoke flows are implemented.
Re-read spec and enumerate remaining ceremony steps here.

- [ ] Audit team-sync-recovery.md:56-69 and enumerate unmet
  ceremony steps.

### Audit coverage
Reveal/copy denial rows, role denials, grant denials, dangerous-
profile read refusals (`--use-dangerous` flag), the degraded-audit
logger + `degraded_audit_log` doctor + perms doctor all shipped.
Remaining audit-action emission gaps:

- [ ] **passkey-register-emission**: `PASSKEY_REGISTER` is in the
  `required_fields_for_action` validator (`audit.rs:572`) but no
  code site emits it. Spec: `docs/specs/audit.md:53`. Touches:
  passkey registration flow once `passkey-platform-register` lands.
- [ ] **schema-migrate-emission**: `SCHEMA_MIGRATE` constant is
  defined but never appended as an audit row in migration paths.
  Spec: `docs/specs/audit.md:55`. Touches: store migration code.

### Local user verification gates
`LocalUserVerifier` + `require_user_verification` shipped;
`get --reveal/--copy --verify-user` enforces.

- [ ] Audit remaining commands in
  `docs/specs/crypto.md:192-218` for verification-gate coverage
  and add subtasks per command that lacks a gate.

### Agent / process hardening
`harden-peer-cred`, `harden-socket-perms`, `harden-memory-lock`,
`harden-zeroize`, `harden-doctor-degraded`, `harden-session-lock`
shipped.

- [ ] **harden-prctl-set-dumpable**: Linux agent must call
  `prctl(PR_SET_DUMPABLE, 0)` and set `RLIMIT_CORE = 0`. Spec:
  `docs/specs/agent.md:53`.
- [ ] **harden-macos-windows-core-dump**: macOS / Windows core-dump
  suppression equivalents (closest platform-supported APIs). Spec:
  `docs/specs/agent.md:54`.

### Import-bundle rotate-on-newer
Already covered above as `bundle-rotate-on-newer`. Cross-link:
`team accept` should trigger the same path once team sync applies
bundle contents.

- [ ] Verify `team accept` shares the same rotate-with-no-grace
  code path as `import-bundle` and add an integration test.
  Pre-req: `bundle-rotate-on-newer`, `team-invite-accept`.

### `device init` first-run-on-machine bootstrap
Spec ref: `docs/specs/team-sync-recovery.md`.

- [ ] **device-init-bootstrap**: master key, recovery envelope,
  recovery code on a teammate clone.

### LocalUserVerifier platform backends
Spec ref: `docs/specs/crypto.md:192-218`,
`docs/specs/engineering.md:144`. Current
`crates/locket-platform/src/user_verification.rs` ships only
`Unavailable` and `Memory` impls.

- [ ] **lauthn-macos**: macOS LocalAuthentication backend per the
  detailed plan in this section. Single-file
  `crates/locket-platform/src/macos_local_authentication.rs`
  marked `#[allow(unsafe_code)]` (the only exception in the
  crate; document why in a `// SAFETY-AUDIT:` comment block at
  the top citing the spec). Inside, expose ONE safe Rust
  function `evaluate_local_user(reason: &str) -> Result<bool,
  LocalAuthError>` wrapping objc2 `LAContext`
  `evaluatePolicy:localizedReason:reply:`. Implement the outer
  `LocalUserVerifier` impl in
  `macos_user_verifier.rs` with no `unsafe`. Update
  `unsafe-inventory`. Tests: `cfg(target_os = "macos")` round-trips
  a deterministic mock when
  `LOCKET_TEST_LOCAL_AUTH=allow|deny`.
- [ ] **lauthn-windows-hello**: Windows Hello backend (same
  structure as macOS plan).
- [ ] **lauthn-linux**: Linux Secret Service / hardware-key-presence
  backend (same structure).

## App / UI

The retired desktop UI campaign slices have been folded into this
checklist so this file remains the single source of task truth.
Slices 1+2 shipped. Each remaining slice is one item.

### Tauri desktop app
Spec ref: `docs/specs/desktop.md:5-65`. Shell + agent client +
tray binding + primary views + tray icon-state pusher +
SubscribeStatus stream consumer + metadata sources for secrets,
versions, runtime sessions, audit, policies, and device/member
directory shipped. Remaining: complete tray menu action wiring and
desktop write/action flows.

- [ ] **tray-menu-actions**: tray context-menu items are present and
  emitted to the webview; finish agent-backed actions beyond lock
  (unlock, switch profile, run policy) and add tests for each action.

### Tray / status panel
Spec ref: `docs/specs/desktop.md:65-108`.

- [ ] Audit desktop.md:65-108 and enumerate unmet tray-panel
  items here.

### Desktop UI campaign — remaining slices
- [ ] **desktop-reveal-modal**: short-lived modal with TTL
  countdown, accessibility scrub on expiry, dismiss-on-blur.
  Pre-req shipped: `agent-reveal-copy-impl`. (Slice 7.)
- [ ] **desktop-clipboard-copy**: copy + scheduled clear after
  TTL with re-check; Wayland degraded path emits
  `unsupported_reason`. Pre-req shipped: `agent-reveal-copy-impl`.
- [ ] **desktop-tray-reveal-copy**: tray context menu actions for
  the selected secret. Pre-req: `tray-menu-actions`,
  `desktop-reveal-modal`, `desktop-clipboard-copy`. (Slice 8.)
- [ ] **agent-policy-doctor-rpc**: RPC exercising `lk://`
  resolution + env-mode expansion. Pre-req:
  `agent-prepare-exec-impl`.
- [ ] **desktop-policy-editor-write**: create/edit/delete forms
  backed by `agent-policy-write` RPC. Dangerous-profile requires
  typed confirmation; `POLICY_UPDATE` audit.
- [ ] **desktop-team-invite-view**: invite issue/accept/revoke +
  member/device removal. Pre-req: team sync apply-path subtasks and
  any ceremony gaps found by the audit above.
- [ ] **desktop-profile-switcher-view**: switch profile +
  dangerous-profile typed confirmation through a desktop Tauri
  wrapper for shipped `agent-set-active-profile`.
- [ ] **desktop-secret-editor-view**: `SecretEditor.vue` set/update
  with TTL-bound reveal. Pre-req: `desktop-reveal-modal`,
  `agent-set-secret`.

### Search / filter UI
Spec ref: `docs/specs/desktop.md`. One subtask per surface; never
exposes values; pre-req is the relevant view's data RPC.

- [ ] Enumerate the search/filter surfaces from `desktop.md` here
  before opening branches.

## Integrations (P2 — surface-completeness)

### VS Code extension backed by the local agent
Spec ref: `docs/specs/integrations.md:39-65`. Extension must never
write audit directly. Agent client, status bar, diagnostics,
reference completion, and the full command palette
(`locket.revealSecret`, `locket.unlock`, `locket.lock`,
`locket.switchProfile`, `locket.runPolicy`, `locket.scanWorkspace`,
`locket.copySecret`, `locket.openAuditView`) all exist. The
`Unlock` RPC now accepts `{ project_id, passphrase: Option<String>,
ttl_seconds, audit }` — the extension's `locket.unlock` should send
this payload (passphrase optional; the agent tries the OS keychain
first). Remaining surfaces:

(All entry-point wiring shipped — see "Recently shipped" above.
The terminal autobind modules and unlock-with-passphrase flow are
live alongside the existing palette commands.)

## Diagnostics, Distribution, and Quality Gates

### Coverage
Spec ref: `docs/specs/testing.md:8-72`. Per-surface subtasks
shipped (policy/env/crypto/store/typed/source-precedence/scanner/
audit-hmac/runtime-sessions).

- [ ] **coverage-gate-baseline**: lower the floor in
  `scripts/coverage.sh` from `--fail-under-lines 90
  --fail-under-branches 90` to `--fail-under-lines 70
  --fail-under-branches 75` so CI is green at today's measured
  levels (70.86% / 77.19%). Add a
  `# TODO(coverage-90): ratchet back to 90 once the per-crate
  subtasks below ship` comment.
- [ ] **coverage-policy-90**: raise
  `crates/locket-core/src/policy/` line+branch coverage to ≥90%.
- [ ] **coverage-bundle-90**: same for
  `crates/locket-core/src/bundle.rs` (manifest parser error
  paths, encrypted payload boundary cases).
- [ ] **coverage-store-90**: same for
  `crates/locket-store/src/{audit,device,team,secrets,
  runtime_session}.rs` (rollback paths, FK violations, schema
  edge cases).
- [ ] **coverage-agent-90**: same for
  `crates/locket-agent/src/{auth,grant,unlock_cache,
  session_lock}.rs`.
- [ ] **coverage-gate-ratchet**: re-run `make coverage-branch`,
  ratchet `scripts/coverage.sh` back to
  `--fail-under-lines 90 --fail-under-branches 90`, remove the
  `TODO(coverage-90)` comment. Pre-req: all four
  `coverage-<crate>-90` subtasks.

### End-to-end coverage
Spec ref: `docs/specs/testing.md:38`.
`e2e-greenfield-init`, `e2e-dotenv-migration`, `e2e-policy-run`,
`e2e-docker-compose`, `e2e-recovery-roundtrip` shipped.

- [ ] **e2e-bundle-roundtrip**: `export --sealed` → `import-bundle`
  (fresh / identical / newer-incoming / divergent),
  `bundle verify` structural-only and decryptable.
  Pre-req: sealed-bundle subtasks above.
- [ ] **e2e-ui-editor-smoke**: smoke flows in the desktop app and
  the VS Code extension. Pre-req: desktop-* and vscode-* items.

### Distribution supply-chain gates
Offline-safe local commands, strict-mode hooks, cargo-vet, unsafe
inventory, SBOM, exception ledger, and provenance policy verifier
exist. Remaining: auditable builds and signing.

(`auditable-builds` shipped — see "Recently shipped" above.)
- [ ] **release-key-offline**: offline release key infrastructure
  for `update-manifest` signing — air-gapped key holder, ceremony
  doc, key-rotation plan. Pre-req for every signed-package item.
- [ ] **release-ci-isolated-runners**: public release artifacts
  built on isolated runners. Spec: `docs/specs/operations.md:39`.

### Package builders and signing
Spec ref: `docs/specs/operations.md:27-53`.

- [ ] **homebrew-formula-publish**: publish the shipped
  `dist/homebrew/locket.rb` formula to a tap (e.g.
  `doublesharp/homebrew-locket`); verify binary against release
  manifest signature once `release-key-offline` lands.
- [ ] **cargo-install-publish**: `crates.io` publish run for
  `locket-cli`. Manifest is now publishable (`dist/cargo-install.md`
  has the dry-run notes); blocked on `release-key-offline` for
  the signed-tag flow.
- [ ] **macos-pkg-signed**: signed `.pkg` with notarization.
  Pre-req: `release-key-offline`.
- [ ] **windows-msi-signed**: signed `.msi` with EV cert.
  Pre-req: `release-key-offline`.
- [ ] **linux-deb-rpm**: signed `.deb` and `.rpm` where toolchain
  is practical. Pre-req: `release-key-offline`.
- [ ] **vsix-signed**: signed VS Code VSIX direct download path.
  Pre-req: `release-key-offline`.

### Cold-start budgets
Spec ref: `docs/specs/performance.md`. Each subtask adds one
bench plus a regression that fails the budget.

(Foundations shipped — see "Recently shipped". Remaining:)

- [ ] **named-reference-runner**: pick and document a named
  reference runner (HW class, OS, CPU governor) before any
  pre-release perf claim. Spec: `docs/specs/performance.md:41`.
- [ ] Audit `docs/specs/performance.md` budget table and add
  one bench-plus-regression subtask per budget. The harness
  exists; we just need to populate it with the rest of the
  budgets.
- [ ] **bench-scripts-chmod-x**: `scripts/bench-regression.sh`
  and `scripts/perf-cli-cold-start.sh` were committed at 0644
  due to a sandbox limitation. Either `chmod +x` the on-disk
  files or `git update-index --chmod=+x` the index entries
  to match the rest of `scripts/`.

## Spec-by-Spec Completion Gates

Final audit pass — only after every TODO above is closed. Each
line means implementation, tests, docs, diagnostics, and failure
modes have all been checked against that spec file. Reopen as new
TODOs above for any gaps found.

- [ ] `product.md` (positioning; no implementation gate)
- [ ] `invariants.md`
- [ ] `architecture.md`
- [ ] `data-model.md`
- [ ] `storage.md`
- [ ] `crypto.md`
- [ ] `project-cli.md`
- [ ] `policy.md`
- [ ] `runtime.md`
- [ ] `agent.md`
- [ ] `integrations.md`
- [ ] `scan-redaction.md`
- [ ] `desktop.md`
- [ ] `audit.md`
- [ ] `team-sync-recovery.md`
- [ ] `operations.md`
- [ ] `performance.md`
- [ ] `errors.md`
- [ ] `engineering.md`
- [ ] `testing.md`
- [ ] `fuzzing.md`

## Reference

| Topic | Where |
| --- | --- |
| Exit-code bands | `docs/specs/errors.md` |
| Typed errors (canonical enum + `exit_code()`) | `crates/locket-core/src/error.rs` |
| Audit actions + metadata shapes | `docs/specs/audit.md`, `docs/specs/data-model.md` |
| Required SQLite tables | `docs/specs/storage.md` |
| Crate ownership | `docs/specs/architecture.md` |
