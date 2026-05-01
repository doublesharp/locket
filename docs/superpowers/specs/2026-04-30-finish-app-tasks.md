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
- `[~]` = in-flight (an agent or human is actively working it).
  Annotate with `(in-flight: agent <id>)` or `(in-flight: <person>)`
  so coordinators can avoid collisions.
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

Updated 2026-05-01. Bundle apply/conflict handling is now
integrated on `main`; team sync parity and imported-audit-chain work
are unblocked. One remaining critical-path item.

| # | Task | Unblocks |
| - | --- | --- |
| 1 | LocalUserVerifier Windows + Linux backends | `--verify-user` works without a memory-only stub on Windows / Linux hosts (macOS shipped) |

## Spec audit follow-ups (2026-05-01)

A 21-file spec-vs-code audit on 2026-05-01 surfaced 36 new gaps not
already tracked above. They are listed here in one block so worker
agents can claim them; the section exists for triage only and items
should be moved into their proper home sections (or removed) as they
ship. Each bullet has spec ref + code ref + suggested touches.

### A. Crypto / recovery / bundle correctness

- [~] (in-flight: feature/recovery-client-envelope) **recovery-rotate-fresh-user-verification**:
  `team-sync-recovery.md:159,164-165` requires `locket recovery rotate`
  to gate on fresh local user verification. `vault/recovery.rs:51-107`
  calls neither helper. Insert verification call + embed
  `UserVerificationAudit` into the `RECOVERY_ROTATE` row.
- [~] (in-flight: feature/recovery-client-envelope) **client-create-writes-to-recovery-envelope**: `crypto.md:172`
  says `locket client create` with `--storage os-keychain` or
  `--storage wrapped-local-file` must add an
  `automation_client_private_key:<client_id>` envelope entry at
  creation. `team/client.rs:40-181` + `store_client_private_key:276-347`
  only write to keychain/local file. Result: `recover_command`
  always counts those as `skipped_automation_client_private`.
- [ ] **bootstrap-shell-tool-presence-follow-up**: bootstrap reports shell
  policy tool checks as `tools_unchecked: shell:<first-token>` because
  safely and portably identifying every referenced tool inside arbitrary
  shell snippets requires shell-aware parsing beyond the local argv check.
### B. Schema / data-model alignment

### C. CLI / runtime / agent

- [x] **agent-windows-named-pipe-sid-path-partial**: follow-up from shipped
  14c socket placement work. `agent.md:20` requires
  `\\.\pipe\locket-agent-<sid>` with a current-user-only DACL.
  Current production startup now uses `$XDG_RUNTIME_DIR/locket` on
  Linux and `~/Library/Application Support/locket` on macOS, but the
  Windows/non-Unix branch still falls back to `<HOME>/.locket` because
  the CLI/agent surface is Unix-socket-only and does not resolve the
  user's SID. Touches: Windows pipe listener/client transport,
  `resolve_default_agent_data_dir`, startup diagnostics, and pipe ACL
  tests.
- [ ] **agent-windows-named-pipe-transport**: finish the remaining hard
  transport work after `agent-windows-named-pipe-sid-path-partial`.
  The partial shipped shared SID-based pipe path helpers, protected
  current-user DACL SDDL generation, Windows diagnostics, and CLI path
  resolution behind `cfg(windows)`. Remaining: create the Tokio Windows
  named-pipe listener/client, pass the generated security descriptor
  into pipe creation, port graceful start/status/stop over the pipe,
  and add on-Windows ACL/transport integration coverage.
### D. Desktop / integrations / scan

- [~] (in-flight: feature/desktop-backup-actions) **backup-recovery-view-not-wired**: `BackupRecovery.vue`
  renders forms for export/import/verify/recovery-rotate but
  `@action` events all funnel into `App.vue:1212-1214`'s
  `triggerBackupAction` which only calls `refresh()`. No agent RPC
  invoked. `desktop.md:20` lists this as a primary view. Touches:
  add Tauri commands wrapping `ExportBundle`/`ImportBundle`/
  `VerifyBundle`/`RecoveryRotate` (some need new agent RPCs — none
  in `agent/method.rs:9-72`); typed-confirmation for destructive
  paths.
- [ ] **secret-row-cross-reference-deprecation**: `desktop.md:34`
  requires secret rows to surface version-level deprecation warnings
  when current policy/command-preview/`lk://...@vN` reference
  depends on a deprecated version with active or expired grace.
  `SecretMetadataList.vue` only shows per-row `hasDeprecatedGrace`
  badge from row's own state.
- [~] (in-flight: feature/desktop-backup-actions) **tray-privacy-alias-not-applied**: `desktop.md:37,72-73,94-95`
  requires tray tooltip + notifications to use stable local aliases
  when `privacy.redact_names = true`. Rust `tray::tooltip_for`
  (`tray.rs:345-347`) returns static `descriptor().label`
  regardless. Forward-looking gap once `status-payload-tray-fields`
  lands and tooltips include project/profile context.

### E. Quality / ops / build

- [~] (in-flight: feature/reference-runner-fuzz-quality) **reference-runner-setup-scripts**:
  `performance-reference-runner.md:87,99` mandates
  `scripts/reference-runners/` per-class setup scripts that record
  applied state into `target/quality/reference-runner-setup.json`
  and are invoked before sample collection. Directory missing
  entirely. Add `arm64-mac.sh` / `x86-linux.sh` + a fingerprint JSON
  writer; wire `bench-smoke.sh` to read the fingerprint.
- [~] (in-flight: feature/reference-runner-fuzz-quality) **fuzz-corpus-seed-thinness**: `fuzzing.md:41` requires
  diverse versioned corpora; most directories under `fuzz/corpus/`
  carry one trivial seed (e.g. `fuzz_lk_uri/basic.txt`). Seed each
  with edge-case / malformed / boundary inputs.
- [~] (in-flight: feature/reference-runner-fuzz-quality) **canary-harness-surface-coverage**: `testing.md:84-89`
  requires the canary helper to cover CLI, agent, scan, redaction,
  audit, debug bundle, UI, tray, VS Code, Docker, and recovery
  flows. Today only `locket-cli/src/tests/leak_canary.rs` and
  `locket-scan/tests/leak_canary.rs`. Extend into agent reveal/copy,
  Docker compose helper, audit row writer, desktop UI smoke, VSIX
  integration.
## P0 — Correctness / Security Drift (audit findings)

These are spec contracts the code currently violates or silently
ignores. Ship before any "v1 ready" claim.

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

(Policy TOML deep enumeration completed 2026-04-30. All keys parse;
the only structural gap was `schema_version` enforcement, now
shipped via worktree `worktree-agent-af6e0d966527edd4f`.)

## Security / Recovery / Team

### Sealed bundle
Spec ref: `docs/specs/team-sync-recovery.md:111-224`.
`bundle-container-format`, `device-private-key-storage`, and
`bundle-import-decrypt` shipped. The remaining apply chain is more
entangled than the original task breakdown implied; a 2026-04-30
attempt found three structural blockers that need separate slices
before the apply chain can ship cleanly:

### Team command surfaces
Spec ref: `docs/specs/team-sync-recovery.md:5-110`.

### Passkey support
Spec ref: `docs/specs/crypto.md:192-218`.
`PlatformPasskeyRegistrar` trait + `MemoryPlatformPasskeyRegistrar` +
PRF-wrap master key helpers + `passkey register` / `passkey unlock`
CLI commands shipped. `KeyringPlatformPasskeyRegistrar` is now the
default real backend: it stores a per-credential PRF seed in macOS
Keychain, Windows Credential Manager, or Linux Secret Service/keyring
through the platform `keyring` backend after the CLI's local user
verification gate, and derives PRF output from that credential seed
without exposing private material. (No remaining passkey backend gaps.)

### Device descriptors
Spec ref: `docs/specs/team-sync-recovery.md:50-58`. `lkdev1_`
descriptor encode/decode, v1 fingerprint hashing, canonical PGP
word-list safety words (256+256 entries), and full device-key
lifecycle (`device init --force`, `device remove`, `team
revoke-device` envelope cleanup, `device_private_key_storage`
doctor check) all shipped. (No remaining device-descriptor work.)

### Invite issuer/recipient trust ceremony
Spec ref: `docs/specs/team-sync-recovery.md:56-69`.

### Audit coverage
Reveal/copy denial rows, role denials, grant denials, dangerous-
profile read refusals (`--use-dangerous` flag), the degraded-audit
logger + `degraded_audit_log` doctor + perms doctor all shipped.
The `team_members.device_id REFERENCES devices(id) ON DELETE SET
NULL` schema behavior is covered by a store verification test.
Remaining audit-action emission gaps:

### Local user verification gates
`LocalUserVerifier` + `require_user_verification` shipped.
2026-04-30 audit pass against `docs/specs/crypto.md:192-218`
protected use cases:

- `get --reveal/--copy --verify-user` enforces gate (shipped).
- Recovery (`vault/recovery.rs`) gates via
  `require_user_verification` (shipped).
- Dangerous-profile switch (`trust/profile.rs`) gates via
  `configured_user_verification` (shipped).
- Device registration (`team/device.rs` init/add) gates via
  `configured_user_verification` (shipped).

### Agent / process hardening
`harden-peer-cred`, `harden-socket-perms`, `harden-memory-lock`,
`harden-zeroize`, `harden-doctor-degraded`, `harden-session-lock`
shipped. Core-dump suppression also shipped on all three platforms:

### `device init` first-run-on-machine bootstrap

### LocalUserVerifier platform backends
Spec ref: `docs/specs/crypto.md:192-218`,
`docs/specs/engineering.md:144`. macOS backend with single-unsafe
`LAContext` wrapper shipped. Linux + Windows backends shipped as
stubs returning `Unavailable` (with documented rollout plans).

- [ ] **lauthn-linux-real**: replace the Linux stub with a real
  Secret Service / FIDO2 (`libfido2-sys`) backend. Documented
  rollout plan is at the top of `linux_local_authentication.rs`.
- [ ] **lauthn-windows-hello-real**: replace the Windows stub with
  a real Windows Hello backend via the `windows` crate's
  `Security::Credentials::UI::UserConsentVerifier`. Documented
  rollout plan is at the top of `windows_local_authentication.rs`.

## App / UI

The retired desktop UI campaign slices have been folded into this
checklist so this file remains the single source of task truth.
Slices 1+2 shipped. Each remaining slice is one item.

### Tauri desktop app
Spec ref: `docs/specs/desktop.md:5-65`. Shell + agent client +
tray binding + primary views + tray icon-state pusher +
SubscribeStatus stream consumer + metadata sources for secrets,
versions, runtime sessions, audit, policies, and device/member
directory shipped. Tray switch-profile, run-policy, and scan paths
now route to agent-backed UI commands. Remaining: desktop write/action
flows.

### Tray / status panel
Spec ref: `docs/specs/desktop.md:65-108`.

- [ ] **tray-panel-spec-deep-audit**: re-read
  `docs/specs/desktop.md:65-108` against `crates/locket-app/`
  and enumerate any unmet tray-panel requirements as concrete
  subtasks. The lighter sweep on 2026-04-30 returned clean; a deep
  pass can surface anything else.

### Desktop UI campaign — remaining slices

### Search / filter UI
Spec ref: `docs/specs/desktop.md`. One subtask per surface; never
exposes values; pre-req is the relevant view's data RPC.

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

## Diagnostics, Distribution, and Quality Gates

### Coverage
Spec ref: `docs/specs/testing.md:8-72`. Per-surface subtasks
shipped (policy/env/crypto/store/typed/source-precedence/scanner/
audit-hmac/runtime-sessions). Per-crate ≥90% slices and the
temporary baseline ratchet have all landed. `scripts/coverage.sh`
now runs branch coverage end-to-end with a current host-verified
ratchet of 89% line / 68% branch coverage by default, overridable via
`COVERAGE_MIN_LINES` and `COVERAGE_MIN_BRANCHES`. Verification on
2026-05-01: `make coverage-branch` passed with line coverage 89.02%
and branch coverage 68.84%.

### End-to-end coverage
Spec ref: `docs/specs/testing.md:38`.
`e2e-greenfield-init`, `e2e-dotenv-migration`, `e2e-policy-run`,
`e2e-docker-compose`, `e2e-recovery-roundtrip` shipped.

- [ ] **e2e-ui-editor-smoke**: smoke flows in the desktop app and
  the VS Code extension. Pre-req: desktop-* and vscode-* items.

### Distribution supply-chain gates
Offline-safe local commands, strict-mode hooks, cargo-vet, unsafe
inventory, SBOM, exception ledger, and provenance policy verifier
exist. Remaining: auditable builds and signing.

### Package builders and signing
Spec ref: `docs/specs/operations.md:27-53`.

- [ ] **homebrew-formula-publish**: publish the shipped
  `dist/homebrew/locket.rb` formula to a tap (e.g.
  `doublesharp/homebrew-locket`); verify binary against release
  manifest signature.
- [ ] **cargo-install-publish**: `crates.io` publish run for
  `locket-cli`. Manifest is now publishable (`dist/cargo-install.md`
  has the dry-run notes); run with the signed-tag flow.
- [ ] **macos-pkg-signed**: signed `.pkg` with notarization.
- [ ] **windows-msi-signed**: signed `.msi` with EV cert.
- [ ] **linux-deb-rpm**: signed `.deb` and `.rpm` where toolchain
  is practical.
- [ ] **vsix-signed**: signed VS Code VSIX direct download path.

### Cold-start budgets
Spec ref: `docs/specs/performance.md`. Each subtask adds one
bench plus a regression that fails the budget.

## Spec-by-Spec Completion Gates

Final audit pass — only after every TODO above is closed. Each
line means implementation, tests, docs, diagnostics, and failure
modes have all been checked against that spec file. Reopen as new
TODOs above for any gaps found.

Marked `(audit clean)` when a 2026-04-30 read-only audit returned
no untracked gaps; marked `(open)` when items above still reference
the spec.

- `product.md` — positioning; no implementation gate.
- `invariants.md` — (audit clean 2026-04-30).
- `architecture.md` — (audit clean 2026-04-30).
- `data-model.md` — (audit clean 2026-04-30 except `RESOLVE_REFERENCE`
  validator entry, tracked above).
- `storage.md` — (audit clean 2026-04-30 except `team_members.device_id`
  FK verification, tracked above).
- `crypto.md` — (open: passkey real-platform backends only;
  `vault-unlock-verify-user` and `team-accept-verify-user` shipped).
- `project-cli.md` — pending.
- `policy.md` — (open: `schema_version` enforcement landed; TOML deep
  audit pass otherwise clean).
- `runtime.md` — (audit clean 2026-04-30).
- `agent.md` — (open: `harden-prctl-set-dumpable`,
  `harden-macos-windows-core-dump`).
- `integrations.md` — (audit clean 2026-04-30).
- `scan-redaction.md` — (audit clean 2026-04-30; inline-suppression
  syntax shipped).
- `desktop.md` — (open: per-surface filter chips for the six surfaces
  with TODO markers, tray-panel deep audit pending).
- `audit.md` — (audit clean 2026-05-01; all four 2026-04-30 emission
  gaps shipped — see "Audit coverage" above).
- `team-sync-recovery.md` — (audit clean 2026-05-01 for tracked
  invite and bundle apply gaps).
- `operations.md` — (open: signing items pre-req on
  `release-key-offline`).
- `performance.md` — (open: per-budget benches in sibling task list).
- `errors.md` — (audit clean 2026-04-30).
- `engineering.md` — (audit clean 2026-04-30).
- `testing.md` — (audit clean 2026-05-01).
- `fuzzing.md` — (audit clean 2026-04-30; all 12 required targets
  shipped).

## Reference

| Topic | Where |
| --- | --- |
| Exit-code bands | `docs/specs/errors.md` |
| Typed errors (canonical enum + `exit_code()`) | `crates/locket-core/src/error.rs` |
| Audit actions + metadata shapes | `docs/specs/audit.md`, `docs/specs/data-model.md` |
| Required SQLite tables | `docs/specs/storage.md` |
| Crate ownership | `docs/specs/architecture.md` |
