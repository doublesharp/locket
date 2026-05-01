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

## Deferred integrations (worktree branches preserved)

Two worktrees ship completed work but couldn't be cleanly merged
to `main` in this round due to stale-base destructive diffs. Their
content is preserved in worktree branches; integration is a careful
manual surgical task for a future session.

- **`worktree-agent-a99ced59da21af66c` (passkey suite):** `PlatformPasskeyRegistrar`
  trait, `MemoryPlatformPasskeyRegistrar`, PRF-wrap master-key
  helper, `passkey register` + `passkey unlock` CLI commands. Touches
  platform/store/cli/crypto crates.
- **`worktree-agent-a89ec54e30f394cc3` (SCHEMA_MIGRATE + passkey-register-emission):**
  `Store::initialize_schema` returns `SchemaMigrationOutcome` and a
  helper appends a `SCHEMA_MIGRATE` audit row when a real version
  bump occurs. Adds `passkey register` audit emission scaffold.

## P0 — Correctness / Security Drift (audit findings)

These are spec contracts the code currently violates or silently
ignores. Ship before any "v1 ready" claim.

(`prepare-exec-grant-return` shipped: `PrepareExecResponse.grant_id`
populated, `policy doctor` reuses the returned id instead of issuing
a separate `RequestGrant(ResolveReference)`.)

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

(All three runtime gaps shipped: env_mode merge/passthrough e2e tests,
DENIED audit rows for policy rejections before spawn,
external_env_names in RUN_POLICY metadata.)

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
- [~] **bundle-include-audit-import** (in-flight: agent 13c): append imported audit rows
  to `imported_audit_chains` with HMAC structural verification.
  Pre-req: `bundle-payload-include-audit-rows`,
  `bundle-apply-and-conflicts`.
- [ ] **bundle-team-accept-parity-test**: integration test
  asserting `team accept` and `import-bundle` produce identical
  store state for newer-incoming. Pre-req:
  `team-accept-row-apply-path`, `bundle-apply-and-conflicts`.

### Team command surfaces
Spec ref: `docs/specs/team-sync-recovery.md:5-110`.
All team commands shipped per 2026-04-30 audit:
`team-store-schema`, `team-init-command`, `team-members-list`,
`team-invite-create`, `team-invite-accept`, invite revoke, member
remove, device revoke. (No remaining team-command gaps.)

### Passkey support
Spec ref: `docs/specs/crypto.md:192-218`.
`PlatformPasskeyRegistrar` trait + `MemoryPlatformPasskeyRegistrar` +
PRF-wrap master key helpers + `passkey register` / `passkey unlock`
CLI commands shipped (against in-flight integration). Real platform
authenticator backends remain.

- [ ] **passkey-macos-platform-backend**: real platform authenticator
  registration on macOS via WebAuthn / TouchID.
- [ ] **passkey-windows-platform-backend**: same for Windows Hello.
- [ ] **passkey-linux-platform-backend**: same for libfido2.

### Device descriptors
Spec ref: `docs/specs/team-sync-recovery.md:50-58`. `lkdev1_`
descriptor encode/decode, v1 fingerprint hashing, canonical PGP
word-list safety words (256+256 entries), and full device-key
lifecycle (`device init --force`, `device remove`, `team
revoke-device` envelope cleanup, `device_private_key_storage`
doctor check) all shipped. (No remaining device-descriptor work.)

### Invite issuer/recipient trust ceremony
Spec ref: `docs/specs/team-sync-recovery.md:56-69`.
Shipped: `invite-codec`, `invite-replay-protect`,
`invite-clock-skew`, signed invite creation, trust-summary display,
issuer fingerprint confirmation, accept denial rows, and revoke
flows. 2026-04-30 audit found one remaining gap:

- [~] **invite-sealed-payload-import** (in-flight: agent 13c): spec lines 7, 28, and 67
  require invites to carry plaintext profile secret/fingerprint
  keys and command policies inside an age-sealed payload addressed
  to the recipient device sealing key, with `team accept` rewrapping
  those keys into the receiver's local `keys` table on import. The
  current `SignedInvite` envelope is signed but not encrypted and
  carries no payload section; `team accept` is metadata-only and
  defers row application to a follow-up `import-bundle`. See the
  SPEC-CLARIFICATION block in
  `crates/locket-cli/src/commands/team/members.rs` for the agreed
  scope. Touches: `crates/locket-core/src/invite.rs` (envelope
  format), `team invite` issuer side (encrypt-to-recipient), and
  `team accept` apply path (rewrap + insert profile/key/policy
  rows). Pre-req: `bundle-profile-key-rewrap-helper` (shipped).

### Audit coverage
Reveal/copy denial rows, role denials, grant denials, dangerous-
profile read refusals (`--use-dangerous` flag), the degraded-audit
logger + `degraded_audit_log` doctor + perms doctor all shipped.
Remaining audit-action emission gaps:

(All four audit-action emission gaps shipped:
- `resolve-reference-emission-validator` — `audit.rs:596` arm with
  `secret_name`, `profile_id`, `source`.
- `schema-team-members-device-fk` — confirmed comment added in
  `schema.rs` (12a); behavior matches spec.
- `passkey-register-emission` — emission shipped in
  `passkey_register_command` (12d / wave commit `2fc738fd`).
- `schema-migrate-emission` — `Store::record_schema_migrate_audit`
  helper at `audit.rs:883` + `SchemaMigrationOutcome` returned from
  `initialize_schema`.)

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

Remaining gates with no enforcement (subtasks):

- [~] **vault-unlock-verify-user** (in-flight: agent 13b): `locket vault unlock
  --verify-user` currently returns `unimplemented_in_build_error`
  (`crates/locket-cli/src/commands/vault/lock.rs:90-93`). Spec line
  205 ("Unlocking the vault with local user verification") requires
  the gate to call `LocalUserVerifier` before unlocking and emit a
  satisfied `user_verification` block in the `UNLOCK` audit row.
- [~] **team-accept-verify-user** (in-flight: agent 13b): `team_accept_command`
  (`crates/locket-cli/src/commands/team/members.rs:299`) does not
  call any user-verification helper. Spec line 206 ("Requiring
  presence/verification before … team invite acceptance") requires
  a `require_user_verification` (or `configured_user_verification`
  via the `team_invite_accept` policy key) call after the
  fingerprint confirmation prompt, with the resulting
  `UserVerificationAudit` propagated into the `TEAM_ACCEPT` audit
  metadata.

### Agent / process hardening
`harden-peer-cred`, `harden-socket-perms`, `harden-memory-lock`,
`harden-zeroize`, `harden-doctor-degraded`, `harden-session-lock`
shipped. Core-dump suppression also shipped on all three platforms:

- Shipped: **harden-prctl-set-dumpable** — Linux core-dump
  suppression via `prctl(PR_SET_DUMPABLE, 0)` + `RLIMIT_CORE=0`
  (commit 97058f69).
- Shipped: **harden-macos-windows-core-dump** — macOS core-dump
  suppression via `RLIMIT_CORE=0`, Windows via `SetErrorMode`
  (commit 9923b7f0).

### `device init` first-run-on-machine bootstrap
(`device-init-bootstrap` shipped: first-run-on-machine generates
master key, recovery envelope, displays recovery code, writes
`BOOTSTRAP` audit row.)

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
directory shipped. Remaining: complete tray menu action wiring and
desktop write/action flows.

- [ ] **tray-menu-actions**: tray context-menu items are present and
  emitted to the webview; finish agent-backed actions beyond lock
  (unlock, switch profile, run policy) and add tests for each action.

### Tray / status panel
Spec ref: `docs/specs/desktop.md:65-108`.

- [ ] **tray-panel-spec-deep-audit**: re-read
  `docs/specs/desktop.md:65-108` against `crates/locket-app/`
  and enumerate any unmet tray-panel requirements as concrete
  subtasks. The lighter sweep on 2026-04-30 returned clean except
  for the tracked `tray-menu-actions` item; a deep pass can
  surface anything else.

### Desktop UI campaign — remaining slices
(Reveal modal + clipboard copy shipped together with tray menu
actions on commit dbf6ab52.)

- Shipped: **desktop-reveal-modal** — short-lived modal with TTL
  countdown, accessibility scrub on expiry, dismiss-on-blur (Slice 7).
- Shipped: **desktop-clipboard-copy** — copy + scheduled clear
  after TTL with re-check; Wayland degraded path emits
  `unsupported_reason`.
- [ ] **desktop-tray-reveal-copy**: tray context menu actions for
  the selected secret. Pre-req: `tray-menu-actions`,
  `desktop-reveal-modal` (shipped), `desktop-clipboard-copy`
  (shipped). (Slice 8.)
- [ ] **agent-policy-doctor-rpc**: RPC exercising `lk://`
  resolution + env-mode expansion. Pre-req:
  `agent-prepare-exec-impl`.
- [ ] **desktop-policy-editor-write**: create/edit/delete forms
  backed by `agent-policy-write` RPC. Dangerous-profile requires
  typed confirmation; `POLICY_UPDATE` audit.
- [ ] **desktop-profile-switcher-view**: switch profile +
  dangerous-profile typed confirmation through a desktop Tauri
  wrapper for shipped `agent-set-active-profile`.

(`desktop-team-invite-view` shipped — `TeamInviteView.vue` +
`team/invite.ts` cover issue/accept/revoke with dangerous-profile
typed confirmation and audit-row reconstruction. Submit handlers
surface a typed "agent surface missing" notice for the four
`*TeamInvite` RPCs that the agent doesn't yet expose; tracked as
follow-on agent-side tasks rather than a desktop gap.)
(`desktop-secret-editor-view` shipped — `SecretEditorView.vue` +
`secret/editor.ts` cover set/rotate via the new
`agent_set_secret` / `agent_rotate_secret` Tauri commands plus
TTL-bound reveal through `RevealModal`. Delete is staged-but-blocked
with typed-confirmation validated; unblocks once agent ships
`DeleteSecret`/`PurgeSecret`.)

### Search / filter UI
Spec ref: `docs/specs/desktop.md`. One subtask per surface; never
exposes values; pre-req is the relevant view's data RPC.

(`desktop-search-filter-enumeration` shipped — `SecretMetadataList.vue`
got source/required/deprecation filter chips backed by `secret/filter.ts`.
The other six metadata surfaces (Audit, Policy, DeviceMember, Scan,
ExecutionMonitor, ProfileSwitcher) already had free-text search; each
got an inline `// TODO(desktop-search-filter):` comment enumerating the
structured filters they still need. Per-surface filter-chip subtasks
should be opened from those TODOs as the data RPCs land.)

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
audit-hmac/runtime-sessions). Per-crate ≥90% slices and the
temporary baseline ratchet have all landed; only the final
ratchet-back to 90/90 remains:

- Shipped: **coverage-gate-baseline** (commit 65803c4a) —
  temporary 70/75 floor with `TODO(coverage-90)` comment.
- Shipped: **coverage-policy-90** (commit 4da332aa).
- Shipped: **coverage-bundle-90** (commit 2632f8c7).
- Shipped: **coverage-store-90** (commit bffddecd).
- Shipped: **coverage-agent-90** (commit f1de2092).
- [~] **coverage-gate-ratchet** (in-flight: agent 13a): re-run `make coverage-branch`,
  ratchet `scripts/coverage.sh` back to
  `--fail-under-lines 90 --fail-under-branches 90`, remove the
  `TODO(coverage-90)` comment. Pre-req: all four
  `coverage-<crate>-90` subtasks (shipped).

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

- Shipped: **named-reference-runner** — reference runner spec
  documented at `docs/specs/performance-reference-runner.md` with
  hardware class, OS, CPU governor, and FS pinning (commit
  dfd0c040).
- Per-budget bench tasks enumerated in
  `docs/superpowers/specs/2026-04-30-perf-budget-tasks.md` (commit
  23fb58b1). Track open per-budget benches in that file rather than
  re-listing here.
(`bench-scripts-chmod-x` shipped — both scripts are now 100755 in
git index and on disk.)
(`doctor_warns_when_degraded_audit_log_is_non_empty` test fix
shipped — 13a corrected the test seed perms to 0600 so the new
perms doctor check doesn't escalate warn → fail.)
- [ ] **fixture-schema-version-drift**: pre-existing test
  `ide_external_env_source_without_agent_context_returns_typed_error`
  fails with `MissingSchemaVersion` because its fixture predates
  the 10b schema_version enforcement. Update the fixture to include
  `schema_version = 1`. Touches:
  `crates/locket-cli/src/tests/exec.rs`.

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
- `crypto.md` — (open: `vault-unlock-verify-user`,
  `team-accept-verify-user`, passkey real-platform backends).
- `project-cli.md` — pending.
- `policy.md` — (open: `schema_version` enforcement landed; TOML deep
  audit pass otherwise clean).
- `runtime.md` — (audit clean 2026-04-30).
- `agent.md` — (open: `harden-prctl-set-dumpable`,
  `harden-macos-windows-core-dump`).
- `integrations.md` — (audit clean 2026-04-30).
- `scan-redaction.md` — (audit clean 2026-04-30; inline-suppression
  syntax shipped).
- `desktop.md` — (open: tray menu actions, policy editor write,
  search/filter UI; tray-panel deep audit pending).
- `audit.md` — (open: `passkey-register-emission`,
  `schema-migrate-emission`).
- `team-sync-recovery.md` — (open: `bundle-apply-and-conflicts`,
  `invite-sealed-payload-import`).
- `operations.md` — (open: signing items pre-req on
  `release-key-offline`).
- `performance.md` — (open: per-budget benches in sibling task list).
- `errors.md` — (audit clean 2026-04-30).
- `engineering.md` — (audit clean 2026-04-30).
- `testing.md` — (audit clean 2026-04-30; only `coverage-gate-ratchet`
  remains).
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
