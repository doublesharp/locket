# Locket Implementation Progress

The work list. Open `[ ]`, in-progress `[~] [<id>]`, shipped slices in
`completed.md`. **Goal:** close the gaps between the local-first
CLI/core baseline and full `docs/specs/` coverage.

## How to use this doc

- **Workers**: read `prompt-worker.md` once, then live in this file.
  Claim a `[ ]` by editing it to `[~] [<your-id>]` on `main`. Keep
  the claim note one line.
- **Integrator**: read `prompt-integrator.md` once, drain `.ready/`,
  move shipped lines to `completed.md`.
- **Mechanics** (claim id, locks, ready-file format, reaper script)
  live in `coordination.md` — don't duplicate them here.
- **Spec is canonical.** A TODO line names the work and points at one
  spec section if non-obvious. Don't restate error variants, audit
  actions, or file paths the spec already covers.

## Definition of Done

Every slice satisfies these. Worker runs scoped tests
(`cargo test -p <crate> -j 12`); integrator runs the full battery
before merging.

1. **Spec match.** Each linked-spec bullet implemented or carried as
   a `[ ]` follow-up.
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

## Critical path

Six root tasks unblock the largest fan-out. Prefer these unless your
skill set fits a leaf better.

| # | Task | Unblocks |
| - | --- | --- |
| 1 | `bundle-age-encryption` | every bundle export/import subtask, `e2e-bundle-roundtrip` |
| 2 | `agent-unlock-cache` | reveal/copy, scan-known-values, resolve-reference, list-secrets/versions, tray menu actions |
| 3 | `agent-grant-table` | `lk-resolve-*`, `run-ttl-grant`, `run-agent-backed`, `policy-ttls`, `agent-prepare-exec-impl` |
| 4 | `lk-resolve-rpc` (≡ `agent-resolve-reference-impl`) | policy-doctor RPC, prepare-exec, VS Code completion |
| 5 | `team-invite-create` | rest of team flows, `e2e-team-invite-accept` |
| 6 | `vscode-agent-client` | every VS Code surface |

## TODO

### Near-Term CLI/Core


### Runtime/DX

- [ ] Local agent daemon (`docs/specs/agent.md`). `agent-socket-server`
  shipped; remaining subtasks below. Later subtasks depend on
  `agent-unlock-cache` / `agent-grant-table` — note deps on your claim.
  - [~] **subtask** — agent-reveal-copy: dispatch arms wired with
    typed `UnlockRequired`. Remaining: value path + `REVEAL`/`COPY`
    audit emission once cache + grant table ship.
  - [~] **subtask** — agent-scan-known-values: dispatch arm wired,
    returns `findings: [], locked: true`. Remaining: in-memory
    matching once cache lands.
  - [~] **subtask** — agent-resolve-reference: dispatch arm wired
    with typed `GrantRequired`. Remaining: `lk://` parsing, version
    pinning + grace, policy auth, `RESOLVE_REFERENCE` audit.
  - [~] **subtask** — agent-prepare-exec: dispatch arm wired with
    empty allow-list. Remaining: real policy resolution + scoped
    allowed-env-name set + policy-declared `ttl_seconds`.
- [~] `locket run` spec coverage. Argv policy execution exists.
  Remaining (`docs/specs/runtime.md:5-122`, `docs/specs/policy.md`):
  - [~] [4ab55ee9] branch agent-4ab55ee9/run-ttl-grant, worktree .worktrees/agent-4ab55ee9-run-ttl-grant; enforce policy ttl grants with process binding for run.
  - [~] [52c592db] branch agent-52c592db/run-agent-backed, worktree .worktrees/agent-52c592db-run-agent-backed; **subtask** — run-agent-backed: route through `ResolveReference`/grant RPCs once daemon ships; surface `AgentUnavailable` (80) when daemon is down and policy declares `require_agent = true`.
- [~] External env source resolution
  (`docs/specs/runtime.md:117-118`). `::Parent`, `::File`, `::Compose`
  shipped. Remaining:
  - [ ] **subtask** — env-source-ide: consume the VS Code
    `LOCKET_IDE_ENV_SESSION` map over the agent socket; names-only
    audit; never persist values. Pre-req: agent socket server (shipped)
    and the IDE-side producer.
- [~] Policy command surface: `policy add`, `policy allow`,
  `policy require`, `policy edit`, `policy delete`, `policy doctor`
  (`docs/specs/policy.md:5-35`). Remaining:
- [ ] Resolve `lk://` references through the agent
  (`docs/specs/runtime.md:123-155`). All subtasks depend on
  `lk-resolve-rpc`.
  - [~] [acda32e4] branch agent-acda32e4/lk-resolve-pinned-version, worktree .worktrees/agent-acda32e4-lk-resolve-pinned-version; **subtask** — lk-resolve-pinned-version: honor pinned versions.
  - [ ] **subtask** — lk-resolve-grace: in-grace versions resolve
    with metadata-only warning audit; reject after grace. Pre-req:
    `lk-resolve-pinned-version`.
- [ ] VS Code extension backed by the local agent
  (`docs/specs/integrations.md:39-65`). Extension never writes audit
  directly. All subtasks depend on `vscode-ext-scaffold` (shipped).
  - [ ] **subtask** — vscode-ide-env-session: terminal injection of
    `LOCKET_IDE_ENV_SESSION` and the agent-socket consumer side.
    Pre-req: `vscode-agent-client`, `env-source-ide`.
- [ ] Automation-client challenge-response auth
  (`docs/specs/agent.md:62-79`). Pre-req:
  `automation-private-key-storage`.
- [ ] Policy TOML — remaining (`docs/specs/policy.md`):

### Security/Recovery/Team

- [ ] Sealed bundle. `bundle-container-format` shipped
  (`docs/specs/team-sync-recovery.md:111-224`).
  - [~] [acda32e4] blocked: bundle import apply needs encrypted payload rows and local device private-key storage; main currently exports only profile summaries and reports private_key_storage unavailable.
  - [ ] **subtask** — bundle-import-conflicts: identical /
    newer-incoming / divergent / deleted-vs-active matrix with
    `--accept-incoming` / `--accept-local` and interactive resolve.
    Pre-req: `bundle-import-apply`.
  - [ ] **subtask** — bundle-include-audit-import: append imported
    audit rows to `imported_audit_chains` with structural
    verification. Pre-req: `bundle-import-apply`.
  - [ ] **subtask** — bundle-rotate-on-newer: import of a newer
    version over an active target runs the rotate-with-no-grace
    lifecycle. Pre-req: `bundle-import-apply`.
- [~] Team command surfaces (`docs/specs/team-sync-recovery.md:5-110`).
  `team-store-schema`, `team-init-command`, `team-members-list`
  shipped. Remaining:
- [ ] Passkey support remaining: platform registration and PRF
  optional key wrapping (`docs/specs/crypto.md:192-218`).
- [ ] Device descriptors (`lkdev1_` base64url JSON), v1 fingerprint
  hash, PGP-word-list safety-word derivation, and full local
  device-key lifecycle (`docs/specs/team-sync-recovery.md:50-58`).
  Note: blocked previously on a license-compatible PGP word list
  source — resolve before reclaiming.
- [ ] Invite issuer/recipient trust ceremony
  (`docs/specs/team-sync-recovery.md:56-69`). `invite-codec`,
  `invite-replay-protect`, `invite-clock-skew` shipped. Remaining:
  - [~] [acda32e4] branch agent-acda32e4/invite-accept-display, worktree .worktrees/agent-acda32e4-invite-accept-display; **subtask** — invite-accept-display: issuer fingerprint + safety words with fail-closed confirmation.
- [ ] Audit coverage for denials. Reveal/copy denial rows shipped.
  Remaining sweep: dangerous-profile reads, locked-vault refusals
  (needs degraded-audit mechanism), role denials, grant denials.
- [~] Local user verification gates. `LocalUserVerifier` and
  `require_user_verification` shipped; `get --reveal/--copy
  --verify-user` enforces. Remaining:
- [ ] Agent/process hardening. `harden-peer-cred`,
  `harden-socket-perms`, `harden-memory-lock`, `harden-zeroize`,
  `harden-doctor-degraded` shipped. Remaining:
  - [ ] **subtask** — harden-session-lock: lock on system sleep,
    screen lock, user-session switch; emit `LOCK` audit row.
- [ ] `import-bundle` / `team accept` apply rotate-with-no-grace
  when importing a newer version over an active target.
- [ ] `locket device init --force` rekey: atomic
  `DEVICE_REVOKE`+`DEVICE_ADD` with recovery-envelope update and
  rollback on envelope failure.
- [ ] `device init` first-run-on-machine bootstrap: master key,
  recovery envelope, and recovery code on a teammate clone
  (`docs/specs/team-sync-recovery.md`).
- [~] [52c592db] blocked: LocalUserVerifier macOS LocalAuthentication backend requires a safe LocalAuthentication wrapper; available objc2 binding exposes unsafe calls while locket-platform forbids unsafe_code.
- [ ] LocalUserVerifier Windows Hello backend.
- [ ] LocalUserVerifier Linux Secret Service / hardware-key-presence
  backend.

### App/UI

Campaign plan: `docs/superpowers/specs/2026-04-29-desktop-ui-campaign.md`.
Slices 1+2 shipped (agent client, tray binding, 6 view scaffolds,
5 typed RPC stubs). Each remaining subtask is one slice.

- [ ] Tauri desktop app (`docs/specs/desktop.md:5-65`). Shell + agent
  client + tray binding + 6 primary views + tray icon-state pusher
  shipped. Remaining: real data sources per view, tray menu actions,
  SubscribeStatus stream consumer.
- [ ] Tray/status panel (`docs/specs/desktop.md:65-108`):
  - [~] [4ab55ee9] branch agent-4ab55ee9/tray-recent-activity, worktree .worktrees/agent-4ab55ee9-tray-recent-activity; tray recent activity shows bounded safe statuses.
- [ ] Desktop UI campaign — remaining slices:
  - [~] [90b9f58a] branch agent-90b9f58a/desktop-subscribe-status, worktree .worktrees/agent-90b9f58a-desktop-subscribe-status; **subtask** — desktop-subscribe-status: replace `useAgent` poll with a Tauri event channel bridging `SubscribeStatus`. Slice 3.
  - [~] [acda32e4] branch agent-acda32e4/desktop-secrets-data, worktree .worktrees/agent-acda32e4-desktop-secrets-data; **subtask** — desktop-secrets-data: wire agent secret list into the view.
  - [~] [acda32e4] branch agent-acda32e4/desktop-versions-data, worktree .worktrees/agent-acda32e4-desktop-versions-data; **subtask** — desktop-versions-data: wire agent version history into the view.
  - [~] [90b9f58a] branch agent-90b9f58a/agent-reveal-copy-impl, worktree .worktrees/agent-90b9f58a-agent-reveal-copy-impl; **subtask** — agent-reveal-copy-impl: real `Reveal` / `Copy` handlers. Pre-reqs shipped.
  - [ ] **subtask** — desktop-reveal-modal: short-lived modal with
    TTL countdown, accessibility scrub on expiry, dismiss-on-blur.
    Pre-req: `agent-reveal-copy-impl`. Slice 7.
  - [ ] **subtask** — desktop-clipboard-copy: copy + scheduled clear
    after TTL with re-check; Wayland degraded path emits
    `unsupported_reason`. Pre-req: `agent-reveal-copy-impl`.
  - [ ] **subtask** — desktop-tray-reveal-copy: tray context menu
    actions for the selected secret. Pre-req: `tray-menu-actions`,
    `desktop-reveal-modal`, `desktop-clipboard-copy`. Slice 8.
  - [~] [52c592db] branch agent-52c592db/desktop-audit-data, worktree .worktrees/agent-52c592db-desktop-audit-data; **subtask** — desktop-audit-data: wire `agent-list-audit` + `agent-verify-audit` into `AuditLog.vue`.
  - [~] [4ab55ee9] branch agent-4ab55ee9/agent-scan-known-values-impl, worktree .worktrees/agent-4ab55ee9-agent-scan-known-values-impl; **subtask** — agent-scan-known-values-impl: real handler.
  - [~] [4ab55ee9] branch agent-4ab55ee9/desktop-settings-data, worktree .worktrees/agent-4ab55ee9-desktop-settings-data; settings view reads and writes desktop config data.
  - [ ] **subtask** — agent-policy-doctor-rpc: RPC exercising
    `lk://` resolution + env-mode expansion. Pre-req:
    `agent-resolve-reference-impl`.
  - [ ] **subtask** — desktop-policy-editor-write: create/edit/delete
    forms backed by `agent-policy-write` RPC. Dangerous-profile
    requires typed confirmation; `POLICY_UPDATE` audit.
  - [~] [90b9f58a] branch agent-90b9f58a/agent-resolve-reference-impl, worktree .worktrees/agent-90b9f58a-agent-resolve-reference-impl; **subtask** — agent-resolve-reference-impl: real `ResolveReference` (cross-references `lk-resolve-rpc` under Runtime/DX). Pre-reqs shipped. **Critical path.**
  - [ ] **subtask** — agent-prepare-exec-impl: real `PrepareExec`
    returning resolved env-name allow-list + TTL. Pre-req:
    `policy-ttls`, `agent-resolve-reference-impl`.
  - [ ] **subtask** — desktop-team-invite-view: invite
    issue/accept/revoke + member/device removal. Pre-req:
    `team-invite-*`, invite-ceremony subtasks.
  - [ ] **subtask** — desktop-profile-switcher-view: switch profile +
    dangerous-profile typed confirmation. Pre-req:
    `agent-set-active-profile`.
  - [~] [52c592db] branch agent-52c592db/agent-set-active-profile, worktree .worktrees/agent-52c592db-agent-set-active-profile; **subtask** — agent-set-active-profile: RPC; invalidates
    profile-scoped grants; documented audit row.
  - [ ] **subtask** — desktop-secret-editor-view: `SecretEditor.vue`
    set/update with TTL-bound reveal. Pre-req:
    `desktop-reveal-modal`, `agent-set-secret`.
  - [ ] **subtask** — agent-set-secret: RPC creating or rotating a
    secret with a value from the webview's secure input. Emits
    `SET` / `ROTATE`. Pre-req: `agent-unlock-cache`,
    `agent-grant-table`.
- [ ] Search/filter UI (`docs/specs/desktop.md`). Each subtask
  renders one surface; never exposes values; pre-req is the
  relevant view's data RPC.
- [~] [90b9f58a] branch agent-90b9f58a/tray-template-policy, worktree .worktrees/agent-90b9f58a-tray-template-policy; Tray template-image policy: macOS template-image (alpha-mask) vs Windows/Linux full-color light/dark variants.
- [ ] Cross-surface error-text parity: CLI / UI / tray / shell /
  VS Code show the same reason and next action per typed error
  (`docs/specs/desktop.md`).

### Code Health and Bug Fixes

Bugs, missing audit rows, and structural debt outside spec coverage.
Re-verify file:line references before editing — they drift. Severity:
**blocker** (security/correctness), **important** (real defect),
**nit** (cleanup).

### Diagnostics, Distribution, and Quality Gates

- [ ] Expand tests toward 90% line/branch on security-critical
  crates. Per-surface subtasks (policy/env/crypto/store/typed/
  source-precedence/scanner/audit-hmac/runtime-sessions) shipped
  (`docs/specs/testing.md:8-72`):
  - [~] [acda32e4] blocked: current branch coverage measures 70.86% overall and 77.19% for security-critical crates, below the existing nominal 90% branch gate; add branch tests before ratcheting `make coverage-branch`.
- [ ] End-to-end coverage. `e2e-greenfield-init`,
  `e2e-dotenv-migration`, `e2e-policy-run`, `e2e-docker-compose`,
  `e2e-recovery-roundtrip` shipped. Remaining
  (`docs/specs/testing.md:38`):
  - [~] [4ab55ee9] branch agent-4ab55ee9/e2e-agent-rpc, worktree .worktrees/agent-4ab55ee9-e2e-agent-rpc; agent RPC e2e covers status, grants, subscription.
  - [ ] **subtask** — e2e-team-invite-accept: `team init` →
    `invite` → `accept` (signature + safety-words) → `revoke-invite`
    failure path. Pre-req: team-* and invite-ceremony subtasks.
  - [ ] **subtask** — e2e-bundle-roundtrip: `export --sealed` →
    `import-bundle` (fresh / identical / newer-incoming /
    divergent), `bundle verify` structural-only and decryptable.
    Pre-req: sealed-bundle subtasks.
  - [ ] **subtask** — e2e-ui-editor-smoke: smoke flows in the
    desktop app and the VS Code extension. Pre-req: desktop-* and
    vscode-* items.
- [ ] Bench harnesses and performance gates. Local smoke/report
  scaffolding, deterministic fixtures, and PR/release tolerance policy
  exist. Remaining: expand measured benchmark coverage beyond the
  current CLI smoke runner (`docs/specs/performance.md`).
- [ ] Distribution supply-chain gates. Offline-safe local commands,
  strict-mode hooks, cargo-vet, unsafe inventory, SBOM, exception
  ledger, and provenance policy verifier exist. Remaining: auditable
  builds and signing.
- [ ] Package builders and signing for Homebrew, signed macOS pkg,
  Windows MSI, and Linux packages (`docs/specs/operations.md:27-53`).
- [ ] Cold-start budgets (`docs/specs/performance.md`). Each subtask
  adds one bench plus a regression that fails the budget:
  - [ ] **subtask** — perf-agent-idle-memory: ≤50 MB RSS after
    documented warmup. Pre-req: agent daemon subtasks.
- [ ] Property-test harness for new uncovered invariants.
  All current `proptest-*` subtasks shipped.
  Add new harnesses as uncovered invariants surface
  (`docs/specs/testing.md:14`).
- [ ] Cross-platform test mocks and mutation tests
  (`docs/specs/testing.md`):

## Spec-by-spec completion gates

Final audit pass — only after every TODO above is closed. Each line
means implementation, tests, docs, diagnostics, and failure modes
have all been checked against that spec file. Reopen as new TODOs
above for any gaps found.

- [ ] `product.md`
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
| Coordination scripts | `coordination.md` (sibling) |
| Worker prompt | `prompt-worker.md` (sibling) |
| Integrator prompt | `prompt-integrator.md` (sibling) |
