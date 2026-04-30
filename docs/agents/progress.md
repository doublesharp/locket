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

- [ ] Scan ignore/suppression: inline markers, `SCAN`/`SUPPRESSED`
  rows, and per-rule severity shipped. Remaining: project-level
  severity overrides and `.env` policy table.
- [ ] Destructive confirmation flows beyond `purge` /
  dangerous-profile / root untrust: policy deletion and other
  sensitive surfaces (`docs/specs/policy.md:26`).
- [ ] Source-precedence and multi-source behavior across `set`,
  `get`, `list`, `rotate`, `rm`, `purge`, `history`, `diff`, `copy`,
  reveal/copy, and execution. Run audit + set-tombstone preflight
  done; remaining commands need the unified resolver
  (`docs/specs/data-model.md`, `docs/specs/runtime.md:188-216`).

### Runtime/DX

- [ ] Local agent daemon (`docs/specs/agent.md`). `agent-socket-server`
  shipped; remaining subtasks below. Later subtasks depend on
  `agent-unlock-cache` / `agent-grant-table` — note deps on your claim.
  - [~] [acda32e4] branch agent-acda32e4/agent-grant-table, worktree .worktrees/agent-acda32e4-agent-grant-table; **subtask** — agent-grant-table: SQLite-backed grant table with `(pid, process_start_time)` binding; `RequestGrant`/`ExpireGrant`/`RevokeGrant` handlers. **Critical path.**
  - [ ] **subtask** — agent-subscribe-status: stream `lock_state`
    change events plus heartbeat cadence on top of the existing
    heartbeat envelope. Depends on `agent-unlock-cache`.
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
- [ ] Replace metadata-only `agent start/status/stop/logs` with real
  process behavior and redacted log retention
  (`docs/specs/agent.md:99-110`).
- [~] `locket run` spec coverage. Argv policy execution exists.
  Remaining (`docs/specs/runtime.md:5-122`, `docs/specs/policy.md`):
  - [ ] **subtask** — run-ttl-grant: enforce policy `ttl = "Xs"`
    grants with `(pid, process_start_time)` binding. Pre-req:
    `agent-grant-table`.
  - [ ] **subtask** — run-agent-backed: route through
    `ResolveReference`/grant RPCs once daemon ships; surface
    `AgentUnavailable` (80) when daemon is down and policy declares
    `require_agent = true`.
- [~] External env source resolution
  (`docs/specs/runtime.md:117-118`). `::Parent`, `::File`, `::Compose`
  shipped. Remaining:
  - [ ] **subtask** — env-source-ide: consume the VS Code
    `LOCKET_IDE_ENV_SESSION` map over the agent socket; names-only
    audit; never persist values. Pre-req: agent socket server (shipped)
    and the IDE-side producer.
- [ ] Policy command surface: `policy add`, `policy allow`,
  `policy require`, `policy edit`, `policy delete`, `policy doctor`
  (`docs/specs/policy.md:5-35`). Files:
  `crates/locket-cli/src/policy_authoring.rs` (currently a stub),
  `crates/locket-core/src/policy/`.
- [ ] Resolve `lk://` references through the agent
  (`docs/specs/runtime.md:123-155`). All subtasks depend on
  `lk-resolve-rpc`.
  - [ ] **subtask** — lk-resolve-rpc: `ResolveReference` handler
    parses `lk://`, looks up the secret, returns the value or a
    typed error. Pre-req: `agent-unlock-cache`. **Critical path.**
  - [ ] **subtask** — lk-resolve-policy-auth: gate by policy
    authorization (resolving caller's policy must allow the target).
  - [ ] **subtask** — lk-resolve-pinned-version: honor pinned
    `lk://...@vN`; `SecretVersionExpired` (75) past `grace_until`.
  - [ ] **subtask** — lk-resolve-grace: in-grace versions resolve
    with metadata-only warning audit; reject after grace. Pre-req:
    `lk-resolve-pinned-version`.
  - [ ] **subtask** — lk-resolve-audit: write `RESOLVE_REFERENCE`
    rows on every resolution (success and failure).
- [ ] `locket exec --all` flow shipped. Remaining: `locket env
  inspect` enhancements and env-layering / override-mode docs.
- [ ] On-demand agent startup: `locket exec`/`run` start the agent
  when missing; `AgentUnavailable` only after on-demand startup fails.
- [ ] VS Code extension backed by the local agent
  (`docs/specs/integrations.md:39-65`). Extension never writes audit
  directly. All subtasks depend on `vscode-ext-scaffold` (shipped).
  - [~] [90b9f58a] branch agent-90b9f58a/vscode-agent-client, worktree .worktrees/agent-90b9f58a-vscode-agent-client; **subtask** — vscode-agent-client: TS client speaking the
    agent socket protocol. **Critical path.**
  - [ ] **subtask** — vscode-status: status-bar element subscribed
    to `SubscribeStatus`. Pre-req: `vscode-agent-client`,
    `agent-subscribe-status`.
  - [ ] **subtask** — vscode-ide-env-session: terminal injection of
    `LOCKET_IDE_ENV_SESSION` and the agent-socket consumer side.
    Pre-req: `vscode-agent-client`, `env-source-ide`.
- [ ] Automation-client flows. Public metadata, allowed
  action/policy fields, nonces, and CLI metadata are in. Remaining:
  private-key storage and challenge-response auth
  (`docs/specs/agent.md:62-79`).
- [ ] Policy TOML — remaining (`docs/specs/policy.md`):
  - [ ] **subtask** — policy-ttls: `ttl` translates to a grant TTL.
    Pre-req: `agent-grant-table`.
- [ ] Clipboard clear-after-TTL only if clipboard still contains the
  value. Wayland-aware pre-copy warning + `unsupported_reason`
  shipped; background TTL clearing remains.

### Security/Recovery/Team

- [ ] Sealed bundle. `bundle-container-format` shipped
  (`docs/specs/team-sync-recovery.md:111-224`).
  - [~] [4ab55ee9] branch agent-4ab55ee9/bundle-age-encryption, worktree .worktrees/agent-4ab55ee9-bundle-age-encryption; **subtask** — bundle-age-encryption: integrate `age`/`rage` with multi-recipient support. **Critical path.**
  - [ ] **subtask** — bundle-export-payload: serialize selected
    profiles, policies, secret metadata, `secret_versions`, blobs,
    and per-profile keys; forbid master/audit/device/recovery key
    material. Pre-req: `bundle-age-encryption`.
  - [ ] **subtask** — bundle-import-apply: decrypt and apply in a
    single SQLite tx; rewrap profile keys under receiver's master.
    Pre-req: `bundle-age-encryption`.
  - [ ] **subtask** — bundle-import-conflicts: identical /
    newer-incoming / divergent / deleted-vs-active matrix with
    `--accept-incoming` / `--accept-local` and interactive resolve.
    Pre-req: `bundle-import-apply`.
  - [ ] **subtask** — bundle-verify-cmd: structural-only and
    decryptable paths both exit 0; malformed →
    `BundleVerificationFailed`; unsupported schema → `ConfigError`.
    Pre-req: `bundle-age-encryption`.
  - [ ] **subtask** — bundle-include-audit-import: append imported
    audit rows to `imported_audit_chains` with structural
    verification. Pre-req: `bundle-import-apply`.
  - [ ] **subtask** — bundle-rotate-on-newer: import of a newer
    version over an active target runs the rotate-with-no-grace
    lifecycle. Pre-req: `bundle-import-apply`.
- [~] Team command surfaces (`docs/specs/team-sync-recovery.md:5-110`).
  `team-store-schema`, `team-init-command`, `team-members-list`
  shipped. Remaining:
  - [~] [52c592db] branch agent-52c592db/team-invite-create, worktree .worktrees/agent-52c592db-team-invite-create; **subtask** — team-invite-create: signed invite with issuer
    keys, recipient fingerprint, expiry, nonce, role, profiles.
    Pre-req: invite codec under the trust-ceremony item.
    **Critical path.**
  - [ ] **subtask** — team-invite-accept: verify signature,
    fingerprint, expiry, replay, safety-words display. Pre-req:
    `team-invite-create`.
  - [ ] **subtask** — team-invite-revoke: `locket team revoke-invite`.
    Pre-req: `team-invite-create`.
- [ ] Role-based authorization for team-managed state
  (`docs/specs/team-sync-recovery.md:75-110`).
- [ ] Passkey support. Metadata storage and `list`/`remove` exist.
  Remaining: platform registration and PRF optional key wrapping
  (`docs/specs/crypto.md:192-218`).
- [ ] Device descriptors (`lkdev1_` base64url JSON), v1 fingerprint
  hash, PGP-word-list safety-word derivation, and full local
  device-key lifecycle (`docs/specs/team-sync-recovery.md:50-58`).
  Note: blocked previously on a license-compatible PGP word list
  source — resolve before reclaiming.
- [ ] Invite issuer/recipient trust ceremony
  (`docs/specs/team-sync-recovery.md:56-69`). `invite-codec`,
  `invite-replay-protect`, `invite-clock-skew` shipped. Remaining:
  - [ ] **subtask** — invite-issue: `team invite` produces a signed
    invite using the device signing key. Pre-req: `team-store-schema`.
  - [ ] **subtask** — invite-accept-display: issuer fingerprint +
    PGP safety words, typed confirmation before applying.
  - [ ] **subtask** — invite-fail-closed: expired / revoked /
    fingerprint-mismatched / signature-invalid invites fail closed
    with typed errors and audit denial rows.
- [ ] Audit coverage for denials. Reveal/copy denial rows shipped.
  Remaining sweep: dangerous-profile reads, locked-vault refusals
  (needs degraded-audit mechanism), role denials, grant denials.
- [ ] Local user verification gates. `LocalUserVerifier` and
  `require_user_verification` shipped; `get --reveal/--copy
  --verify-user` enforces. Remaining sweep: `unlock`, `recovery`,
  team/device, dangerous-profile actions.
- [ ] Privacy-mode rendering across status, context, redaction
  labels, debug bundles via `privacy_alias` /
  `privacy_redact_names_enabled`; tray/desktop/editor renderers
  pending until those crates exist.
- [ ] Agent/process hardening. `harden-peer-cred`,
  `harden-socket-perms`, `harden-memory-lock`, `harden-zeroize`,
  `harden-doctor-degraded` shipped. Remaining:
  - [ ] **subtask** — harden-session-lock: lock on system sleep,
    screen lock, user-session switch; emit `LOCK` audit row.
- [ ] `imported_audit_chains` structural verifier (monotonic
  sequence, prev-HMAC linkage, checkpoint HMAC match) used by
  `import-bundle` / `team accept` and surfaced via `audit verify`.
- [ ] `import-bundle` / `team accept` apply rotate-with-no-grace
  when importing a newer version over an active target.
- [ ] `locket device init --force` rekey: atomic
  `DEVICE_REVOKE`+`DEVICE_ADD` with recovery-envelope update and
  rollback on envelope failure.
- [ ] `locket recover` restores Locket-managed automation-client
  private keys from the envelope; `--force` rotates intact keychain
  entries and records the override in the `RECOVER` audit row.
- [ ] Typed `metadata_json` shape validator per audit action family
  (required fields, no unknown fields without a schema bump).
- [ ] `device init` first-run-on-machine bootstrap: master key,
  recovery envelope, and recovery code on a teammate clone
  (`docs/specs/team-sync-recovery.md`).
- [ ] LocalUserVerifier macOS LocalAuthentication backend.
- [ ] LocalUserVerifier Windows Hello backend.
- [ ] LocalUserVerifier Linux Secret Service / hardware-key-presence
  backend.
- [ ] Passkey RP ID policy: `webauthn_relying_party_id` storage,
  `locket.localhost` default, controlled signed-distribution RP ID
  with re-registration migration, synced-passkey backup-eligibility
  display (`docs/specs/crypto.md`).

### App/UI

Campaign plan: `docs/superpowers/specs/2026-04-29-desktop-ui-campaign.md`.
Slices 1+2 shipped (agent client, tray binding, 6 view scaffolds,
5 typed RPC stubs). Each remaining subtask is one slice.

- [ ] Tauri desktop app (`docs/specs/desktop.md:5-65`). Shell + agent
  client + tray binding + 6 primary views + tray icon-state pusher
  shipped. Remaining: real data sources per view, tray menu actions,
  SubscribeStatus stream consumer.
- [ ] Tray/status panel (`docs/specs/desktop.md:65-108`):
  - [ ] **subtask** — tray-status-binding: subscribe to
    `SubscribeStatus`; replace today's 5 s `agent_status` poll.
    Pre-req: `agent-subscribe-status`. Pairs with
    `desktop-subscribe-status`.
  - [ ] **subtask** — tray-menu-actions: open / lock / unlock /
    switch profile / run policy / scan, all routed through the agent.
  - [ ] **subtask** — tray-recent-activity: bounded counts/safe
    statuses only. Source from `agent-list-audit`.
- [ ] Desktop UI campaign — remaining slices:
  - [ ] **subtask** — desktop-subscribe-status: replace `useAgent`
    poll with a Tauri event channel bridging `SubscribeStatus`.
    Slice 3.
  - [ ] **subtask** — agent-list-secrets: RPC returning metadata-only
    rows for the active profile with source-precedence ordering.
    Pre-req: `agent-unlock-cache`.
  - [ ] **subtask** — desktop-secrets-data: wire `agent-list-secrets`
    into `SecretMetadataList.vue` + last-refreshed timestamp. Slice 4.
  - [ ] **subtask** — agent-list-versions: RPC returning current /
    deprecated / purged metadata + rotation summary. Pre-req:
    `agent-unlock-cache`.
  - [ ] **subtask** — desktop-versions-data: wire into
    `SecretVersionHistory.vue`. Slice 5.
  - [ ] **subtask** — agent-list-runtime-sessions: RPC scoped to
    active profile, with privacy aliases applied.
  - [ ] **subtask** — desktop-execution-data: wire into
    `ExecutionMonitor.vue` + stale-session classifier. Slice 6.
  - [ ] **subtask** — agent-reveal-copy-impl: real `Reveal` / `Copy`
    handlers (today both stub `UnlockRequired`). Pre-req:
    `agent-unlock-cache`, `agent-grant-table`.
  - [ ] **subtask** — desktop-reveal-modal: short-lived modal with
    TTL countdown, accessibility scrub on expiry, dismiss-on-blur.
    Pre-req: `agent-reveal-copy-impl`. Slice 7.
  - [ ] **subtask** — desktop-clipboard-copy: copy + scheduled clear
    after TTL with re-check; Wayland degraded path emits
    `unsupported_reason`. Pre-req: `agent-reveal-copy-impl`.
  - [ ] **subtask** — desktop-tray-reveal-copy: tray context menu
    actions for the selected secret. Pre-req: `tray-menu-actions`,
    `desktop-reveal-modal`, `desktop-clipboard-copy`. Slice 8.
  - [ ] **subtask** — desktop-tray-notifications: route the four
    `TrayNotificationKind` cases via `passive_notification`; honor
    DND. Names and values never leak.
  - [ ] **subtask** — agent-list-audit: RPC with filters (action,
    profile, status, time range) returning `AuditLogRow` shape +
    `hmac_ok` / `first_break_sequence` chain status.
  - [ ] **subtask** — agent-verify-audit: RPC returning a structural
    HMAC check result. Used by audit-view "Verify".
  - [ ] **subtask** — desktop-audit-data: wire `agent-list-audit` +
    `agent-verify-audit` into `AuditLog.vue`. Slice 9.
  - [ ] **subtask** — agent-scan-known-values-impl: real handler.
    Pre-req: `agent-unlock-cache` (matching) + `locket-scan`
    (pattern/entropy fallback). Emit `SCAN` rows.
  - [ ] **subtask** — desktop-scan-data: wire into `ScanResults.vue`
    + rescan trigger. Slice 10.
  - [ ] **subtask** — agent-config-read-write: RPCs for
    `privacy.redact_names`, `unlock_ttl_seconds`, verification
    policy, dangerous-profile flag. Writes emit `CONFIG_UPDATE`.
  - [ ] **subtask** — desktop-settings-data: wire into `Settings.vue`;
    propagate `privacy.redact_names` reactively. Slice 11.
  - [ ] **subtask** — agent-list-policies: RPC returning saved
    `CommandPolicy` metadata (argv vs shell, required/optional
    secrets, gates) without exposing resolved values.
  - [ ] **subtask** — agent-policy-doctor-rpc: RPC exercising
    `lk://` resolution + env-mode expansion. Pre-req:
    `agent-resolve-reference-impl`.
  - [ ] **subtask** — desktop-policy-editor-view: `PolicyEditor.vue`
    (read-only). Slice 12a.
  - [ ] **subtask** — desktop-policy-editor-write: create/edit/delete
    forms backed by `agent-policy-write` RPC. Dangerous-profile
    requires typed confirmation; `POLICY_UPDATE` audit.
  - [ ] **subtask** — agent-resolve-reference-impl: real
    `ResolveReference` (cross-references `lk-resolve-rpc` under
    Runtime/DX). Pre-req: `agent-grant-table`, `agent-unlock-cache`.
    **Critical path.**
  - [ ] **subtask** — agent-prepare-exec-impl: real `PrepareExec`
    returning resolved env-name allow-list + TTL. Pre-req:
    `policy-ttls`, `agent-resolve-reference-impl`.
  - [ ] **subtask** — desktop-backup-recovery-view:
    `BackupRecovery.vue` — export/import/verify/recovery-rotate.
    Slice 12b.
  - [ ] **subtask** — desktop-team-invite-view: invite
    issue/accept/revoke + member/device removal. Pre-req:
    `team-invite-*`, invite-ceremony subtasks.
  - [ ] **subtask** — desktop-project-dashboard-view: aggregator
    over existing RPCs.
  - [ ] **subtask** — desktop-profile-switcher-view: switch profile +
    dangerous-profile typed confirmation. Pre-req:
    `agent-set-active-profile`.
  - [ ] **subtask** — agent-set-active-profile: RPC; invalidates
    profile-scoped grants; documented audit row.
  - [ ] **subtask** — desktop-secret-editor-view: `SecretEditor.vue`
    set/update with TTL-bound reveal. Pre-req:
    `desktop-reveal-modal`, `agent-set-secret`.
  - [ ] **subtask** — agent-set-secret: RPC creating or rotating a
    secret with a value from the webview's secure input. Emits
    `SET` / `ROTATE`. Pre-req: `agent-unlock-cache`,
    `agent-grant-table`.
- [ ] Tauri hardening. Empty deny-by-default baseline shipped with
  `tauri-shell`. Remaining (`docs/specs/desktop.md`):
  - [ ] **subtask** — tauri-capabilities-per-view: each new Tauri
    command opts into the minimum capability in
    `capabilities/desktop.json`; CI regression fails if a command
    is added without a paired capability entry.
- [ ] Search/filter UI (`docs/specs/desktop.md`). Each subtask
  renders one surface; never exposes values; pre-req is the
  relevant view's data RPC.
  - [ ] **subtask** — search-projects-profiles
  - [ ] **subtask** — search-secrets-metadata
  - [ ] **subtask** — search-policies
  - [ ] **subtask** — search-audit
  - [ ] **subtask** — search-scan-findings
  - [ ] **subtask** — search-devices-members
- [ ] Tray template-image policy: macOS template-image (alpha-mask)
  vs Windows/Linux full-color light/dark variants. Placeholder PNGs
  ship today (`docs/specs/desktop.md`).
  - [ ] **subtask** — tray-icons-real: Lucide-derived assets
    (`lock-open`, `lock`, `shield-alert`, `alert-triangle`) in macOS
    template + Win/Linux light/dark variants.
- [ ] Cross-surface error-text parity: CLI / UI / tray / shell /
  VS Code show the same reason and next action per typed error
  (`docs/specs/desktop.md`).
  - [ ] **subtask** — error-copy-table: extract typed-error display
    copy into a shared table consumed by CLI, desktop
    `AgentUnavailableBanner`, tray dispatcher, shell prompt.
    Regression asserts every `LocketError` variant has a row.
- [ ] VS Code diagnostics: `process.env.KEY` missing in active
  profile; pinned `lk://...@vN` near/past `grace_until`
  (`docs/specs/integrations.md:48-49`).
- [ ] VS Code reference completion for `lk://` in `.env.example`,
  JSON, TOML, YAML, shell, source files
  (`docs/specs/integrations.md:48`).
- [ ] VS Code gated reveal webview with short-lived data, no
  plaintext persistence (`docs/specs/integrations.md:50-51`).
- [ ] Profile-scoped grant invalidation on `locket use <profile>`;
  hook re-prompts `GrantRequired` when no `directory_grants` row
  for the now-active profile (`docs/specs/integrations.md:26`).

### Code Health and Bug Fixes

Bugs, missing audit rows, and structural debt outside spec coverage.
Re-verify file:line references before editing — they drift. Severity:
**blocker** (security/correctness), **important** (real defect),
**nit** (cleanup).

- [~] [acda32e4] branch agent-acda32e4/typed-error-sweep, worktree .worktrees/agent-acda32e4-typed-error-sweep; **important** — Typed error system underused: audit remaining callsites and map failures to typed `LocketError` variants.

### Diagnostics, Distribution, and Quality Gates

- [ ] Expand tests toward 90% line/branch on security-critical
  crates. Per-surface subtasks (policy/env/crypto/store/typed/
  source-precedence/scanner/audit-hmac/runtime-sessions) shipped
  (`docs/specs/testing.md:8-72`):
  - [ ] **subtask** — tests-coverage-ratchet: raise the
    `make coverage-branch` gate by visible deltas after each
    `tests-*` subtask lands.
- [ ] End-to-end coverage. `e2e-greenfield-init`,
  `e2e-dotenv-migration`, `e2e-policy-run`, `e2e-docker-compose`,
  `e2e-recovery-roundtrip` shipped. Remaining
  (`docs/specs/testing.md:38`):
  - [ ] **subtask** — e2e-agent-rpc: drive the agent socket through
    `Status`, `Lock`, `Unlock`, `RequestGrant`, `RevokeGrant`,
    `SubscribeStatus`. Pre-req: daemon subtasks.
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
  scaffolding exists. Remaining: full spec fixtures, hard
  p95/throughput budgets, `make bench` / `bench-ci` / `bench-report`
  PR-vs-release modes (`docs/specs/performance.md`).
- [ ] Branch coverage and mutation gates (`make coverage-branch`,
  `make mutation`). Local fallbacks exist; line coverage still <90%.
- [ ] Supply-chain tooling. Offline-safe local commands and
  strict-mode hooks exist. Remaining: enforced `cargo deny`/`audit`,
  cargo-vet, unsafe inventory, SBOM, auditable builds, provenance,
  signing.
- [ ] Leak canary harness. Scanner/redactor tests + `make
  leak-canary` exist. Remaining: broader CLI/agent/UI scanning.
- [ ] Signed distribution packaging and update-check verification.
  Offline signed update-manifest verifier + typed
  `UpdateManifestInvalid` shipped. Remaining: package builders +
  signing for Homebrew / signed macOS pkg / Windows MSI / Linux
  package / VS Code extension (`docs/specs/operations.md:27-53`).
- [ ] Cold-start budgets (`docs/specs/performance.md`). Each subtask
  adds one bench plus a regression that fails the budget:
  - [ ] **subtask** — perf-passphrase-unlock: ≤300 ms cold.
  - [ ] **subtask** — perf-recovery-envelope-unlock: ≤2 s cold.
  - [ ] **subtask** — perf-agent-idle-memory: ≤50 MB RSS after
    documented warmup. Pre-req: agent daemon subtasks.
- [ ] Dependency hygiene gates: `cargo machete`/`udeps` in CI;
  OpenSSF Scorecard once public; keyless signing with transparency
  logs for CI artifacts; frontend `pnpm lint`/`typecheck`/`test`/
  `build` once `locket-app` exists.
- [ ] Property tests. All current `proptest-*` subtasks shipped.
  Add new harnesses as uncovered invariants surface
  (`docs/specs/testing.md:14`).
- [ ] Cross-platform test mocks and mutation tests
  (`docs/specs/testing.md`):
  - [ ] **subtask** — mock-peer-credentials: in-process socket
    harness returning spoofable peer creds for testing
    peer-validation logic without root. Pre-req:
    `agent-peer-validation` (shipped).
- [ ] Bench fixtures: metadata, runtime, reference-resolution,
  staged-scan, full-scan, Argon2 (`docs/specs/performance.md`).
- [ ] PR vs release tolerance gate: 10% PR / 20% tracked-regression
  / no-tolerance release (`docs/specs/performance.md`).
- [ ] `make coverage-html` and `make test` Make targets exposed
  (`docs/specs/testing.md`).
- [ ] `cargo geiger` (or equivalent) unsafe inventory before public
  release and after any crypto/IPC/platform/storage dep change
  (`docs/specs/engineering.md`).
- [ ] RustSec advisory severity policy: high/critical block, medium
  runtime block, dev-only exception, low triage
  (`docs/specs/engineering.md`).
- [ ] Supply-chain exception ledger (package, version, reason,
  compensating controls, owner, expiration) enforced by CI;
  no-expiration entries are invalid (`docs/specs/engineering.md`).
- [ ] SLSA v1.2 provenance verification + Build L3 hosted-runner
  targeting (`docs/specs/operations.md`).
- [ ] Pre-migration backup of `store.db` and recovery files before
  schema-mutating migrations; `locket doctor` reports backup-skipped
  migrations and last backup path (`docs/specs/storage.md`).
- [ ] Prune expired `automation_client_nonces` during automation
  client authentication. Pairs with the doctor-side prune; lands
  with challenge-response auth in the Automation-client item.

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
