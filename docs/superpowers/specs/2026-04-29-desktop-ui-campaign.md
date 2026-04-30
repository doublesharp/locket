# Desktop UI campaign: 12 slices to full spec coverage

Companion to `docs/specs/desktop.md`, `docs/specs/agent.md`, and the
`tauri-shell` slice spec at
`docs/superpowers/specs/2026-04-29-tauri-shell-design.md`.

This is the dependency map and slice order for fully implementing the
Tauri desktop UI + system tray. Each slice is sized to be reviewable in
isolation under the project's worker / integrator flow rules.

## Status as of 2026-04-29

**Shipped:**

- `crates/locket-app/src-tauri/`: Tauri 2 binary `locket-desktop` with
  empty IPC surface, deny-by-default capability set, restrictive release
  CSP byte-for-byte equal to `ReleaseWebviewPolicy::default()`, devtools
  gated on `cfg(debug_assertions)`.
- `crates/locket-app/ui/`: Vue 3 + Vite + TypeScript with `pnpm`
  build/lint/typecheck and Makefile targets (`app-ui-{install,check,build}`).
- `crates/locket-app/src/lib.rs`: pure descriptor types for primary
  views, tray icon states, denial reasons, empty states, accessibility
  requirements, version history fields, execution monitor fields.

**Agent-side already on main:**

- `agent-socket-server` — Unix domain socket with peer-cred validation.
- `Status`, `Lock`, `Unlock`, `RequestGrant`, `RevokeGrant`, `ExpireGrant`,
  `SubscribeStatus` RPC handlers.

## RPCs gating UI progress

| RPC | Status | Blocks UI |
|-----|--------|-----------|
| `Reveal` / `Copy` | not started | Slice 7, Slice 8 |
| `ScanKnownValues` | not started | Slice 10 |
| `ResolveReference` | partial decomposition (`lk-resolve-*` subtasks) | Slice 12 (policy doctor) |
| `PrepareExec` | not started | Slice 12 (policy preview) |
| `CancelSubscription` | not started | minor |
| `RegisterClient` / `RevokeClient` | not started | future automation-client UI |

Slices 1–6, 8–9, 11 can proceed without these. Slices 7, 10, 12 are
blocked on agent-side RPC work.

## Slice plan

### Slice 1 — `tauri-agent-client`

**Pairs with TODO:** App/UI → Build the Tauri desktop app → tauri-agent-client.

TypeScript module that speaks the agent socket protocol. Surfaces
`AgentUnavailable` and `ProtocolError` distinctly. Provides a
`useAgent()` Vue composable for connection state. No views ship yet —
just the client + a fallback banner when the daemon is offline.

- Pre-req: `agent-socket-server` (shipped).
- Adds: client module under `crates/locket-app/ui/src/agent/`,
  `connect-agent` / `disconnect-agent` Tauri commands in
  `src-tauri/src/lib.rs`, capability opt-in for `core:default`.
- Audit: none (read-only status).
- Tests: connection success, daemon-offline path, reconnection on
  daemon restart.

### Slice 2 — `tray-bind-platform`

**Pairs with TODO:** App/UI → Build the tray/status panel → tray-bind-platform.

Register the Tauri 2 tray icon and menu on macOS, Windows, and Linux.
Use `tray_icon_descriptors()` and `tray_icon_asset_styles_for_os()` from
`locket-app::*`. macOS gets the template-image variant; Windows/Linux
get full-color light/dark variants.

- Pre-req: Slice 1 (agent client) for status queries.
- Adds: `src-tauri/src/tray.rs`, icon assets under
  `src-tauri/icons/tray/{macos,windows,linux}/`.
- Tests: platform-specific asset loading; state-to-icon mapping for all
  five `TrayIconState` variants.

### Slice 3 — `tray-status-binding`

**Pairs with TODO:** App/UI → Build the tray/status panel → tray-status-binding.

Subscribe the desktop and tray to the agent's `SubscribeStatus` stream.
Update icon, label, and a desktop status banner on lock-state changes
and heartbeat events. Honor `privacy.redact_names` for project / profile
names in the tray label.

- Pre-req: Slices 1 + 2; `agent-subscribe-status` (shipped).
- Adds: subscription lifecycle in `useAgent()`; tray label updater.
- Tests: subscription open/close, heartbeat cadence, state-change
  ordering, privacy alias rendering.

### Slice 4 — Secret metadata view (read-only list)

**Pairs with TODO:** App/UI → Primary desktop views → secret metadata list.

Render secrets for the active profile by querying the local store.
Source-precedence visible (team / user / machine). Search and filter
respect `privacy.redact_names`. Empty state offers `locket set <KEY>`
or `locket import`.

- Pre-req: Slice 1 (agent client for active-profile context).
- Adds: `ui/src/views/SecretMetadataList.vue`; store-query Tauri command
  `list_secrets_metadata` (metadata only, never values).
- Audit: none (read-only).
- Tests: source-precedence ordering; privacy alias rendering; empty
  state.

### Slice 5 — Secret version history view

**Pairs with TODO:** App/UI → Primary desktop views → secret version history.

Use the existing `VersionHistoryState` / `VersionHistoryField`
descriptors. Show current / deprecated / purged states, `deprecated_at`,
`grace_until`, pinned-reference eligibility, scan inclusion, and the
rotation audit summary.

- Pre-req: Slice 4.
- Adds: `ui/src/views/SecretVersionHistory.vue`; query for
  `secret_versions` rows.
- Audit: none (read-only).
- Tests: descriptor mapping; grace-window expiry rendering;
  pinned-reference eligibility logic.

### Slice 6 — Execution monitor view

**Pairs with TODO:** App/UI → Primary desktop views → execution / session monitor.

Use the existing `ExecutionMonitorState` / `ExecutionMonitorField`
descriptors. Render `runtime_sessions` rows. Profile and policy names
honor privacy aliases. Secret count only; never names or values.

- Pre-req: Slice 4 (profile context).
- Adds: `ui/src/views/ExecutionMonitor.vue`; query for runtime_sessions.
- Audit: none.
- Tests: state descriptor mapping; alias rendering; secret-count
  derivation.

### Slice 7 — Reveal / Copy UI gates

**Pairs with TODO:** App/UI → Reveal/copy UI gates with short-lived plaintext handling.

Implement `Reveal` and `Copy` RPC handlers in the agent (gated by
unlock + grant), then desktop webview that displays a TTL-bound value
with accessibility-metadata scrub on expiry, and a clipboard helper
that clears the copy after TTL only if the clipboard still contains the
value.

- Pre-req: Slice 1; agent-side `Reveal`/`Copy` (not started — adds new
  TODO subtask under Local agent daemon).
- Adds: `ui/src/views/RevealModal.vue`, `ui/src/clipboard.ts`,
  `src-tauri/src/lib.rs` Tauri commands, agent `Reveal`/`Copy` handlers.
- Audit: `REVEAL`, `COPY` audit rows with `ttl_seconds`,
  `access_mode`; never values.
- Tests: TTL expiry hides value; clipboard clear; metadata scrub.

### Slice 8 — Tray reveal/copy and notifications

**Pairs with TODO:** App/UI → Build the tray/status panel (extension).

Surface reveal/copy in the tray context menu (one selected secret at a
time). Render passive notifications using `TrayNotificationKind`
descriptors — generic labels only, never names or values.

- Pre-req: Slices 2 + 4 + 7.
- Adds: tray context menu actions; notification dispatcher.
- Audit: `REVEAL`/`COPY` rows via agent (not duplicated by tray).
- Tests: tray context-menu invocation; notification text scrubbing.

### Slice 9 — Audit log + verification view

**Pairs with TODO:** App/UI → Audit, policy, profile, scan, and bootstrap views (audit slice).

Render `audit_log` rows. Filter by action, profile, status, timestamp.
Privacy aliases when redacting names. Surface chain-break detection via
`audit verify`.

- Pre-req: Slice 1.
- Adds: `ui/src/views/AuditLog.vue`; query commands; verification
  trigger.
- Audit: none (querying existing rows).
- Tests: HMAC verification path; chain-break detection; privacy alias
  rendering.

### Slice 10 — Scan results view

**Pairs with TODO:** App/UI → Audit, policy, profile, scan, and bootstrap views (scan slice).

Display findings (rule id, path, line, column, severity, redacted
summary). Trigger `ScanKnownValues` from the UI. Show suppression
metadata when present.

- Pre-req: Slice 4; agent-side `ScanKnownValues` (not started — adds
  new TODO subtask under Local agent daemon).
- Adds: `ui/src/views/ScanResults.vue`; rescan trigger.
- Audit: `SCAN` rows already logged by CLI; UI is read-only.
- Tests: redacted finding rendering; suppression display; rescan
  integration.

### Slice 11 — Settings + privacy-mode toggle

**Pairs with TODO:** App/UI → Privacy-mode rendering + Settings.

Show and toggle `privacy.redact_names`. Show TTL unlock duration,
verification policy, dangerous-profile flag. Propagate setting changes
to all open views immediately.

- Pre-req: Slice 4 (to verify alias rendering propagates).
- Adds: `ui/src/views/Settings.vue`; settings store and reactive
  propagation.
- Audit: `CONFIG_UPDATE` row via CLI/store (not desktop directly).
- Tests: toggle propagation; alias rendering on/off; TTL field
  rendering.

### Slice 12 — Policy editor + backup/recovery views

**Pairs with TODO:** App/UI → Build the Tauri desktop app (policy editor + backup/recovery sub-views).

Compound slice. Policy editor showing argv vs shell mode, required vs
optional secrets, gates (`confirm`, `require_user_verification`, `ttl`).
Backup/recovery view with `export --sealed`, `import-bundle`, and
`bundle verify` flows. Recovery code display and secure input.

- Pre-req: Slice 1, Slice 5 (deprecated grace rendering); agent-side
  `ResolveReference` (decomposed but not shipped) and `PrepareExec` (not
  started).
- Adds: `ui/src/views/PolicyEditor.vue`,
  `ui/src/views/BackupRecovery.vue`; secure recovery-code input
  component; dangerous-profile typed-confirmation flow.
- Audit: `POLICY_UPDATE`, `BACKUP_EXPORT`, `RECOVER`, `TEAM_ACCEPT` rows
  via core commands (not desktop directly).
- Tests: policy validation errors; dangerous-profile confirmation;
  recovery code display (one-time, scrollback warning, optional screen
  clear); invite fingerprint and safety-words rendering.

## New TODO subtasks to add to IMPLEMENTATION_PROGRESS.md

These spec items currently lack `[ ]` lines and should be added when
the next claim is made:

1. Agent `Reveal` / `Copy` RPC handlers under `Local agent daemon`
   (pre-req: `agent-unlock-cache`). Slice 7 needs them.
2. Agent `ScanKnownValues` RPC handler under `Local agent daemon`.
   Slice 10 needs it.
3. Agent `PrepareExec` RPC handler under `Local agent daemon`. Slice 12
   needs it.
4. Cross-surface error-text parity check (CLI / UI / tray / shell / VS
   Code show the same reason + next action) — already partially listed
   under `App/UI` but not decomposed by surface.

These will land as separate progress-doc edits when the slice that
needs them claims work.

## Cross-cutting invariants

Every slice must respect:

- **Privacy mode**: render aliases when `privacy.redact_names = true`.
  Aliases are deterministic by id; never stored in audit metadata.
- **Accessibility**: keyboard navigation, visible focus, screen-reader
  labels, contrast budgets, reduced-motion support, post-TTL
  accessibility-metadata scrub.
- **Plaintext lifecycle**: never persisted in frontend state outside of
  a TTL-bound reveal/copy scope. Cleared from accessibility metadata
  when the TTL expires.
- **Capabilities discipline**: every new Tauri command opts in to the
  minimum permission set; deny-by-default stays the default for
  `fs`/`shell`/`network`/`updater`/`clipboard`.
- **CSP discipline**: release CSP must continue to match
  `ReleaseWebviewPolicy::default()` byte-for-byte. The
  `tests/config.rs` regression in `locket-desktop` is the load-bearing
  test.
- **No direct audit writes from desktop**: every audit-emitting action
  flows through an agent RPC or core command.

## How an integrator should consume this plan

This document is informational. Each slice still claims its own TODO
line in `IMPLEMENTATION_PROGRESS.md`, gets its own worktree + branch +
ready-file, and is rebased + tested + merged independently. Slices
should never bundle work outside their listed deliverable unless the
claim line documents the bundle (as `tauri-shell` did).
