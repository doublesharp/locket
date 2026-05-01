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

### B. Schema / data-model alignment

### C. CLI / runtime / agent

- [~] (in-flight: feature/windows-transport-final) **agent-windows-named-pipe-transport**: finish the remaining hard
  transport work after `agent-windows-named-pipe-sid-path-partial`.
  The partial shipped shared SID-based pipe path helpers, protected
  current-user DACL SDDL generation, Windows diagnostics, and CLI path
  resolution behind `cfg(windows)`. Progress on
  `feature/agent-windows-transport`: Tokio named-pipe listener/client
  skeleton plus Windows CLI endpoint routing for start/status/stop.
  Remaining: pass the generated current-user SECURITY_ATTRIBUTES into
  pipe creation, replace the temporary Windows stop `Lock`+terminate
  behavior with a graceful shutdown request, wire the full agent
  dispatcher over named pipes, and add on-Windows ACL/transport
  integration coverage.
### D. Desktop / integrations / scan

- [~] (in-flight: feature/agent-bundle-import-recovery) **agent-export-bundle-audit-chain**: agent `ExportBundle`
  now writes sealed bundles for selected profile scope using unlock
  audit context, recipient descriptor validation, encrypted blobs,
  profile keys, export audit metadata, and metadata-only response.
  Remaining export parity: support `include_audit=true` by extracting
  CLI sealed audit-chain encryption into shared bundle helpers instead
  of returning the current typed `PolicyValidationIncomplete` error.
- [~] (in-flight: feature/agent-bundle-import-recovery) **agent-export-bundle-command-policies**: agent `ExportBundle`
  currently exports store-backed profiles/secrets/versions/blobs/profile
  keys only. Add a shared policy-document/snapshot source so command
  policies are included in the sealed payload without depending on CLI
  `RuntimeContext`.
- [~] (in-flight: feature/agent-bundle-import-recovery) **agent-import-bundle-core**: `ImportBundle` reaches the typed
  agent path, validates unlock state and input path, then returns
  `not-implemented`. Extract/apply the bundle import core in the
  agent with conflict policies (`review`, `accept-incoming`,
  `accept-local`) and local audit writes.
- [~] (in-flight: feature/agent-bundle-import-recovery) **agent-recovery-rotate-core**: `RecoveryRotate` reaches the
  typed agent path and enforces one-time-display acknowledgement, but
  still lacks fresh platform/current-code verification and recovery
  envelope rewrite from `vault/recovery.rs`.
- [x] **secret-row-cross-reference-deprecation**: desktop secret rows now
  derive metadata-only warnings from loaded policy and version rows when
  pinned policy/command-preview `lk://...@vN` references target deprecated
  versions with active or expired grace. Badges show version, grace state,
  reference surface, and count only; no secret values or command text.
### E. Quality / ops / build

- [~] (in-flight: feature/os-validation-final) **canary-packaged-os-follow-up**: remaining canary surfaces that
  genuinely require OS/manual packaging jobs: signed desktop webview
  smoke, OS clipboard/tray integration on each target, packaged VSIX
  execution, and full recovery restore e2e with artifact scanning.
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
`LAContext` wrapper shipped. Linux Secret Service and Windows Hello
backends are wired behind target cfgs.

- [~] (in-flight: feature/os-validation-final) **lauthn-linux-fido2-fallback**: add and validate the
  `libfido2-sys` hardware-key user-presence fallback on a Linux host
  with a physical security key. The Secret Service backend is wired;
  this remains the headless/security-key fallback path.
- [~] (in-flight: feature/os-validation-final) **lauthn-real-host-validation**: exercise Linux Secret Service on
  locked/unlocked desktop sessions and Windows Hello
  `UserConsentVerifier` on an enrolled Windows host. macOS cannot
  locally execute those OS prompt APIs.

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

Deep audit on 2026-05-01 found no remaining tray-panel subtasks.
`crates/locket-app/` covers the compact status surface, safe project/profile
labels, running session / scan / audit / pinned-reference counts, agent state,
tray action routing, selection-gated reveal/copy, saved-policy-only launch,
notification privacy, and platform icon variants from `desktop.md:65-108`.

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
`e2e-docker-compose`, `e2e-recovery-roundtrip`, and
`e2e-ui-editor-smoke` shipped.

### Distribution supply-chain gates
Offline-safe local commands, strict-mode hooks, cargo-vet, unsafe
inventory, SBOM, exception ledger, and provenance policy verifier
exist. Remaining: auditable builds and signing.

### Package builders and signing
Spec ref: `docs/specs/operations.md:27-53`.

- [~] (in-flight: feature/release-operator-final) **homebrew-tap-publish-operator**: with signed source tarball URL
  and SHA-256, run `scripts/render-homebrew-formula.sh`, run
  `LOCKET_HOMEBREW_AUDIT=1`, and open the tap PR using tap credentials.
- [~] (in-flight: feature/release-operator-final) **cargo-install-publish-operator**: after internal `locket-*`
  crates are published or reserved, run `cargo publish --dry-run -p
  locket-cli --locked` and the real publish with `CARGO_REGISTRY_TOKEN`
  from the signed release tag.
- [~] (in-flight: feature/release-operator-final) **macos-pkg-sign-notarize-operator**: run
  `scripts/package-native-installers.sh --target macos-pkg` on the
  release macOS signer with Developer ID Installer and notarization
  credentials.
- [~] (in-flight: feature/release-operator-final) **windows-msi-sign-operator**: run
  `scripts/package-native-installers.sh --target windows-msi` on the
  release Windows signer with the EV certificate available to `signtool`.
- [~] (in-flight: feature/release-operator-final) **linux-deb-rpm-sign-operator**: run
  `scripts/package-native-installers.sh --target linux-deb` and
  `--target linux-rpm` with the release GPG keys, then publish through
  the package repository operator path.
- [~] (in-flight: feature/release-operator-final) **vsix-release-sign-operator**: run
  `scripts/package-vscode-extension.sh --sign <key-id>` on the offline
  signing host with `LOCKET_MINISIGN_SECRET_KEY`; verify the detached
  signature against `dist/keys/<key-id>.pub` before upload.

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
