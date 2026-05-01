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

- [ ] **device-key-recovery-envelope-entries**: recovery envelope
  must carry `device_signing_private_key` + `device_sealing_private_key`
  per `crypto.md:158,171` and `team-sync-recovery.md:131`. Today
  envelope only carries `master_key` + `automation_client_private_key:*`,
  so a host that loses its keychain wedges at `KeychainEntryMissing`.
  Touches: `team/device.rs:683-694` (bootstrap envelope creation)
  and `vault/recovery.rs:25-39` (restore path); map missing entries
  to `LocalVaultUnrecoverable` per spec table line 147.
- [ ] **device-init-force-rewraps-envelope**: `team-sync-recovery.md:44`
  requires `device init --force` to atomically update the recovery
  envelope with new device-key wraps. `team/device.rs:84-118` +
  `replace_local_device_with_audit:461-501` only swap the
  wrapped-local-file storage. Pre-req: `device-key-recovery-envelope-entries`.
- [ ] **recovery-rotate-fresh-user-verification**:
  `team-sync-recovery.md:159,164-165` requires `locket recovery rotate`
  to gate on fresh local user verification. `vault/recovery.rs:51-107`
  calls neither helper. Insert verification call + embed
  `UserVerificationAudit` into the `RECOVERY_ROTATE` row.
- [ ] **recovery-rotate-carries-device-keys**: `crypto.md:172` says
  rotate must rewrap all active managed client private keys "in the
  same atomic replacement as the master and device key wraps". Pair
  with `device-key-recovery-envelope-entries`.
(`bundle-verify-attempts-decrypt-when-recipient` shipped — bundle_verify_command now matches local device fingerprint against recipients, attempts trial decrypt + reports inner counts; fingerprint-match-but-decrypt-fail surfaces as BundleVerificationFailed (exit 110).)
(`bundle-import-rotate-uses-import-timestamp` shipped — apply_bundle_payload's divergent UPDATE binds local now to last_rotated_at instead of bundle's value; e2e regression added.)
- [ ] **client-create-writes-to-recovery-envelope**: `crypto.md:172`
  says `locket client create` with `--storage os-keychain` or
  `--storage wrapped-local-file` must add an
  `automation_client_private_key:<client_id>` envelope entry at
  creation. `team/client.rs:40-181` + `store_client_private_key:276-347`
  only write to keychain/local file. Result: `recover_command`
  always counts those as `skipped_automation_client_private`.
- [x] **bootstrap-checklist-coverage-incomplete** shipped:
  `locket bootstrap` now checks agent running/startable state, probes the
  active profile's local key unlockability, checks argv policy tool
  presence through local paths/PATH, and executes a configured
  `smoke_policy` through the existing `locket run <policy>` path.
- [ ] **bootstrap-shell-tool-presence-follow-up**: bootstrap reports shell
  policy tool checks as `tools_unchecked: shell:<first-token>` because
  safely and portably identifying every referenced tool inside arbitrary
  shell snippets requires shell-aware parsing beyond the local argv check.
- Shipped: **privacy-alias-canonical-encoding** — moved every
  surface (`locket-core::privacy_alias`, CLI `privacy_alias` shim,
  agent local copies, UI `privacyAlias`) onto the canonical
  `SHA-256("locket-privacy-alias-v1" || field("kind", kind) ||
  field("id", id))` body with length-prefixed UTF-8 `field()` from
  `crypto.md:134`. Added Rust + TS vector tests with cross-language
  KATs and a guard that the new digest does NOT match the legacy
  `kind:{kind};id:{id}` body. Removed five duplicate `privacy_alias`
  copies inside `locket-agent`.

### B. Schema / data-model alignment

(`audit-verify-validator-arm` shipped — AUDIT_VERIFY arm added to required_fields_for_action; rejection test covers stripped metadata.)
- [ ] **passkey-credentials-missing-cols**: `passkey_credentials`
  (`schema.rs:298-313`) lacks `device_id`, `member_id`, `public_key`,
  `user_handle` per `data-model.md:267-285`. WebAuthn assertion
  needs `public_key`; `user_handle` is the stable random handle.
  Touches: schema migration + `PasskeyCredentialRecord` updates in
  `locket-store/src/passkey.rs` + registrar plumbing in
  `locket-platform`.
(`directory-grants-missing-revoked-and-granted-by` shipped —
`directory_grants` now persists nullable `granted_by` + `revoked_at`,
deny paths soft-revoke rows instead of deleting, active lookups
filter revoked grants, and allow revives the prior scope row while
preserving stable audit correlation.)
(`imported-audit-chain-optionality` shipped — spec was wrong;
updated data-model.md:421-432 to drop Option from encrypted-rows
fields (schema is canonical).)
(`bundle-conflict-index-by-profile-name-version` shipped — added
`secrets_bundle_conflict_idx(project_id, profile_id, name, source,
state, current_version)`, kept `secret_versions(secret_id, version)`
as the version-side lookup, added planner/index-shape tests, and
surfaced the index in `locket doctor` as `bundle_conflict_index`.)
(`devices-missing-member-id-and-label` shipped — `devices` now has
nullable `member_id` with active-member index plus separate non-null
`label`; store records and CLI/device descriptor paths populate/read
both while preserving `name` as the stable selector.)
- [ ] **store-schema-migration-framework**: 14b's three column
  additions land via `CREATE TABLE IF NOT EXISTS`, which only
  applies to brand-new stores. Pre-v1 ship is fine, but before
  shipping publicly we need an ALTER-based migration framework
  keyed on `SCHEMA_VERSION` so existing stores get the new columns
  + indexes. Touches: `crates/locket-store/src/schema.rs` and the
  `SchemaMigrationOutcome` machinery.

### C. CLI / runtime / agent

(`agent-register-revoke-client-rpc` shipped — agent dispatch now
implements `RegisterClient` / `RevokeClient`, writes automation
client rows, and emits `CLIENT_ADD` / `CLIENT_REVOKE` audit rows.)
(`agent-socket-path-xdg-runtime-dir` shipped for Unix production
paths — Linux uses `$XDG_RUNTIME_DIR/locket` when set with fallback
to `~/.locket`; macOS uses `~/Library/Application Support/locket`.
Windows named-pipe/SID transport remains tracked below.)
- [ ] **agent-windows-named-pipe-sid-path**: follow-up from shipped
  14c socket placement work. `agent.md:20` requires
  `\\.\pipe\locket-agent-<sid>` with a current-user-only DACL.
  Current production startup now uses `$XDG_RUNTIME_DIR/locket` on
  Linux and `~/Library/Application Support/locket` on macOS, but the
  Windows/non-Unix branch still falls back to `<HOME>/.locket` because
  the CLI/agent surface is Unix-socket-only and does not resolve the
  user's SID. Touches: Windows pipe listener/client transport,
  `resolve_default_agent_data_dir`, startup diagnostics, and pipe ACL
  tests.
(`external-env-file-error-band` shipped — resolve_external_env_file now surfaces InvalidPolicy (band 65); 3 existing tests updated.)
(`external-env-file-symlink-tests` shipped — two #[cfg(unix)] tests added for symlink-out (rejected) and symlink-in (accepted).)

### D. Desktop / integrations / scan

- [ ] **status-payload-tray-fields**: `desktop.md:69-78` requires
  the tray panel to surface running session count, recent
  scan-warning count, recent audit status, active expiring/expired
  pinned-reference warning count. `agent/status.rs:22-36` carries
  none of those. Touches: extend `StatusPayload` + `StatusHub`
  publish path, recompute on relevant audit/scan/runtime-session
  writes, render in tray tooltip.
- [ ] **scan-warning-tray-state-producer**: tray icon-state machine
  has `ScanWarning` variant with PNG assets (`tray.rs:373,383,393`)
  but `deriveTrayState` in `useTray.ts:35-58` never returns
  `'scan-warning'`. Spec (`desktop.md:105`) ties this icon to "one
  or more unresolved scan warnings". Pre-req:
  `status-payload-tray-fields` for `scan_warning_count`.
- [ ] **backup-recovery-view-not-wired**: `BackupRecovery.vue`
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
- [~] (in-flight: agent 14f) **integrations-suppress-marker-spec-conflict**:
  `integrations.md:115` mandates `locket-allow` /
  `locket-allow-next-line` markers; `scan-redaction.md:80-95`
  mandates `locket-suppress*` family. `suppressions.rs:30-39` only
  honors `locket-suppress*`. **Spec-vs-spec contradiction** — pick
  one canonical marker family, edit the loser spec.
- [~] (in-flight: agent 14f) **process-env-pattern-non-js-coverage**: VS Code diagnostic
  in `extensions/vscode/src/diagnosticsModel.ts:34` only matches
  `process.env.KEY` (Node). `integrations.md:49` says "process.env.KEY
  *and similar references*". Python (`os.environ["KEY"]`,
  `os.getenv`), Rust (`env::var`), Go (`os.Getenv`), shell
  (`$KEY`/`${KEY}`) not detected, even though `referenceCompletion.ts:11-32`
  registers diagnostics-eligible language IDs for all of them.
- [ ] **tray-privacy-alias-not-applied**: `desktop.md:37,72-73,94-95`
  requires tray tooltip + notifications to use stable local aliases
  when `privacy.redact_names = true`. Rust `tray::tooltip_for`
  (`tray.rs:345-347`) returns static `descriptor().label`
  regardless. Forward-looking gap once `status-payload-tray-fields`
  lands and tooltips include project/profile context.

### E. Quality / ops / build

- [ ] **github-actions-workflows-missing**: repo has **no
  `.github/` directory at all**. `dist/release-ci-runners.md` and
  `operations.md:39` document `release.yml`; `fuzzing.md:39`
  requires nightly fuzz CI; coverage/SLSA gates are documented but
  not enforced anywhere outside local `make` invocation. Ship
  `.github/workflows/{ci.yml,release.yml,fuzz-nightly.yml}` matching
  the existing `make` targets.
- [ ] **reference-runner-setup-scripts**:
  `performance-reference-runner.md:87,99` mandates
  `scripts/reference-runners/` per-class setup scripts that record
  applied state into `target/quality/reference-runner-setup.json`
  and are invoked before sample collection. Directory missing
  entirely. Add `arm64-mac.sh` / `x86-linux.sh` + a fingerprint JSON
  writer; wire `bench-smoke.sh` to read the fingerprint.
- [~] (in-flight: agent 14f) **fuzz-corpus-seed-thinness**: `fuzzing.md:41` requires
  diverse versioned corpora; most directories under `fuzz/corpus/`
  carry one trivial seed (e.g. `fuzz_lk_uri/basic.txt`). Seed each
  with edge-case / malformed / boundary inputs.
- [x] **mutation-scope-mismatch**: `testing.md:43` and
  `engineering.md:34` require mutation testing on policy / env-merge
  / typed-error / authz **areas**. `scripts/mutation-smoke.sh` now
  drives `cargo mutants --file <glob>` per area (policy_evaluation,
  env_merge, typed_error_map, authz_boundaries) instead of whole
  packages, and the fallback package set includes `locket-cli`.
- [ ] **canary-harness-surface-coverage**: `testing.md:84-89`
  requires the canary helper to cover CLI, agent, scan, redaction,
  audit, debug bundle, UI, tray, VS Code, Docker, and recovery
  flows. Today only `locket-cli/src/tests/leak_canary.rs` and
  `locket-scan/tests/leak_canary.rs`. Extend into agent reveal/copy,
  Docker compose helper, audit row writer, desktop UI smoke, VSIX
  integration.
- [x] **doublcov-html-not-canonical**: `testing.md:48` names
  `cargo llvm-cov` as canonical. `scripts/coverage.sh html` now
  defaults to `cargo llvm-cov --html` (output under `coverage/html/`).
  Set `COVERAGE_HTML_TOOL=doublcov` or pass `--use-doublcov` to opt
  into the legacy renderer. Makefile + README updated.
- [x] **bench-report-spec-claim**: `performance.md:31` lists
  `make bench-report` as required. `bench-smoke.sh report` now
  auto-invokes `bench-smoke.sh ci` to produce
  `target/quality/bench-report.md` if it is missing. Set
  `BENCH_REPORT_AUTORUN=0` to require a prior `make bench-ci` run.
  Makefile target documents the relationship.
- [x] **sanitizer-not-required-in-smoke**: `fuzzing.md:43` says
  smoke jobs should use ASan/UBSan where available.
  `scripts/fuzz-smoke.sh` now defaults `FUZZ_SANITIZER=address` for
  smoke and run modes on Linux + macOS hosts; nightly default is
  unchanged. `FUZZ_SANITIZER=none` opts out.
- [ ] **fuzz-nightly-ci-job**: subtask of
  `github-actions-workflows-missing`. Schedule `make fuzz-nightly`
  with artifact upload of `fuzz/artifacts/` and `fuzz/corpus/` per
  `fuzzing.md:39`.

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

(14c shipped `RegisterClient` / `RevokeClient` dispatch with
automation-client row writes and `CLIENT_ADD` / `CLIENT_REVOKE` audit
emission. 14c also moved production Unix socket, pid, and log placement
to the spec paths: `$XDG_RUNTIME_DIR/locket` on Linux when set, falling
back to `~/.locket`, and `~/Library/Application Support/locket` on
macOS. The remaining Windows named-pipe/SID transport work is tracked
as `agent-windows-named-pipe-sid-path` above.)

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

(`bundle-apply-and-conflicts` shipped — commit `c0fba305` lands the
single-transaction apply path with the full conflict matrix
(identical / newer-incoming / divergent / deleted-vs-active) and
extends `BACKUP_IMPORT` `metadata_json` with applied counts and
`conflict_counts`. E2E coverage in
`crates/locket-cli/src/tests/e2e_bundle_roundtrip.rs` exercises
each conflict arm.)

(`bundle-include-audit-import` shipped — `import-bundle --include-audit`
decrypts the carried audit-chain payload, structurally verifies it
via `verify_imported_audit_chain_structure`, and only then writes
the encrypted blob into `imported_audit_chains`. Tamper paths roll
back the apply transaction. CLI emits `imported_audit_chain_count`
and the `BACKUP_IMPORT` audit row carries the same field. Two e2e
tests cover the golden round-trip and byte-flipped tamper path
(commit `62f63881`).)
(`bundle-team-accept-parity-test` shipped — new test
`team_accept_then_import_bundle_matches_import_only_state` in
`crates/locket-cli/src/tests/e2e_bundle_roundtrip.rs` proves the
two flows converge on the same substantive 5-tuple
(profiles/secrets/secret_versions/blobs/command_policies) plus
pins that `team accept` is metadata-only (commit `5cfc8ba3`).)

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
Shipped: `invite-codec`, `invite-replay-protect`,
`invite-clock-skew`, signed invite creation, trust-summary display,
issuer fingerprint confirmation, accept denial rows, and revoke
flows. 2026-04-30 audit found one remaining gap:

- [~] **invite-sealed-payload-import** (in-flight: Codex, partial — type lands; encrypt+apply deferred): spec lines 7, 28, and 67
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
  Status: type definition shipped (`SealedInvitePayloadV1` +
  optional `InvitePayload.sealed_payload`, signature-covered,
  legacy-byte-stable, commit `21064bfa`); the encrypt-on-issue
  and decrypt+apply-on-accept slices are deferred behind
  `TODO(invite-sealed-payload-apply)` breadcrumbs and remain open.

### Audit coverage
Reveal/copy denial rows, role denials, grant denials, dangerous-
profile read refusals (`--use-dangerous` flag), the degraded-audit
logger + `degraded_audit_log` doctor + perms doctor all shipped.
The `team_members.device_id REFERENCES devices(id) ON DELETE SET
NULL` schema behavior is covered by a store verification test.
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

All previously-tracked gates now shipped:

(`vault-unlock-verify-user` shipped — `lock.rs` calls
`require_user_verification(context, "vault unlock", "unlock vault")`
and serializes the returned `UserVerificationAudit` into the
`UNLOCK` row's `user_verification` block. Allow/deny tests added
to `config_passkey_lock.rs`. Commit `842b48ca`.)
(`team-accept-verify-user` shipped — `team_accept_command` calls
`configured_user_verification(...)` after the fingerprint
confirmation, embeds the verification block in `TEAM_ACCEPT`
metadata, and emits a `DENIED` row with
`failure_reason: "user_verification_failed"` on rejection. Commit
`19e1a672`.)

### Agent / process hardening
`harden-peer-cred`, `harden-socket-perms`, `harden-memory-lock`,
`harden-zeroize`, `harden-doctor-degraded`, `harden-session-lock`
shipped. Core-dump suppression also shipped on all three platforms:

- Shipped: **harden-prctl-set-dumpable** — Linux core-dump
  suppression via `prctl(PR_SET_DUMPABLE, 0)` + `RLIMIT_CORE=0`
  (commit 97058f69).
- Shipped: **harden-macos-core-dump** — macOS core-dump suppression
  via `RLIMIT_CORE=0` (part of commit 9923b7f0).
- Shipped: **harden-windows-core-dump-real** — wired
  `windows-sys` (gated behind `target_os = "windows"`) and replaced
  the stub with `SetErrorMode(SEM_NOGPFAULTERRORBOX |
  SEM_FAILCRITICALERRORS)`. Added a `Suppressed` variant to
  `CoreDumpHardening`, taught `core_dump_hardening_state` to read
  `GetErrorMode`, taught `locket doctor` (`diagnostics.rs:873`) to
  treat `Suppressed` as a pass, and added Windows-only compile +
  idempotency tests. Spec ref: `docs/specs/agent.md`.

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
(Reveal modal + clipboard copy shipped together with tray menu
actions on commit dbf6ab52.)

- Shipped: **desktop-reveal-modal** — short-lived modal with TTL
  countdown, accessibility scrub on expiry, dismiss-on-blur (Slice 7).
- Shipped: **desktop-clipboard-copy** — copy + scheduled clear
  after TTL with re-check; Wayland degraded path emits
  `unsupported_reason`.
- Shipped: **agent-policy-doctor-rpc** — agent `PolicyDoctor` dry-run
  RPC with desktop bridge/client types and metadata-only reference
  validation.
(`desktop-tray-reveal-copy` shipped — commit `7302818f` adds
selection-aware reveal/copy tray context-menu items.)
(`desktop-policy-editor-write` shipped — commit `0a9e5f96` adds
create/edit/delete forms backed by `RegisterCommandPolicies` RPC
with dangerous-profile typed confirmation and `POLICY_UPDATE`
audit emission.)
(`desktop-profile-switcher-view` shipped — commit `4676a61a` adds
the switch-profile view with dangerous-profile typed confirmation.)

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

(`vscode-diagnostics-similar-env-refs` shipped — diagnostics now
thread VS Code `document.languageId` into the model and cover common
environment-reference idioms across JS/TS, Python, Rust, Go, Ruby,
Java/Kotlin, PHP, C/C++, C#, Swift, and shell while preserving the
Node-style fallback for unknown document types. The integrations
spec also points scanner suppression wording at the canonical
`locket-suppress*` directives in `scan-redaction.md`.)

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

- Shipped: **coverage-gate-baseline** (commit 65803c4a) —
  temporary 70/75 floor with `TODO(coverage-90)` comment.
- Shipped: **coverage-policy-90** (commit 4da332aa).
- Shipped: **coverage-bundle-90** (commit 2632f8c7).
- Shipped: **coverage-store-90** (commit bffddecd).
- Shipped: **coverage-agent-90** (commit f1de2092).

### End-to-end coverage
Spec ref: `docs/specs/testing.md:38`.
`e2e-greenfield-init`, `e2e-dotenv-migration`, `e2e-policy-run`,
`e2e-docker-compose`, `e2e-recovery-roundtrip` shipped.

(`e2e-bundle-roundtrip` shipped —
`crates/locket-cli/src/tests/e2e_bundle_roundtrip.rs` exercises
fresh / identical / newer-incoming / divergent / deleted-vs-active
arms plus corrupt-payload + missing-private-key verification
failures.)

- [ ] **e2e-ui-editor-smoke**: smoke flows in the desktop app and
  the VS Code extension. Pre-req: desktop-* and vscode-* items.

### Distribution supply-chain gates
Offline-safe local commands, strict-mode hooks, cargo-vet, unsafe
inventory, SBOM, exception ledger, and provenance policy verifier
exist. Remaining: auditable builds and signing.

(`auditable-builds` and `release-key-offline` shipped — see
`dist/release-key-offline.md`, `dist/keys/`, and
`dist/ceremonies/2026-05-01-release-key-ceremony.md`.)
- [ ] **release-ci-isolated-runners**: public release artifacts
  built on isolated runners. Spec: `docs/specs/operations.md:39`.

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
(`fixture-schema-version-drift` shipped — the IDE external-env test
fixture now includes `schema_version = 1`.)

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
- `team-sync-recovery.md` — (open: `invite-sealed-payload-import`
  apply path; `bundle-include-audit-import` and
  `bundle-team-accept-parity-test` shipped).
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
