# Locket Completed Items

Slices that have merged to `main` and verified. Open work tracked in
`progress.md` (sibling). `git log` is authoritative for who-did-what.

## Full Spec Coverage TODO — Near-Term CLI/Core

- [x] `locket init` spec coverage.
- [x] `locket init` rolls back late resume failures across store rows,
  recovery files, and newly created master-key material.
- [x] High-entropy scanning supports project thresholds, public-id exclusions,
  and `policy doctor` warnings for non-default settings.
- [x] Duration grammar regressions cover core parsing plus policy TTL,
  config, runtime-session retention, and rotate grace-TTL readers.
- [x] `locket status` spec coverage.
- [x] `locket emit-example` spec coverage.
- [x] `locket completion <shell>`.
- [x] `locket bootstrap` command surface and checklist behavior.
- [x] `locket import` spec coverage.
- [x] `locket redact` spec coverage.
- [x] `locket redact --stdin` streams as bytes; non-UTF-8 segments pass
  through unchanged with a metadata-only warning and audit flag.
- [x] `locket context` spec coverage.
- [x] `locket ai-safe` spec coverage.
- [x] Direct-CLI `LOCK`/`UNLOCK` audit rows record method
  (`OsKeychain`/`Passphrase`); locked-vault path stays metadata-only.
  Agent-backed RPC and `ttl_seconds` tracked under the daemon
  decomposition.
- [x] Trusted-root management.
- [x] Dangerous-profile flow.
- [x] `locket meta`.
- [x] `locket history`.
- [x] `locket diff`.
- [x] `locket copy` (role/team auth tracked under Team).
- [x] `locket get --copy` and reveal/copy gates (user verification
  tracked under the local-verification gate).
- [x] `locket new --from-template`.
- [x] `locket config` spec coverage.
- [x] `locket install-hooks`.
- [x] Secure interactive secret input for `set`/`rotate`.
- [x] Stable typed CLI error mapping and exit codes across all command families.
- [x] Secret-name (`^[A-Z_][A-Z0-9_]*$`) and profile-name
  (`^[a-z][a-z0-9_-]{0,63}$`) regex validation plus `_default` reserved
  name; reject at every editor before write.
- [x] Dotenv import: name-level parity check (never run user app) and
  explicit post-import confirmation to delete `.env`.
- [x] `.env.example` Locket-managed block markers
  (`# --- BEGIN/END LOCKET MANAGED ---`); rewrite only between markers;
  tombstoned secrets excluded from the cross-profile union.
- [x] `example.auto_refresh` config key wired through
  `refresh_example_for_project_if_enabled` at all current call sites
  (`set`/`rotate`/`rm`/`purge`/`copy`/`import`); `team accept` will hook
  in when that command lands.
- [x] Pre-commit hook block markers
  (`# --- BEGIN/END LOCKET PRE-COMMIT ---`), idempotent rewrite, typed
  confirmation when prepending to a non-Locket hook, and `HOOK_INSTALL`
  audit row when project context is available.
  - Spec: `docs/specs/integrations.md` Git Integration & Pre-Commit.
  - Errors: `ConfirmationFailed` (68).
  - Audit: `HOOK_INSTALL`.
  - Files: `crates/locket-cli/src/commands/project/install_hooks.rs`.
- [x] `locket scan --no-gitignore` flag and `--require-known`
  pre-commit mode (locked → `UnlockRequired`; outside project →
  `ProjectNotFound`).
- [x] Known-value scan coverage includes deleted current versions with
  blobs and grace-window deprecated versions, while excluding purged
  versions.
- [x] Store/schema coverage for the full required-tables set
  (automation/teams/passkey/imported-audit tables + indexes/triggers,
  with `SCHEMA_MIGRATE` audit on migrations).
- [x] scan-severity-policy: Scan severity now follows project policy for provider-token
  and .env findings.

## Full Spec Coverage TODO — Runtime/DX

- [x] SQLite pragma posture: `foreign_keys = ON`, WAL mode, 5 s busy
  timeout; `locket doctor` runs `PRAGMA integrity_check`.
- [x] Status-stream heartbeats (`StatusEvent kind="heartbeat"`, ≥30 s,
  monotonic `sequence`, not treated as state change).
- [x] Process-bound grant binding via `(pid, process_start_time)` per
  platform; PIDs are never trusted alone.
- [x] agent-unlock-cache: Agent lock/unlock now drives the in-memory cache,
  live grants, and metadata-only status snapshots.
- [x] `ExternalEnvSource::Parent` re-injects only policy-allowed
  parent names for `locket run`.
- [x] Shell prompt indicator renders lock state and respects privacy
  aliases (degrades to "stopped" when the agent is unreachable).
- [x] Shell command surface (`shellenv`, `hook`, `allow`, `deny`)
  (agent-hook install and live-grant TTL tracked under the agent daemon).
- [x] Wire Docker and Docker Compose into policy-backed CLI.
- [x] Runtime session storage/retention primitives and runtime execution
  recording for `exec`/`run` (doctor process-liveness classification is a
  follow-up under doctor enhancements).
- [x] Env layering modes distinguish `merge`/`passthrough`; explicit
  `override` tracking drives doctor/run warnings and audit metadata.
- [x] Conservative env allowlist
  (`PATH HOME USER SHELL TMPDIR LANG LC_* TERM CI`) applied in `minimal`
  mode with `LC_*` matching; `policy doctor` surfaces it.
- [x] `locket diff --since` resolves git revisions via direct
  `git log -1 --format=%ct <rev>` (no shell construction).
- [x] `compose run` flag plumbing: `--project-directory`, `--profile`,
  and post-`--` passthrough flow through to `docker compose`.
- [x] `inherit_env` extends (not replaces) the active `env_mode`
  allowlist via `merge_environment` in `crates/locket-core/src/env.rs`.
- [x] `lk://` parser rejects `?source=imported` with typed
  `InvalidReferenceUri::ImportedSource`; regression covers it.
- [x] vscode-agent-client: VS Code extension now has a typed local agent
  socket client covering framed RPCs, status calls, and status streams.
- [x] `get --reveal` requires a TTY unless `--force` is passed;
  noninteractive denials write a `REVEAL/DENIED` audit row and
  successful reveals echo `force=true` in metadata.
- [x] `locket exec --secret KEY` single-key injection records selected
  source metadata in `EXEC` audit rows and fails typed pre-spawn when
  the vault is locked.
- [x] Docker active-context detection refuses remote/TCP/SSH contexts
  unless `allow_remote_docker = true`; typed confirmation required;
  mismatch exits `ConfirmationFailed` (68).
- [x] `set`/`rotate`/`import` reject NUL and multiline secret values
  via `validate_secret_value_str` (`MetadataInvalid` 64).
- [x] Audit-tx atomicity: rollback regression tests lock in the in-tx
  invariant — no phantom row, no sequence gap on rollback.
- [x] `metadata_json` ≤64 KiB per-row cap enforced at write time;
  `AuditMetadataTooLarge` typed error (`MetadataInvalid` 64).
- [x] Negative-path decryption tests: 9 cases covering wrong key/nonce
  and changed AAD fields all exit `DecryptionFailed`.
- [x] `locket export --sealed` dangerous-profile confirmation gate;
  mismatch returns `ConfirmationFailed` (68) before any bundle is written.
- [x] `locket bundle verify` writes a `BUNDLE_VERIFY` audit row when
  the bundle's project matches the cwd; unknown-project stays metadata-only.
- [x] supply-chain-exception-ledger: Supply-chain exceptions now have a checked ledger
  and fail the gate when missing or expired.
- [x] env-inspect-layers: Environment inspection now reports resolved external layers
  and final metadata-only decisions. External file values stay out of command output.
- [x] mock-peer-credentials: Added spoofable peer-credential tests for agent socket
  validation.

## Full Spec Coverage TODO — Security/Recovery/Team

- [x] `recovery rotate` prints the scrollback warning after revealing
  the new code (matches `init` behavior).
- [x] Passphrase fallback beyond OS-key-store path.
- [x] Recovery command surfaces (`recover`, `recovery rotate`).
- [x] Recovery-code generation, one-time display, restore, and rotation.
- [x] Device command surfaces (`device init`, `pubkey`, `add`, `list`,
  `remove`); local private-key persistence/recovery tracked under device
  descriptors and sealed-bundle/team work.
- [x] Metadata privacy validation across secret/config/policy/template/
  team/member/device editors via the shared
  `crates/locket-core/src/metadata.rs` validator
  (`MetadataInvalid` 64, `MetadataLooksLikeSecret` 66).
- [x] Recovery-code Crockford Base32 encoding with two checksum chars
  (detect-only; never auto-correct).
- [x] Recovery envelope v1 binary container with magic, schema,
  `kdf_profile_id`, HKDF-derived entry keys, and AAD; KDF parameters
  fail closed on mismatch (`crates/locket-platform/src/recovery.rs`,
  `crates/locket-crypto/src/recovery_envelope.rs`).
- [x] Recovery `kdf.toml` ↔ envelope-header `lk_kdf_*` id match check
  rejects mismatched ids during recovery.
- [x] Sealed-bundle plaintext manifest minimization: no profile, secret,
  policy names; no member/device labels (only digest, recipients,
  project id, schema, `created_at`, profile count).
- [x] Audit-chain HMAC verification recomputes each row using the row's
  stored `schema_version`, not the binary's current version.
- [x] Core-dump suppression helper disables Unix `RLIMIT_CORE` and Linux
  dumpability before CLI secret-bearing work starts.
- [x] team-invite-create: Team invite creation now writes signed invite files and
  pending invite metadata.
- [x] bundle-age-encryption: Sealed bundle export now writes an encrypted bundle payload
  using age recipients. Verification handles the encrypted container structurally until
  local device private keys land.
- [x] passkey-rp-id-policy: Passkey credentials now persist and display their WebAuthn
  relying party metadata.

## Full Spec Coverage TODO — App/UI

- [x] `locket-app` workspace crate scaffolded under `crates/locket-app/`.
- [x] Tray icon state set (Lucide-based) reflects
  locked/unlocked/scan-warn/alert with platform-appropriate styling.
- [x] Tray notification policy: no secret values, no secret names by default
  (use generic "secret"/"policy"/"project" labels until the user opens the app).
  - Spec: `docs/specs/desktop.md:94-96`.
- [x] Accessibility baseline descriptors cover keyboard navigation, focus,
  labels, contrast, reduced motion, and post-TTL metadata scrubbing.
- [x] Secret version history descriptors cover current/deprecated/purged
  states, grace metadata, pinned eligibility, scan inclusion, and audit fields.
- [x] Empty-state guidance for `locket init`/`team accept`/
  `profile create dev`/`set`/`import`/`policy add`/`agent start`/
  `device init`.
- [x] Denial UX differentiates locked vault, missing grant, policy denial,
  dangerous-profile, revoked device, and expired invite with distinct copy and
  recovery affordances.
  - Spec: `docs/specs/desktop.md` UX Requirements.
  - Files: `crates/locket-app/ui/` error views.
- [x] Execution monitor descriptors backed by `runtime_sessions`, covering
  running/completed/failed/stale states and metadata-only field labels.
- [x] `locket deny --all` revokes directory grants across all profiles
  for the project; `DENY_DIRECTORY` audit metadata echoes the deny command.
- [x] Tauri 2 desktop shell scaffolded under `crates/locket-app/src-tauri/`
  (`locket-desktop` binary): empty IPC surface, deny-by-default capability set,
  release CSP byte-for-byte equal to `ReleaseWebviewPolicy::default()`, and
  devtools gated on `cfg(debug_assertions)`. Vue 3 + Vite + TypeScript frontend
  under `crates/locket-app/ui/` with `pnpm` build/lint/typecheck and Makefile
  targets `app-ui-{install,check,build}` (skip when `pnpm` is missing).
- [x] tauri-agent-client: desktop connects to the agent's Unix socket over
  the v1 framed JSON protocol. Typed `AgentClientError` distinguishes
  Unavailable/Protocol/Rejected; `useAgent` composable polls every 5 s and
  drives the lock/project/profile labels and an `AgentUnavailableBanner`.
- [x] tray-bind-platform: Tauri 2 tray icon registered with platform-specific
  assets (template image on macOS, light/dark variants on Windows/Linux).
  `update_tray_state` maps the 5 `TrayIconState` variants to baked-in PNG
  bytes and tooltip text; `useTray` composable derives state from
  `AgentStatus`/`AgentClientError` and pushes via `tray_set_state`.
- [x] Six primary desktop views scaffolded as standalone Vue 3 SFCs:
  `SecretMetadataList`, `SecretVersionHistory`, `ExecutionMonitor`,
  `AuditLog`, `ScanResults`, `Settings`. All metadata-only,
  privacy-mode-aware, keyboard-accessible, with empty-state copy from the
  desktop UX spec. `App.vue` mounts them under a 6-tab side navigation.
- [x] Agent RPC dispatch arms shipped as typed stubs for `Reveal`, `Copy`,
  `ScanKnownValues`, `ResolveReference`, and `PrepareExec`. Each returns
  the spec-correct denial envelope (UnlockRequired / GrantRequired) or an
  empty success payload, so the desktop UI exercises the full request /
  response path before the unlock-cache and grant-table back-ends land.
- [x] Frontend toolchain refresh via `ncu`: Vue 3.5.33, Vite 8, TypeScript
  6.0, ESLint 10, Prettier 3.8, `@tauri-apps/api` 2.10.
  `eslint-config-prettier` aligns the two; `pnpm-lock.yaml` is committed.
- [x] vscode-reference-completion: The VS Code extension now registers
  `lk://` reference completion for supported local file types.
- [x] desktop-project-dashboard-view: The desktop app now opens on a
  project dashboard with status, health, and navigation into detail views.
- [x] tauri-capabilities-per-view: Desktop Tauri commands now have explicit
  app-local capability coverage.
- [x] profile-grant-invalidation: Shell hook install now validates the active profile's
  durable grant before proceeding. Switching profiles requires a matching grant before
  the hook can recreate live access.
- [x] desktop-policy-editor-view: Adds the read-only policy editor surface to the
  desktop shell. Wires the Policies nav entry to metadata-only policy rows.
- [x] agent-list-runtime-sessions: Added the agent runtime-session list RPC for the
  desktop execution monitor.
- [x] search-projects-profiles: Added a dashboard search and filter surface for
  project/profile metadata.

## Full Spec Coverage TODO — Code Health and Bug Fixes

- [x] **blocker** — `import --overwrite` matched the literal string
  `"already exists"`; now uses the typed `SecretAlreadyExists` (67)
  across set/profile/policy/recovery callsites.
- [x] **blocker** — `locket recover` now appends a `RECOVER` audit row
  (metadata-only) after successful keychain write.
- [x] **blocker** — `locket new` now appends an `INIT` audit row.
- [x] **important** — `ConfigKeySpec`/`ConfigValueKind`/`CONFIG_KEY_SPECS`
  and validators/parsers moved out of `main.rs` into
  `commands/config/spec.rs`.
- [x] **important** — `SecretAlreadyExists` (67) added to `LocketError`
  (closed alongside the import-overwrite blocker).
- [x] **important** — `EnvMap` values now wrap in `Zeroizing` so
  decrypted secrets clear on drop.
- [x] **important** — `profile create` now appends a `PROFILE_CREATE`
  audit row.
- [x] **important** — `locket use` now appends a `PROFILE_CHANGE` audit
  row with prior/new profile metadata.
- [x] **important** — `*_audit_if_available` helpers no longer swallow
  audit-key load failures; missing keys hard-fail the command.
- [x] **important** — typed-error-sweep: Clipboard copy failures now use a
  typed external-source error and CLI config constructors are typed.
- [x] **nit** — Optional-value formatters unified on the `"-"` sentinel
  across history/diff/audit output.
- [x] **nit** — Audit-write helpers reuse the caller's store handle
  instead of re-opening.

## Full Spec Coverage TODO — Diagnostics, Distribution, and Quality Gates

- [x] `locket audit verify` spec coverage.
- [x] `locket doctor`.
- [x] `locket doctor` opportunistically prunes expired
  `automation_client_nonces` and reports the count; client-auth
  half tracked under Automation-client flows.
- [x] `locket doctor` reports `core_dumps` hardening status
  (`active`/`degraded`/`unsupported`).
- [x] Redacted `locket agent logs`.
- [x] `locket debug bundle --redacted`.
- [x] Required fuzz targets landed under `fuzz/fuzz_targets/` (cadence
  and sanitizer gates tracked under the fuzz tooling TODO below).
- [x] Markdown/spec link checks via `make docs-check`.
- [x] `agent logs` retention: JSON Lines, 1 MiB rotation, 5 files,
  default 200 lines, `--lines` cap 10000, RFC 3339 / Unix `--since`,
  `--follow` streaming; typed invalid-input errors and retention-boundary
  regressions landed in `agent-bec7ddfc/agent-logs-retention`.
- [x] Update-manifest fetch keyed only by channel/platform/arch/version
  (no project/device/host/user/install ids); release-key rotation
  requires a dual-signed manifest (`docs/specs/operations.md`).
- [x] Performance reference-runner spec, required report fields, and
  sampling rules (warmup, sample counts, p95 index, throughput formula)
- [x] make-test-targets: Testing Make targets are documented and guarded
  by docs-check so required coverage/test entrypoints stay exposed.
  (`docs/specs/performance.md`).
- [x] cargo-geiger-inventory: Unsafe inventory now produces a reviewable
  release artifact and is part of the strict quality gate.
- [x] rustsec-severity-policy: RustSec advisory checks now apply the project
  severity policy and write a review report.
- [x] Production-crate clippy denies (`unwrap_used`, `expect_used`,
  `panic`, `todo`, `unimplemented`, `dbg_macro`, `print_stdout`,
  `print_stderr`) plus workspace-wide `unsafe_code = "forbid"`.
- [x] Fuzz tooling and gates: `make fuzz-list`/`fuzz-smoke`/`fuzz`/
  `fuzz-nightly`; PR gate ≥60 s/target on touched fuzzed paths;
  nightly ≥15 min/target with ASan+UBSan; pre-public-release
  ≥8 cumulative CPU-hours/target since prior release; deterministic
  per-target resource limits and codified finding workflow
  (`docs/specs/fuzzing.md`).
- [x] `runtime.session_secret_name_retention`: doctor reports expired
  runtime-session name metadata and prunes only `secret_names` on request.
- [x] **subtask** — mock-user-verification: `MemoryLocalUserVerifier`
  covers allow, deny, platform-unsupported, and user-cancelled paths.
- [x] **subtask** — mock-docker-compose: Compose external env
  resolution has a process-stub harness that runs without Docker.
- [x] **subtask** — mock-clipboard: clipboard tests use a memory
  backend for copy success, matching-value clear, changed value, and
  unsupported clear.
- [x] **subtask** — mock-os-keychain: `MockMasterKeyStore` covers
  get/set/delete success and injected error paths in platform and CLI tests.
- [x] **subtask** — mutation-deny-by-default: policy tests reject
  permissive secret fields and do not infer allowed secrets from env settings.
- [x] **subtask** — mutation-audit-tamper: store tests mutate appended
  audit rows and chain links, then assert audit verification fails closed.
- [x] **subtask** — tests-typed-errors: per-variant exit-code regression
  for all `LocketError` variants.
- [x] **subtask** — mutation-locked-vault-scan: locked vault scan stays
  metadata-only; no leakage; `--require-known` exits `UnlockRequired`.
- [x] **subtask** — tests-env-merge: 9 env merge edge-case tests.
- [x] **subtask** — tests-policy-evaluation: 14 policy evaluation tests.
- [x] **subtask** — tests-scanner-rules: 12 scanner rule and finding metadata tests.
- [x] **subtask** — tests-audit-hmac: 2 schema_version HMAC regression tests.
- [x] **subtask** — tests-runtime-sessions: 5 session storage and recording tests.
- [x] **subtask** — e2e-greenfield-init: init → device_init → profile_create → set → get E2E.
- [x] **subtask** — e2e-dotenv-migration: import from .env with delete-confirmation E2E.

- [x] `locket allow` requires trusted root; regression test confirms
  untrusted root exits 71, no `ALLOW_DIRECTORY` row written.
- [x] `mlockall(MCL_CURRENT|MCL_FUTURE)` at CLI startup; `Degraded`
  on low `RLIMIT_MEMLOCK`, `Unsupported` on macOS/Windows.
- [x] Markdown lint integrated into `make docs-check`: trailing
  whitespace, tabs, empty files, missing newlines, unclosed fences.
- [x] `locket ai-safe --pattern-only` degraded locked-vault mode, `--output <file>` 0600 transcript with refuse-overwrite-without-`--force`, and partial-line buffer cap.
- [x] **subtask** — team-remove-member: `locket team remove` with `TEAM_REMOVE` audit and `TeamRoleDenied` typed error.
- [x] **subtask** — team-revoke-device: `locket team revoke-device` with `DEVICE_REVOKE` audit, `TeamRoleDenied`, idempotent for already-revoked.
- [x] Optional screen-clear after one-time recovery code display on `init` and `recovery rotate`; ANSI clear only when stdout is a TTY.
- [x] **subtask** — e2e-recovery-roundtrip: `init` → `recover` → `recovery rotate`; refusal-when-keychain-valid and `--force` path covered.
- [x] Caller-side summarization: `summarize_names` applied to exec/docker/run/redact audit sites to stay under 64 KiB cap.
- [x] Bytes-after-UTF-8 sweep: non-ASCII UTF-8 values pass byte-for-byte through exec, docker, run, redact, and scan paths.
- [x] **subtask** — tests-crypto-aad: AAD construction, key-wrap canonicalization, audit HMAC, recovery envelope, and device descriptor parsing.
- [x] **subtask** — tests-store-migrations: schema migration paths, `SCHEMA_MIGRATE` audit on every step, rollback on failure.
- [x] **subtask** — invite-codec: `SignedInvite` encode/decode/verify with ed25519 in `crates/locket-core/src/invite.rs`.
- [x] **subtask** — harden-zeroize: `Zeroizing` wrappers at all key/value owner sites; recovery envelope open return wrapped.
- [x] **subtask** — agent-socket-server: Unix domain socket daemon with 0600/0700 perms, tokio accept loop, Status/Heartbeat stubs, `AgentSocketInUse` on collision.
- [x] **subtask** — proptest-policy-toml: policy TOML parse → normalize → re-serialize round-trip; rejection of disallowed fields.
- [x] **subtask** — proptest-lk-uri: `lk://` parser round-trip, fragment/query rejection, pinned-version normalization.
- [x] **subtask** — proptest-canonical-json: canonical JSON encoder is total-ordered, idempotent, stable across permutations.
- [x] **subtask** — proptest-device-descriptor: descriptor codec round-trip; rejects malformed `lkdev1_` payloads.
- [x] **subtask** — bundle-container-format: versioned sealed-bundle container with 8-byte magic, u16 schema, u32 manifest length, u64 payload length; `BundleContainer` new/serialize/deserialize; manifest allow-list enforced; 10 tests.
- [x] **subtask** — invite-clock-skew: `SignedInvite::check_expiry` with `INVITE_CLOCK_SKEW_SECONDS = 300`; rejects past-window invites via `InviteExpiryError::Expired`; pure-core helper.
- [x] **subtask** — harden-socket-perms: refuse to bind agent socket when parent directory has group/other mode bits; re-verify freshly bound socket is 0o600; 3 tests.
- [x] **subtask** — tests-source-precedence: 12 tests covering get/set/list/rotate/rm/purge/history/exec source-resolution invariants in `source_precedence.rs`.
- [x] **subtask** — e2e-policy-run: golden-path and denial tests for `locket run`; covers policy create, `policy doctor`, required/optional secrets, `PolicyNotFound`, `InvalidPolicy`.
- [x] **subtask** — e2e-docker-compose: `prepare_docker_policy_execution` + `prepare_compose_policy_execution` E2E; names-only `RUN` audit; remote-`DOCKER_HOST` refusal.
- [x] **subtask** — mutation-dangerous-profile: gate `locket use <profile>` on typed confirmation when target is dangerous; `new_profile_dangerous` in `PROFILE_CHANGE` audit; 3 mutation tests.
- [x] Solo-developer authorization: no-Team projects allow all Owner-level operations; `team members` shows `team: none`; `team init` creates team; duplicate `team init` exits `SecretAlreadyExists` (67).
- [x] Member/device revocation rotation checklist: `team remove` and `team revoke-device` emit per-profile active-secret counts and total; honors `privacy.redact_names`.
- [x] **subtask** — mutation-malformed-crypto: tampered ciphertext body tests; `IntegrityFailure` on modified tag/nonce.
- [x] **subtask** — proptest-bundle-manifest: 10 property tests in `crates/locket-core/tests/proptest_bundle_manifest.rs`; round-trip, schema-version gate, oversized-manifest rejection, payload-length mismatch, corrupt-magic detection.
- [x] **subtask** — invite-replay-protect: `Store::mark_invite_accepted` with replay detection; `InviteReplayDetected` and `InviteNotFound` error variants; prevents double-accept of the same `SignedInvite`.
- [x] **subtask** — harden-peer-cred: Linux `SO_PEERCRED` uid check at agent accept time; `SocketServerError::PeerCredentialDenied { peer_uid, daemon_uid }` variant; rejects cross-user and root-to-user connections.
- [x] **subtask** — agent-peer-validation: `crates/locket-agent/src/peer_cred.rs` with `validate_peer_stream`, `validate_peer_uid`, `current_process_uid`; `ConnectionOutcome::Rejected` variant in `server.rs`; 5 unit tests covering matching/cross-user/root-to-user/round-trip cases.
- [x] **subtask** — mutation-expired-versions: gate pinned `lk://...@vN` secrets past `grace_until` on `SecretVersionExpired`; tests in `crates/locket-core/tests/mutation_expired_versions.rs`.
- [x] **subtask** — ephemeral-env-file: `locket-exec` ephemeral env-file helper; 0600/0700 permissions; RAII cleanup on drop; used by exec pipeline to pass secrets as temp file.
- [x] **subtask** — vscode-ext-scaffold: `extensions/vscode/` TypeScript skeleton with `package.json`, `tsconfig.json`, ESLint config; activation stub; no behavior yet.
- [x] **subtask** — policy-parser: typed `CommandPolicy` with structural validation in `crates/locket-core/src/policy/`; parse errors map to `InvalidPolicy` (65).
- [x] **subtask** — policy-deny-default: evaluator only ever resolves `required_secrets`/`optional_secrets`; everything else is implicitly denied.
- [x] **subtask** — policy-required-secrets: missing required secret returns `InvalidPolicy` (65).
- [x] **subtask** — policy-confirm: `confirm = true` enforced via `RuntimeContext::confirmation_reader` in `locket run`.
- [x] **subtask** — policy-user-verification: `require_user_verification` calls the user-verification gate before allowing the command.
- [x] **subtask** — policy-shell-vs-argv: parser distinguishes `argv = [...]` vs `shell = "..."`; evaluator dispatches on `CommandSpec`.
- [x] **subtask** — proptest-dotenv: `.env` parser round-trip and rejection invariants in `crates/locket-cli/src/tests/proptest_dotenv.rs`.

## Spec-by-Spec Completion Gates

- [x] `index.md`
