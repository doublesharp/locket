# Locket Completed Items

Slices that have merged to `main` and verified. Open work tracked in
`IMPLEMENTATION_PROGRESS.md`. `git log` is authoritative for who-did-what.

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

## Full Spec Coverage TODO — Runtime/DX

- [x] SQLite pragma posture: `foreign_keys = ON`, WAL mode, 5 s busy
  timeout; `locket doctor` runs `PRAGMA integrity_check`.
- [x] Status-stream heartbeats (`StatusEvent kind="heartbeat"`, ≥30 s,
  monotonic `sequence`, not treated as state change).
- [x] Process-bound grant binding via `(pid, process_start_time)` per
  platform; PIDs are never trusted alone.
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
- [x] `get --reveal` requires a TTY unless `--force` is passed;
  noninteractive denials write a `REVEAL/DENIED` audit row and
  successful reveals echo `force=true` in metadata.
- [x] `locket exec --secret KEY` single-key injection records selected
  source metadata in `EXEC` audit rows and fails typed pre-spawn when
  the vault is locked.

## Full Spec Coverage TODO — Security/Recovery/Team

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
- [x] Sealed-bundle plaintext manifest minimization: no profile, secret,
  policy names; no member/device labels (only digest, recipients,
  project id, schema, `created_at`, profile count).
- [x] Audit-chain HMAC verification recomputes each row using the row's
  stored `schema_version`, not the binary's current version.
- [x] Core-dump suppression helper disables Unix `RLIMIT_CORE` and Linux
  dumpability before CLI secret-bearing work starts.

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
- [x] **nit** — Optional-value formatters unified on the `"-"` sentinel
  across history/diff/audit output.
- [x] **nit** — Audit-write helpers reuse the caller's store handle
  instead of re-opening.

## Full Spec Coverage TODO — Diagnostics, Distribution, and Quality Gates

- [x] `locket audit verify` spec coverage.
- [x] `locket doctor`.
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
  (`docs/specs/performance.md`).
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

## Spec-by-Spec Completion Gates

- [x] `index.md`
