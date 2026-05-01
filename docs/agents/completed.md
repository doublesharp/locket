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
- [x] source-precedence-get: Added explicit source selection for get metadata and
  value-access paths.
- [x] source-precedence-purge: Added regression coverage for ambiguous purge source
  selection.
- [x] policy-delete-confirmation: Required typed policy-name confirmation before policy
  deletion.
- [x] source-precedence-rm: Made rm fail closed when source selection is ambiguous.
- [x] source-precedence-sweep: Centralized source precedence selection so lifecycle and
  runtime callers share the same choice.

## Full Spec Coverage TODO — Runtime/DX

- [x] SQLite pragma posture: `foreign_keys = ON`, WAL mode, 5 s busy
  timeout; `locket doctor` runs `PRAGMA integrity_check`.
- [x] Status-stream heartbeats (`StatusEvent kind="heartbeat"`, ≥30 s,
  monotonic `sequence`, not treated as state change).
- [x] agent-subscribe-status: status stream now emits lock-state change
  events alongside heartbeat cadence.
- [x] agent-start-socket-idempotency: `locket agent start` preserves an
  existing live socket owner instead of replacing it.
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
- [x] policy-doctor-agent-validation: Policy doctor now exits with a distinct incomplete
  status when agent-backed reference validation is unavailable.
- [x] leak-canary-cli-artifacts: Leak canary coverage now includes CLI outputs and
  generated project/debug artifacts.
- [x] mutation-critical-packages: The mutation smoke gate now covers the
  security-critical package set when cargo-mutants is available.
- [x] automation-nonce-auth-prune: Automation auth nonce recording now prunes expired
  replay rows atomically.
- [x] agent-grant-table: Agent grants are now stored and validated with caller process
  binding.
- [x] on-demand-agent-startup: `locket exec`/`run` start the local
  agent on demand before agent-backed execution paths.
- [x] pre-migration-backups: schema initialization now records
  pre-migration backup metadata for doctor reporting.
- [x] policy-index-refresh: policy authoring mutations refresh the
  SQLite command-policy index before returning.
- [x] policy-edit-command: editor-backed policy edits validate saved
  TOML before replacing the active policy row.
- [x] policy-ttls: Agent grant requests now use the saved policy TTL
  when a policy is named.
- [x] lk-resolve-rpc: `ResolveReference` parses `lk://` references,
  validates grants, and returns typed resolution errors.
- [x] lk-resolve-audit: Agent reference resolution now records
  metadata-only audit rows for success and failure.
- [x] automation-private-key-storage: Locket-managed automation client
  private keys are stored by metadata-only key references.
- [x] clipboard-ttl-clear: clipboard copies schedule TTL clearing and
  clear only when the clipboard still contains the same value.
- [x] lk-resolve-pinned-version: Pinned lk references now have focused resolver coverage
  for selection and no-fallback behavior.
- [x] e2e-agent-rpc: Agent RPC coverage now drives the socket through the core
  lifecycle. The test keeps the flow metadata-only and closes the subscription cleanly.
- [x] automation-client-auth: Automation clients can authenticate signed agent requests.
- [x] run-agent-backed: Run policies can opt into the agent-backed grant and
  reference-resolution path.
- [x] agent-resolve-reference-impl: Enforced the live grant profile scope during agent
  reference resolution.
- [x] bench-smoke-coverage: Benchmark smoke coverage now measures metadata status and
  staged scan paths. The policy summary gates all three sampled PR smoke surfaces.
- [x] e2e-team-invite-accept: Team invite e2e now covers invite creation, acceptance,
  and revoked-invite denial. The regression keeps command output and audit metadata
  value-free.
- [x] mutation-platform-mocks: Platform abstraction mocks now run under the mutation
  smoke default. The fallback gate exercises the platform package when cargo-mutants is
  unavailable.
- [x] perf-agent-idle-memory: Agent idle memory now has a release-profile RSS perf gate.
  The harness isolates HOME, warms status, samples RSS, and fails above budget.
- [x] proptest-update-manifest: Signed update manifests now have generated coverage for
  valid payloads and tamper rejection. The property harness checks metadata changes stay
  bound to the release signature.
- [x] run-ttl-grant: Policy runs now issue TTL-bound live grants for the spawned
  process. Run audit metadata records the grant TTL and process binding without values.

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
- [x] device-force-user-verification: Forced local device rekey now requires fresh user
  verification before it can proceed.
- [x] recovery-user-verification: Forced recovery override now requires fresh user
  verification before overwriting intact keychain state.
- [x] team-invite-revoke: Added local-first team invite revocation.
- [x] passkey-remove-user-verification: Required local verification before passkey
  removal.
- [x] invite-issue: Team invite creation now prints the issuing device fingerprint.
- [x] bundle-export-payload: Sealed bundle export now builds a real encrypted payload
  for selected profile data. Safe export and audit counts cover the serialized sections
  without exposing names or values.
- [x] team-role-authorization: team mutations now enforce owner/developer
  role constraints with typed denials.
- [x] imported-audit-chain-verifier: imported audit chains now validate
  monotonic sequence, prev-HMAC linkage, and checkpoint HMAC structure.
- [x] bundle-verify-cmd: bundle verification now fails typed on
  malformed bundles and unsupported schema versions.
- [x] team-invite-accept: invite acceptance verifies signature,
  fingerprint, expiry, replay state, and safety-word confirmation.
- [x] invite-fail-closed: team accept fails closed for invalid
  invites and records denial audit rows.
- [x] team-dangerous-user-verification: dangerous team/device actions
  now require fresh local user verification.
- [x] device-force-rekey-atomic: Forced local device rekey now records the replacement
  lifecycle in one transaction.
- [x] invite-accept-display: Team invite acceptance now fails closed with a recorded
  denial when issuer confirmation does not match.

## Full Spec Coverage TODO — App/UI

- [x] `locket-app` workspace crate scaffolded under `crates/locket-app/`.
- [x] Tray icon state set (Lucide-based) reflects
  locked/unlocked/scan-warn/alert with platform-appropriate styling.
- [x] Tray notification policy: no secret values, no secret names by default
  (use generic "secret"/"policy"/"project" labels until the user opens the app).
  - Spec: `docs/specs/desktop.md:94-96`.
- [x] desktop-tray-notifications: tray notification kinds now route
  through passive notifications without leaking names or values.
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
- [x] desktop-scan-data: Wires the desktop scan view to the typed agent scan command.
  Shows scan timestamp, locked state, and metadata-only scan errors.
- [x] search-secrets-metadata: Adds metadata-only search to the desktop secrets view.
  Filtering honors privacy aliases and never inspects secret values.
- [x] search-audit: Adds metadata-only search to the desktop audit log view. Filtering
  avoids raw metadata_json and respects privacy aliases.
- [x] vscode-diagnostics: The VS Code extension now plans and publishes metadata-only
  diagnostics for missing active-profile env references and pinned reference grace
  windows.
- [x] tauri-permission-guard: Release desktop hardening now has stricter CSP and
  permission regressions.
- [x] tray-icons-real: Tray icons are now generated as visible template and light/dark
  raster assets.
- [x] error-copy-table: Typed error display copy is now shared across shell, UI, and
  tray clients.
- [x] desktop-execution-data: Desktop execution monitor now loads metadata-only runtime
  sessions from the agent. The view refreshes state, aliases, stale rows, and safe
  audit/session fields.
- [x] agent-list-policies: The agent protocol now exposes a metadata-only ListPolicies
  RPC with privacy aliases. Saved policy rows can be filtered by project without
  returning secret values.
- [x] search-policies: Policy editor rows can now be filtered with a metadata-only
  search control. Privacy mode avoids matching raw secret-name fields while filtering.
- [x] search-scan-findings: Scan findings can now be filtered by metadata in the desktop
  view. The filter searches only existing redacted finding summaries and safe row
  fields.
- [x] agent-list-secrets: The agent protocol now returns metadata-only active-profile
  secret rows ordered by source precedence.
- [x] agent-list-versions: The agent protocol now returns metadata-only current,
  deprecated, and purged version rows with rotation metadata.
- [x] privacy-rendering-sweep: desktop status and labels now use privacy aliases
  instead of raw project/profile names when redaction is enabled.
- [x] tray-menu-actions: tray menu actions for open, lock, unlock,
  profile switching, policy run, and scan route through the agent.
- [x] agent-list-audit: the agent exposes filtered metadata-only audit
  rows with audit-chain status.
- [x] agent-verify-audit: the agent exposes structural audit HMAC
  verification results.
- [x] agent-config-read-write: settings RPCs cover privacy, unlock TTL,
  verification policy, and dangerous-profile configuration.
- [x] tray-status-binding: Tray status now follows the agent
  SubscribeStatus stream; unavailable streams leave the tray stopped.
- [x] desktop-backup-recovery-view: BackupRecovery view covers
  export, import, verify, and recovery-rotate surfaces.
- [x] search-devices-members: desktop device/member metadata can be
  filtered without exposing secret values.
- [x] vscode-reveal-webview: VS Code exposes a gated short-lived reveal
  webview for allowed references.
- [x] tray-template-policy: Added tray icon asset policy coverage for macOS template masks and full-color desktop variants.
- [x] desktop-secrets-data: The desktop secrets view now refreshes from the agent-backed metadata list.
- [x] agent-scan-known-values-impl: Agent known-value scans now run through the live
  cache and grant path. Responses stay redacted while covered scans record safe
  activity.
- [x] agent-set-secret: Agent SetSecret RPC creates and rotates webview-submitted values
  through grant and unlock gates.
- [x] cross-surface-error-parity: VS Code agent errors now show the shared typed reason
  and next action copy.

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
- [x] bench-fixtures: deterministic metadata, runtime, reference, scan,
  full-scan, and Argon2 fixture generator for performance runs.
- [x] performance-tolerance-gate: benchmark policy enforces PR/release
  hard budgets and tracked-regression tolerance reports.
- [x] perf-passphrase-unlock: passphrase unlock cold-path performance
  harness and `make` target.
- [x] perf-recovery-envelope-unlock: recovery-envelope unlock cold-path
  performance harness and `make` target.
- [x] make-test-targets: Testing Make targets are documented and guarded
  by docs-check so required coverage/test entrypoints stay exposed.
  (`docs/specs/performance.md`).
- [x] cargo-vet-gate: strict supply-chain checks now expose a cargo-vet
  target and docs-check requires the Make target.
- [x] dependency-hygiene-gates: local cargo-machete/cargo-udeps gate
  writes a review report and skips absent optional tools outside strict mode.
- [x] property-audit-hmac: property-test harness covers audit HMAC
  canonical byte invariants.
- [x] slsa-provenance-policy: offline SLSA provenance policy verifier
  validates artifact digest, builder, repository, build type, workflow,
  and optional signature/L3 requirements.
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
- [x] audit-metadata-validator: audit rows now validate metadata
  shapes per action family and reject unknown fields without a schema bump.
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
- [x] vscode-vsix-package: VS Code extension packaging now builds a VSIX
  artifact and release digest output.
- [x] **subtask** — lk-resolve-policy-auth: ResolveReference now
  checks the caller policy before returning values.
- [x] vscode-status: VS Code now shows a metadata-only Locket status
  bar driven by SubscribeStatus; the agent stream path has coverage.
- [x] recover-automation-client-keys: Recovery now restores managed
  automation-client key entries from the envelope.

## Spec-by-Spec Completion Gates

- [x] `index.md`
