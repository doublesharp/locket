# Locket Implementation Progress

This file tracks open implementation work and coordination state across agents.
History of merged slices lives in `git log`; do not duplicate it here.

## Current Goal

Close the remaining gaps between the local-first CLI/core baseline and full
`docs/specs/` coverage.

## Work Rules

There are multiple agents working so it is imperative that you maintain an agent ID file, and keep the shared task list up to date with claims. Do not remove other agent files or claims.

- Keep docs and implementation in sync when implementation choices change the spec.
- Commit coherent slices. Do not commit this progress file as part of a feature slice.
- Do not log, print, or persist secret values in tests or diagnostics.
- Prefer focused tests for each behavior before or alongside implementation.
- Use parallel agents when work is independent (see Multi-Agent Coordination below).
- This machine has 12 cores; use Cargo `-j 12` for compile/test/check/clippy where
  supported.
- Before marking any item here `[x]`, run `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and the
  workspace test suite (`cargo test --workspace --all-targets --all-features` or
  scoped equivalents for the touched crates).
- Don't repeat info that already lives in another spec doc or in the
  Reference Quick-Index. A TODO line should name the work, point at the
  spec section once if needed, and stop. Skip routine error/audit/file
  enumerations — agents can read the spec.

## Definition of Done

In addition to the verification commands above, every slice must:

1. **Spec match.** Implement each linked-spec bullet, or carry the gap
   as a `[ ]` follow-up.
2. **Typed errors.** Failures return a `LocketError` in the right
   exit-code band; new variants land in the central enum.
3. **Audit rows.** Spec-defined success/denial/failure events write
   through `crates/locket-store/src/audit.rs` in the same SQLite tx as
   the data change. Metadata is JSON and metadata-only.
4. **Convenience columns.** When `secret_name`/`command` are populated,
   echo them inside `metadata_json`. Never write `null` literals there.
5. **Locked-vault behavior.** Locked-safe commands succeed metadata-only
   when locked; key-requiring commands fail with `UnlockRequired`
   before any work.
6. **Privacy mode.** Output respects `privacy.redact_names` via the
   `*_label` helpers everywhere the spec permits aliases.
7. **Typed confirmations.** Destructive flows read the spec-formatted
   literal through `RuntimeContext::confirmation_reader`; `--force`
   only where the spec calls for it.
8. **Permissions.** New non-SQLite files are 0600 / equivalent ACL via
   `set_user_only_file_permissions`.
9. **Tests.** Cover golden path, locked-vault (when applicable), every
   typed error, and the audit-row shape.
10. **Leak canary.** `make leak-canary` clean; new artifact paths are
    reachable from the canary scanner.

## Multi-Agent Coordination

### Claiming an agent id

Each session generates an 8-char hex id used in claim files and
branch/worktree names. Registry: `<repo>/.agents/active/<id>.toml`,
resolved via the git common dir so all worktrees on this host share it.
Keep `/.agents/` out of commits.

Run once at session start (atomic write, retries on collision):

```sh
reg="$(cd "$(dirname "$(git rev-parse --git-common-dir)")" && pwd)/.agents/active"
mkdir -p "${reg}"
while :; do
    AGENT_ID="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
    f="${reg}/${AGENT_ID}.toml"
    # set -C makes `:` fail if the file already exists. With 4B ids this
    # almost never collides; the loop just covers the theoretical case.
    if (set -C; : > "${f}") 2>/dev/null; then
        printf 'id = "%s"\nclaimed_at = "%s"\npid = %s\nhostname = "%s"\nworktree = "%s"\n' \
            "${AGENT_ID}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$(hostname)" "$(pwd)" > "${f}"
        export AGENT_ID
        echo "Claimed agent id: ${AGENT_ID}"
        break
    fi
done
```

Release on clean exit:

```sh
reg="$(cd "$(dirname "$(git rev-parse --git-common-dir)")" && pwd)/.agents/active"
rm -f "${reg}/${AGENT_ID}.toml"
```

Reap stale claims (safe only for pids on this host):

```sh
reg="$(cd "$(dirname "$(git rev-parse --git-common-dir)")" && pwd)/.agents/active"
for f in "${reg}"/*.toml; do
    [ -e "${f}" ] || continue
    h="$(awk -F'"' '/^hostname/ {print $2}' "${f}")"
    p="$(awk -F' = ' '/^pid/ {print $2}' "${f}")"
    [ "${h}" = "$(hostname)" ] && [ -n "${p}" ] && ! kill -0 "${p}" 2>/dev/null && rm -f "${f}"
done
```

### Claiming work

Status legend: `[ ]` unclaimed · `[~] [<id>]` in progress (8-char agent
id from your claim file) · `[x]` merged and verified.

1. Pick an open `[ ]` item; never pick `[x]`.
2. Flip it to `[~] [<your-agent-id>]` and add a one-line note (branch,
   worktree, scope). The agent id MUST be the 8-char hex id of your live
   claim file under `.agents/active/`. Commit on your feature branch.
3. If a `[~]` line names an id with no live claim file (per the reaper),
   it's free to reassign — replace the id with yours.

### Worktree and branch naming

- Branch: `agent-<id>/<short-topic>`.
- Worktree: `.worktrees/agent-<id>-<short-topic>`.
- Create with
  `git worktree add ".worktrees/agent-${AGENT_ID}-<topic>" -b "agent-${AGENT_ID}/<topic>" main`.

### Scope discipline

- One slice per TODO item; don't bundle.
- Don't edit code another active claim owns. If you need it first, note
  the dependency on your claim line and pick something else.
- Never overwrite or revert another agent's committed work; if `main`
  conflicts with your expectations, stop and surface it.

### Audit-row discipline

Before merging, confirm: success path writes the documented action with
metadata-only fields; failure paths write the spec-required denial/failure
rows; no secret values or high-entropy strings in metadata;
`make leak-canary` passes.

### Conflict policy

- Prefer rebase over merge for worker branches.
- If two agents produce overlapping work, the more complete slice wins
  and the loser rebases or abandons.
- Never `--no-verify`, `--no-gpg-sign`, or `git push --force` on `main`.

### Communicating state

This file is the source of truth for open / claimed / done.
Don't record who-did-what — `git log` is authoritative.

## Active Plan

Items with a live claim file under `.agents/active/`. Move to `[x]` in the
relevant TODO section once merged, then remove from this list. Drop entries
whose claim is stale.

_(no active claims)_

## Full Spec Coverage TODO

Open items name the work and, if the location isn't obvious, point at one
spec section. Don't restate error variants, audit actions, or file paths
the spec already covers. Closed items are 1–2 lines about what shipped.

### Near-Term CLI/Core

- [x] `locket init` spec coverage.
- [x] `locket status` spec coverage.
- [x] `locket emit-example` spec coverage.
- [x] `locket completion <shell>`.
- [x] `locket bootstrap` command surface and checklist behavior.
- [x] `locket import` spec coverage.
- [x] `locket redact` spec coverage.
- [x] `locket context` spec coverage.
- [x] `locket ai-safe` spec coverage.
- [~] [539d8266] ready: agent-539d8266/lock-unlock-audit @ 5230342 — direct-CLI `LOCK`/`UNLOCK` audit rows landed; `unlock` records `method` (`OsKeychain` | `Passphrase`) and the locked-vault path stays metadata-only. Agent-backed RPC wiring and `ttl_seconds` remain a follow-up under the daemon slice (`docs/specs/agent.md:81-95`).
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
- [~] [723116e9] Scan ignore/suppression spec coverage. Inline suppression markers and a
  metadata-only `SCAN`/`SUPPRESSED` audit row are wired. Remaining: per-rule
  severity (`.env` warning vs. blocking, provider-token blocking) and the rest of
  the documented scan policies.
  Claim: branch agent-723116e9/scan-severity, worktree .worktrees/agent-723116e9-scan-severity. Scope: introduce per-rule severity (`warning`/`blocking`), wire `.env` patterns to warning and provider-tokens/known-values to blocking, map scan exit code by max severity, surface severity in `SCAN` audit metadata.
  - Spec: `docs/specs/scan-redaction.md`.
  - Errors: `ScanFinding` (66), `InvalidConfig` (64).
  - Audit actions: `SCAN` (already wired); add severity field to existing rows.
  - Files: `crates/locket-scan/src/rules.rs` (severity table),
    `crates/locket-cli/src/scan.rs` (exit-code mapping by max severity).
- [x] Secure interactive secret input for `set`/`rotate`.
- [~] Destructive confirmation flows: `purge`, dangerous-profile, and
  root untrust shipped. Remaining: policy deletion and other sensitive
  surfaces (`docs/specs/policy.md:26`).
- [~] [70c448c4] ready: agent-70c448c4/source-precedence @ f20dfcb — run audit records selected source by precedence; set tombstone preflight returns typed SecretDeleted.
  Claim: branch agent-70c448c4/source-precedence, worktree .worktrees/agent-70c448c4-source-precedence.
  `rotate`, `rm`, `purge`, `history`, `diff`, `copy`, reveal/copy, and execution.
  - Spec: `docs/specs/data-model.md` (`SecretSource` precedence ordering),
    `docs/specs/runtime.md:188-216` (rotation/history/diff/copy semantics).
  - Errors: `SecretSourceConflict` (71), `SecretNotFound` (74), `SecretDeleted` (75).
  - Audit actions: existing `SECRET_*` actions; add `source` field uniformly.
  - Files: shared resolver in `crates/locket-store/src/secret/queries.rs`,
    callers in `crates/locket-cli/src/secrets_cmd.rs`.
- [x] Stable typed CLI error mapping and exit codes across all command families.
- [x] Secret-name (`^[A-Z_][A-Z0-9_]*$`) and profile-name
  (`^[a-z][a-z0-9_-]{0,63}$`) regex validation plus `_default` reserved
  name; reject at every editor before write.
- [ ] `locket init` atomic rollback and resumable-partial-state when
  store/keychain/recovery-envelope creation fails mid-flight.
- [x] Dotenv import: name-level parity check (never run user app) and
  explicit post-import confirmation to delete `.env`.
- [x] `.env.example` Locket-managed block markers
  (`# --- BEGIN/END LOCKET MANAGED ---`); rewrite only between markers;
  tombstoned secrets excluded from the cross-profile union.
- [~] `example.auto_refresh` config key (default `true`, project-override-wins)
  is wired through the shared `refresh_example_for_project_if_enabled` gate at
  the `set`/`rotate`/`rm`/`purge`/`copy`/`import` command call sites with
  user-config and project-override regression coverage. `team accept` remains
  pending under the team-commands item.
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
- [x] Store/schema coverage for the full required-tables set
  (automation/teams/passkey/imported-audit tables + indexes/triggers,
  with `SCHEMA_MIGRATE` audit on migrations).

### Runtime/DX

- [ ] Local agent daemon (`docs/specs/agent.md`): socket/pipe server,
  peer validation, unlock cache, TTL grants, grant revocation, status
  streaming. Decomposed below; later subtasks depend on
  `agent-socket-server` — note the dependency on the claim line if you
  take a downstream task.
  - [ ] **subtask** — agent-socket-server: bind a per-user Unix domain
    socket on Linux/macOS (and a named pipe on Windows) with 0600/equivalent
    permissions, accept connections in a loop, decode the existing
    length-prefixed framing, dispatch to a stub RPC handler covering
    `Status` and `Heartbeat`. Errors: `AgentSocketInUse` (81). Tests: socket
    is created with the right permissions, a second daemon fails closed,
    framing round-trips. Pre-req for the other agent subtasks.
  - [ ] **subtask** — agent-peer-validation: validate the connecting peer
    against the daemon's uid (`SO_PEERCRED` on Linux, `LOCAL_PEERPID` +
    `LOCAL_PEEREPID` on macOS, named-pipe peer SID on Windows). Reject
    cross-user connections with `AccessDenied`. Tests: a non-matching uid
    is closed with the typed error. Depends on `agent-socket-server`.
  - [ ] **subtask** — agent-unlock-cache: in-memory unlock-key cache keyed
    by project_id with TTL eviction that fires `LOCK` audit on expiry. Add
    `Lock`/`Unlock`/`Status` RPC handlers. Errors: `UnlockRequired` (72).
    Audit: `LOCK`, `UNLOCK` with `method = OsKeychain | Passphrase |
    RecoveryEnvelope` and `ttl_seconds`. Tests: unlock-then-lock writes both
    audit rows; cache entry honors TTL. Depends on `agent-socket-server`.
  - [ ] **subtask** — agent-grant-table: SQLite-backed grant table from
    `docs/specs/agent.md` with `(pid, process_start_time)` binding (helper
    landed in `agent-4efea70d/process-grant-binding`).
    `RequestGrant`/`ExpireGrant`/`RevokeGrant` RPC handlers. Errors:
    `GrantRequired` (72). Audit: `AGENT_REVOKE`, `GRANT_EXPIRED` with
    `grant_id`. Tests: a pid-recycle case correctly invalidates a stale
    grant. Depends on `agent-socket-server`.
  - [ ] **subtask** — agent-subscribe-status: wire `SubscribeStatus` stream
    on top of the existing heartbeat envelope. Stream `lock_state` change
    events plus the documented heartbeat cadence. Errors: `ProtocolError`
    (82). Tests: client receives initial state, a state change, and at
    least one heartbeat within the documented window. Depends on
    `agent-socket-server` and `agent-unlock-cache`.
- [x] Status-stream heartbeats (`StatusEvent kind="heartbeat"`, ≥30 s,
  monotonic `sequence`, not treated as state change).
- [x] Process-bound grant binding via `(pid, process_start_time)` per
  platform; PIDs are never trusted alone.
- [ ] Replace metadata-only `agent start/status/stop/logs` with real
  agent process behavior and redacted log retention
  (`docs/specs/agent.md:99-110`).
- [~] `locket run` spec coverage. Argv policy execution exists. Remaining work
  is broken into subtasks below; pick any open one.
  - Spec: `docs/specs/runtime.md:5-122`, `docs/specs/policy.md`.
  - Files: `crates/locket-exec/src/`, `crates/locket-cli/src/commands/exec/run.rs`.
  - [ ] **subtask** — run-shell-policy: support shell-mode command policies
    (`shell = "..."` + `args = [...]`) alongside the existing argv form. Wire
    parser/normalizer in `crates/locket-core/src/policy/`, evaluator and
    spawn path in `commands/exec/run.rs`. Errors: `InvalidPolicy` (65). Audit:
    extend `RUN` metadata with `shape: "argv" | "shell"`. Tests cover argv
    success, shell success, mixed/invalid policy rejection.
  - [~] [723116e9] **subtask** — run-confirm-gate: implement `confirm = true` policy
    gate via `RuntimeContext::confirmation_reader` with the documented
    typed-string format. Audit: `RUN`/`DENIED` with
    `denial_reason: "confirmation_required"` on rejection; `RUN` with
    `confirmation_source` on success. Errors: `ConfirmationFailed` (68).
  - [ ] **subtask** — run-user-verification-gate: implement
    `require_user_verification = true` gate via
    `crates/locket-platform/src/user_verification.rs`. Audit: `RUN` records
    `user_verification = { required, satisfied, method }`. Errors:
    `UserVerificationFailed` (74).
  - [ ] **subtask** — run-ttl-grant: enforce policy-declared `ttl = "Xs"`
    grants with `(pid, process_start_time)` binding. Reuses the
    process-start-time helper landed in
    `agent-4efea70d/process-grant-binding`. Errors: `GrantRequired` (73).
    Audit: `RUN` records `grant_id`, `grant_ttl_seconds`.
  - [x] **subtask** — run-audit-metadata: `RUN_POLICY` audit row now
    carries `policy_id`, `allowed_secret_names`, `required_secret_names`,
    `external_sources`, `confirmation_source` (null pending confirm-gate),
    and `child_exit` from `ExitStatus::code()` in `711c1c4`. Tests assert
    `child_exit=0` on success and the documented exit code on failure.
  - [ ] **subtask** — run-agent-backed: route `locket run` through the
    local agent's `ResolveReference`/grant RPCs once the daemon ships.
    Depends on the `Local agent daemon` item below. Surface
    `AgentUnavailable` (80) when the daemon is down and the policy declares
    `require_agent = true`.
- [~] [70c448c4] ready: agent-70c448c4/external-env-parent @ 829b571 — `ExternalEnvSource::Parent` re-injects only policy-allowed parent names for `locket run`.
  Claim: branch agent-70c448c4/external-env-parent, worktree .worktrees/agent-70c448c4-external-env-parent.
- [ ] External env source resolution: `::File` (canonical, in-project,
  non-symlink-escape; `policy doctor` warns), `::Compose` (shell out to
  `docker compose config --format json`, names-only audit), `::Ide`
  (consume `LOCKET_IDE_ENV_SESSION` over the agent socket; names-only;
  no persistence) (`docs/specs/runtime.md:117-118`).
- [x] Shell prompt indicator renders lock state and respects privacy
  aliases (degrades to "stopped" when the agent is unreachable).
- [~] [70c448c4] blocked: policy surface changes require `crates/locket-cli/src/commands/policy.rs`, currently owned by active claim agent-6e4d05db/audit-key-failures.
  Claim: branch agent-70c448c4/policy-surface, worktree .worktrees/agent-70c448c4-policy-surface.
  Policy command surface: `policy add`, `policy allow`, `policy require`,
  `policy edit`, `policy delete`, `policy doctor`.
  - Spec: `docs/specs/policy.md:5-35`.
  - Errors: `InvalidPolicy` (65), `ConfirmationFailed` (66),
    `AgentUnavailable` (80) for `policy doctor` `lk://` validation.
  - Audit actions: `POLICY_UPDATE` (add/edit/delete; deletion includes affected
    hooks/tray actions/clients/tasks summary), `POLICY_DOCTOR`.
  - Files: `crates/locket-cli/src/policy_authoring.rs` (currently a stub),
    `crates/locket-core/src/policy/`.
- [x] Shell command surface (`shellenv`, `hook`, `allow`, `deny`)
  (agent-hook install and live-grant TTL tracked under the agent daemon).
- [ ] Resolve `lk://` references through the agent (policy
  authorization, pinned-version resolution, expired-grace behavior;
  `RESOLVE_REFERENCE` audit never carries the value)
  (`docs/specs/runtime.md:123-155`).
- [x] Wire Docker and Docker Compose into policy-backed CLI.
- [~] `locket exec --all` typed-confirmation flow and `EXEC` audit
  shipped. Remaining: `locket env inspect` enhancements and env-layering /
  override-mode docs.
- [ ] VS Code extension backed by the local agent
  (`docs/specs/integrations.md:39-65`); extension never writes audit
  directly.
- [~] Automation-client flows. Public metadata storage, allowed
  action/policy fields, nonce primitives, and CLI metadata are in.
  Remaining: private-key storage and challenge-response authentication
  (`docs/specs/agent.md:62-79`).
- [ ] Policy TOML parsing/normalization with deny-by-default
  evaluation, required/optional secret semantics, `confirm`,
  `require_user_verification`, TTLs, and shell-vs-argv handling
  (`docs/specs/policy.md`).
- [x] Runtime session storage/retention primitives and runtime execution
  recording for `exec`/`run` (doctor process-liveness classification is a
  follow-up under doctor enhancements).
- [ ] Env layering modes `merge`/`passthrough` distinct from
  `minimal`/`strict`, plus `override = "preserve"`/`"error"` with a
  warning when a policy chooses neither.
- [~] [70c448c4] Conservative env allowlist
  Claim: branch agent-70c448c4/conservative-env-allowlist, worktree .worktrees/agent-70c448c4-conservative-env-allowlist.
  (`PATH HOME USER SHELL TMPDIR LANG LC_* TERM CI`) applied in `minimal`
  mode and surfaced in `policy doctor`.
  - Spec: `docs/specs/runtime.md` Runtime Execution.
  - Files: `crates/locket-exec/src/env_layer.rs` (or equivalent).
- [ ] Ephemeral env-file fallback for children that can't accept an env
  map: 0700 parent / 0600 file outside project tree, post-spawn delete,
  audited delivery mode, secure-erase warning when unsupported.
- [ ] Clipboard clear-after-TTL only if clipboard still contains the
  value, with pre-copy warning where reliable clearing isn't possible
  (e.g. some Wayland compositors).
- [x] `locket diff --since` resolves git revisions via direct
  `git log -1 --format=%ct <rev>` (no shell construction).

### Security/Recovery/Team

- [x] Passphrase fallback beyond OS-key-store path.
- [x] Recovery command surfaces (`recover`, `recovery rotate`).
- [x] Recovery-code generation, one-time display, restore, and rotation.
- [x] Device command surfaces (`device init`, `pubkey`, `add`, `list`,
  `remove`); local private-key persistence/recovery tracked under device
  descriptors and sealed-bundle/team work.
- [ ] Sealed bundle: age-compatible encryption, profile key payloads,
  decrypted `import-bundle` state application, conflict resolution
  (`--accept-incoming`/`--accept-local`), decryptability checks in
  `bundle verify`, audit import
  (`docs/specs/team-sync-recovery.md:111-224`).
- [~] Team command surfaces and behavior: `team init`, `team invite`,
  `team accept`, `team revoke-invite`, `team members`, `team remove`,
  `team revoke-device`. An unclaimed prior worktree exists at
  `.worktrees/agent-c-team-metadata` on branch `agent-c/team-metadata`; an
  agent picking up any subtask may inspect or salvage that branch but should
  rebase onto current `main` (or rebuild from scratch) before integration.
  Decomposed into subtasks below; pick any open one (later subtasks depend
  on `team-store-schema`).
  - Spec: `docs/specs/team-sync-recovery.md:5-110`.
  - Errors: `KeychainEntryMissing` (100), `TeamRoleDenied` (113),
    `InviteExpired` (113), `InviteRevoked` (113), `InviteSignatureInvalid` (113),
    `InviteFingerprintMismatch` (113), `ReplayDetected` (113).
  - Audit actions: `TEAM_INIT`, `TEAM_INVITE` (creation + revocation),
    `TEAM_ACCEPT`, `TEAM_REMOVE`, `DEVICE_REVOKE`.
  - Files: `crates/locket-cli/src/` (new `commands/team/`),
    `crates/locket-store/src/teams.rs` (new module + tables `teams`,
    `team_members`, `team_invites`).
  - [x] **subtask** — team-store-schema: `teams`, `team_members`,
    `team_invites` tables already live in `crates/locket-store/src/schema.rs`
    with the spec-required column constraints (role check, profiles_json,
    nonce length, expires_at>created_at, accepted_at/revoked_at integrity).
    No migration bump needed for this slice.
  - [ ] **subtask** — team-init-command: implement `locket team init` with a
    `TEAM_INIT` audit row and golden-path coverage. Errors: `TeamRoleDenied`
    on a re-init attempt without role. Depends on `team-store-schema`.
  - [ ] **subtask** — team-invite-create: implement `locket team invite`
    issuance — signed invite file with issuer keys, recipient fingerprint,
    expiry, nonce, role, profiles. Audit `TEAM_INVITE` (creation). Errors:
    `TeamRoleDenied`. Depends on `team-store-schema` and the invite codec
    work tracked under `Invite issuer/recipient trust ceremony`.
  - [ ] **subtask** — team-invite-accept: implement `locket team accept`
    verifying signature, recipient fingerprint, expiry, replay protection,
    safety-word display. Audit `TEAM_ACCEPT`. Errors: `InviteExpired`,
    `InviteRevoked`, `InviteSignatureInvalid`, `InviteFingerprintMismatch`,
    `ReplayDetected`. Depends on `team-invite-create`.
  - [ ] **subtask** — team-invite-revoke: implement `locket team
    revoke-invite`. Audit `TEAM_INVITE` (revocation). Errors:
    `TeamRoleDenied`. Depends on `team-invite-create`.
  - [ ] **subtask** — team-members-list: implement `locket team members`
    metadata-only listing with privacy aliases. Errors: none for the
    listing itself. Depends on `team-store-schema`.
  - [ ] **subtask** — team-remove-member: implement `locket team remove`.
    Audit `TEAM_REMOVE`. Errors: `TeamRoleDenied`. Depends on
    `team-store-schema`.
  - [ ] **subtask** — team-revoke-device: implement `locket team
    revoke-device`. Audit `DEVICE_REVOKE`. Errors: `TeamRoleDenied`. Depends
    on `team-store-schema`.
- [ ] Role-based authorization for team-managed state
  (`docs/specs/team-sync-recovery.md:75-110`).
- [~] Passkey support. Metadata storage and `list`/`remove` CLI behavior exist.
  Remaining: platform registration and PRF optional key wrapping.
  - Spec: `docs/specs/crypto.md:192-218` (local user verification + passkey
    PRF wrapping).
  - Errors: `PasskeyUnsupported` (102), `UserVerificationFailed` (76).
  - Audit actions: `PASSKEY_ADD`, `PASSKEY_REMOVE`, `UNLOCK` with
    method = `Passkey`.
  - Files: new platform-specific module under `crates/locket-platform/src/`
    (WebAuthn / hmac-secret bindings), `crates/locket-cli/src/passkey.rs`.
- [~] [70c448c4] blocked: canonical PGP word-list safety words need a license-compatible in-repo source before implementing descriptor completion.
  Claim: branch agent-70c448c4/device-descriptor, worktree .worktrees/agent-70c448c4-device-descriptor.
  Device descriptors (`lkdev1_` base64url JSON: `v`, `device_id`, `label`,
  `signing_public_key_ed25519`, `sealing_public_key_x25519`, `fingerprint_sha256`,
  `safety_words`), v1 fingerprint hash, PGP-word-list safety-word derivation,
  and full local device-key lifecycle.
  - Spec: `docs/specs/team-sync-recovery.md:50-58`.
  - Errors: `DeviceDescriptorInvalid` (113), `KeychainEntryMissing` (100).
  - Audit actions: `DEVICE_INIT`, `DEVICE_REGISTER`, `DEVICE_REVOKE`.
  - Files: `crates/locket-platform/src/helpers.rs` (descriptor codec),
    `crates/locket-crypto/src/` (fingerprint hash + safety-words derivation).
- [ ] Invite issuer/recipient trust ceremony: signed invites with
  issuer/recipient/expiry/nonce/role/profiles/project; `team accept`
  displays issuer fingerprint + safety words for out-of-band
  confirmation; replay protection and 5-minute clock-skew tolerance;
  expired/revoked/mismatched invites fail closed
  (`docs/specs/team-sync-recovery.md:56-69`).
- [~] [bec7ddfc] ready: agent-bec7ddfc/audit-coverage-denials @ 1e2b5c7 — first
  reveal/copy denial slice landed (`get --reveal` now writes a `REVEAL` audit
  row with `status = DENIED` and `denial_reason = "noninteractive_terminal"`
  when stdout is not a TTY and `--force` is not passed; `command` echo added
  to `write_value_access_audit_if_available` per DoD #4). Remaining sweep:
  dangerous-profile reads, locked-vault refusals (need a degraded-audit
  mechanism since the audit key is locked too), role denials, grant denials.
  - Spec: `docs/specs/audit.md`, plus action references throughout other specs.
  - Errors: any new `LocketError` variants needed for denied paths; existing
    typed errors when behavior changes class.
  - Audit actions: see Reference Quick-Index for the canonical action set;
    backfill missing denial rows around dangerous-profile reads, locked-vault
    refusals, role denials, grant denials, and reveal/copy denials.
  - Files: `crates/locket-store/src/audit.rs` (helper writers); per-command
    call sites.
- [~] [bec7ddfc] ready: agent-bec7ddfc/user-verification-gates @ d21fced — first
  slice landed: `LocalUserVerifier` is on `RuntimeContext`, `require_user_verification`
  helper lives in `crates/locket-cli/src/runtime/user_verification.rs`, and
  `get --reveal/--copy --verify-user` calls it before decrypt/copy. Denials
  return typed `UserVerificationFailed` (exit 74) and write `REVEAL`/`COPY`
  rows with `status: DENIED, denial_reason: user_verification_failed,
  user_verification.required: true, satisfied: false`. Successful
  verifications echo `user_verification.method` in metadata. Item stays
  `[~]` for the broader sweep across `unlock`, `recovery`, team/device, and
  dangerous-profile actions.
  - Spec: `docs/specs/crypto.md:192-218`.
  - Errors: `UserVerificationFailed` (76), `PasskeyUnsupported` (102).
  - Audit actions: extend `UNLOCK`, `REVEAL`, `COPY`, `TEAM_*`, `RECOVER*`
    rows with `user_verification = { required, satisfied, method }`.
  - Files: `crates/locket-platform/src/user_verification.rs` (already mockable);
    add `require_user_verification(...)` helper used by every gated command.
- [~] [bec7ddfc] Privacy-mode rendering across status, context, redaction labels, debug
  Claim: branch agent-bec7ddfc/privacy-rendering, worktree .worktrees/agent-bec7ddfc-privacy-rendering.
  bundles, tray, UI, and editor surfaces. Redaction aliases exist only for
  known-value redaction.
  - Spec: `docs/specs/storage.md:179-182`, `docs/specs/desktop.md:37`.
  - Errors: none.
  - Audit actions: privacy mode itself does not write audit; ensure rows still
    contain exact names internally even when output uses aliases.
  - Files: extend the `*_label` helpers in `crates/locket-cli/src/main.rs` to
    cover redact label output, debug-bundle renderer in
    `crates/locket-cli/src/diagnostics.rs`, future tray/desktop renderers.
- [ ] Agent/process hardening: peer credential validation, narrow
  socket/pipe permissions, core-dump suppression, memory locking,
  zeroization, sleep/session-switch locking, degraded-hardening
  reporting via doctor.
- [x] Metadata privacy validation across secret/config/policy/template/
  team/member/device editors via the shared
  `crates/locket-core/src/metadata.rs` validator
  (`MetadataInvalid` 64, `MetadataLooksLikeSecret` 66).
- [ ] Member/device revocation produces a rotation checklist for every
  profile/secret the revoked principal could access.
- [x] Recovery-code Crockford Base32 encoding with two checksum chars
  (detect-only; never auto-correct).
- [x] Sealed-bundle plaintext manifest minimization: no profile, secret,
  policy names; no member/device labels (only digest, recipients,
  project id, schema, `created_at`, profile count).
- [ ] `imported_audit_chains` structural verifier (monotonic sequence,
  prev-HMAC linkage, checkpoint HMAC match) used by
  `import-bundle`/`team accept` and surfaced via `audit verify`.
- [ ] `import-bundle`/`team accept` apply rotate-with-no-grace lifecycle
  when importing a newer version over an active target.
- [ ] `locket device init --force` rekey: atomic
  `DEVICE_REVOKE`+`DEVICE_ADD` with recovery-envelope update and
  rollback on envelope failure.
- [ ] `locket recover` restores Locket-managed automation-client private
  keys from the envelope; `--force` rotates intact keychain entries and
  records the override in the `RECOVER` audit row.
- [~] [b67f47d6] ready: agent-b67f47d6/audit-schema-version @ f8acb31 — audit-chain verification is covered by a regression row signed with its stored `schema_version`.
- [ ] Typed `metadata_json` shape validator per audit action family
  (required fields, no unknown fields without a schema bump).

### App/UI

- [x] `locket-app` workspace crate scaffolded under `crates/locket-app/`.
- [ ] Build the Tauri desktop app (`docs/specs/desktop.md:5-65`).
- [ ] Build the tray/status panel (`docs/specs/desktop.md:65-108`).
- [ ] Reveal/copy UI gates with short-lived plaintext handling
  (`REVEAL`/`COPY` go through the agent).
- [ ] Status subscriptions from the agent (`SubscribeStatus`).
- [ ] Privacy-mode rendering in desktop, tray, and editor-facing UI.
- [ ] Audit, policy, profile, scan, and bootstrap views.
- [ ] Secret version history view (current/deprecated/purged with
  `deprecated_at`, `grace_until`, pinned-reference eligibility).
- [ ] Execution/session monitor view backed by `runtime_sessions`.
- [x] Tray icon state set (Lucide-based) reflects
  locked/unlocked/scan-warn/alert with platform-appropriate styling.
- [x] Tray notification policy: no secret values, no secret names by default
  (use generic "secret"/"policy"/"project" labels until the user opens the app).
  - Spec: `docs/specs/desktop.md:94-96`.
- [ ] Tauri hardening: restrictive CSP, release devtools off, scoped
  commands, deny-by-default capabilities (fs/shell/network/updater/
  clipboard).
- [ ] Search/filter UI across projects, profiles, secrets, policies,
  audit, scan findings, devices, members (never reveals values).
- [ ] Accessibility: keyboard nav, focus states, screen-reader labels,
  contrast, reduced motion, no post-TTL value leak via a11y metadata.
- [ ] Empty-state guidance for `locket init`/`team accept`/
  `profile create dev`/`set`/`import`/`policy add`/`agent start`/
  `device init`.
- [~] [4efea70d] Denial UX differentiates locked vault, missing grant, policy
  Claim: branch agent-4efea70d/denial-ux-descriptors, worktree .worktrees/agent-4efea70d-denial-ux-descriptors.
  Status: in progress; `crates/locket-app/src/lib.rs` has uncommitted denial
  descriptor changes in the worktree. Focused `cargo test -p locket-app`
  passed; full DoD gate and merge not run.
  denial, dangerous-profile, revoked device, and expired invite with
  distinct copy and recovery affordances.
  - Spec: `docs/specs/desktop.md` UX Requirements.
  - Files: `crates/locket-app/ui/` error views.

### Code Health and Bug Fixes

Bugs, missing audit rows, and structural debt outside spec coverage. Each
item is independently claimable; re-verify file:line references before
editing — they drift. Severity: **blocker** (security/correctness),
**important** (real defect), **nit** (cleanup).

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

- [~] **important** — Typed error system underused: ~6 typed callers vs ~249
  `CliError::Config`.
  Partial: `SecretNotFound` (77), `ProfileNotFound` (78), `ConfirmationFailed`
  (68), `InvalidSecretName` / `InvalidProfileName` (64) variants added across
  `e6e2447`, `52c14ce`, `49bb397`, `7a17462`. Highest-frequency callsites and
  ISO-date / config-key migrations are done. Remaining sweep is decomposed
  below; pick any open subtask:
  - [x] **subtask** — typed-recovery-format: 8 recovery `format!`-ed
    callsites in `commands/vault/recovery.rs` migrated to
    `metadata_invalid_error(...)` (exit 64) in `8013f25`. Regression covers
    a corrupted `recovery/kdf.toml` exiting 64.
  - [~] [bec7ddfc] ready: agent-bec7ddfc/typed-policy-not-found @ d3c4355 —
    `PolicyNotFound` (exit 64) added and wired for command-policy misses in
    `main.rs` / `commands/policy.rs` plus automation-client revoke misses;
    docs/spec error tables and focused CLI/core regressions updated. Verified:
    fmt, clippy, workspace tests, and leak-canary pass.
  - [~] [70c448c4] ready: agent-70c448c4/typed-project-not-found @ a2d9a1e — `ProjectNotFound` (exit 64) added and wired for project resolution misses in `require_project` and `ai-safe`; focused CLI/core regressions added. Verified after merge to `main`: fmt, clippy, workspace tests, and leak-canary pass.
    Claim: branch agent-70c448c4/typed-project-not-found, worktree .worktrees/agent-70c448c4-typed-project-not-found.
  - [x] **subtask** — typed-secret-overflow: migrate `secret version overflow`
    (3 sites) to a new `LocketError::SecretVersionOverflow` variant (input or
    integrity band, per spec). Regression covers a stubbed overflow path.
  - [~] [b67f47d6] ready: agent-b67f47d6/typed-config-values @ 5c4c3d4 — config value validators now return typed `MetadataInvalid`/`MetadataLooksLikeSecret`; per-class regressions landed.
    **subtask** — typed-config-value-validation: migrate the per-value
    config validators in `crates/locket-cli/src/commands/config/spec.rs`
    (`config value must be true or false`, `invalid config duration`,
    `config section is not a table`, `invalid stored config value for {key}`,
    `runtime.session_secret_name_retention must be a duration or off`,
    `updates.manifest_url must be an HTTPS URL` 3x, enum-message strings,
    `config value looks like a secret`) to typed `MetadataInvalid` or
    `MetadataLooksLikeSecret`. Regression per validator class.
  - [x] **subtask** — typed-tty-confirmation: migrate the two `format!`-ed
    `{prompt} requires interactive confirmation` and `{reason} requires an
    interactive TTY` callsites to a new `LocketError::TtyRequired` variant
    (or reuse `ConfirmationFailed` if the spec treats them equivalently).
  - [~] [b67f47d6] ready: agent-b67f47d6/typed-template-validation @ cd002be — onboarding template validators now return typed `MetadataInvalid`; focused CLI regressions landed.
    **subtask** — typed-template-validation: migrate the
    `commands/project/onboarding.rs` template validators (`template profile
    name is invalid`, `template expected secret name is invalid`, `invalid
    template command policy: {error}`, `{field} must be an array`) to typed
    `MetadataInvalid`. Regression on at least one rejected template.
  - [~] [b67f47d6] **subtask** — typed-residual-strings: sweep the residual long tail
    Claim: branch agent-b67f47d6/typed-residual-strings, worktree .worktrees/agent-b67f47d6-typed-residual-strings.
    in `crates/locket-cli/src/` (anything still as `CliError::Config(...)`
    after the above subtasks) and either map each to an existing typed
    variant or document the remainder as intentional generic-input failures.
  - Where: `crates/locket-cli/src/` (verify scope with `grep -rn
    "CliError::Config(" crates/locket-cli/src/ | wc -l`).
  - Where: `crates/locket-cli/src/` (verify with
    `grep -rn "typed_cli_error\|CliError::Typed " crates/locket-cli/src/`
    and `grep -rn "CliError::Config(" crates/locket-cli/src/`). A
    `unimplemented_in_build_error` helper now wraps
    `LocketError::PolicyValidationIncomplete` and is wired into
    `commands/exec/run.rs:51-64` (4 sites), `main.rs:1275-1288` (4 sites),
    and `commands/vault/lock.rs:28`. Many remaining `Config` callsites have
    an obvious typed kind (`secret not found`, `profile not found`,
    `confirmation did not match`, etc.) and currently collapse to exit 64
    (`InvalidReference`) instead of the spec-correct band. The failure-mode
    contract is leaking.
  - Fix: audit each `CliError::Config(...)` callsite, classify it, and map
    to a typed `LocketError` variant from `crates/locket-core/src/error.rs`.
    Add new variants only when no existing one fits, and update the
    Reference Quick-Index table at the bottom of this doc in the same
    commit.
  - Tests: per-variant exit-code regression covering at least one callsite
    per variant.

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

### Diagnostics, Distribution, and Quality Gates

- [x] `locket audit verify` spec coverage.
- [x] `locket doctor`.
- [x] Redacted `locket agent logs`.
- [x] `locket debug bundle --redacted`.
- [ ] Expand tests toward spec coverage (90% line/branch gate).
- [ ] End-to-end coverage for agent, policy/run, Docker/Compose,
  recovery, bundles, team invite accept, and UI/editor smoke flows.
- [x] Required fuzz targets landed under `fuzz/fuzz_targets/` (cadence
  and sanitizer gates tracked under the fuzz tooling TODO below).
- [~] Bench harnesses and performance gates. Local smoke/report
  scaffolding exists. Remaining: full spec fixtures, hard p95/throughput
  budgets, and `make bench`/`bench-ci`/`bench-report` PR vs release
  modes (`docs/specs/performance.md`).
- [~] Branch coverage and mutation gates (`make coverage-branch`,
  `make mutation`). Local fallbacks exist; line coverage still below 90%.
- [~] Supply-chain tooling. Offline-safe local commands and strict-mode
  hooks exist. Remaining: enforced `cargo deny`/`audit`, cargo-vet,
  unsafe inventory, SBOM, auditable builds, provenance, signing.
- [~] Leak canary harness. Scanner/redactor tests and `make leak-canary`
  exist. Remaining: broader CLI/agent/UI artifact scanning.
- [~] [b67f47d6] ready: agent-b67f47d6/update-manifest-verifier @ ed8dfde — offline signed update-manifest verifier and typed `UpdateManifestInvalid` landed; package builders/signing workflows remain.
  Signed distribution packaging and opt-in update-check verification
  (Homebrew, signed macOS package, signed Windows MSI, Linux package, signed
  VS Code extension).
  - Spec: `docs/specs/operations.md:27-53`.
  - Errors: `UpdateManifestInvalid` (89) for opt-in update verification.
  - Audit actions: none (release tooling is out-of-process).
  - Files: `scripts/release/`, signing config in `Cargo.toml` workspace
    metadata once tooling is chosen.
- [x] Markdown/spec link checks via `make docs-check`.
- [ ] `agent logs` retention: JSON Lines, 1 MiB rotation, 5 files,
  default 200 lines, `--lines` cap 10000, RFC 3339 / Unix `--since`,
  `--follow` streaming (`docs/specs/operations.md`).
- [ ] Update-manifest fetch keyed only by channel/platform/arch/version
  (no project/device/host/user/install ids); release-key rotation
  requires a dual-signed manifest (`docs/specs/operations.md`).
- [ ] Performance reference-runner spec, required report fields, and
  sampling rules (warmup, sample counts, p95 index, throughput formula)
  (`docs/specs/performance.md`).
- [ ] Cold-start budgets: passphrase fallback unlock <300 ms,
  recovery-envelope unlock <2 s, agent idle memory <50 MB
  (`docs/specs/performance.md`).
- [ ] Production-crate clippy denies (`unwrap_used`, `expect_used`,
  `panic`, `todo`, `unimplemented`, `dbg_macro`, `print_stdout`,
  `print_stderr`); security-critical crates additionally deny
  undocumented `unsafe` (`docs/specs/engineering.md`).
- [ ] Dependency hygiene gates: `cargo machete`/`udeps` in CI; OpenSSF
  Scorecard once public; keyless signing with transparency logs for CI
  artifacts; frontend `pnpm lint`/`typecheck`/`test`/`build` once
  `locket-app` exists.
- [ ] Property tests for `.env` parsing, policy TOML normalization,
  `lk://` parsing, canonical JSON, device descriptors, and bundle
  manifests.
- [ ] Cross-platform test mocks for OS keychain, user verification,
  peer credentials, memory locking, sockets/named pipes, clipboard
  clearing, and Docker/Compose; mutation/negative-path tests for
  deny-by-default policy, malformed AAD/nonces, replayed nonces, audit
  tampering, locked-vault scans, expired versions, and
  dangerous-profile.
- [~] [6e4d05db] Fuzz tooling and gates: `make fuzz-list`/`fuzz-smoke`/`fuzz`/
  Claim: branch agent-6e4d05db/fuzz-tooling-gates, worktree .worktrees/agent-6e4d05db-fuzz-tooling-gates.
  `fuzz-nightly`; PR gate ≥60 s/target on touched fuzzed paths;
  nightly ≥15 min/target with ASan+UBSan; pre-public-release
  ≥8 cumulative CPU-hours/target since prior release; deterministic
  per-target resource limits and codified finding workflow
  (`docs/specs/fuzzing.md`).

## Spec-by-Spec Completion Gates

Do this after all the other tasks are completed.

Final audit pass before claiming full spec coverage. Each item means the
implementation, tests, docs, diagnostics, and failure modes have been checked
against the named spec file.

- [x] `index.md`
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

- Exit-code bands: `docs/specs/errors.md`.
- Typed errors: `crates/locket-core/src/error.rs` (canonical enum with
  `exit_code()`).
- Audit actions and metadata shapes: `docs/specs/audit.md`,
  `docs/specs/data-model.md`.
- Required SQLite tables: `docs/specs/storage.md`.
- Crate ownership: `docs/specs/architecture.md`.

