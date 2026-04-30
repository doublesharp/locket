# Locket Implementation Progress

This file tracks open implementation work and coordination state across agents.
History of merged slices lives in `git log`; do not duplicate it here.

## Current Goal

Close the remaining gaps between the local-first CLI/core baseline and full
`docs/specs/` coverage.

## Work Rules

Multiple agents work this list in parallel. Don't remove other agents'
claim files or claim lines. The progress doc on `main` is the shared
state — keep it current throughout your slice.

### Slice lifecycle

Every agent follows this exact ordered flow. Each step's edit to this
doc must reach `main` before the next agent reads the file.

1. **Claim an agent id** at session start (see "Claiming an agent id"
   below). Your id is the 8-char hex name of your file under
   `.agents/active/`.
2. **Pick an open `[ ]` item** on `main`. Skip `[x]`. A
   `[~] [<id>]` whose id has no live claim file (per the reaper) is
   free to reassign.
3. **Mark the claim on `main`.** Edit the line to
   `[~] [<your-agent-id>]` and append a one-line note (branch,
   worktree, scope). Land that edit on `main` before touching code,
   so other agents see your claim.
4. **Create the worktree and branch** (`agent-<id>/<topic>` under
   `.worktrees/agent-<id>-<topic>`; see Worktree and branch naming).
   Do all implementation there.
5. **Implement and verify.** Run `cargo fmt --all -- --check`,
   `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
   and the workspace tests (or scoped equivalents). Use
   `cargo -j 12` (12 cores). Add focused tests alongside the change.
6. **Merge to `main`.** Rebase onto current `main` and fast-forward.
   Never `--no-verify`, `--no-gpg-sign`, or `git push --force` on
   `main`. Never overwrite or revert another agent's committed work.
7. **Close out on `main`.** In one commit on `main`:
   - Flip the line to `[x]` and **compress the description to 1–2
     short lines** about what shipped. Drop spec/error/audit/file
     pointers and any claim note — those only belong on `[ ]`/`[~]`.
   - Remove the worktree and delete the branch:
     `git worktree remove .worktrees/agent-<id>-<topic>` then
     `git branch -D agent-<id>/<topic>`.
8. **Pick the next item** and repeat.

### Other rules

- Keep docs and implementation in sync when an implementation choice
  changes the spec.
- Commit coherent slices. Don't include this progress file in a
  feature commit — its updates land separately on `main`.
- Never log, print, or persist secret values in tests or diagnostics.
- Don't restate spec content here. A TODO line names the work, points
  at one spec section if non-obvious, and stops. No routine
  error/audit/file enumerations — agents can read the spec.

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

### Status legend

`[ ]` unclaimed · `[~] [<id>]` in progress (8-char hex id from your
live claim file) · `[x]` merged and verified.

### Worktree and branch naming

- Branch: `agent-<id>/<short-topic>`.
- Worktree: `.worktrees/agent-<id>-<short-topic>`.
- Create with
  `git worktree add ".worktrees/agent-${AGENT_ID}-<topic>" -b "agent-${AGENT_ID}/<topic>" main`.

### Scope and conflicts

- One slice per TODO item; don't bundle. Don't edit code another active
  claim owns; note the dependency on your claim line and pick something
  else.
- If two agents produce overlapping work, the more complete slice wins
  and the loser rebases or abandons.
- `git log` is authoritative for who-did-what — don't record it here.

## Active Plan

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
- [~] Scan ignore/suppression: inline markers, `SCAN`/`SUPPRESSED` audit
  rows, and per-rule severity (`ScanFindingBlocked` 69) shipped.
  Remaining: project-level severity overrides and `.env` policy table.
- [x] Secure interactive secret input for `set`/`rotate`.
- [~] Destructive confirmation flows: `purge`, dangerous-profile, and
  root untrust shipped. Remaining: policy deletion and other sensitive
  surfaces (`docs/specs/policy.md:26`).
- [~] Source-precedence and multi-source behavior across `set`, `get`,
  `list`, `rotate`, `rm`, `purge`, `history`, `diff`, `copy`,
  reveal/copy, and execution. Run audit records selected source by
  precedence and set tombstone preflight returns typed `SecretDeleted`;
  remaining commands still need the unified resolver
  (`docs/specs/data-model.md`, `docs/specs/runtime.md:188-216`).
- [x] Stable typed CLI error mapping and exit codes across all command families.
- [x] Secret-name (`^[A-Z_][A-Z0-9_]*$`) and profile-name
  (`^[a-z][a-z0-9_-]{0,63}$`) regex validation plus `_default` reserved
  name; reject at every editor before write.
- [~] [70c448c4] `locket init` atomic rollback and resumable-partial-state when
  Claim: branch agent-70c448c4/init-rollback-resume, worktree .worktrees/agent-70c448c4-init-rollback-resume, scope init rollback/resume failures.
  store/keychain/recovery-envelope creation fails mid-flight.
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
  - [x] **subtask** — run-shell-policy: `CommandSpec::Shell` now spawns
    `/bin/sh -c` on Unix and `cmd.exe /C` on Windows; audit records
    `command_type = "shell"`.
  - [x] **subtask** — run-confirm-gate: `confirm = true` policies now require
    a typed `run <policy-name>` confirmation; success records
    `confirmation_source` on the audit row. `RUN/DENIED` rows remain a
    follow-up under audit-coverage.
  - [x] **subtask** — run-user-verification-gate: `require_user_verification`
    policies route through the user verifier; success records
    `user_verification = { required, satisfied, method }` on `RUN_POLICY`.
  - [ ] **subtask** — run-ttl-grant: enforce policy-declared `ttl = "Xs"`
    grants with `(pid, process_start_time)` binding. Reuses the
    process-start-time helper landed in
    `agent-4efea70d/process-grant-binding`. Errors: `GrantRequired` (73).
    Audit: `RUN` records `grant_id`, `grant_ttl_seconds`.
  - [x] **subtask** — run-audit-metadata: `RUN_POLICY` audit row carries
    `policy_id`, `allowed_secret_names`, `required_secret_names`,
    `external_sources`, `confirmation_source`, and `child_exit`.
  - [ ] **subtask** — run-agent-backed: route `locket run` through the
    local agent's `ResolveReference`/grant RPCs once the daemon ships.
    Depends on the `Local agent daemon` item below. Surface
    `AgentUnavailable` (80) when the daemon is down and the policy declares
    `require_agent = true`.
- [x] `ExternalEnvSource::Parent` re-injects only policy-allowed
  parent names for `locket run`.
- [~] External env source resolution
  (`docs/specs/runtime.md:117-118`). `::Parent` and `::File` shipped.
  Remaining subtasks:
  - [ ] **subtask** — env-source-compose: shell out to
    `docker compose config --format json`, parse the env block, write a
    names-only `external_sources: ["compose"]` field on `RUN`/`EXEC`.
    Errors: `ExternalSourceUnavailable` (89) when compose isn't on
    PATH or returns non-zero.
  - [ ] **subtask** — env-source-ide: consume the VS Code terminal
    `LOCKET_IDE_ENV_SESSION` map over the agent socket; names-only
    audit on `RUN`/`EXEC`; never persist values. Depends on the
    agent-socket-server subtask under Local agent daemon.
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
- [ ] Resolve `lk://` references through the agent
  (`docs/specs/runtime.md:123-155`). Decomposed below; later subtasks
  depend on `lk-resolve-rpc`.
  - [ ] **subtask** — lk-resolve-rpc: agent `ResolveReference` handler
    parses `lk://`, looks up the secret, returns the value or a typed
    error. Pre-req: `agent-socket-server` and `agent-unlock-cache` from
    the Local agent daemon decomposition.
  - [ ] **subtask** — lk-resolve-policy-auth: gate the resolver by
    policy authorization (the resolving caller's policy must allow the
    target secret). Errors: `AccessDenied` (70). Depends on
    `lk-resolve-rpc`.
  - [ ] **subtask** — lk-resolve-pinned-version: honor pinned
    `lk://...@vN`; return `SecretVersionExpired` (75) past
    `grace_until`. Depends on `lk-resolve-rpc`.
  - [ ] **subtask** — lk-resolve-grace: deprecated-but-in-grace
    versions resolve with a metadata-only warning audit row; reject
    after grace. Depends on `lk-resolve-pinned-version`.
  - [ ] **subtask** — lk-resolve-audit: write `RESOLVE_REFERENCE` rows
    (reference id, profile id, version, grant id; never the value) on
    every successful and failed resolution. Depends on
    `lk-resolve-rpc`.
- [x] Wire Docker and Docker Compose into policy-backed CLI.
- [~] `locket exec --all` typed-confirmation flow and `EXEC` audit
  shipped. Remaining: `locket env inspect` enhancements and env-layering /
  override-mode docs.
- [ ] VS Code extension backed by the local agent
  (`docs/specs/integrations.md:39-65`). Extension never writes audit
  directly; everything goes through agent RPCs. Decomposed below;
  later subtasks depend on `vscode-ext-scaffold`.
  - [ ] **subtask** — vscode-ext-scaffold: `extensions/vscode/`
    (out-of-tree TS) project skeleton with build/lint/test scripts.
  - [ ] **subtask** — vscode-agent-client: TypeScript client that
    speaks the agent socket protocol; surface
    `AgentUnavailable`/`ProtocolError` distinctly. Pre-req:
    `vscode-ext-scaffold`, `agent-socket-server`.
  - [ ] **subtask** — vscode-status: status-bar element subscribed
    to `SubscribeStatus`. Pre-req: `vscode-agent-client`,
    `agent-subscribe-status`.
  - [ ] **subtask** — vscode-ide-env-session: terminal injection of
    `LOCKET_IDE_ENV_SESSION` and the agent-socket consumer side
    that resolves it. Pre-req: `vscode-agent-client`,
    `env-source-ide` subtask.
- [~] Automation-client flows. Public metadata storage, allowed
  action/policy fields, nonce primitives, and CLI metadata are in.
  Remaining: private-key storage and challenge-response authentication
  (`docs/specs/agent.md:62-79`).
- [ ] Policy TOML parsing/normalization (`docs/specs/policy.md`).
  Decomposed below; later subtasks depend on `policy-parser`.
  - [ ] **subtask** — policy-parser: parse `locket.toml`
    `[commands.<name>]` blocks into a typed `CommandPolicy` with
    structural validation. Errors: `InvalidPolicy` (65).
  - [ ] **subtask** — policy-deny-default: evaluator denies by
    default; only explicit allow/require entries pass. Pre-req:
    `policy-parser`.
  - [ ] **subtask** — policy-required-secrets: `required`/`optional`
    secret semantics — required missing → `InvalidPolicy`. Pre-req:
    `policy-parser`.
  - [ ] **subtask** — policy-confirm: `confirm = true` enforced via
    `RuntimeContext::confirmation_reader`. Pre-req: `policy-parser`.
  - [ ] **subtask** — policy-user-verification:
    `require_user_verification` calls the user-verification gate
    before allowing the command. Pre-req: `policy-parser` and
    user-verification gates infra.
  - [ ] **subtask** — policy-ttls: `ttl` translates to a grant TTL
    used by the agent grant table. Pre-req: `policy-parser`,
    `agent-grant-table`.
  - [ ] **subtask** — policy-shell-vs-argv: parser distinguishes
    `argv = [...]` vs `shell = "..."` and the evaluator picks the
    right spawn path. Pre-req: `policy-parser` and
    `run-shell-policy`.
- [x] Runtime session storage/retention primitives and runtime execution
  recording for `exec`/`run` (doctor process-liveness classification is a
  follow-up under doctor enhancements).
- [x] Env layering modes distinguish `merge`/`passthrough`; explicit
  `override` tracking drives doctor/run warnings and audit metadata.
- [x] Conservative env allowlist
  (`PATH HOME USER SHELL TMPDIR LANG LC_* TERM CI`) applied in `minimal`
  mode with `LC_*` matching; `policy doctor` surfaces it.
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
- [ ] Sealed bundle (`docs/specs/team-sync-recovery.md:111-224`).
  Decomposed below; later subtasks depend on `bundle-age-encryption`.
  - [ ] **subtask** — bundle-age-encryption: age-compatible recipient
    encryption for the bundle payload in
    `crates/locket-crypto/src/`. Tests: round-trip encrypt/decrypt
    against fixture recipients; tampering fails closed with
    `BundleAuthFailed`.
  - [ ] **subtask** — bundle-profile-keys: include profile key
    payloads in the encrypted manifest so `import-bundle` can write
    them on apply. Depends on `bundle-age-encryption`.
  - [ ] **subtask** — bundle-import-apply: decrypt and apply
    `import-bundle` state to the local store (insert profiles,
    secret_versions, blobs, fingerprints). Depends on
    `bundle-age-encryption`.
  - [ ] **subtask** — bundle-conflict-resolution: `--accept-incoming`
    / `--accept-local` for divergent versions during apply, with
    typed `BundleConflict` when neither flag is passed and versions
    differ. Depends on `bundle-import-apply`.
  - [ ] **subtask** — bundle-verify-decryptability: `bundle verify`
    runs a decryptability probe against a recipient and reports
    success/failure metadata-only (no plaintext logged).
  - [ ] **subtask** — bundle-audit-import: import remote audit chains
    into `imported_audit_chains` and surface chain status on
    `BACKUP_IMPORT`. Depends on `bundle-import-apply`.
- [~] Team command surfaces (`team init`, `invite`, `accept`,
  `revoke-invite`, `members`, `remove`, `revoke-device`). Decomposed
  below; later subtasks depend on `team-store-schema`
  (`docs/specs/team-sync-recovery.md:5-110`).
  - [x] **subtask** — team-store-schema: `teams`, `team_members`,
    `team_invites` tables and constraints are in place; no migration bump
    needed.
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
  - [~] [cb2437f7] **subtask** — team-members-list: implement `locket team members`
    metadata-only listing with privacy aliases. Errors: none for the
    listing itself. Depends on `team-store-schema`.
    Claim: branch agent-cb2437f7/team-members-list, worktree .worktrees/agent-cb2437f7-team-members-list, scope team members metadata listing.
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
- [ ] Invite issuer/recipient trust ceremony
  (`docs/specs/team-sync-recovery.md:56-69`). Subtasks below; later
  ones depend on `invite-codec`.
  - [ ] **subtask** — invite-codec: signed-invite struct (issuer pub
    keys, recipient fingerprint, expiry, nonce, role, profiles,
    project) plus encode/decode/verify in
    `crates/locket-core/src/invite.rs`.
  - [ ] **subtask** — invite-issue: `team invite` produces a signed
    invite using the device signing key; emit `TEAM_INVITE` audit.
    Pre-req: `invite-codec`, team-store-schema.
  - [ ] **subtask** — invite-accept-display: `team accept` displays
    issuer fingerprint + PGP safety words and requires typed
    confirmation before applying. Pre-req: `invite-codec`.
  - [ ] **subtask** — invite-replay-protect: track accepted invite
    ids; reject second use with `ReplayDetected` (113). Pre-req:
    `invite-codec`.
  - [ ] **subtask** — invite-clock-skew: 5-minute clock-skew tolerance
    on expiry; outside → `InviteExpired`. Pre-req: `invite-codec`.
  - [ ] **subtask** — invite-fail-closed: expired/revoked/
    fingerprint-mismatched/signature-invalid invites fail closed with
    typed errors and audit denial rows.
- [~] Audit coverage for denials: reveal/copy denial rows shipped
  (`status = DENIED`, `denial_reason`). Remaining sweep:
  dangerous-profile reads, locked-vault refusals (needs degraded-audit
  mechanism), role denials, grant denials.
- [~] Local user verification gates: `LocalUserVerifier` and
  `require_user_verification` shipped; `get --reveal/--copy --verify-user`
  enforces and writes typed denial rows. Remaining sweep: `unlock`,
  `recovery`, team/device, and dangerous-profile actions.
- [~] Privacy-mode rendering across status, context, redaction labels,
  and debug bundles via `privacy_alias`/`privacy_redact_names_enabled`;
  tray/desktop/editor renderers pending until those crates exist.
- [ ] Agent/process hardening (`docs/specs/agent.md`,
  `docs/specs/operations.md`). Subtasks are largely independent;
  `harden-peer-cred` and `harden-socket-perms` are pre-reqs for the
  agent daemon listening on real connections.
  - [ ] **subtask** — harden-peer-cred: peer credential validation
    (`SO_PEERCRED`/`LOCAL_PEERCRED`/named-pipe SID) on the agent
    socket. Pre-req: `agent-socket-server`.
  - [ ] **subtask** — harden-socket-perms: 0600/equivalent socket and
    pipe permissions; refuse to start if the bind path is wider.
  - [ ] **subtask** — harden-core-dumps: disable core dumps in the
    agent and CLI processes that hold key material (per-platform).
  - [ ] **subtask** — harden-memory-lock: `mlock`/equivalent for
    unwrapped key buffers; warn on unsupported platforms.
  - [ ] **subtask** — harden-zeroize: ensure unwrapped keys/values
    are wrapped in `Zeroizing`/equivalent at every owner; audit
    sites that haven't been migrated.
  - [ ] **subtask** — harden-session-lock: lock on system sleep,
    screen lock, and user-session switch; emit `LOCK` audit row.
  - [ ] **subtask** — harden-doctor-degraded: doctor reports each
    hardening feature's status (`active`/`degraded`/`unsupported`)
    so users can see fall-backs.
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
- [x] Audit-chain HMAC verification recomputes each row using the row's
  stored `schema_version`, not the binary's current version.
- [ ] Typed `metadata_json` shape validator per audit action family
  (required fields, no unknown fields without a schema bump).

### App/UI

- [x] `locket-app` workspace crate scaffolded under `crates/locket-app/`.
- [ ] Build the Tauri desktop app (`docs/specs/desktop.md:5-65`).
  Pre-req: `locket-app` workspace crate (already `[x]`).
  Decomposed below; later subtasks depend on `tauri-shell`.
  - [ ] **subtask** — tauri-shell: Tauri 2 main window + IPC plumbing
    in `crates/locket-app/src-tauri/`; opens, renders an empty UI,
    exits cleanly on every supported platform.
  - [ ] **subtask** — tauri-agent-client: connect the desktop app to
    the local agent over its socket; surface a typed
    `AgentUnavailable` banner when the daemon isn't running. Pre-req:
    `tauri-shell`; agent-side pre-req: `agent-socket-server`.
  - [ ] **subtask** — tauri-frontend-bootstrap: pick the JS framework
    (per spec), wire `pnpm` build/lint/typecheck, render the empty
    project shell. Pre-req: `tauri-shell`.
- [ ] Build the tray/status panel (`docs/specs/desktop.md:65-108`).
  Pre-req: `tauri-shell`.
  - [ ] **subtask** — tray-bind-platform: register the tray icon and
    menu on macOS, Windows, and Linux using the Tauri tray API.
  - [ ] **subtask** — tray-status-binding: subscribe to the agent's
    `SubscribeStatus` and update tray label/icon on lock-state and
    heartbeat events. Pre-req: `tray-bind-platform`,
    `agent-subscribe-status`.
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
- [ ] Tauri hardening (`docs/specs/desktop.md`). Independent subtasks
  — pre-req: `locket-app` Tauri shell exists.
  - [ ] **subtask** — tauri-csp: restrictive Content-Security-Policy
    on every renderer window; reject inline scripts/styles.
  - [ ] **subtask** — tauri-devtools-release: gate devtools open
    behind `cfg(debug_assertions)`; never expose in release builds.
  - [ ] **subtask** — tauri-command-scope: every Tauri command is
    explicitly scoped to the minimum capability set it needs.
  - [ ] **subtask** — tauri-capabilities-deny-default: deny-by-default
    `fs`/`shell`/`network`/`updater`/`clipboard` capabilities; opt
    each in only where the spec calls for it.
- [ ] Search/filter UI (`docs/specs/desktop.md`). Each subtask renders
  one surface and never exposes values; pre-req: the relevant view.
  - [ ] **subtask** — search-projects-profiles
  - [ ] **subtask** — search-secrets-metadata
  - [ ] **subtask** — search-policies
  - [ ] **subtask** — search-audit
  - [ ] **subtask** — search-scan-findings
  - [ ] **subtask** — search-devices-members
- [x] Accessibility baseline descriptors cover keyboard navigation, focus,
  labels, contrast, reduced motion, and post-TTL metadata scrubbing.
- [x] Empty-state guidance for `locket init`/`team accept`/
  `profile create dev`/`set`/`import`/`policy add`/`agent start`/
  `device init`.
- [x] Denial UX differentiates locked vault, missing grant, policy denial,
  dangerous-profile, revoked device, and expired invite with distinct copy and
  recovery affordances.
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
  - [x] **subtask** — typed-recovery-format: recovery file `format!`-ed
    Config errors migrated to `MetadataInvalid`.
  - [x] **subtask** — typed-policy-not-found @ 4671015:
    `PolicyNotFound` (exit 64) added and wired for command-policy misses in
    `main.rs` / `commands/policy.rs` plus automation-client revoke misses;
    docs/spec error tables and focused CLI/core regressions updated. Verified:
    fmt, clippy, workspace tests, and leak-canary pass.
  - [x] **subtask** — typed-project-not-found: `ProjectNotFound` exits 64
    for project resolution misses in `require_project` and `ai-safe`.
  - [x] **subtask** — typed-secret-overflow: migrate `secret version overflow`
    (3 sites) to a new `LocketError::SecretVersionOverflow` variant (input or
    integrity band, per spec). Regression covers a stubbed overflow path.
  - [x] **subtask** — typed-config-value-validation: config value validators
    now return typed `MetadataInvalid`/`MetadataLooksLikeSecret`; per-class
    regressions landed.
  - [x] **subtask** — typed-tty-confirmation: migrate the two `format!`-ed
    `{prompt} requires interactive confirmation` and `{reason} requires an
    interactive TTY` callsites to a new `LocketError::TtyRequired` variant
    (or reuse `ConfirmationFailed` if the spec treats them equivalently).
  - [x] **subtask** — typed-template-validation: onboarding template
    validators now return typed `MetadataInvalid`; focused CLI regressions
    landed.
  - [x] **subtask** — typed-residual-strings: residual
    `CliError::Config(...)` constructors under `crates/locket-cli/src` were
    mapped to typed helpers; the CLI source sweep returns zero matches.
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
- [~] Signed distribution packaging and update-check verification.
  Offline signed update-manifest verifier and typed
  `UpdateManifestInvalid` shipped. Remaining: package builders and
  signing workflows for Homebrew / signed macOS pkg / Windows MSI /
  Linux package / VS Code extension
  (`docs/specs/operations.md:27-53`).
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
- [ ] Cold-start budgets: passphrase fallback unlock <300 ms,
  recovery-envelope unlock <2 s, agent idle memory <50 MB
  (`docs/specs/performance.md`).
- [x] Production-crate clippy denies (`unwrap_used`, `expect_used`,
  `panic`, `todo`, `unimplemented`, `dbg_macro`, `print_stdout`,
  `print_stderr`) plus workspace-wide `unsafe_code = "forbid"`.
- [ ] Dependency hygiene gates: `cargo machete`/`udeps` in CI; OpenSSF
  Scorecard once public; keyless signing with transparency logs for CI
  artifacts; frontend `pnpm lint`/`typecheck`/`test`/`build` once
  `locket-app` exists.
- [ ] Property tests for `.env` parsing, policy TOML normalization,
  `lk://` parsing, canonical JSON, device descriptors, and bundle
  manifests.
- [ ] Cross-platform test mocks and mutation tests
  (`docs/specs/testing.md`). Subtasks are independent — pick any:
  - [ ] **subtask** — mock-os-keychain: trait-based mock for
    `crates/locket-platform/src/keychain/` covering get/set/delete
    success and error paths, used in CLI/store tests.
  - [~] [6e4d05db] **subtask** — mock-user-verification: extend the existing
    Claim: branch agent-6e4d05db/mock-user-verification, worktree .worktrees/agent-6e4d05db-mock-user-verification.
    `LocalUserVerifier` mock to cover platform-unsupported and
    user-cancelled paths in tests.
  - [ ] **subtask** — mock-peer-credentials: in-process socket harness
    that returns spoofable peer creds so the agent's peer-validation
    logic can be tested without root. Pre-req:
    `agent-peer-validation` subtask under Local agent daemon.
  - [ ] **subtask** — mock-clipboard: trait mock for the clipboard
    module covering copy success, post-TTL clear, and the
    cannot-clear platform path.
  - [ ] **subtask** — mock-docker-compose: process-stub harness that
    lets `docker compose config` tests run without Docker installed.
  - [ ] **subtask** — mutation-deny-by-default: policy-evaluator
    tests that explicitly inject permissive variants and assert
    deny-by-default still rejects.
  - [ ] **subtask** — mutation-malformed-crypto: tamper AAD/nonces
    and replay automation-client nonces; assert typed
    `IntegrityFailure`/`ReplayDetected` paths.
  - [ ] **subtask** — mutation-audit-tamper: append-then-modify rows
    in a fixture chain and assert `audit verify` flags
    `IntegrityFailure`.
  - [ ] **subtask** — mutation-locked-vault-scan: scan against a
    locked vault asserts the metadata-only path stays within the
    locked-safe envelope.
  - [ ] **subtask** — mutation-expired-versions: pinned `lk://...@vN`
    past `grace_until` returns typed `SecretVersionExpired`.
  - [ ] **subtask** — mutation-dangerous-profile: dangerous-profile
    reads emit the documented denial audit and refuse value access.
- [x] Fuzz tooling and gates: `make fuzz-list`/`fuzz-smoke`/`fuzz`/
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
