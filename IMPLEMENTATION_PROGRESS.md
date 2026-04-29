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

## Definition of Done

A TODO item is finishable when, in addition to the verification commands above,
all of these hold. Use this as the standing checklist for every slice.

1. **Spec match.** Every behavior bullet in the linked spec section is implemented
   or explicitly out of scope with a remaining `[ ]` follow-up.
2. **Typed errors mapped.** All failure paths return a `LocketError` variant from
   `crates/locket-core/src/error.rs` whose exit code falls in the band documented
   in `docs/specs/errors.md` (see Reference Quick-Index below). New variants must
   be added to the central error enum, not bolted onto a CLI module.
3. **Audit rows.** Every spec-defined success, denial, and failure event writes a
   row through `crates/locket-store/src/audit.rs`. Action names match the
   canonical set in `docs/specs/data-model.md` and `docs/specs/audit.md` (see
   Reference Quick-Index below). Metadata is JSON, metadata-only, and matches the
   shape documented in `docs/specs/audit.md` (sequence, prev-HMAC, current HMAC,
   schema version on row). The append must run inside the same SQLite transaction
   as the data change.
4. **Convenience-column consistency.** When `AuditLog.secret_name` or
   `.command` are populated, the same string MUST appear inside `metadata_json`
   so the HMAC chain covers it. Never write `"secret_name": null` or
   `"command": null` literals.
5. **Locked-vault behavior.** Commands that the spec marks as locked-safe must
   succeed in metadata-only form when the vault is locked. Commands that require
   keys must fail with `UnlockRequired` (exit 70) before doing any work.
6. **Privacy-mode honored.** Output must respect `privacy.redact_names` for all
   project, profile, secret, policy, member, and device names where the spec
   permits aliases. See `docs/specs/storage.md:179-182` and the privacy renderer
   helpers in `crates/locket-cli/src/main.rs` (`status_*_label`, `context_*_label`).
7. **Typed confirmations.** Destructive flows accept a literal-string confirmation
   matching the documented format (e.g. `purge <profile>/<source>/<key>/<vN|all>`)
   read through `RuntimeContext::confirmation_reader`. Provide `--force` only
   where the spec calls for it.
8. **Permissions.** Any new file Locket writes outside SQLite is created
   user-only (mode 0600 on Unix, equivalent ACL on Windows) via
   `crates/locket-platform/src/helpers.rs::set_user_only_file_permissions` (or the
   directory variant) before any sensitive content is written.
9. **Tests.** Add focused tests under `crates/locket-cli/src/tests/` and the
   relevant store/core modules. Cover the golden path, the locked-vault path
   when applicable, every typed error, and the audit-row shape.
10. **Leak canary.** Run `make leak-canary`. Any new artifact path (logs, bundles,
    debug output, transcripts) must be reachable from the canary scanner.

## Multi-Agent Coordination

Multiple agents (A, B, C, ...) often run in parallel against this repository.
Follow these rules so work composes cleanly.

### Claiming an agent id

Each running agent generates a unique 8-character lowercase hex id at session
start. With ~4 billion possible ids the collision probability is negligible
even with hundreds of concurrent agents across hosts. The id is used in TODO
claims and in branch and worktree names (e.g. `agent-3f7a91c2/team-metadata`).

The registry lives at `<repo-root>/.agents/active/<id>.toml`, resolved through
the git common directory so all worktrees on this host share one registry. It
is **not tracked in git** — keep `/.agents/` out of commits (add it to your
`.gitignore` or global excludesfile).

Run this once at session start. The id is generated from `/dev/urandom` and
the registry write is atomic.

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

- Branch: `agent-<id>/<short-topic>` (e.g. `agent-3f7a91c2/team-metadata`).
- Worktree: `.worktrees/agent-<id>-<Mshort-topic>` for in-repo worktrees, or a
  sibling directory `../locket-agent-<id>-<short-topic>` if disk layout requires
  it. Either is fine; record the path on the claim line.
- Create with `git worktree add ".worktrees/agent-${AGENT_ID}-<topic>" -b "agent-${AGENT_ID}/<topic>" main`.

### Scope discipline

- Each slice covers ONE TODO item. Do not bundle unrelated changes.
- Do not edit code owned by another active claim. If you need a change from another
  agent's branch to land first, note the dependency on your claim line and pick a
  different item, or coordinate via the integration agent.
- Never overwrite or revert another agent's committed work to "fix" a merge. If
  root `main` has changes that conflict with what you expect, stop and surface the
  conflict; the owning agent resolves it.

### Audit-row discipline

Every spec-defined sensitive event MUST write an audit row. Before claiming a
slice complete, confirm:

- The success path writes the documented audit action with metadata-only fields.
- Failure paths write the matching denial/failure rows where the spec requires.
- No secret values, plaintext tokens, or high-entropy strings appear in audit
  metadata.
- The leak canary harness (`make leak-canary`) still passes.

### Conflict policy

- Prefer rebase over merge for worker branches. Merge commits are acceptable when
  integrating multiple worker branches into a single integration branch.
- If two agents independently produce overlapping work, the integration agent
  picks the more complete slice and credits the other in the commit message; the
  losing agent rebases or abandons.
- Do not use `--no-verify`, `--no-gpg-sign`, or `git push --force` on `main`.

### Communicating state through this file

- Use this file as the source of truth for what is open, claimed, in review, and
  done. Do not rely on chat history.
- Keep the Active Plan list short (only what is currently in motion). Once a slice
  is merged, flip its TODO line to `[x]` and drop the entry from Active Plan.
- Do not record who did what historically — `git log` is authoritative.

## Active Plan

Items currently in motion. An entry here means an agent has a live claim file
under `.agents/active/` and is working the slice. Move items to `[x]` in the
relevant TODO section once merged, then remove from this list. Drop entries
whose claim is stale.

_(no active claims)_

## Full Spec Coverage TODO

Each item describes the spec-complete behavior and lists, when open, the spec
pointer, the error variants and audit actions to use, and the primary file/crate
to touch. Items marked `[x]` are merged to `main` and verified.

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
- [ ] Replace metadata-only `locket lock` and `locket unlock` with spec-complete
  direct CLI and agent-backed behavior.
  - Spec: `docs/specs/agent.md:81-95` (`Lock`, `Unlock` RPCs); `docs/specs/runtime.md:5-50`.
  - Errors: `UnlockRequired` (70), `KeychainEntryMissing` (100), `RecoveryUnavailable` (101), `AgentUnavailable` (80).
  - Audit actions: `UNLOCK`, `LOCK`. Both must record method (`OsKeychain` |
    `Passphrase` | `RecoveryEnvelope`) and TTL where applicable.
  - Files: `crates/locket-cli/src/lock.rs` (currently metadata-only at lines
    15 and 38); add agent client wiring once daemon ships.
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
- [~] Destructive confirmation flows. `purge`, dangerous-profile, root untrust
  done. Remaining: policy deletion and other sensitive surfaces.
  - Spec: `docs/specs/policy.md:26` (`policy delete`); also any future
    UI/editor-driven sensitive flows.
  - Errors: `ConfirmationFailed` (66).
  - Audit actions: `POLICY_UPDATE` with deletion metadata.
  - Files: future `crates/locket-cli/src/policy_authoring.rs` deletion path.
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
- [ ] Secret-name (`^[A-Z_][A-Z0-9_]*$`) and profile-name
  (`^[a-z][a-z0-9_-]{0,63}$`) regex validation plus `_default` reserved
  name; reject at every editor before write.
  - Spec: `docs/specs/project-cli.md` CLI Contract.
  - Errors: `MetadataInvalid` (64).
  - Files: shared validator in `crates/locket-core/src/metadata.rs`.
- [ ] `locket init` atomic rollback and resumable-partial-state when
  store/keychain/recovery-envelope creation fails mid-flight.
  - Spec: `docs/specs/project-cli.md` CLI Contract.
  - Errors: `StorageError` (90), `KeychainEntryMissing` (100).
  - Files: `crates/locket-cli/src/commands/project/init.rs`.
- [ ] Dotenv import: name-level migration parity check (never run user
  app) and explicit post-import confirmation prompt to delete `.env`.
  - Spec: `docs/specs/project-cli.md` Onboarding Flows.
  - Errors: `ConfirmationFailed` (68).
  - Audit: `IMPORT` plus an explicit deletion audit when accepted.
  - Files: `crates/locket-cli/src/commands/secrets/import.rs`.
- [ ] `.env.example` Locket-managed block markers
  (`# --- BEGIN/END LOCKET MANAGED ---`) with rewrite-only-between-markers
  semantics; tombstoned secrets excluded from the cross-profile union.
  - Spec: `docs/specs/integrations.md` Git Integration & Pre-Commit.
  - Files: `crates/locket-cli/src/` example-emitter.
- [ ] `example.auto_refresh` config key (default `true`,
  project-override-wins) governing automatic `.env.example` refresh on
  set/rotate/rm/purge/import/copy/team accept.
  - Spec: `docs/specs/integrations.md` Git Integration & Pre-Commit;
    `docs/specs/storage.md` Config schema.
  - Files: `crates/locket-cli/src/commands/config/spec.rs`,
    example-emitter callers.
- [ ] Pre-commit hook block markers
  (`# --- BEGIN/END LOCKET PRE-COMMIT ---`), idempotent rewrite, typed
  confirmation when prepending to a non-Locket hook, and `HOOK_INSTALL`
  audit row when project context is available.
  - Spec: `docs/specs/integrations.md` Git Integration & Pre-Commit.
  - Errors: `ConfirmationFailed` (68).
  - Audit: `HOOK_INSTALL`.
  - Files: `crates/locket-cli/src/commands/project/install_hooks.rs`.
- [ ] `locket scan --no-gitignore` flag and `--require-known` pre-commit
  mode (fails with `UnlockRequired` when locked, `ProjectNotFound`
  outside any project).
  - Spec: `docs/specs/integrations.md`,
    `docs/specs/scan-redaction.md`.
  - Errors: `UnlockRequired` (72), `ProjectRootUntrusted` (71).
  - Files: `crates/locket-cli/src/commands/scan/scanner.rs`.
- [x] Store/schema coverage for the full required-tables set.
  - Spec: `docs/specs/storage.md:26-50` (required tables list),
    `docs/specs/storage.md:55-160` (column-level constraints).
  - Errors: `StorageError` (90), `SchemaMismatch` (91), `Concurrency` (92),
    `IntegrityFailure` (93).
  - Audit actions: `SCHEMA_MIGRATE` for migrations.
  - Files: `crates/locket-store/src/schema.rs` (migrations + column DDL),
    new modules under `crates/locket-store/src/` per missing table family.
  - Required tables not yet covered (verify each): `automation_clients`,
    `automation_client_private_key_refs`, `automation_client_nonces`, `teams`,
    `team_members`, `team_invites`, `command_policies` index/cache,
    `imported_audit_chains`, `passkey_credentials` PRF wrapping, plus indexes,
    triggers, and concurrency tests for all of the above.

### Runtime/DX

- [~] Local agent daemon: socket/pipe server, peer validation, unlock cache,
  TTL grants, grant revocation, status streaming. Decomposed into subtasks
  below; pick any open one (later subtasks depend on `agent-socket-server` —
  note the dependency on the claim line if you take a downstream task).
  - Spec: `docs/specs/agent.md` (whole file). RPC method list at `:81-96`.
  - Errors: `AgentUnavailable` (80), `AgentSocketInUse` (81),
    `ProtocolError` (82), `GrantRequired` (72).
  - Audit actions: `LOCK`, `UNLOCK`, `AGENT_REVOKE`, `GRANT_EXPIRED`,
    `CLIENT_ADD`, `CLIENT_REVOKE`.
  - Files: `crates/locket-agent/src/` (daemon, socket, IPC); CLI client wiring
    in `crates/locket-cli/src/commands/agent.rs`.
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
- [ ] Replace metadata-only `agent start/status/stop/logs` with real agent
  process behavior and redacted log retention.
  - Spec: `docs/specs/agent.md:99-110` (start/stop/status semantics),
    `docs/specs/operations.md` (logs).
  - Errors: `AgentSocketInUse` (81), `AgentUnavailable` (80).
  - Audit actions: `LOCK` on stop where keys were held; `AGENT_REVOKE` per
    revoked grant.
  - Files: `crates/locket-cli/src/agent.rs`, `crates/locket-agent/src/`.
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
  - [ ] **subtask** — run-confirm-gate: implement `confirm = true` policy
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
  - [ ] **subtask** — run-audit-metadata: extend the existing `RUN` audit row
    with the spec-required fields (`policy_id`, `allowed_secret_names`,
    `required_secret_names`, `confirmation_source`, `child_exit`,
    `external_sources`). No behavioural changes; pure metadata enrichment
    plus test coverage.
  - [ ] **subtask** — run-agent-backed: route `locket run` through the
    local agent's `ResolveReference`/grant RPCs once the daemon ships.
    Depends on the `Local agent daemon` item below. Surface
    `AgentUnavailable` (80) when the daemon is down and the policy declares
    `require_agent = true`.
- [~] [70c448c4] External env source resolution: `ExternalEnvSource::Parent` (re-inject
  Claim: branch agent-70c448c4/external-env-parent, worktree .worktrees/agent-70c448c4-external-env-parent. Scope: implement parent external env resolution first; leave File/Compose/Ide follow-ups explicit if still pending.
  only allowed names), `::File(path)` (canonical, in-project, non-symlink-escape;
  `policy doctor` warns), `::Compose` (shell out to `docker compose config
  --format json`, names-only audit), `::Ide` (consume VS Code terminal
  `LOCKET_IDE_ENV_SESSION` map over the agent socket, names-only audit, no
  persistence).
  - Spec: `docs/specs/runtime.md:117-118`.
  - Errors: `InvalidPolicy` (65), `ExternalSourceUnavailable` (89).
  - Audit actions: existing `RUN`/`EXEC` rows with `external_sources` name list.
  - Files: `crates/locket-core/src/policy/` (enum + validation),
    `crates/locket-exec/src/` (resolver), `crates/locket-cli/src/main.rs`
    (Compose subprocess invocation, IDE socket consumer).
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
- [ ] Resolve `lk://` references through the agent (policy authorization,
  pinned-version resolution, expired-grace behavior).
  - Spec: `docs/specs/runtime.md:123-155`.
  - Errors: `AccessDenied` (73), `SecretVersionExpired` (75),
    `SecretDeleted` (75), `GrantRequired` (72).
  - Audit actions: `RESOLVE_REFERENCE` with reference id, profile id, version,
    grant id; never includes the resolved value.
  - Files: agent `ResolveReference` RPC handler; CLI consumers via `lk://`
    resolver in `crates/locket-core/src/reference.rs`.
- [x] Wire Docker and Docker Compose into policy-backed CLI.
- [~] `locket exec --all` typed-confirmation flow and `EXEC` audit done.
  Remaining: `locket env inspect` enhancements and documented env layering /
  override-mode docs.
  - Spec: `docs/specs/runtime.md` env layering section; `docs/specs/project-cli.md`
    for `env inspect`.
  - Errors: `InvalidPolicy` (65).
  - Audit actions: metadata-only `ENV_INSPECT` (or extend existing summary path).
  - Files: `crates/locket-cli/src/main.rs` env-inspect handler.
- [ ] VS Code extension integration backed by the local agent.
  - Spec: `docs/specs/integrations.md:39-65`, `docs/specs/desktop.md` for
    privacy-aware UI behavior.
  - Errors: `AgentUnavailable` (80), `ProtocolError` (82).
  - Audit actions: same as agent-mediated commands; extension never writes
    audit directly.
  - Files: new `extensions/vscode/` (out-of-tree TS) or under `crates/locket-app/`
    once that crate exists; `LOCKET_IDE_ENV_SESSION` plumbing in shell.
- [~] Automation-client flows. Public metadata storage, allowed action/policy
  fields, nonce primitives, CLI metadata flows are in. Remaining: private-key
  storage and challenge-response authentication.
  - Spec: `docs/specs/agent.md:62-79` (canonical-request hashing),
    `docs/specs/data-model.md` automation-client section.
  - Errors: `ClientUnknown` (83), `ClientRevoked` (83), `ProtocolError` (82),
    `ReplayDetected` (83).
  - Audit actions: `CLIENT_ADD`, `CLIENT_REVOKE`,
    `CLIENT_AUTH` (success/failure).
  - Files: `crates/locket-store/src/automation_client*` (private key refs +
    nonces), agent challenge-response handler.
- [ ] Policy TOML parsing/normalization, deny-by-default evaluation,
  required/optional secret semantics, `confirm`, `require_user_verification`,
  TTLs, shell-vs-argv handling.
  - Spec: `docs/specs/policy.md`, `docs/specs/runtime.md:5-122`.
  - Errors: `InvalidPolicy` (65), `AccessDenied` (73),
    `UserVerificationFailed` (76).
  - Audit actions: `POLICY_UPDATE` on parse/normalize commit; runtime denials
    write `RUN`/`EXEC` failure rows with the deny reason.
  - Files: `crates/locket-core/src/policy/` (parser, normalizer, evaluator).
- [x] Runtime session storage/retention primitives and runtime execution
  recording for `exec`/`run` (doctor process-liveness classification is a
  follow-up under doctor enhancements).

### Security/Recovery/Team

- [x] Passphrase fallback beyond OS-key-store path.
- [x] Recovery command surfaces (`recover`, `recovery rotate`).
- [x] Recovery-code generation, one-time display, restore, and rotation.
- [x] Device command surfaces (`device init`, `pubkey`, `add`, `list`,
  `remove`); local private-key persistence/recovery tracked under device
  descriptors and sealed-bundle/team work.
- [~] Sealed bundle behavior. Metadata-safe command surfaces (`export --sealed`,
  `import-bundle`, `bundle verify`) and structural verification exist.
  Remaining: age-compatible encryption, profile key payloads, decrypted
  `import-bundle` state application, conflict resolution with
  `--accept-incoming` / `--accept-local` for divergent versions, decryptability
  checks in `bundle verify`, audit import.
  - Spec: `docs/specs/team-sync-recovery.md:111-224`.
  - Errors: `BundleInvalid` (110), `BundleConflict` (111), `BundleAuthFailed` (112).
  - Audit actions: `BACKUP_EXPORT` (selected profile ids, recipient
    fingerprints, bundle digest, output path kind, `include_audit`, counts;
    never the full output path), `BACKUP_IMPORT`, `TEAM_ACCEPT` for invite-flow
    imports.
  - Files: `crates/locket-cli/src/bundle.rs`, new sealing module under
    `crates/locket-crypto/src/` (age-compatible recipients).
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
  - [ ] **subtask** — team-store-schema: define and migrate the `teams`,
    `team_members`, `team_invites` tables with the column constraints from
    `docs/specs/storage.md:26-50`. Add a `SCHEMA_MIGRATE` audit row for the
    bump. Pre-req for the rest of the team subtasks.
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
- [ ] Role-based authorization for team-managed state.
  - Spec: `docs/specs/team-sync-recovery.md:75-110` (role table).
  - Errors: `TeamRoleDenied` (113).
  - Audit actions: extend existing `TEAM_*`/`POLICY_UPDATE`/`SECRET_*` rows
    with denying role evaluator id.
  - Files: shared role-check helper in `crates/locket-core/src/team/role.rs`
    (new); call from every team-managed action.
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
- [ ] Invite issuer/recipient trust ceremony: signed invite files containing
  issuer public keys, recipient fingerprint, expiry, nonce, role, profiles,
  project id; `team accept` displays issuer fingerprint + safety words for
  out-of-band confirmation; replay protection via accepted-invite ids and
  5-minute clock-skew tolerance; expired/revoked/mismatched invites fail closed.
  - Spec: `docs/specs/team-sync-recovery.md:56-69`.
  - Errors: `InviteExpired` (113), `InviteRevoked` (113),
    `InviteSignatureInvalid` (113), `InviteFingerprintMismatch` (113),
    `ReplayDetected` (113).
  - Audit actions: `TEAM_INVITE`, `TEAM_ACCEPT`.
  - Files: shared invite codec in new `crates/locket-core/src/invite.rs`;
    consumer in `crates/locket-cli/src/team.rs`.
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
- [~] [bec7ddfc] Local user verification gates for unlock, dangerous actions, recovery,
  team/device trust, and reveal/copy.
  Claim: branch agent-bec7ddfc/user-verification-gates, worktree .worktrees/agent-bec7ddfc-user-verification-gates. Scope: introduce the shared verification helper and wire the `get --reveal/--copy --verify-user` gate with typed failure/audit metadata.
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
- [ ] Agent/process hardening: peer credential validation, narrow socket/pipe
  permissions, core-dump suppression, memory locking where available,
  zeroization, sleep/session-switch locking, degraded-hardening reporting.
  - Spec: `docs/specs/agent.md` hardening bullets; `docs/specs/operations.md`.
  - Errors: `HardeningDegraded` (89) reported via doctor, not as an unlock
    failure.
  - Audit actions: `LOCK` on session-switch-triggered lock; doctor output
    includes degraded flags.
  - Files: `crates/locket-platform/src/` (per-OS hardening modules),
    `crates/locket-agent/src/`.
- [x] Metadata privacy validation for secret metadata, config, policies,
  templates, team/member/device labels, and UI edits.
  - Spec: `docs/specs/data-model.md` (metadata validation rules);
    `docs/specs/audit.md:40+` (no plaintext secrets in metadata).
  - Errors: `MetadataInvalid` (64), `MetadataLooksLikeSecret` (66).
  - Audit actions: validation-failure rows where the spec already requires
    them (e.g. `META` failure path).
  - Files: shared validator in `crates/locket-core/src/metadata.rs` (used by
    every editor of metadata).

### App/UI

- [x] Add the `locket-app` workspace crate/application.
  - Spec: `docs/specs/architecture.md`, `docs/specs/desktop.md`.
  - Files: `crates/locket-app/` (new), workspace `Cargo.toml`.
- [ ] Build the Tauri desktop app.
  - Spec: `docs/specs/desktop.md:5-65`.
  - Files: `crates/locket-app/src-tauri/`, `crates/locket-app/ui/`.
- [ ] Build the tray/status panel.
  - Spec: `docs/specs/desktop.md:65-108`.
- [ ] Reveal/copy UI gates with short-lived plaintext handling.
  - Spec: `docs/specs/runtime.md:156-187`, `docs/specs/desktop.md`.
  - Audit actions: `REVEAL`, `COPY` (already defined; UI must call through agent).
- [ ] Status subscriptions from the agent.
  - Spec: `docs/specs/agent.md:65, 95` (`SubscribeStatus`).
- [ ] Privacy-mode rendering in desktop, tray, and editor-facing UI.
  - Spec: `docs/specs/desktop.md:37, 94-96`.
- [ ] Audit, policy, profile, scan, and bootstrap views per spec.
  - Spec: `docs/specs/desktop.md:5-38`.
- [ ] Secret version history view (current/deprecated/purged with
  `deprecated_at`, `grace_until`, pinned-reference eligibility).
  - Spec: `docs/specs/desktop.md:15`.
- [ ] Execution/session monitor view.
  - Spec: `docs/specs/desktop.md:17`; data source is the existing
    `runtime_sessions` table.
- [x] Tray icon state set (Lucide-based; reflects locked/unlocked/scan-warn/
  alert states; macOS template image, Windows/Linux full-color light/dark).
  - Spec: `docs/specs/desktop.md:98-108`.
- [ ] Tray notification policy: no secret values, no secret names by default
  (use generic "secret"/"policy"/"project" labels until the user opens the app).
  - Spec: `docs/specs/desktop.md:94-96`.

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
  - [~] [723116e9] **subtask** — typed-recovery-format: migrate the 5 recovery file
    Claim: branch agent-723116e9/typed-recovery-format, worktree .worktrees/agent-723116e9-typed-recovery-format.
    `format!`-ed errors in `crates/locket-cli/src/commands/vault/recovery.rs`
    (`recovery/kdf.toml: {error}` 2x, `recovery/envelope.bin: {error}` 2x,
    `recovery kdf salt: {error}` 2x, `save recovery kdf: {error}`,
    `save recovery envelope: {error}`) to a typed `MetadataInvalid` or new
    `RecoveryEnvelopeInvalid` variant. Add a regression test that a corrupted
    `recovery/envelope.bin` exits in the documented band.
  - [ ] **subtask** — typed-policy-not-found: migrate `command policy not
    found: {name}` (3 sites in `main.rs`/`commands/policy.rs`) and
    `automation client not found: {client_ref}` (1 site) to a new
    `LocketError::PolicyNotFound` typed variant (band 64-69). Update the
    Reference Quick-Index. Add per-site exit-code regression.
  - [ ] **subtask** — typed-project-not-found: migrate `project not found`
    (2 sites: `main.rs`, `commands/scan/redact.rs`) to a new
    `LocketError::ProjectNotFound` typed variant (input band) — semantically
    distinct from `ProjectRootUntrusted`. Regression covers both callers.
  - [ ] **subtask** — typed-secret-overflow: migrate `secret version overflow`
    (3 sites) to a new `LocketError::SecretVersionOverflow` variant (input or
    integrity band, per spec). Regression covers a stubbed overflow path.
  - [ ] **subtask** — typed-config-value-validation: migrate the per-value
    config validators in `crates/locket-cli/src/commands/config/spec.rs`
    (`config value must be true or false`, `invalid config duration`,
    `config section is not a table`, `invalid stored config value for {key}`,
    `runtime.session_secret_name_retention must be a duration or off`,
    `updates.manifest_url must be an HTTPS URL` 3x, enum-message strings,
    `config value looks like a secret`) to typed `MetadataInvalid` or
    `MetadataLooksLikeSecret`. Regression per validator class.
  - [~] [4efea70d] **subtask** — typed-tty-confirmation: migrate the two `format!`-ed
    Claim: branch agent-4efea70d/typed-tty-confirmation, worktree .worktrees/agent-4efea70d-typed-tty-confirmation.
    `{prompt} requires interactive confirmation` and `{reason} requires an
    interactive TTY` callsites to a new `LocketError::TtyRequired` variant
    (or reuse `ConfirmationFailed` if the spec treats them equivalently).
  - [~] [b67f47d6] **subtask** — typed-template-validation: migrate the
    Claim: branch agent-b67f47d6/typed-template-validation, worktree .worktrees/agent-b67f47d6-typed-template-validation. Scope: map onboarding template validators to typed metadata errors and add focused CLI regressions.
    `commands/project/onboarding.rs` template validators (`template profile
    name is invalid`, `template expected secret name is invalid`, `invalid
    template command policy: {error}`, `{field} must be an array`) to typed
    `MetadataInvalid`. Regression on at least one rejected template.
  - [ ] **subtask** — typed-residual-strings: sweep the residual long tail
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
- [ ] Expand tests from current core/CLI coverage toward spec coverage targets.
  - Spec: `docs/specs/testing.md`.
  - Files: per-crate `tests/` modules; current line coverage gate at 90%.
- [ ] Integration and end-to-end coverage for agent, policy/run, Docker/Compose,
  recovery, bundles, team invite accept, and UI/editor smoke flows.
  - Spec: `docs/specs/testing.md`.
  - Files: new `tests/e2e/` workspace under each integration owner crate.
- [~] [6e4d05db] Full fuzz coverage for required parsers/protocols.
  Claim: branch agent-6e4d05db/fuzz-required-targets, worktree .worktrees/agent-6e4d05db-fuzz-required-targets.
  - Spec: `docs/specs/fuzzing.md`.
  - Files: `fuzz/fuzz_targets/` — current targets are smoke only; spec lists
    required corpora and sanitizer/nightly cadence.
- [~] Bench harnesses and performance gates. Local bench smoke/report scaffolding
  exists. Remaining: full spec fixtures (metadata: 3 profiles / 150 secret
  metadata rows / 50 active secrets / 10 policies / 5 trusted roots / valid
  audit chain; runtime: 50 active secrets 16 B–4 KiB; reference: 500+ `lk://`
  refs across current/pinned/grace/expired/missing/unauthorized; staged-scan:
  1.5–2 MB deterministic corpus; full-scan: ≥250 MB PR / ≥1 GB release; Argon2
  fixture with deterministic salts/passphrases). Hard budgets: metadata p95
  <100 ms, `run` prep p95 <150 ms (≤50 secrets), `lk://` resolution p95 <25 ms,
  `scan --staged` p95 <500 ms, full-repo scan ≥25 MB/s. Wire `make bench`,
  `make bench-ci`, `make bench-report` with PR-tolerance vs. release-strict
  modes.
  - Spec: `docs/specs/performance.md:1-67`.
  - Files: `Makefile` targets, new `benches/` per crate, fixture builders
    under `crates/locket-cli/src/tests/fixtures/`.
- [~] Branch coverage and mutation gates (`make coverage-branch`, `make mutation`).
  Commands and local fallbacks exist; current line coverage remains below the
  90% gate.
  - Spec: `docs/specs/testing.md` (90% line + branch gates).
  - Files: `Makefile`, `scripts/coverage*`.
- [~] Supply-chain tooling. Offline-safe local commands and strict-mode hooks
  exist. Remaining: enforced `cargo deny`, `cargo audit`, cargo-vet records,
  unsafe inventory, SBOM, auditable builds, provenance, signing.
  - Spec: `docs/specs/engineering.md`.
  - Files: `deny.toml` (already present), `Makefile`, CI workflow definitions.
- [~] Leak canary harness. Scanner/redactor canary tests and `make leak-canary`
  exist. Remaining: broader CLI/agent/UI artifact scanning.
  - Spec: `docs/specs/testing.md` leak-canary section.
  - Files: `scripts/leak-canary*` and the canary test harness.
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

## Reference Quick-Index

Use this section instead of grepping the specs every time. If the table here
disagrees with the spec, the spec wins — fix the table and open a PR.

### Exit-code bands (`docs/specs/errors.md:9-15`)

| Band | Class |
|---|---|
| `0` | success |
| `1` | doctor non-critical fail (doctor only; never produced by other commands) |
| `2` | doctor critical fail (doctor only) |
| `64-69` | input, config, reference validation |
| `70-79` | authorization, trust, secret access |
| `80-89` | agent + automation client |
| `90-99` | storage, schema, concurrency, integrity |
| `100-109` | keychain, recovery |
| `110-119` | team, device, sealed-bundle |

### Canonical typed errors (`crates/locket-core/src/error.rs`)

Input/config band (64-69): `InvalidReference` / `GitWorktreeRequired` /
`MetadataInvalid` (64), `PolicyValidationIncomplete` (65),
`EnvironmentConflict` / `MetadataLooksLikeSecret` (66), `SecretAlreadyExists`
(67), `ConfirmationFailed` (68).

Auth/trust/secret-access band (70-79): `AccessDenied` (70),
`ProjectRootUntrusted` (71), `UnlockRequired` (72), `GrantRequired` (73),
`UserVerificationFailed` (74), `SecretVersionExpired` (75),
`SecretDeleted` (76), `SecretNotFound` (77), `ProfileNotFound` (78).

Agent/automation band (80-89): `AgentUnavailable` (80), `AgentSocketInUse` (81),
`ProtocolError` (82), `ClientUnknown` / `ClientRevoked` / `ReplayDetected` (83),
`UpdateManifestInvalid` (89).

Storage/schema/integrity band (90-99): `StorageError` (90),
`SchemaMismatch` (91), `Concurrency` (92), `IntegrityFailure` (93).

Keychain/recovery band (100-109): `KeychainEntryMissing` (100),
`RecoveryUnavailable` (101), `PasskeyUnsupported` (102).

Team/device/sealed-bundle band (110-119): `BundleInvalid` (110),
`BundleConflict` (111), `BundleAuthFailed` (112),
`TeamRoleDenied` / `Invite*` (113).

When you need a new variant, add it to `LocketError`, give it the right exit
code, and update the table above.

### Canonical audit actions (`docs/specs/data-model.md`, `docs/specs/audit.md`)

Lifecycle: `INIT`, `BOOTSTRAP`, `IMPORT`, `EMIT_EXAMPLE`, `META`,
`PROFILE_CHANGE`.

Secret lifecycle: `SECRET_SET`, `SECRET_ROTATE`, `SECRET_RM`, `SECRET_PURGE`,
`SECRET_COPY`, `REVEAL`, `COPY`.

Scan/redaction: `SCAN`, `SCAN_SUPPRESSED`, `REDACT`.

Run/exec/reference: `RUN`, `EXEC`, `RESOLVE_REFERENCE`, `ENV_INSPECT`.

Trust/grants: `TRUST_ROOT`, `UNTRUST_ROOT`, `ALLOW_DIRECTORY`,
`DENY_DIRECTORY`, `AGENT_REVOKE`, `GRANT_EXPIRED`.

Auth/devices/clients/passkeys: `UNLOCK`, `LOCK`, `DEVICE_INIT`,
`DEVICE_REGISTER`, `DEVICE_REVOKE`, `CLIENT_ADD`, `CLIENT_REVOKE`,
`CLIENT_AUTH`, `PASSKEY_ADD`, `PASSKEY_REMOVE`.

Recovery/team/bundle: `RECOVERY_GENERATE`, `RECOVER`, `RECOVERY_ROTATE`,
`TEAM_INIT`, `TEAM_INVITE`, `TEAM_ACCEPT`, `TEAM_REMOVE`, `BACKUP_EXPORT`,
`BACKUP_IMPORT`.

Diagnostics: `AUDIT_VERIFY`, `DOCTOR`, `POLICY_UPDATE`, `POLICY_DOCTOR`,
`SCHEMA_MIGRATE`, `INSTALL_HOOKS`.

Every row carries: `sequence`, `prev_hmac`, `hmac`, `schema_version`,
`timestamp`, `project_id`, `profile_id?`, `action`, `status`,
`metadata_json` (action-specific shape; metadata-only).

Convenience columns (`secret_name`, `command`) when populated MUST also be
echoed inside `metadata_json` so the HMAC chain covers them. Never write
`null` literals for those keys.

### Required SQLite tables (`docs/specs/storage.md:26-50`)

`projects`, `project_roots`, `profiles`, `secrets`, `secret_versions`, `blobs`,
`keys`, `devices`, `passkey_credentials`, `automation_clients`,
`automation_client_private_key_refs`, `automation_client_nonces`, `teams`,
`team_members`, `team_invites`, `command_policies`, `directory_grants`,
`audit_log`, `imported_audit_chains`, `fingerprints`, `runtime_sessions`,
`schema_migrations`.

### Crate ownership

| Concern | Crate |
|---|---|
| CLI command surfaces, parsers, output | `crates/locket-cli/` |
| Domain types, IDs, policy, references, errors | `crates/locket-core/` |
| Crypto, AAD, key wrap, recovery envelope | `crates/locket-crypto/` |
| SQLite schema, queries, audit append, runtime sessions | `crates/locket-store/` |
| Daemon, IPC, protocol framing, RPC handlers | `crates/locket-agent/` |
| Process spawn, env layering, child supervision | `crates/locket-exec/` |
| Docker / Docker Compose policy helpers | `crates/locket-docker/` |
| OS keychain, passphrase fallback, user verification, hardening | `crates/locket-platform/` |
| Pattern/entropy/known-value scanner, redactor | `crates/locket-scan/` |
| Tauri desktop, tray (planned) | `crates/locket-app/` |

### Where each command lives

`init` / `bootstrap` / `emit-example` / `new` / `completion` →
`crates/locket-cli/src/bootstrap.rs` and `onboarding.rs`.
`status` / `context` → `crates/locket-cli/src/main.rs` (status_*/context_* fns).
`set` / `get` / `list` / `rotate` / `rm` / `purge` / `copy` / `history` →
`crates/locket-cli/src/secrets_cmd.rs`.
`meta` → `meta.rs`. `diff` → `diff.rs`. `redact` → `redact.rs`.
`scan` → `scan.rs`. `audit` → `audit.rs`.
`config` → `config_cmd.rs`. `debug` → `debug_cmd.rs`. `lock`/`unlock` → `lock.rs`.
`profile` / `use` → `profile.rs`. `project` → `project.rs`.
`shellenv` / `hook` / `allow` / `deny` → `shell.rs`.
`bundle` (export/import/verify) → `bundle.rs`.
`recovery` (`recover`, `recovery rotate`) → `recovery.rs`.
`device` → `device.rs`. `passkey` → `passkey.rs`. `client` → `client.rs`.
`agent` → `agent.rs`. `doctor` / `debug bundle` → `diagnostics.rs`.
`policy *` → `policy_authoring.rs` (currently mostly stubbed).
`team *` → not yet created (`team.rs`).

## Latest Verified Checkpoint

- Tip of `main`: `d0506aa` ("Define tray icon state descriptors").
- `cargo fmt --all -- --check` clean on `main`.
- `cargo test --workspace --all-targets --all-features` passes on `main`.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
  on `main`.
- `make leak-canary` clean on `main`.
- `make ci-local` last passed at `603ca53` (fmt, clippy, workspace tests, leak
  canary, bench smoke, supply-chain local fallback). Re-run before the next
  release-readiness checkpoint.
- `cargo +nightly fuzz list` passes; short focused fuzz runs (e.g.
  `cargo +nightly fuzz run fuzz_redactor -- -runs=128`) pass against the current
  redactor surface. Full all-target fuzzing remains tracked under quality gates.

## Notes

- The full spec is larger than any single slice. Keep slices coherent, test
  edges, and respect the audit/redaction/privacy invariants on every change.
- When you finish a slice and update this file, also remove any obsolete
  Active Plan entries the slice supersedes.
- If you add a new typed error variant, audit action, or required table, update
  the Reference Quick-Index in the same commit.
