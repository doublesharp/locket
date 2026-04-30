# Locket Implementation Progress

This file tracks open implementation work and coordination state across agents.
History of merged slices lives in `git log`; do not duplicate it here.
Completed slices live in `IMPLEMENTATION_COMPLETED.md`.

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
   - **Move the line to `IMPLEMENTATION_COMPLETED.md`** under its
     section heading, flipping it to `[x]` and **compressing the
     description to 1–2 short lines** about what shipped. Drop
     spec/error/audit/file pointers and any claim note. The line
     does not stay in `IMPLEMENTATION_PROGRESS.md`.
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
live claim file). Merged slices move to `IMPLEMENTATION_COMPLETED.md`
as `[x]`. Subtasks under an open `[~]` parent may be `[x]` in place
to record what's done within the slice.

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
the spec already covers. Closed slices land in
`IMPLEMENTATION_COMPLETED.md`.

### Near-Term CLI/Core

- [~] Scan ignore/suppression: inline markers, `SCAN`/`SUPPRESSED` audit
  rows, and per-rule severity (`ScanFindingBlocked` 69) shipped.
  Remaining: project-level severity overrides and `.env` policy table.
- [~] Destructive confirmation flows: `purge`, dangerous-profile, and
  root untrust shipped. Remaining: policy deletion and other sensitive
  surfaces (`docs/specs/policy.md:26`).
- [~] Source-precedence and multi-source behavior across `set`, `get`,
  `list`, `rotate`, `rm`, `purge`, `history`, `diff`, `copy`,
  reveal/copy, and execution. Run audit records selected source by
  precedence and set tombstone preflight returns typed `SecretDeleted`;
  remaining commands still need the unified resolver
  (`docs/specs/data-model.md`, `docs/specs/runtime.md:188-216`).
- [~] [70c448c4] Default high-entropy scan rule (≥20 chars, Shannon ≥4.5
  Claim: branch agent-70c448c4/scan-entropy-policy, worktree .worktrees/agent-70c448c4-scan-entropy-policy.
  bits/char, exclude UUIDs/checksums/public ids) with project
  overrides in `locket.toml`; `policy doctor` reports non-default
  thresholds (`docs/specs/scan-redaction.md:24`).
- [~] [bec7ddfc] Known-value scan must include deleted-source current versions
  Claim: branch agent-bec7ddfc/known-scan-deleted-grace, worktree .worktrees/agent-bec7ddfc-known-scan-deleted-grace.
  with blobs and deprecated versions still within `grace_until`;
  exclude purged versions (`docs/specs/scan-redaction.md:17`).
- [ ] `locket redact --stdin` streaming mode with non-UTF-8 byte
  segment pass-through (warn metadata-only); pattern-only fallback
  label `lk_redacted_PATTERN_N` for matches not tied to a known id
  (`docs/specs/scan-redaction.md:43-49`).
- [ ] `locket ai-safe --pattern-only` degraded locked-vault mode and
  `--output <file>` 0600 transcript with refuse-overwrite-without-
  `--force`; partial-line buffer cap with redact-and-warn behavior
  (`docs/specs/scan-redaction.md:72-76`).
- [ ] `Duration` grammar parser/normalizer
  (`^[1-9][0-9]*(s|m|h|d|w)$`, reject compound/fractional/zero/
  negative/uppercase/whitespace) used everywhere durations are read
  (`docs/specs/data-model.md:27`).

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
- [~] External env source resolution
  (`docs/specs/runtime.md:117-118`). `::Parent`, `::File`, and
  `::Compose` shipped.
  Remaining subtasks:
  - [x] **subtask** — env-source-compose: `locket run` resolves Compose
    env names via `docker compose config --format json` with typed
    provider failures and metadata-only audit labels.
  - [ ] **subtask** — env-source-ide: consume the VS Code terminal
    `LOCKET_IDE_ENV_SESSION` map over the agent socket; names-only
    audit on `RUN`/`EXEC`; never persist values. Depends on the
    agent-socket-server subtask under Local agent daemon.
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
- [~] `locket exec --all` typed-confirmation flow and `EXEC` audit
  shipped. Remaining: `locket env inspect` enhancements and env-layering /
  override-mode docs.
- [ ] `locket exec --secret KEY` single-key injection (distinct from
  `--all`); writes `EXEC` row.
- [ ] On-demand agent startup: `locket exec`/`run` start the agent
  when missing; `AgentUnavailable` only after on-demand startup fails.
- [ ] Docker active-context detection refuses remote/TCP/SSH contexts
  unless `allow_remote_docker = true` and a typed confirmation passes.
- [ ] `compose run` flag plumbing: `--project-directory`,
  `--profile`, and post-`--` passthrough.
- [ ] `inherit_env` extends the active `env_mode` allowlist rather
  than replacing it (`docs/specs/runtime.md`).
- [ ] `lk://` parser rejects `?source=imported` (provenance lives on
  the secret, not the reference).
- [ ] `get --reveal` requires a TTY unless `--force` is passed; the
  `REVEAL` row records `force=true`.
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
  - [~] [bec7ddfc] **subtask** — policy-parser: parse `locket.toml`
    `[commands.<name>]` blocks into a typed `CommandPolicy` with
    structural validation. Errors: `InvalidPolicy` (65).
    Claim: branch agent-bec7ddfc/policy-parser-typed, worktree .worktrees/agent-bec7ddfc-policy-parser-typed.
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
- [ ] Ephemeral env-file fallback for children that can't accept an env
  map: 0700 parent / 0600 file outside project tree, post-spawn delete,
  audited delivery mode, secure-erase warning when unsupported.
- [~] Clipboard clear-after-TTL only if clipboard still contains the
  value. Wayland-aware pre-copy warning and `COPY` audit
  `unsupported_reason` shipped; background TTL clearing remains.
### Security/Recovery/Team

- [ ] Sealed bundle. Decomposed below; later subtasks depend on
  `bundle-container-format` (`docs/specs/team-sync-recovery.md:111-224`).
  - [ ] **subtask** — bundle-container-format: implement the versioned
    container (magic header, schema version, plaintext-minimal
    manifest, encrypted-payload section) plus a writer/reader pair.
    Manifest minimization is enforced in code (no profile/secret/
    policy/member/device names). Errors: `BundleVerificationFailed`
    (110). Tests: round-trip a synthetic container; rejects unknown
    schema, oversized manifest, and disallowed manifest fields.
    Pre-req for all other bundle subtasks.
  - [ ] **subtask** — bundle-age-encryption: integrate `age`/`rage`
    library for the encrypted payload with multi-recipient support.
    Errors: `BundleVerificationFailed` (110) on AAD/auth-tag failure.
    Tests: encrypt to N recipients, decrypt with matching key, reject
    on tag tamper. Depends on `bundle-container-format`.
  - [ ] **subtask** — bundle-export-payload: serialize selected
    profiles, policies, secret metadata, `secret_versions`, blobs, and
    per-profile `ProfileSecret`/`ProfileFingerprint` keys into the
    canonical encrypted payload. Forbid master/audit/device/recovery
    key material in the payload. Audit: `BACKUP_EXPORT` records counts
    and recipient fingerprints only. Tests: golden-path export,
    dangerous-profile typed-confirmation gate,
    refuse-when-output-exists. Depends on `bundle-age-encryption`.
  - [ ] **subtask** — bundle-import-apply: decrypt and apply imported
    state — rewrap profile keys under the receiver's master key,
    append blobs, and write metadata rows in a single SQLite
    transaction. Audit: `BACKUP_IMPORT` and `TEAM_ACCEPT` (when
    invoked through team accept). Errors:
    `BundleVerificationFailed` (110), `StorageError`. Tests:
    fresh-target import, idempotent re-import of identical content.
    Depends on `bundle-age-encryption`.
  - [ ] **subtask** — bundle-import-conflicts: implement the conflict
    matrix (identical, newer-incoming, divergent, deleted-vs-active)
    with metadata-only summary, `--accept-incoming` and
    `--accept-local`, and interactive resolution. Errors:
    `ConfirmationFailed` (68) on user abort. Tests: each cell of the
    matrix with metadata-only output. Depends on `bundle-import-apply`.
  - [ ] **subtask** — bundle-verify-cmd: implement `locket bundle
    verify` structural-only and decryptable paths, exiting `0` for
    both; malformed → `BundleVerificationFailed` (110); unsupported
    schema → `ConfigError`. Audit: `BUNDLE_VERIFY` records bundle
    digest, schema version, decryptability, counts. Tests:
    structural-only (no matching recipient), decryptable success,
    malformed rejection, unsupported-schema rejection. Depends on
    `bundle-age-encryption`.
  - [ ] **subtask** — bundle-include-audit-import: when
    `--include-audit` is set, append imported audit rows to
    `imported_audit_chains` with structural verification (monotonic
    sequence, prev-HMAC linkage, checkpoint HMAC match against the
    bundle checkpoint). Errors: `BundleVerificationFailed` (110) on
    chain inconsistency. Tests: valid chain, broken sequence, broken
    prev-HMAC, mismatched checkpoint. Pairs with the existing
    `imported_audit_chains` structural verifier line in this section.
    Depends on `bundle-import-apply`.
  - [ ] **subtask** — bundle-rotate-on-newer: when import applies a
    newer version over an active target, run the `rotate`-with-no-grace
    lifecycle (mark prior `Deprecated`, set `last_rotated_at` to import
    timestamp, incoming becomes current). Tests: import v2 over v1,
    import v1 into a missing target leaves `last_rotated_at = None`.
    Pairs with the existing `rotate-with-no-grace` follow-up below.
    Depends on `bundle-import-apply`.
- [~] Team command surfaces (`team init`, `invite`, `accept`,
  `revoke-invite`, `members`, `remove`, `revoke-device`). Decomposed
  below; later subtasks depend on `team-store-schema`
  (`docs/specs/team-sync-recovery.md:5-110`).
  - [x] **subtask** — team-store-schema: `teams`, `team_members`,
    `team_invites` tables and constraints are in place; no migration bump
    needed.
  - [~] [aa40a4ce] **subtask** — team-init-command: implement `locket team init` with a
    Claim: branch agent-aa40a4ce/team-init-command, worktree .worktrees/agent-aa40a4ce-team-init-command. Scope: golden-path init + TEAM_INIT audit + already-initialized rejection. Role-gated re-init deferred to team-role helper subtask.
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
  - [x] **subtask** — team-members-list: `locket team members` lists
    member metadata and pending invites with privacy aliases; locked vaults
    remain metadata-only.
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
  - [~] [d7d049a4] **subtask** — harden-core-dumps: disable core dumps in the
    agent and CLI processes that hold key material (per-platform).
    Claim: branch agent-d7d049a4/harden-core-dumps, worktree .worktrees/agent-d7d049a4-harden-core-dumps. Scope: Unix `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0` (Linux) helper in `locket-platform`, called from CLI startup; Windows is a no-op for now with a `[ ]` follow-up.
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
- [ ] Member/device revocation produces a rotation checklist for every
  profile/secret the revoked principal could access.
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
- [ ] Typed `metadata_json` shape validator per audit action family
  (required fields, no unknown fields without a schema bump).
- [ ] Audit-tx atomicity: append + data change share one SQLite
  transaction; sequence assigned at commit; rollback leaves no gap
  or phantom row (`docs/specs/audit.md`).
- [ ] `metadata_json` ≤64 KiB per-row cap enforced at write time;
  large `secret_names`/`redacted_secret_names` collections summarize
  to stay under the cap (`docs/specs/audit.md`,
  `docs/specs/data-model.md:400`).
- [ ] Recovery code one-time display with scrollback warning and
  optional screen-clear on `init`/`device init`/`recovery rotate`
  (`docs/specs/team-sync-recovery.md`).
- [ ] `device init` first-run-on-machine bootstrap: creates master
  key, recovery envelope, and recovery code on a teammate clone
  (`docs/specs/team-sync-recovery.md`).
- [ ] `locket export --sealed --recipient ... [--profile|--all-profiles]
  [--include-audit] [--output]` command surface, default
  `locket-bundle-<utc>.locket-bundle` filename, dangerous-profile
  typed confirmation, and `BACKUP_EXPORT` audit row.
- [ ] `locket bundle verify` non-destructive command (structural
  checks, age-decryptability probe, `BUNDLE_VERIFY` audit row,
  documented exit-code rules).
- [ ] Solo-developer authorization: treat the local user as Owner
  when no `Team` record exists, while still enforcing typed
  confirmations / verification / audit / source-selection rules
  (`docs/specs/team-sync-recovery.md`).
- [ ] LocalUserVerifier macOS LocalAuthentication backend.
- [ ] LocalUserVerifier Windows Hello backend.
- [ ] LocalUserVerifier Linux Secret Service / hardware-key-presence
  backend.
- [ ] Passkey RP ID policy: `webauthn_relying_party_id` storage,
  `locket.localhost` default, controlled signed-distribution RP ID
  with re-registration migration, synced-passkey backup-eligibility
  display (`docs/specs/crypto.md`).
- [ ] Recovery envelope v1 binary container parser/writer
  (`recovery/envelope.bin` + `recovery/kdf.toml`): magic, schema,
  `kdf_profile_id`, entry layout, HKDF entry-key derivation, AAD;
  KDF parameters upgrade-only and fail closed when the binary cannot
  meet stored params (`docs/specs/crypto.md`).
- [ ] Recovery `kdf.toml` ↔ envelope-header `lk_kdf_*` id match
  check; mismatched ids fail recovery closed
  (`docs/specs/storage.md:24`).
- [ ] Negative-path decryption tests across wrong key/nonce/AAD/
  project/profile/secret-id/name/version dimensions
  (`docs/specs/crypto.md`).
- [ ] Secret value encoding: reject NUL bytes / multiline values in
  `set`/`import`; treat values as bytes-after-UTF-8 across docker/
  compose/exec/redact/scan paths (`docs/specs/crypto.md`).

### App/UI

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
- [ ] Primary desktop views beyond version-history/execution-monitor:
  project dashboard, profile switcher, secret metadata list, secret
  editor, command-policy editor, scan results, audit log/verification,
  backup/recovery, and Settings (`docs/specs/desktop.md`).
- [ ] Tray template-image policy: macOS template-image (alpha-mask)
  vs Windows/Linux full-color light/dark variants
  (`docs/specs/desktop.md`).
- [ ] Cross-surface error-text parity: CLI/UI/tray/shell/VS Code show
  the same reason and next action for each typed error
  (`docs/specs/desktop.md`).
- [ ] Tray bounded recent-activity surface: counts/safe statuses
  only; details remain in the in-app audit view
  (`docs/specs/desktop.md`).
- [ ] VS Code diagnostics: `process.env.KEY` missing in active
  profile and pinned `lk://...@vN` near/past `grace_until`
  (`docs/specs/integrations.md:48-49`).
- [ ] VS Code reference completion for `lk://` in `.env.example`,
  JSON, TOML, YAML, shell, and source files
  (`docs/specs/integrations.md:48`).
- [ ] VS Code gated reveal webview with short-lived data and no
  plaintext persistence (separate from the generic Reveal/copy UI
  gates) (`docs/specs/integrations.md:50-51`).
- [ ] `locket allow` requires the current root hash to be trusted;
  fails `ProjectRootUntrusted` before any grant
  (`docs/specs/integrations.md:25`).
- [ ] Profile-scoped grant invalidation on `locket use <profile>`;
  hook re-prompts `GrantRequired` when no `directory_grants` row
  exists for the now-active profile (`docs/specs/integrations.md:26`).
- [ ] `locket deny --all` revokes every directory grant for the
  project across all profiles (`docs/specs/integrations.md:27`).

### Code Health and Bug Fixes

Bugs, missing audit rows, and structural debt outside spec coverage. Each
item is independently claimable; re-verify file:line references before
editing — they drift. Severity: **blocker** (security/correctness),
**important** (real defect), **nit** (cleanup).

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

### Diagnostics, Distribution, and Quality Gates

- [ ] Expand tests toward spec coverage (90% line/branch gate).
  Decomposed by spec surface; subtasks are independent and may be
  claimed in parallel. Each subtask must add tests that demonstrably
  raise covered lines/branches; cite `cargo llvm-cov` deltas in the
  commit message (`docs/specs/testing.md:8-72`).
  - [ ] **subtask** — tests-policy-evaluation: cover
    `crates/locket-core/src/policy/` deny-by-default evaluation,
    required vs optional secret semantics, malformed-policy rejection,
    and `confirm`/`require_user_verification`/`ttl` edge cases.
  - [ ] **subtask** — tests-env-merge: cover `minimal`/`strict`/
    `merge`/`passthrough` modes, `override = "preserve"`/"error",
    the conservative allowlist, and `LC_*` matching.
  - [ ] **subtask** — tests-crypto-aad: cover AAD construction,
    key-wrap canonicalization, audit HMAC canonicalization, recovery
    envelope parsing, and device descriptor parsing in
    `crates/locket-crypto/`.
  - [ ] **subtask** — tests-store-migrations: cover schema migration
    paths, `SCHEMA_MIGRATE` audit on every step, and rollback on
    failure in `crates/locket-store/`.
  - [ ] **subtask** — tests-typed-errors: a per-variant exit-code
    regression covering at least one callsite per `LocketError`
    variant in `crates/locket-core/src/error.rs`.
  - [ ] **subtask** — tests-source-precedence: cover the unified
    resolver across `set`, `get`, `list`, `rotate`, `rm`, `purge`,
    `history`, `diff`, `copy`, reveal/copy, and execution. Pairs with
    the source-precedence item under `Near-Term CLI/Core`.
  - [ ] **subtask** — tests-scanner-rules: cover `crates/locket-scan/`
    rule matching, severity overrides, suppression markers, and the
    `--require-known` pre-commit mode.
  - [ ] **subtask** — tests-audit-hmac: verify the audit chain HMAC
    recomputes against each row's stored `schema_version`; pairs with
    the existing audit-chain HMAC line in `Security/Recovery/Team`.
  - [ ] **subtask** — tests-runtime-sessions: cover
    `runtime_sessions` storage, retention, and `exec`/`run` recording.
  - [ ] **subtask** — tests-coverage-ratchet: raise the
    `make coverage-branch` gate by visible deltas after each `tests-*`
    subtask lands. Final acceptance for the parent: 90% line and
    branch on the listed security-critical crates.
- [ ] End-to-end coverage. Decomposed by representative flow; each
  subtask is one E2E harness that drives the CLI/agent/UI through a
  golden path plus the documented failure paths
  (`docs/specs/testing.md:38`). Subtasks are independent.
  - [ ] **subtask** — e2e-greenfield-init: `locket init` →
    `device init` → `profile create dev` → `set` → `get`. Asserts
    audit chain integrity and 0600 file modes.
  - [ ] **subtask** — e2e-dotenv-migration: `import` from `.env` →
    confirmation prompt → tombstone old → emit `.env.example`. Covers
    the post-import delete-`.env` confirmation.
  - [ ] **subtask** — e2e-agent-rpc: drive the agent socket through
    `Status`, `Lock`, `Unlock`, `RequestGrant`, `RevokeGrant`,
    `SubscribeStatus`. Depends on the daemon subtasks.
  - [ ] **subtask** — e2e-policy-run: write a policy, `policy doctor`,
    `locket run` argv path with required/optional secrets, deny path,
    confirm gate, user-verification gate. Pairs with the `locket run`
    subtask tree.
  - [ ] **subtask** — e2e-docker-compose: `locket exec` and
    `locket run` against a stub `docker compose`, names-only audit,
    refusal of remote contexts.
  - [ ] **subtask** — e2e-recovery-roundtrip: `init` → record code →
    `recover` → `recovery rotate`. Covers refusal-when-keychain-valid
    and `--force` audit override.
  - [ ] **subtask** — e2e-team-invite-accept: `team init` →
    `team invite` → `team accept` (signature + safety-words display)
    → `team revoke-invite` failure path. Depends on the team-* and
    invite-ceremony subtasks.
  - [ ] **subtask** — e2e-bundle-roundtrip: `export --sealed` →
    `import-bundle` (fresh, identical, newer-incoming, divergent),
    `bundle verify` structural-only and decryptable. Depends on the
    sealed-bundle subtasks.
  - [ ] **subtask** — e2e-ui-editor-smoke: smoke flows in the desktop
    app (vault status, secrets list, reveal/copy gates) and the VS
    Code extension. Depends on `desktop-tauri-shell` and the VS Code
    extension item.
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
- [ ] Cold-start budgets. Decomposed per metric; each subtask adds
  one bench plus a regression that fails the budget
  (`docs/specs/performance.md`). Depends on the perf reference-runner
  sampling work above.
  - [ ] **subtask** — perf-passphrase-unlock: ≤300 ms passphrase
    fallback unlock, measured cold (no warm cache).
  - [ ] **subtask** — perf-recovery-envelope-unlock: ≤2 s recovery-
    envelope unlock, measured cold.
  - [ ] **subtask** — perf-agent-idle-memory: ≤50 MB agent idle RSS
    after a documented warmup window. Depends on the agent daemon
    subtasks landing first.
- [ ] Dependency hygiene gates: `cargo machete`/`udeps` in CI; OpenSSF
  Scorecard once public; keyless signing with transparency logs for CI
  artifacts; frontend `pnpm lint`/`typecheck`/`test`/`build` once
  `locket-app` exists.
- [ ] Property tests. Decomposed per surface; subtasks are
  independent and each lands one `proptest`/`quickcheck` harness
  asserting the documented invariants
  (`docs/specs/testing.md:14`).
  - [ ] **subtask** — proptest-dotenv: `.env` parser round-trip and
    rejection invariants.
  - [ ] **subtask** — proptest-policy-toml: policy TOML parse →
    normalize → re-serialize round-trip; rejection of disallowed
    fields.
  - [ ] **subtask** — proptest-lk-uri: `lk://` parser round-trip,
    fragment/query rejection, and pinned-version normalization.
  - [ ] **subtask** — proptest-canonical-json: canonical JSON encoder
    is total-ordered, idempotent, and stable across permutations.
  - [ ] **subtask** — proptest-device-descriptor: descriptor codec
    round-trip; rejects malformed `lkdev1_` payloads, version-bump
    behavior. Depends on the descriptor codec landing.
  - [ ] **subtask** — proptest-bundle-manifest: plaintext-manifest
    round-trip; rejects forbidden fields (profile/secret/policy/
    member/device names). Depends on `bundle-container-format`.
- [ ] Cross-platform test mocks and mutation tests
  (`docs/specs/testing.md`). Subtasks are independent — pick any:
  - [~] [6e4d05db] **subtask** — mock-os-keychain: trait-based mock for
    Claim: branch agent-6e4d05db/mock-os-keychain, worktree .worktrees/agent-6e4d05db-mock-os-keychain.
    `crates/locket-platform/src/keychain/` covering get/set/delete
    success and error paths, used in CLI/store tests.
  - [ ] **subtask** — mock-peer-credentials: in-process socket harness
    that returns spoofable peer creds so the agent's peer-validation
    logic can be tested without root. Pre-req:
    `agent-peer-validation` subtask under Local agent daemon.
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
- [ ] Bench fixtures: metadata, runtime, reference-resolution,
  staged-scan, full-scan, and Argon2 fixtures used by `make bench`
  (`docs/specs/performance.md`).
- [ ] PR vs release tolerance gate for benches: 10% PR / 20%
  tracked-regression / no-tolerance release
  (`docs/specs/performance.md`).
- [ ] `make coverage-html` and `make test` Make targets exposed
  alongside `coverage-branch`/`mutation` (`docs/specs/testing.md`).
- [ ] `cargo geiger` (or equivalent) unsafe inventory before public
  release and after any crypto/IPC/platform/storage dep change
  (`docs/specs/engineering.md`).
- [ ] RustSec advisory severity policy: high/critical block,
  medium runtime block, dev-only exception, low triage
  (`docs/specs/engineering.md`).
- [ ] Markdown lint alongside `make docs-check`
  (`docs/specs/engineering.md`).
- [ ] Supply-chain exception ledger (package, version, reason,
  compensating controls, owner, expiration) enforced by CI;
  no-expiration entries are invalid (`docs/specs/engineering.md`).
- [ ] SLSA v1.2 provenance verification (artifact digest, builder
  identity, source repo, build params) and Build L3 hosted-runner
  targeting (`docs/specs/operations.md`).
- [ ] SQLite pragma posture: `foreign_keys = ON`, WAL mode, 5000 ms
  busy timeout default; `locket doctor` runs an integrity check
  (`docs/specs/storage.md`).
- [ ] Pre-migration backup of `store.db` and recovery files
  (user-only perms) before schema-mutating migrations; `locket doctor`
  reports backup-skipped migrations and last backup path
  (`docs/specs/storage.md`).
- [ ] `automation_client_nonces` opportunistic pruning during client
  auth and via `locket doctor` (`docs/specs/storage.md`).
- [~] [cb2437f7] `runtime.session_secret_name_retention` enforcement: doctor
  reports past-retention rows and prunes only `secret_names`; `off`
  disables storing the field for new rows
  (`docs/specs/storage.md:139`).
  Claim: branch agent-cb2437f7/runtime-session-retention, worktree .worktrees/agent-cb2437f7-runtime-session-retention, scope doctor retention reporting/pruning and config-off coverage.

## Spec-by-Spec Completion Gates

Do this after all the other tasks are completed.

Final audit pass before claiming full spec coverage. Each item means the
implementation, tests, docs, diagnostics, and failure modes have been checked
against the named spec file.

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
