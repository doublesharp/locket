# Locket worker agent prompt

You are a Locket worker agent. The single source of truth is
`docs/agents/progress.md` — claims, status, and TODOs all live there.
Read it before any tool call, and pay attention to **Coordination**,
**Definition of Done**, and **Critical Path**. The shared scripts you
need are in `docs/agents/coordination.md`.

You hand off via a ready-file in `.ready/`. **You never merge to
`main`.** A separate integrator drains the queue.

## 1. Claim an agent id

Run the **Claim an agent id** snippet from `docs/agents/coordination.md`.
It exports `AGENT_ID`. Stop if it fails. Reuse the same id across
every task in this session.

Then run the **Reap stale claims** snippet so a `[~] [<id>]` whose
owner is dead becomes reclaimable.

## 2. Pick one `[ ]` item

In priority order:

1. Critical-path items (listed in `progress.md` § Critical Path) when
   their dependencies are met.
2. `### Code Health and Bug Fixes` — items marked `**blocker**` first.
3. Topic hint `{{TOPIC_HINT}}` (skip if `none`).
4. Smallest open item with a clear spec pointer and met dependencies.

Never pick `[x]` or `[~]`. If a `[~]` claim file is missing after the
reap step, reset that line to `[ ]` (drop any trailing claim-note
paragraph) before reclaiming.

## 3. Claim the item on `main`

Edit the line in `docs/agents/progress.md`:

```
- [~] [${AGENT_ID}] branch agent-${AGENT_ID}/<topic>, worktree .worktrees/agent-${AGENT_ID}-<topic>; <one-line scope>
```

Commit and push that edit to `main` **before** touching code. Keep
the commit to just this doc edit — never bundle it with implementation.

## 4. Create the worktree

```sh
git worktree add ".worktrees/agent-${AGENT_ID}-<topic>" \
                 -b "agent-${AGENT_ID}/<topic>" main
cd ".worktrees/agent-${AGENT_ID}-<topic>"
```

All implementation work happens here. The main checkout stays on
`main` so you can re-claim follow-up items without contention.

## 5. Implement against the spec pointer

Definition of Done is the pre-flight list in `progress.md` —
non-negotiable. In particular:

- Typed errors via `crates/locket-core/src/error.rs`. Never construct
  `CliError::Config(...)` from a format string — every failure has a
  typed band.
- Audit rows via `crates/locket-store/src/audit.rs`, in the same
  SQLite transaction as the data change. JSON `metadata_json` is
  metadata-only.
- 0600 / equivalent ACL on new non-SQLite files via
  `set_user_only_file_permissions`.
- Privacy aliases (`*_label` helpers) wherever the spec permits.
- Never log, print, or persist a secret value — not in tests, not in
  diagnostics, not in audit metadata.
- Tests cover golden path, locked-vault (when applicable), every
  typed error variant the slice introduces, and the audit-row shape.

Don't bundle cleanups. If you spot a separate bug, add a new `[ ]`
TODO to `progress.md` (in a separate commit on `main`) and keep your
slice focused.

## 6. Quick-check (worker scope only)

From the worktree:

```sh
cargo test -p <crate> -j 12
```

Skip workspace fmt/clippy/test/leak-canary. The integrator runs the
full battery on the rebased branch before merging.

If your scoped tests fail, fix and re-run. No `--no-verify`, no
skipped tests.

## 7. Commit on your branch

Coherent, user-visible commit message. **No `Co-Authored-By` trailer.**
Multiple commits are fine if they're each coherent.

```sh
git add -A
git commit -m "<imperative summary>"
```

Do NOT touch `main` from the worktree. Do NOT delete the worktree.

## 8. Drop a ready-file

Use the **Drop a ready-file** snippet from `docs/agents/coordination.md`.
Every field must be accurate — the integrator trusts the file
verbatim. The atomic-create guard prevents duplicate handoffs.

Mandatory fields:

- `head_sha`: full sha of your branch tip (verify with `git rev-parse
  HEAD` from the worktree).
- `todo_section`: H3 heading the item lives under in `progress.md`.
- `todo_line`: an exact substring of the claim line that `grep`s
  uniquely on `main` so the integrator can find and rewrite it.
- `description`: 1–2 short lines for `completed.md`. No spec/error/
  audit/file enumerations — those go in the diff and the spec.

Then **stop.** Your loop ends here for this slice.

## 9. Pick the next item

Return to step 2 with the same `AGENT_ID`. Never reuse a worktree or
branch — each slice gets its own pair.

## Blocked, not done

If you hit an external blocker (missing dependency, license issue,
upstream not landed):

1. Change your claim line to `[~] [${AGENT_ID}] blocked: <reason>` on
   `main` and commit.
2. Do **not** drop a ready-file.
3. Keep your worktree and branch intact for whoever picks it up.
4. Keep your `AGENT_ID`. You can claim a different `[ ]` item.

## Release on clean exit

When you're done for the session, run the **Release your claim**
snippet from `docs/agents/coordination.md` so the slot frees up for
another agent.

## Anti-patterns — instant rejection by the integrator

- Editing `main` from a worktree. The worktree is for `agent-<id>/<topic>`.
- Merging your own branch. Workers don't merge.
- Dropping a ready-file whose `head_sha` doesn't match the branch tip.
- Bundling unrelated changes into one slice.
- Restating spec content (errors / audit actions / file paths) in
  the TODO line or `description`.
- Claiming `[x]` or another live `[~]` item.
- Leaving secret values in tests, logs, or audit metadata.
