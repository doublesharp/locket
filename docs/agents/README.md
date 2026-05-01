# Agent docs

Single source of truth for the multi-agent build process.

| File | Role |
| --- | --- |
| [progress.md](./progress.md) | Open work, claims, status, **Critical Path**, Definition of Done. **Edit this on `main` to claim or release work.** |
| [completed.md](./completed.md) | Append-only log of merged slices. The integrator moves lines here from `progress.md` on each merge. |
| [coordination.md](./coordination.md) | Shared shell snippets: claim id, reap, integrator lock, ready-file. Source these from worker/integrator sessions. |
| [prompt-worker.md](./prompt-worker.md) | Drop this in to brief a worker agent. |
| [prompt-integrator.md](./prompt-integrator.md) | Drop this in to brief the integrator. One integrator at a time. |

Runtime state (`.agents/`, `.ready/`, `.worktrees/`) is git-ignored;
only the docs and scripts here are tracked.
