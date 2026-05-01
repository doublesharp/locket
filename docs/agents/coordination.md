# Agent coordination scripts

Shared shell snippets referenced by `prompt-worker.md` and
`prompt-integrator.md` (siblings). Source these at session start. The
runtime state directories (`.agents/`, `.ready/`, `.worktrees/`) are
git-ignored — only the scripts themselves are tracked.

## Layout

```
.agents/
  active/<agent-id>.toml      # one file per live agent claim
  integrator.lock             # single-writer guard (integrator only)
.ready/
  <agent-id>-<topic>.toml     # worker handoff queue (oldest first)
  conflict/<...>.toml         # rebase failed
  failed/<...>.toml           # full battery failed
  rejected/<...>.toml         # ready-file didn't match disk
.worktrees/
  agent-<id>-<topic>/         # one per claim, exactly this shape
```

## Claim an agent id (workers + integrator)

Run once at session start. Atomic create on collision; the loop is
just for the theoretical case.

```sh
reg="$(cd "$(dirname "$(git rev-parse --git-common-dir)")" && pwd)/.agents/active"
mkdir -p "${reg}"
while :; do
    AGENT_ID="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
    f="${reg}/${AGENT_ID}.toml"
    if (set -C; : > "${f}") 2>/dev/null; then
        printf 'id = "%s"\nclaimed_at = "%s"\npid = %s\nhostname = "%s"\nworktree = "%s"\n' \
            "${AGENT_ID}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$(hostname)" "$(pwd)" > "${f}"
        export AGENT_ID
        echo "Claimed agent id: ${AGENT_ID}"
        break
    fi
done
```

## Reap stale claims (run before claiming work)

Safe only for pids on this host. Removes claim files whose owner
process is gone.

```sh
reg="$(cd "$(dirname "$(git rev-parse --git-common-dir)")" && pwd)/.agents/active"
for f in "${reg}"/*.toml; do
    [ -e "${f}" ] || continue
    h="$(awk -F'"' '/^hostname/ {print $2}' "${f}")"
    p="$(awk -F' = ' '/^pid/ {print $2}' "${f}")"
    [ "${h}" = "$(hostname)" ] && [ -n "${p}" ] && [ "${p}" != "0" ] \
        && ! kill -0 "${p}" 2>/dev/null && rm -f "${f}" && echo "reaped ${f}"
done
```

A `[~] [<id>]` line in `progress.md` whose claim file is missing
after reaping is free to reset to `[ ]` and reclaim. Drop the trailing
claim-note line too.

## Release your claim on clean exit

```sh
reg="$(cd "$(dirname "$(git rev-parse --git-common-dir)")" && pwd)/.agents/active"
rm -f "${reg}/${AGENT_ID}.toml"
```

## Integrator lock (integrator only)

Single-writer guard so two integrators never race on `main`.

```sh
lock="$(cd "$(dirname "$(git rev-parse --git-common-dir)")" && pwd)/.agents/integrator.lock"
if (set -C; : > "${lock}") 2>/dev/null; then
    printf 'agent_id = "%s"\npid = %s\nclaimed_at = "%s"\n' \
        "${AGENT_ID}" "$$" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${lock}"
else
    p="$(awk -F' = ' '/^pid/ {print $2}' "${lock}")"
    if [ -n "${p}" ] && ! kill -0 "${p}" 2>/dev/null; then
        rm -f "${lock}" && exec "$0" "$@"
    fi
    echo "integrator already active" >&2; exit 1
fi
trap 'rm -f "${lock}"' EXIT
```

## Drop a ready-file (worker handoff)

Atomic create with the schema in `progress.md` ("Ready-file format").
Fail loudly if the file already exists — that means the topic was
already handed off.

```sh
ready=".ready/${AGENT_ID}-<topic>.toml"
(set -C; cat > "${ready}" <<EOF
agent_id = "${AGENT_ID}"
topic = "<topic>"
branch = "agent-${AGENT_ID}/<topic>"
worktree = ".worktrees/agent-${AGENT_ID}-<topic>"
head_sha = "$(git -C ".worktrees/agent-${AGENT_ID}-<topic>" rev-parse HEAD)"
todo_section = "<H3 under Full Spec Coverage TODO>"
todo_line = "<exact match for grep on main>"
description = "<1-2 lines for COMPLETED.md>"
files_touched = []
typed_errors_added = []
audit_actions_added = []
scoped_tests_run = "cargo test -p <crate> -j 12"
notes = ""
EOF
) || { echo "ready-file already exists" >&2; exit 1; }
```
