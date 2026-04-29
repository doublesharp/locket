# Policy Authoring

This file is part of the normative planned Locket implementation spec. Start at [index.md](index.md).

## Policy Authoring

Policy authoring must be usable from CLI and UI without hand-editing TOML for common cases.

Commands:

```bash
locket policy add dev -- pnpm dev
locket policy allow dev DATABASE_URL
locket policy require dev DATABASE_URL
locket policy edit dev
locket policy delete dev
locket policy doctor
```

Behavior:

- `policy add` creates a structured `argv` command by default.
- `policy allow` permits optional secret access.
- `policy require` marks a secret as required before spawn.
- `policy edit` opens the configured editor on the policy file or launches the UI editor.
- `policy delete <name>` shows a metadata-only summary of affected shell hooks, tray actions, automation clients, and VS Code tasks, requires typed confirmation of the policy name, removes the saved policy, revokes live grants for that policy, and writes a `POLICY_UPDATE` audit row with deletion metadata.
- `policy doctor` validates command existence, required secrets, profile availability, dangerous-profile confirmations, and `lk://` references. If the agent is unavailable, it warns that `lk://` reference validation was skipped, lists unvalidated references, and exits with a distinct non-zero status separate from ordinary policy validation failure.
- UI policy editing must expose argv vs shell mode clearly and warn when shell mode is selected.
- Docker/Compose policy editing must expose `allow_remote_docker` clearly. The default is `false`; enabling it requires typed confirmation because remote Docker contexts deliver local secrets to another machine.

Policy source of truth:

- Project command policies are canonical in `locket.toml` under `[commands.<name>]` so they can be reviewed in Git and shared with teammates without exporting secret values.
- The SQLite `command_policies` table stores a normalized local index/cache used by the agent, UI, tray, VS Code, and policy doctor.
- `policy add`, `policy allow`, `policy require`, `policy edit`, and `policy delete` update `locket.toml` first, then refresh the SQLite index in the same user-visible operation.
- If `locket.toml` and SQLite disagree, `locket.toml` wins after a successful parse; invalid TOML fails closed and leaves the prior SQLite index read-only for diagnostics only.
