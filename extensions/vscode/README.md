# Locket VS Code Extension

Out-of-tree TypeScript skeleton for the Locket VS Code extension.

This package is the host for upcoming subtasks under the
"VS Code extension backed by the local agent" item in
`IMPLEMENTATION_PROGRESS.md`. It is not yet wired into any agent
RPCs; only the build/lint/test scripts are scaffolded so the next
subtask can drop in actual extension code without touching the
project setup.

## Build

```sh
cd extensions/vscode
pnpm install
pnpm run build
```

## Lint

```sh
pnpm run lint
```

## Test

```sh
pnpm run test
```

(Test runner lands with `vscode-agent-client`.)

## Scope

- `src/extension.ts` — empty `activate`/`deactivate` stubs.
- No agent RPC behavior yet. All Locket actions go through the agent
  socket once `vscode-agent-client` lands; the extension itself
  never writes audit rows directly.
