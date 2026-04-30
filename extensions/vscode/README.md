# Locket VS Code Extension

Out-of-tree TypeScript skeleton for the Locket VS Code extension.

This package hosts the VS Code extension backed by the local Locket
agent. It includes a TypeScript agent socket client for the v1 framed
JSON protocol; UI features land in follow-up slices.

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

## Package

```sh
make vscode-vsix-package
```

The package artifact and SHA-256 sidecar are written under
`target/package/vscode/`.

## Scope

- `src/extension.ts` — extension activation and client lifecycle.
- `src/agentClient.ts` — metadata-only agent socket protocol client.
- The extension itself never writes audit rows directly.
