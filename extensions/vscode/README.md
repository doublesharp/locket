# Locket VS Code Extension

Out-of-tree TypeScript skeleton for the Locket VS Code extension.

This package hosts the VS Code extension backed by the local Locket
agent. It includes a TypeScript agent socket client for the v1 framed
JSON protocol. The build/lint/test scripts remain scaffolded so
follow-up UI subtasks can extend the extension without touching the
project setup.

## Project workflow

Trust the workspace and install the matching Locket CLI on an absolute PATH outside the project. The extension reads the active editor or terminal directory, finds its Locket project through the CLI, and uses the stored project/profile IDs. With multiple workspace folders, it asks you to choose only when the active editor and terminal do not identify one.

Unlock and audit use the project's resolved local store. Reveal and Copy ask for a portable secret name and open an interactive CLI terminal. The CLI uses the project's current profile and owns consent, local verification, and clipboard expiry. The extension does not capture plaintext or announce that a copy succeeded. Reveal writes plaintext to the terminal, where it can remain in scrollback. Dangerous-profile reads may require explicit CLI consent; the extension never supplies bypass flags. Switching profiles asks for the target name and, when required by the agent, a typed dangerous-profile confirmation.

Run Policy lists saved policies and launches the selected command in an integrated terminal. CLI confirmations and exit status remain visible there. Create Terminal registers a names-only IDE session for that terminal. Project sessions are never installed in the global terminal environment.

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
