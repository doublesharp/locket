// Locket VS Code extension entry point. The skeleton activates as a
// no-op so the marketplace package shape is valid; agent RPC wiring
// lands in the `vscode-agent-client` subtask.

import type { ExtensionContext } from 'vscode';

export function activate(_context: ExtensionContext): void {
  // Intentionally empty — `vscode-agent-client` registers the
  // commands, status-bar item, and IDE-env-session hook.
}

export function deactivate(): void {
  // Nothing to clean up yet.
}
