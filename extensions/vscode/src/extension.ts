// Locket VS Code extension entry point.

import type { ExtensionContext } from 'vscode';

import { AgentClient } from './agentClient';

export function activate(context: ExtensionContext): void {
  const agentClient = new AgentClient();
  context.subscriptions.push({
    dispose: () => {
      agentClient.dispose();
    },
  });
}

export function deactivate(): void {
  // Request-scoped sockets are closed by AgentClient after every call.
}
