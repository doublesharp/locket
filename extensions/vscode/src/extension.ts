// Locket VS Code extension entry point.

import type { ExtensionContext } from 'vscode';

import { AgentClient } from './agentClient';
import { registerReferenceCompletionProvider } from './referenceCompletion';

export function activate(context: ExtensionContext): void {
  const agentClient = new AgentClient();
  context.subscriptions.push(registerReferenceCompletionProvider(agentClient));
  context.subscriptions.push({
    dispose: () => {
      agentClient.dispose();
    },
  });
}

export function deactivate(): void {
  // Request-scoped sockets are closed by AgentClient after every call.
}
