// Locket VS Code extension entry point.

import * as vscode from 'vscode';

import { AgentClient } from './agentClient';
import { registerLocketCommands } from './commands';
import { registerLocketDiagnostics } from './diagnostics';
import { registerReferenceCompletionProvider } from './referenceCompletion';
import { registerLocketStatusBar } from './statusBar';
import { registerLocketTerminalAutobind } from './terminalAutobind';

export function activate(context: vscode.ExtensionContext): void {
  const agentClient = new AgentClient();
  context.subscriptions.push(registerLocketDiagnostics());
  context.subscriptions.push(registerLocketStatusBar(agentClient));
  context.subscriptions.push(registerReferenceCompletionProvider(agentClient));
  context.subscriptions.push(registerLocketCommands(agentClient));
  context.subscriptions.push(registerLocketTerminalAutobind(context, agentClient));
  context.subscriptions.push({
    dispose: () => {
      agentClient.dispose();
    },
  });
}

export function deactivate(): void {
  // Request-scoped sockets are closed by AgentClient after every call.
}
