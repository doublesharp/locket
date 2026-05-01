// Locket VS Code extension entry point.

import { randomBytes } from 'node:crypto';
import * as vscode from 'vscode';

import { AgentClient, AgentClientError } from './agentClient';
import { registerLocketDiagnostics } from './diagnostics';
import { registerReferenceCompletionProvider } from './referenceCompletion';
import {
  RevealResponsePayload,
  buildRevealRequest,
  buildRevealWebviewHtml,
  revealTtlMilliseconds,
} from './revealWebview';
import { registerLocketStatusBar } from './statusBar';

export function activate(context: vscode.ExtensionContext): void {
  const agentClient = new AgentClient();
  context.subscriptions.push(registerLocketDiagnostics());
  context.subscriptions.push(registerLocketStatusBar(agentClient));
  context.subscriptions.push(registerReferenceCompletionProvider(agentClient));
  context.subscriptions.push(
    vscode.commands.registerCommand('locket.revealSecret', () => revealSecret(agentClient)),
    {
      dispose: () => {
        agentClient.dispose();
      },
    },
  );
}

export function deactivate(): void {
  // Request-scoped sockets are closed by AgentClient after every call.
}

async function revealSecret(agentClient: AgentClient): Promise<void> {
  const secretName = await vscode.window.showInputBox({
    title: 'Locket Reveal',
    prompt: 'Secret name',
    placeHolder: 'DATABASE_URL',
    ignoreFocusOut: false,
  });
  if (secretName === undefined) {
    return;
  }

  const profileId = await vscode.window.showInputBox({
    title: 'Locket Reveal',
    prompt: 'Profile id',
    placeHolder: 'default',
    ignoreFocusOut: false,
  });
  if (profileId === undefined) {
    return;
  }

  let request;
  try {
    request = buildRevealRequest(secretName, profileId);
  } catch {
    void vscode.window.showWarningMessage('Enter a secret name and profile id to reveal.');
    return;
  }

  try {
    const response = await agentClient.invoke<RevealResponsePayload>('Reveal', request);
    showRevealPanel(request.secret_name, response);
  } catch (error) {
    void vscode.window.showErrorMessage(revealErrorMessage(error));
  }
}

function showRevealPanel(secretName: string, response: RevealResponsePayload): void {
  const panel = vscode.window.createWebviewPanel(
    'locketReveal',
    'Locket Reveal',
    vscode.ViewColumn.Active,
    {
      enableScripts: true,
      retainContextWhenHidden: false,
    },
  );
  const ttlMs = revealTtlMilliseconds(response.ttl_seconds);
  const disposeTimer = setTimeout(() => {
    panel.dispose();
  }, ttlMs + 500);

  panel.onDidDispose(() => {
    clearTimeout(disposeTimer);
  });
  panel.webview.html = buildRevealWebviewHtml({
    nonce: randomBytes(16).toString('base64'),
    secretName,
    ttlSeconds: response.ttl_seconds,
    value: response.value,
  });
}

function revealErrorMessage(error: unknown): string {
  if (error instanceof AgentClientError) {
    if (error.displayReason !== undefined) {
      return `${error.displayReason} ${error.nextAction ?? ''}`.trim();
    }
    if (error.kind === 'agent' && error.code !== undefined) {
      return `Locket agent denied reveal: ${error.code}`;
    }
    if (error.kind === 'protocol') {
      return `Locket agent protocol error: ${error.message}`;
    }
    return `Locket agent unavailable: ${error.message}`;
  }
  return 'Locket reveal failed.';
}
