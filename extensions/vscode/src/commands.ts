// Command handlers for Locket VS Code command-palette entries.
//
// Every handler is a thin router over `AgentClient`. The extension never
// performs key unwrap, never writes audit rows, and never persists secret
// values; those are agent-side concerns.

import { randomBytes } from 'node:crypto';
import * as os from 'node:os';
import * as path from 'node:path';
import * as vscode from 'vscode';

import { AgentClient, AgentMethod, StatusPayload } from './agentClient';
import { buildAuditWebviewHtml } from './auditView';
import {
  CopyResponsePayload,
  ListAuditResponsePayload,
  ListPoliciesResponsePayload,
  ResolvedLocketProject,
  agentErrorMessage,
  buildListAuditRequest,
  buildListPoliciesRequest,
  buildLockRequest,
  buildScanKnownValuesRequest,
  buildSetActiveProfileRequest,
} from './commandsModel';
import {
  RevealResponsePayload,
  buildRevealRequest,
  buildRevealWebviewHtml,
  revealTtlMilliseconds,
} from './revealWebview';
import { runUnlockFlow } from './unlockHandler';

// Register every Locket command-palette entry against `agentClient`.
export function registerLocketCommands(agentClient: AgentClient): vscode.Disposable {
  const disposables: vscode.Disposable[] = [
    vscode.commands.registerCommand('locket.revealSecret', () =>
      revealSecret(agentClient),
    ),
    vscode.commands.registerCommand('locket.copySecret', () => copySecret(agentClient)),
    vscode.commands.registerCommand('locket.unlock', () => unlock(agentClient)),
    vscode.commands.registerCommand('locket.lock', () => lock(agentClient)),
    vscode.commands.registerCommand('locket.switchProfile', () => switchProfile(agentClient)),
    vscode.commands.registerCommand('locket.runPolicy', () => runPolicy(agentClient)),
    vscode.commands.registerCommand('locket.scanWorkspace', () => scanWorkspace(agentClient)),
    vscode.commands.registerCommand('locket.openAuditView', () => openAuditView(agentClient)),
  ];
  return new vscode.Disposable(() => {
    for (const item of disposables) {
      item.dispose();
    }
  });
}

async function promptForActiveProject(agentClient: AgentClient): Promise<{
  projectId: string;
  profileName: string | null;
} | undefined> {
  let status: StatusPayload | undefined;
  try {
    status = await agentClient.status();
  } catch {
    status = undefined;
  }
  const fromStatus = typeof status?.project_id === 'string' ? status.project_id : '';
  const projectId = await vscode.window.showInputBox({
    title: 'Locket',
    prompt: 'Project id',
    placeHolder: fromStatus.length > 0 ? fromStatus : 'lk_proj_...',
    value: fromStatus,
    ignoreFocusOut: false,
  });
  if (projectId === undefined) {
    return undefined;
  }
  return {
    projectId,
    profileName: typeof status?.profile_name === 'string' ? status.profile_name : null,
  };
}

async function revealSecret(agentClient: AgentClient): Promise<void> {
  await gatedValueAccess(agentClient, 'Reveal', 'Locket Reveal');
}

async function copySecret(agentClient: AgentClient): Promise<void> {
  await gatedValueAccess(agentClient, 'Copy', 'Locket Copy');
}

// Shared gated-access flow for `Reveal` and `Copy`. Reveal opens a
// short-lived webview; Copy writes the value to the OS clipboard for
// the response's TTL and then clears it.
async function gatedValueAccess(
  agentClient: AgentClient,
  method: Extract<AgentMethod, 'Reveal' | 'Copy'>,
  title: string,
): Promise<void> {
  const secretName = await vscode.window.showInputBox({
    title,
    prompt: 'Secret name',
    placeHolder: 'DATABASE_URL',
    ignoreFocusOut: false,
  });
  if (secretName === undefined) {
    return;
  }
  const profileId = await vscode.window.showInputBox({
    title,
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
    void vscode.window.showWarningMessage('Enter a secret name and profile id.');
    return;
  }
  try {
    if (method === 'Reveal') {
      const response = await agentClient.invoke<RevealResponsePayload>('Reveal', request);
      showRevealPanel(request.secret_name, response);
    } else {
      const response = await agentClient.invoke<CopyResponsePayload>('Copy', request);
      await pushToClipboardWithTtl(response.value, response.ttl_seconds);
      void vscode.window.showInformationMessage(
        `Locket copied ${request.secret_name} to clipboard for ${Math.max(1, Math.floor(response.ttl_seconds))}s.`,
      );
    }
  } catch (error) {
    void vscode.window.showErrorMessage(agentErrorMessage(error));
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

// Push a value to the clipboard and clear it after `ttlSeconds`. The
// TTL upper bound mirrors `revealTtlMilliseconds` so the clipboard
// never holds plaintext longer than the gated-access spec allows.
async function pushToClipboardWithTtl(value: string, ttlSeconds: number): Promise<void> {
  await vscode.env.clipboard.writeText(value);
  const ttlMs = revealTtlMilliseconds(ttlSeconds);
  setTimeout(() => {
    void (async () => {
      const current = await vscode.env.clipboard.readText();
      if (current === value) {
        await vscode.env.clipboard.writeText('');
      }
    })();
  }, ttlMs);
}

async function unlock(agentClient: AgentClient): Promise<void> {
  // The agent owns the keychain/passphrase unwrap path: the wire
  // payload now carries `project_id`, `passphrase: null`, a `ttl_seconds`
  // hint, and an `audit` block with the store path so the agent can
  // append the UNLOCK row. We attempt OS-keychain unwrap first
  // (`passphrase: null`); on a typed `UnlockRequired` rejection we
  // prompt for the vault passphrase and retry once. The flow itself
  // lives in `unlockHandler.ts` so it can be unit-tested without the
  // `vscode.window` API; this adapter just wires the prompts in.
  await runUnlockFlow(agentClient, {
    promptProjectId: async () => {
      const project = await promptForActiveProject(agentClient);
      return project?.projectId;
    },
    promptStorePath: () =>
      Promise.resolve(
        vscode.window.showInputBox({
          title: 'Locket Unlock',
          prompt: 'Path to store.db',
          placeHolder: '~/.locket/store.db',
          ignoreFocusOut: false,
        }),
      ),
    promptPassphrase: () =>
      Promise.resolve(
        vscode.window.showInputBox({
          password: true,
          prompt: 'Locket vault passphrase',
          ignoreFocusOut: false,
        }),
      ),
    showInfo: (message) => {
      void vscode.window.showInformationMessage(message);
    },
    showWarning: (message) => {
      void vscode.window.showWarningMessage(message);
    },
    showError: (message) => {
      void vscode.window.showErrorMessage(message);
    },
    profileId: null,
  });
}

async function lock(agentClient: AgentClient): Promise<void> {
  try {
    await agentClient.invoke('Lock', buildLockRequest());
    void vscode.window.showInformationMessage('Locket vault is locked.');
  } catch (error) {
    void vscode.window.showErrorMessage(agentErrorMessage(error));
  }
}

async function switchProfile(agentClient: AgentClient): Promise<void> {
  const project = await promptForActiveProject(agentClient);
  if (project === undefined) {
    return;
  }
  const configPath = await vscode.window.showInputBox({
    title: 'Locket Switch Profile',
    prompt: 'Path to project locket.toml',
    placeHolder: '/path/to/project/locket.toml',
    ignoreFocusOut: false,
  });
  if (configPath === undefined) {
    return;
  }
  const storePath = await vscode.window.showInputBox({
    title: 'Locket Switch Profile',
    prompt: 'Path to store.db',
    placeHolder: '~/.locket/store.db',
    ignoreFocusOut: false,
  });
  if (storePath === undefined) {
    return;
  }
  const profileName = await vscode.window.showInputBox({
    title: 'Locket Switch Profile',
    prompt: 'Profile name',
    placeHolder: 'dev',
    value: project.profileName ?? '',
    ignoreFocusOut: false,
  });
  if (profileName === undefined) {
    return;
  }
  let request;
  try {
    request = buildSetActiveProfileRequest(configPath, storePath, project.projectId, profileName);
  } catch (error) {
    void vscode.window.showWarningMessage(
      error instanceof Error ? error.message : 'Locket switch profile inputs were invalid.',
    );
    return;
  }
  try {
    await agentClient.invoke('SetActiveProfile', request);
    void vscode.window.showInformationMessage(`Locket active profile is now ${request.profile_name}.`);
  } catch (error) {
    void vscode.window.showErrorMessage(agentErrorMessage(error));
  }
}

async function runPolicy(agentClient: AgentClient): Promise<void> {
  const project = await promptForActiveProject(agentClient);
  if (project === undefined) {
    return;
  }
  let request;
  try {
    request = buildListPoliciesRequest(project.projectId);
  } catch {
    return;
  }
  let policies: ListPoliciesResponsePayload;
  try {
    policies = await agentClient.invoke<ListPoliciesResponsePayload>('ListPolicies', request);
  } catch (error) {
    void vscode.window.showErrorMessage(agentErrorMessage(error));
    return;
  }
  if (policies.rows.length === 0) {
    void vscode.window.showInformationMessage('Locket has no saved command policies for this project.');
    return;
  }
  const pick = await vscode.window.showQuickPick(
    policies.rows.map((row) => ({
      label: row.name,
      description: row.command_kind,
      detail: row.command_preview,
      policyId: row.id,
    })),
    { title: 'Locket: Run Policy', placeHolder: 'Select a saved command policy' },
  );
  if (pick === undefined) {
    return;
  }
  try {
    await agentClient.invoke('PrepareExec', {
      project_id: project.projectId,
      policy_name: pick.label,
    });
    void vscode.window.showInformationMessage(
      `Locket prepared policy ${pick.label}. Run via the integrated terminal or CLI.`,
    );
  } catch (error) {
    void vscode.window.showErrorMessage(agentErrorMessage(error));
  }
}

async function scanWorkspace(agentClient: AgentClient): Promise<void> {
  const folders = vscode.workspace.workspaceFolders ?? [];
  const paths = folders.map((folder) => folder.uri.fsPath);
  if (paths.length === 0) {
    void vscode.window.showInformationMessage('Locket scan requires an open workspace folder.');
    return;
  }
  try {
    await agentClient.invoke('ScanKnownValues', buildScanKnownValuesRequest(paths));
    void vscode.window.showInformationMessage('Locket scan completed; see the diagnostics view for findings.');
  } catch (error) {
    void vscode.window.showErrorMessage(agentErrorMessage(error));
  }
}

async function openAuditView(agentClient: AgentClient): Promise<void> {
  const project = await promptForActiveProject(agentClient);
  if (project === undefined) {
    return;
  }
  const storePath = await vscode.window.showInputBox({
    title: 'Locket Audit',
    prompt: 'Path to store.db',
    placeHolder: '~/.locket/store.db',
    ignoreFocusOut: false,
  });
  if (storePath === undefined) {
    return;
  }
  let request;
  try {
    request = buildListAuditRequest(storePath, project.projectId);
  } catch (error) {
    void vscode.window.showWarningMessage(
      error instanceof Error ? error.message : 'Locket audit inputs were invalid.',
    );
    return;
  }
  let response: ListAuditResponsePayload;
  try {
    response = await agentClient.invoke<ListAuditResponsePayload>('ListAudit', request);
  } catch (error) {
    void vscode.window.showErrorMessage(agentErrorMessage(error));
    return;
  }
  const panel = vscode.window.createWebviewPanel(
    'locketAudit',
    'Locket Audit',
    vscode.ViewColumn.Active,
    { enableScripts: false, retainContextWhenHidden: false },
  );
  panel.webview.html = buildAuditWebviewHtml({
    nonce: randomBytes(16).toString('base64'),
    rows: response.rows,
    chainStatus: response.chain_status,
  });
}

/// Resolves the Locket project that contains `cwd` by walking the
/// VS Code workspace folders. The terminal-autobind handler calls this
/// for every newly-opened integrated terminal; it must remain cheap and
/// return `undefined` whenever `cwd` is outside any workspace folder.
///
/// VS Code does not expose project ids directly; we surface a stable
/// fallback derived from the workspace folder name so the agent has a
/// non-empty key to dedupe against. A real project id is resolved by
/// the agent against `locket.toml` once a grant is requested.
export function resolveLocketProject(cwd: string): ResolvedLocketProject | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (folders === undefined || folders.length === 0) {
    return undefined;
  }
  const normalized = path.resolve(cwd);
  let bestMatch: { root: string; name: string } | undefined;
  for (const folder of folders) {
    const root = folder.uri.fsPath;
    if (normalized === root || normalized.startsWith(`${root}${path.sep}`)) {
      if (bestMatch === undefined || root.length > bestMatch.root.length) {
        bestMatch = { root, name: folder.name };
      }
    }
  }
  if (bestMatch === undefined) {
    return undefined;
  }
  return {
    root: bestMatch.root,
    projectId: `lk_proj_${bestMatch.name}`,
    defaultProfileId: 'default',
  };
}

/// Returns the store-db path the extension uses for agent calls that
/// need to address the local store (e.g. the autobind directory grant
/// audit and the IDE env-session register payload). The shared default
/// follows the same `~/.locket/store.db` convention the other commands
/// use; users can override via the `LOCKET_STORE_PATH` environment
/// variable when they keep the store outside the home directory.
export function resolveStorePath(): string {
  const override = process.env.LOCKET_STORE_PATH?.trim();
  if (override !== undefined && override.length > 0) {
    return override;
  }
  return path.join(os.homedir(), '.locket', 'store.db');
}
