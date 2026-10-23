// Command handlers for Locket VS Code command-palette entries.
//
// Commands resolve local project metadata. Value access and saved policies
// run through the CLI so its authorization and clipboard gates apply.

import { randomBytes } from 'node:crypto';
import * as path from 'node:path';
import * as vscode from 'vscode';

import { AgentClient, AgentClientError } from './agentClient';
import { buildAuditWebviewHtml } from './auditView';
import {
  ListAuditResponsePayload,
  ListPoliciesResponsePayload,
  agentErrorMessage,
  buildListAuditRequest,
  buildListPoliciesRequest,
  buildLockRequest,
  buildSetActiveProfileRequest,
} from './commandsModel';
import { runUnlockFlow } from './unlockHandler';
import { ProjectContext } from './projectContext';
import { resolveActiveProjectContext } from './vscodeProject';

type ProjectResolver = () => Promise<ProjectContext | undefined>;
export interface CommandDependencies {
  readonly resolveProject?: ProjectResolver;
}

// Register every Locket command-palette entry against `agentClient`.
export function registerLocketCommands(agentClient: AgentClient, deps: CommandDependencies = {}): vscode.Disposable {
  const resolveProject: ProjectResolver = async () => {
    if (!vscode.workspace.isTrusted) { void vscode.window.showWarningMessage('Locket requires a trusted workspace.'); return undefined; }
    try { return await (deps.resolveProject ?? resolveActiveProjectContext)(); }
    catch (error) { void vscode.window.showErrorMessage(error instanceof Error ? error.message : 'Locket project metadata is unavailable.'); return undefined; }
  };
  const disposables: vscode.Disposable[] = [
    vscode.commands.registerCommand('locket.revealSecret', () =>
      revealSecret(resolveProject),
    ),
    vscode.commands.registerCommand('locket.copySecret', () => copySecret(resolveProject)),
    vscode.commands.registerCommand('locket.unlock', () => unlock(agentClient, resolveProject)),
    vscode.commands.registerCommand('locket.lock', () => lock(agentClient)),
    vscode.commands.registerCommand('locket.switchProfile', () => switchProfile(agentClient, resolveProject)),
    vscode.commands.registerCommand('locket.runPolicy', () => runPolicy(agentClient, resolveProject)),
    vscode.commands.registerCommand('locket.scanWorkspace', () => scanWorkspace(resolveProject)),
    vscode.commands.registerCommand('locket.openAuditView', () => openAuditView(agentClient, resolveProject)),
  ];
  return new vscode.Disposable(() => {
    for (const item of disposables) {
      item.dispose();
    }
  });
}

async function revealSecret(resolveProject: ProjectResolver): Promise<void> {
  await terminalValueAccess('Reveal', resolveProject);
}

async function copySecret(resolveProject: ProjectResolver): Promise<void> {
  await terminalValueAccess('Copy', resolveProject);
}

// Plaintext stays in the CLI/terminal or OS clipboard. The extension never
// captures the value and never reports success before the CLI executes.
async function terminalValueAccess(
  action: 'Reveal' | 'Copy',
  resolveProject: ProjectResolver,
): Promise<void> {
  const project = await resolveProject();
  if (project === undefined) { return; }
  const enteredName = await vscode.window.showInputBox({
    title: `Locket ${action} in Terminal`,
    prompt: 'Secret name',
    placeHolder: 'DATABASE_URL',
    ignoreFocusOut: false,
  });
  if (enteredName === undefined) { return; }
  const secretName = enteredName.trim();
  if (!/^[A-Z_][A-Z0-9_]*$/u.test(secretName)) {
    void vscode.window.showWarningMessage('Enter a portable secret name using A-Z, 0-9, and underscores.');
    return;
  }
  const terminal = vscode.window.createTerminal({
    name: `Locket ${action} approval: ${secretName}`,
    shellPath: project.cliPath,
    shellArgs: ['get', action === 'Reveal' ? '--reveal' : '--copy', '--', secretName],
    cwd: project.root,
  });
  terminal.show();
  void vscode.window.showInformationMessage(
    `Continue Locket ${action} approval in the terminal. The CLI uses this project's current profile, last detected as ${project.profileName}.`,
  );
}

async function unlock(agentClient: AgentClient, resolveProject: ProjectResolver): Promise<void> {
  const project = await resolveProject();
  if (project === undefined) { return; }
  await runUnlockFlow(agentClient, {
    promptProjectId: async () => project.projectId,
    promptStorePath: async () => project.storePath,
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
    profileId: project.defaultProfileId,
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

async function switchProfile(agentClient: AgentClient, resolveProject: ProjectResolver): Promise<void> {
  const project = await resolveProject();
  if (project === undefined) {
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
    request = buildSetActiveProfileRequest(path.join(project.root, 'locket.toml'), project.storePath, project.projectId, profileName);
  } catch (error) {
    void vscode.window.showWarningMessage(
      error instanceof Error ? error.message : 'Locket switch profile inputs were invalid.',
    );
    return;
  }
  try {
    try { await agentClient.invoke('SetActiveProfile', request); }
    catch (error) {
      if (!(error instanceof AgentClientError) || error.code !== 'ConfirmationFailed') { throw error; }
      const confirmation = await vscode.window.showInputBox({title:'Locket Switch Profile',prompt:`Type '${request.profile_name}' to confirm this dangerous profile`,ignoreFocusOut:false});
      if (confirmation === undefined) { return; }
      if (confirmation !== request.profile_name) { void vscode.window.showWarningMessage('Profile confirmation did not match.'); return; }
      await agentClient.invoke('SetActiveProfile', {...request, confirmation});
    }
    void vscode.window.showInformationMessage(`Locket active profile is now ${request.profile_name}.`);
  } catch (error) {
    void vscode.window.showErrorMessage(agentErrorMessage(error));
  }
}

async function runPolicy(agentClient: AgentClient, resolveProject: ProjectResolver): Promise<void> {
  const project = await resolveProject();
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
  if (pick.label.startsWith('-') || /[\0\r\n]/u.test(pick.label)) {
    void vscode.window.showWarningMessage('This policy name cannot be launched from the editor.');
    return;
  }
  const terminal = vscode.window.createTerminal({name:`Locket: ${pick.label}`,shellPath:project.cliPath,shellArgs:['run',pick.label],cwd:project.root});
  terminal.show();
}

async function scanWorkspace(resolveProject: ProjectResolver): Promise<void> {
  const project = await resolveProject();
  if (project === undefined) { return; }
  try {
    const terminal = vscode.window.createTerminal({
      name: 'Locket Scan', shellPath: project.cliPath,
      shellArgs: ['scan', '--require-known'], cwd: project.root,
    });
    terminal.show();
    void vscode.window.showInformationMessage('Continue the scan in the terminal. Known-value coverage requires an unlocked vault; findings and coverage are reported there.');
  } catch (error) {
    void vscode.window.showErrorMessage(agentErrorMessage(error));
  }
}

async function openAuditView(agentClient: AgentClient, resolveProject: ProjectResolver): Promise<void> {
  const project = await resolveProject();
  if (project === undefined) {
    return;
  }
  let request;
  try {
    request = buildListAuditRequest(project.storePath, project.projectId);
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
