import * as vscode from 'vscode';

import { AgentClient } from './agentClient';
import { resolveLocketProject, resolveStorePath } from './commands';
import { WarnOnceLatch } from './terminalAutobindModel';
import {
  TerminalAutobindHandlerDeps,
  handleOpenTerminal,
} from './terminalAutobindHandler';

export function registerLocketTerminalAutobind(
  context: vscode.ExtensionContext,
  agentClient: AgentClient,
): vscode.Disposable {
  const warnOnce = new WarnOnceLatch();
  const deps: TerminalAutobindHandlerDeps = {
    agentClient,
    environmentVariableCollection: context.environmentVariableCollection,
    autobindContext: {
      resolveProject: (cwd) => (cwd === undefined ? undefined : resolveLocketProject(cwd)),
      pid: process.pid,
      processStartTime: hostProcessStartTime(),
    },
    storePath: resolveStorePath(),
    notifyDirectoryGrantRejected: (reason) => {
      void vscode.window.showWarningMessage(`Locket: ${reason}`);
    },
    warnOnce,
  };
  return vscode.window.onDidOpenTerminal((terminal) => {
    void handleOpenTerminal(workingDirectoryForTerminal(terminal), deps);
  });
}

function workingDirectoryForTerminal(terminal: vscode.Terminal): string | undefined {
  const opts = terminal.creationOptions as { cwd?: string | vscode.Uri } | undefined;
  if (opts !== undefined && opts.cwd !== undefined) {
    if (typeof opts.cwd === 'string') {
      return opts.cwd;
    }
    if (typeof opts.cwd === 'object' && 'fsPath' in opts.cwd) {
      return opts.cwd.fsPath;
    }
  }
  return firstWorkspaceFolderPath();
}

function firstWorkspaceFolderPath(): string | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (folders === undefined || folders.length === 0) {
    return undefined;
  }
  return folders[0]!.uri.fsPath;
}

function hostProcessStartTime(): string {
  // VS Code does not expose the host process start time directly; we
  // approximate with a stable per-process token derived from `process.pid`
  // and `process.uptime` rounded to seconds. The agent only requires the
  // value to be stable across the lifetime of the bound process.
  const startUnix = Math.floor(Date.now() / 1000 - process.uptime());
  return `pid-${process.pid}-start-${startUnix}`;
}
