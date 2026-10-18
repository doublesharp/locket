import * as vscode from 'vscode';
import { AgentClient } from './agentClient';
import { LOCKET_IDE_ENV_SESSION_VARIABLE, clearIdeEnvSessionFromTerminals } from './ideEnvSession';
import { WarnOnceLatch } from './terminalAutobindModel';
import { TerminalAutobindHandlerDeps, handleOpenTerminal } from './terminalAutobindHandler';
import { resolveActiveProjectContext, resolveProjectForCwd, workingDirectoryForTerminal } from './vscodeProject';

export function registerLocketTerminalAutobind(context: vscode.ExtensionContext, agentClient: AgentClient): vscode.Disposable {
  const clearGlobalSession = (): void => clearIdeEnvSessionFromTerminals(context.environmentVariableCollection);
  clearGlobalSession();
  const deps: TerminalAutobindHandlerDeps = {
    agentClient,
    environmentVariableCollection: context.environmentVariableCollection,
    autobindContext: {resolveProject:()=>undefined,pid:process.pid,processStartTime:hostProcessStartTime()},
    resolveProject: resolveProjectForCwd,
    storePath:'',
    notifyDirectoryGrantRejected:(reason)=>{void vscode.window.showWarningMessage(`Locket: ${reason}`);},
    warnOnce:new WarnOnceLatch(),
  };
  const createTerminal = async (): Promise<void> => {
    try {
      const project = await resolveActiveProjectContext();
      if (project === undefined) { return; }
      const outcome = await handleOpenTerminal(project.root,deps);
      const terminal=vscode.window.createTerminal({
        cwd:project.root,name:'Locket',
        env:outcome.sessionId===undefined?{}:{[LOCKET_IDE_ENV_SESSION_VARIABLE]:outcome.sessionId},
      });
      terminal.show();
    } catch (error) {void vscode.window.showErrorMessage(error instanceof Error ? error.message : 'Locket project is unavailable.');}
  };
  return vscode.Disposable.from(
    vscode.commands.registerCommand('locket.createTerminal',createTerminal),
    vscode.workspace.onDidChangeWorkspaceFolders(clearGlobalSession),
    vscode.window.onDidOpenTerminal((terminal)=>{void handleOpenTerminal(workingDirectoryForTerminal(terminal),deps);}),
    new vscode.Disposable(clearGlobalSession),
  );
}

function hostProcessStartTime(): string {
  const startUnix=Math.floor(Date.now()/1000-process.uptime());
  return `pid-${process.pid}-start-${startUnix}`;
}
