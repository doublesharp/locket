import * as path from 'node:path';
import * as vscode from 'vscode';
import { ProjectContext, pathIsWithin, resolveProjectContext } from './projectContext';

export async function resolveActiveProjectContext(): Promise<ProjectContext | undefined> {
  if (!vscode.workspace.isTrusted) { throw new Error('Locket requires a trusted workspace.'); }
  const folders = vscode.workspace.workspaceFolders ?? [];
  if (folders.length === 0) { throw new Error('Open a project folder to use Locket.'); }
  const editorFile = vscode.window.activeTextEditor?.document.uri;
  const editorCwd = editorFile?.scheme === 'file' ? path.dirname(editorFile.fsPath) : undefined;
  const terminalCwd = workingDirectoryForTerminal(vscode.window.activeTerminal);
  let cwd = [editorCwd, terminalCwd].find((candidate) => candidate !== undefined && folders.some((folder) => pathIsWithin(candidate, folder.uri.fsPath)));
  if (cwd === undefined) {
    if (folders.length === 1) { cwd = folders[0]?.uri.fsPath; }
    else {
      const picked = await vscode.window.showQuickPick(folders.map((folder) => ({label:folder.name,description:folder.uri.fsPath,root:folder.uri.fsPath})), {title:'Locket project',placeHolder:'Choose the project folder'});
      cwd = picked?.root;
    }
  }
  return resolveProjectForCwd(cwd);
}

export async function resolveProjectForCwd(cwd: string | undefined): Promise<ProjectContext | undefined> {
  if (!vscode.workspace.isTrusted || cwd === undefined) { return undefined; }
  const roots = (vscode.workspace.workspaceFolders ?? []).map((folder) => folder.uri.fsPath);
  if (!roots.some((root) => pathIsWithin(cwd, root))) { return undefined; }
  return resolveProjectContext({trusted:true,cwd,workspaceRoots:roots});
}

export function workingDirectoryForTerminal(terminal: vscode.Terminal | undefined): string | undefined {
  const withIntegration = terminal as (vscode.Terminal & {shellIntegration?:{cwd?:vscode.Uri}}) | undefined;
  const integrationCwd = withIntegration?.shellIntegration?.cwd;
  if (integrationCwd?.scheme === 'file') { return integrationCwd.fsPath; }
  const cwd = terminal?.creationOptions && 'cwd' in terminal.creationOptions ? terminal.creationOptions.cwd : undefined;
  if (typeof cwd === 'string') { return cwd; }
  if (cwd?.scheme === 'file') { return cwd.fsPath; }
  return undefined;
}
