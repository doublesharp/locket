import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { access, realpath, stat } from 'node:fs/promises';
import * as path from 'node:path';
import { ResolvedLocketProject } from './commandsModel';

export interface ProjectContext extends ResolvedLocketProject {
  readonly projectName: string;
  readonly profileName: string;
  readonly storePath: string;
  readonly cliPath: string;
}
export interface ResolveProjectOptions {
  readonly trusted: boolean;
  readonly cwd: string;
  readonly workspaceRoots: readonly string[];
  readonly pathEnvironment?: string;
}
export const CONTEXT_TIMEOUT_MS = 5000;
export const CONTEXT_MAX_BUFFER = 64 * 1024;

export function pathIsWithin(candidate: string, root: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

export async function resolveProjectContext(options: ResolveProjectOptions): Promise<ProjectContext> {
  if (!options.trusted) { throw new Error('Locket requires a trusted workspace.'); }
  const cwd = await realpath(options.cwd);
  const rootResults = await Promise.allSettled(options.workspaceRoots.map((root) => realpath(root)));
  const roots: string[] = [];
  const excludedRoots = options.workspaceRoots.map((root) => path.resolve(root));
  for (const [index, result] of rootResults.entries()) {
    if (result.status === 'fulfilled') {
      roots.push(result.value);
      excludedRoots.push(result.value);
    } else {
      const root = options.workspaceRoots[index];
      if (root !== undefined) {
        excludedRoots.push(await physicalExclusionForUnavailableRoot(root));
      }
    }
  }
  if (!roots.some((root) => pathIsWithin(cwd, root))) {
    throw new Error('Locket requires a directory inside the selected workspace.');
  }
  const cliPath = await discoverCli(options.pathEnvironment ?? process.env.PATH ?? '', excludedRoots);
  const stdout = await new Promise<string>((resolve, reject) => {
    execFile(cliPath, ['context', '--json'], {
      cwd, timeout: CONTEXT_TIMEOUT_MS, maxBuffer: CONTEXT_MAX_BUFFER, encoding: 'utf8', windowsHide: true,
    }, (error, output) => {
      if (error !== null) { reject(new Error('Locket could not resolve this project. Run locket init in its folder and check the local store.')); }
      else { resolve(output); }
    });
  });
  let metadata: unknown;
  try { metadata = JSON.parse(stdout); } catch { throw new Error('Locket returned invalid project metadata.'); }
  if (typeof metadata !== 'object' || metadata === null) { throw new Error('Locket returned invalid project metadata.'); }
  const fields = metadata as Record<string, unknown>;
  const required = ['root', 'project_id', 'project_name', 'profile_id', 'profile_name', 'store_path'] as const;
  if (required.some((field) => typeof fields[field] !== 'string' || (fields[field] as string).trim().length === 0 || (fields[field] as string).includes('\0'))) {
    throw new Error('Locket returned invalid project metadata.');
  }
  const root = fields.root as string;
  const storePath = fields.store_path as string;
  if (!path.isAbsolute(root) || !path.isAbsolute(storePath) || !pathIsWithin(cwd, root)) {
    throw new Error('Locket returned unrelated project metadata.');
  }
  return { root, storePath, cliPath, projectId: fields.project_id as string, projectName: fields.project_name as string, defaultProfileId: fields.profile_id as string, profileName: fields.profile_name as string };
}

async function discoverCli(pathEnvironment: string, workspaceRoots: readonly string[]): Promise<string> {
  for (const directory of pathEnvironment.split(path.delimiter)) {
    if (!path.isAbsolute(directory) || workspaceRoots.some((root) => pathIsWithin(directory, root))) { continue; }
    try {
      const candidate = await realpath(path.join(directory, process.platform === 'win32' ? 'locket.exe' : 'locket'));
      if (workspaceRoots.some((root) => pathIsWithin(candidate, root))) { continue; }
      if (!(await stat(candidate)).isFile()) { continue; }
      await access(candidate, constants.X_OK);
      return candidate;
    } catch { /* Continue through trusted absolute PATH entries. */ }
  }
  throw new Error('Install the Locket CLI on an absolute PATH outside the workspace.');
}

// Missing/disconnected roots cannot establish membership. Their lexical paths
// remain excluded, and a reachable parent preserves physical symlink exclusions.
async function physicalExclusionForUnavailableRoot(root: string): Promise<string> {
  let ancestor = path.resolve(root);
  const suffix: string[] = [];
  for (;;) {
    try {
      return path.join(await realpath(ancestor), ...suffix);
    } catch {
      const parent = path.dirname(ancestor);
      if (parent === ancestor) { return path.resolve(root); }
      suffix.unshift(path.basename(ancestor));
      ancestor = parent;
    }
  }
}
