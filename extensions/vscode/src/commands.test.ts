import Module from 'node:module';
import test from 'node:test';
import assert from 'node:assert/strict';

import type { AgentClient, AgentMethod, LockState } from './agentClient';

type RegisteredCommand = (...args: readonly unknown[]) => unknown;
type ModuleLoader = (
  request: string,
  parent: NodeJS.Module | null,
  isMain: boolean,
) => unknown;

interface VscodeWindowStub {
  inputValues: string[];
  quickPickValue:
    | {
        readonly label: string;
        readonly description?: string;
        readonly detail?: string;
        readonly policyId?: string;
      }
    | undefined;
  infos: string[];
  warnings: string[];
  errors: string[];
  showInputBox(): Promise<string | undefined>;
  showQuickPick<T>(items: readonly T[]): Promise<T | undefined>;
  showInformationMessage(message: string): Promise<string | undefined>;
  showWarningMessage(message: string): Promise<string | undefined>;
  showErrorMessage(message: string): Promise<string | undefined>;
}

interface VscodeWorkspaceStub {
  workspaceFolders:
    | ReadonlyArray<{
        readonly name: string;
        readonly uri: { readonly fsPath: string };
      }>
    | undefined;
}

const registeredCommands = new Map<string, RegisteredCommand>();

const vscodeWindow: VscodeWindowStub = {
  inputValues: [],
  quickPickValue: undefined,
  infos: [],
  warnings: [],
  errors: [],
  showInputBox: async () => vscodeWindow.inputValues.shift(),
  showQuickPick: async <T>(items: readonly T[]) => {
    if (vscodeWindow.quickPickValue === undefined) {
      return undefined;
    }
    return items.find(
      (item) =>
        typeof item === 'object' &&
        item !== null &&
        'label' in item &&
        item.label === vscodeWindow.quickPickValue?.label,
    );
  },
  showInformationMessage: async (message: string) => {
    vscodeWindow.infos.push(message);
    return undefined;
  },
  showWarningMessage: async (message: string) => {
    vscodeWindow.warnings.push(message);
    return undefined;
  },
  showErrorMessage: async (message: string) => {
    vscodeWindow.errors.push(message);
    return undefined;
  },
};

const vscodeWorkspace: VscodeWorkspaceStub = {
  workspaceFolders: undefined,
};

class DisposableStub {
  public constructor(private readonly onDispose: () => void = () => undefined) {}

  public dispose(): void {
    this.onDispose();
  }

  public static from(...items: readonly DisposableStub[]): DisposableStub {
    return new DisposableStub(() => {
      for (const item of items) {
        item.dispose();
      }
    });
  }
}

const vscodeStub = {
  commands: {
    registerCommand: (id: string, callback: RegisteredCommand): DisposableStub => {
      registeredCommands.set(id, callback);
      return new DisposableStub(() => {
        registeredCommands.delete(id);
      });
    },
  },
  window: {
    ...vscodeWindow,
    createWebviewPanel: () => ({
      dispose: () => undefined,
      onDidDispose: () => undefined,
      webview: { html: '' },
    }),
  },
  workspace: {
    get workspaceFolders() {
      return vscodeWorkspace.workspaceFolders;
    },
  },
  env: {
    clipboard: {
      readText: async () => '',
      writeText: async () => undefined,
    },
  },
  ViewColumn: {
    Active: 1,
  },
  Disposable: DisposableStub,
};

const moduleWithLoader = Module as unknown as { _load: ModuleLoader };
const originalLoad = moduleWithLoader._load;
moduleWithLoader._load = function loadWithVscodeStub(
  request: string,
  parent: NodeJS.Module | null,
  isMain: boolean,
): unknown {
  if (request === 'vscode') {
    return vscodeStub;
  }
  return originalLoad.call(this, request, parent, isMain);
};

let registerLocketCommands: typeof import('./commands').registerLocketCommands;

test.before(async () => {
  ({ registerLocketCommands } = await import('./commands'));
});

test.after(() => {
  moduleWithLoader._load = originalLoad;
});

test.beforeEach(() => {
  registeredCommands.clear();
  vscodeWindow.inputValues = [];
  vscodeWindow.quickPickValue = undefined;
  vscodeWindow.infos = [];
  vscodeWindow.warnings = [];
  vscodeWindow.errors = [];
  vscodeWorkspace.workspaceFolders = undefined;
});

test('run policy sends PrepareExec with project id, default profile id, and policy name', async () => {
  const invocations: Array<{ readonly method: AgentMethod; readonly payload: unknown }> = [];
  const agentClient = {
    status: async () => ({
      lock_state: 'unlocked' as LockState,
      project_id: 'lk_proj_demo',
      live_grant_count: 0,
      agent_version: 'test',
    }),
    invoke: async (method: AgentMethod, payload: unknown) => {
      invocations.push({ method, payload });
      if (method === 'ListPolicies') {
        return {
          rows: [
            {
              id: 'policy-1',
              name: 'deploy',
              command_kind: 'shell',
              command_preview: 'npm run deploy',
              required_secrets: [],
              optional_secrets: [],
            },
          ],
        };
      }
      return {};
    },
  } as unknown as AgentClient;

  vscodeWorkspace.workspaceFolders = [
    { name: 'demo', uri: { fsPath: '/workspace/demo' } },
  ];
  vscodeWindow.inputValues = ['lk_proj_demo'];
  vscodeWindow.quickPickValue = { label: 'deploy' };

  const disposable = registerLocketCommands(agentClient);
  try {
    const runPolicy = registeredCommands.get('locket.runPolicy');
    assert.notEqual(runPolicy, undefined);

    await runPolicy?.();
  } finally {
    disposable.dispose();
  }

  assert.deepEqual(invocations, [
    {
      method: 'ListPolicies',
      payload: { project_id: 'lk_proj_demo', privacy_redact_names: false },
    },
    {
      method: 'PrepareExec',
      payload: {
        project_id: 'lk_proj_demo',
        profile_id: 'default',
        policy_name: 'deploy',
      },
    },
  ]);
});

test('run policy prompts for profile id when no resolved project supplies one', async () => {
  const invocations: Array<{ readonly method: AgentMethod; readonly payload: unknown }> = [];
  const agentClient = {
    status: async () => ({
      lock_state: 'unlocked' as LockState,
      project_id: 'lk_proj_demo',
      profile_name: 'dev',
      live_grant_count: 0,
      agent_version: 'test',
    }),
    invoke: async (method: AgentMethod, payload: unknown) => {
      invocations.push({ method, payload });
      if (method === 'ListPolicies') {
        return {
          rows: [
            {
              id: 'policy-1',
              name: 'deploy',
              command_kind: 'shell',
              command_preview: 'npm run deploy',
              required_secrets: [],
              optional_secrets: [],
            },
          ],
        };
      }
      return {};
    },
  } as unknown as AgentClient;

  vscodeWindow.inputValues = ['lk_proj_demo', 'prof-dev'];
  vscodeWindow.quickPickValue = { label: 'deploy' };

  const disposable = registerLocketCommands(agentClient);
  try {
    const runPolicy = registeredCommands.get('locket.runPolicy');
    assert.notEqual(runPolicy, undefined);

    await runPolicy?.();
  } finally {
    disposable.dispose();
  }

  assert.deepEqual(invocations.at(-1), {
    method: 'PrepareExec',
    payload: {
      project_id: 'lk_proj_demo',
      profile_id: 'prof-dev',
      policy_name: 'deploy',
    },
  });
});
