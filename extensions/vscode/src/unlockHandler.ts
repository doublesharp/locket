// Pure unlock-flow handler for the `locket.unlock` command.
//
// The flow lives here in a vscode-free module so the keychain-first
// then-passphrase fallback can be unit-tested against a real
// `AgentClient` and a stubbed UI surface. The matching command in
// `commands.ts` is a thin adapter that wires `vscode.window` prompts
// and notifications into the dependency callbacks below.
//
// Wire shape mirrors the agent-real-unlock contract:
//   { project_id, passphrase: Option<String>, ttl_seconds, audit: { store_path, profile_id } }
// The first attempt always sends `passphrase: null` so the agent can
// try the OS-keychain unwrap path. Only when the agent returns the
// typed `UnlockRequired` error do we collect a passphrase from the
// user and retry once. A second `UnlockRequired` is treated as a
// failed authentication and surfaced as such; any other agent error is
// passed through verbatim.

import { AgentClient, AgentClientError } from './agentClient';
import { agentErrorMessage, buildUnlockRequest } from './commandsModel';

/// UI surface the unlock flow drives. Keeping this an interface lets
/// the test suite swap in deterministic stubs without touching the
/// real `vscode.window` API.
export interface UnlockHandlerUi {
  /// Prompt for the project id; resolves to `undefined` when the user
  /// dismisses the input box.
  readonly promptProjectId: () => Promise<string | undefined>;
  /// Prompt for the path to the local `store.db`; resolves to
  /// `undefined` when dismissed.
  readonly promptStorePath: () => Promise<string | undefined>;
  /// Prompt for the vault passphrase. The adapter must use a masked
  /// input (`password: true`); resolves to `undefined` when dismissed.
  readonly promptPassphrase: () => Promise<string | undefined>;
  /// Show a non-blocking informational message.
  readonly showInfo: (message: string) => void;
  /// Show a warning for invalid input.
  readonly showWarning: (message: string) => void;
  /// Show an error toast.
  readonly showError: (message: string) => void;
  /// Optional override for the active profile id (carried into the
  /// audit block). The command in `commands.ts` resolves it from the
  /// most recent `Status` snapshot; the test suite passes `null`.
  readonly profileId?: string | null;
}

/// Outcome of one full pass of the unlock flow. Surfacing the verdict
/// here keeps the unit tests deterministic without inspecting the UI
/// stub's recorded messages.
export type UnlockOutcome =
  | { readonly status: 'unlocked' }
  | { readonly status: 'cancelled' }
  | { readonly status: 'invalid_input' }
  | { readonly status: 'agent_error'; readonly code?: string }
  | { readonly status: 'auth_failed' };

/// Run the unlock flow once. Driven by `commands.ts` for the real
/// command-palette entry, and by `unlockHandler.test.ts` against a
/// real `AgentClient` connected to a fake agent socket.
///
/// The function never throws; every failure path resolves to a
/// `UnlockOutcome` and the UI stub records the user-facing message.
export async function runUnlockFlow(
  agentClient: AgentClient,
  ui: UnlockHandlerUi,
): Promise<UnlockOutcome> {
  const projectId = await ui.promptProjectId();
  if (projectId === undefined) {
    return { status: 'cancelled' };
  }
  const storePath = await ui.promptStorePath();
  if (storePath === undefined) {
    return { status: 'cancelled' };
  }
  const profileId = ui.profileId ?? null;

  let firstRequest;
  try {
    firstRequest = buildUnlockRequest(projectId, storePath, profileId, null);
  } catch (error) {
    ui.showWarning(
      error instanceof Error ? error.message : 'Locket unlock inputs were invalid.',
    );
    return { status: 'invalid_input' };
  }

  // First attempt: keychain unwrap path. The agent returns
  // `UnlockRequired` when the OS keychain entry is missing or the
  // platform refused unwrap; only then do we prompt for a passphrase.
  try {
    await agentClient.invoke('Unlock', firstRequest);
    ui.showInfo('vault unlocked');
    return { status: 'unlocked' };
  } catch (error) {
    if (!(error instanceof AgentClientError) || error.code !== 'UnlockRequired') {
      ui.showError(agentErrorMessage(error));
      return {
        status: 'agent_error',
        code: error instanceof AgentClientError ? error.code : undefined,
      };
    }
  }

  const passphrase = await ui.promptPassphrase();
  if (passphrase === undefined) {
    return { status: 'cancelled' };
  }

  let retryRequest;
  try {
    retryRequest = buildUnlockRequest(projectId, storePath, profileId, passphrase);
  } catch (error) {
    ui.showWarning(
      error instanceof Error ? error.message : 'Locket unlock inputs were invalid.',
    );
    return { status: 'invalid_input' };
  }

  try {
    await agentClient.invoke('Unlock', retryRequest);
    ui.showInfo('vault unlocked');
    return { status: 'unlocked' };
  } catch (error) {
    if (error instanceof AgentClientError && error.code === 'UnlockRequired') {
      ui.showError('passphrase did not authenticate');
      return { status: 'auth_failed' };
    }
    ui.showError(agentErrorMessage(error));
    return {
      status: 'agent_error',
      code: error instanceof AgentClientError ? error.code : undefined,
    };
  }
}
