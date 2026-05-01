import * as vscode from 'vscode';

import { AgentClient, AgentClientError, StatusEvent } from './agentClient';
import {
  StatusBarPlan,
  connectingStatusBarPlan,
  heartbeatTooltipPlan,
  reconnectDelayMs,
  statusEventBarPlan,
  unavailableStatusBarPlan,
} from './statusBarModel';

export function registerLocketStatusBar(agentClient: AgentClient): vscode.Disposable {
  const item = vscode.window.createStatusBarItem('locket.status', vscode.StatusBarAlignment.Left, 100);
  item.name = 'Locket Agent Status';
  item.command = 'locket.revealSecret';
  const controller = new LocketStatusBarController(agentClient, {
    showItem: () => item.show(),
    apply: (plan) => applyPlanTo(item, plan),
    setTimeout: (handler, ms) => globalThis.setTimeout(handler, ms),
    clearTimeout: (handle) => {
      // The host abstraction stores the handle as `unknown` so tests
      // can swap in numeric handles; cast here at the boundary with
      // the real Node API.
      globalThis.clearTimeout(handle as ReturnType<typeof globalThis.setTimeout>);
    },
    disposeItem: () => item.dispose(),
  });
  controller.start();
  return controller;
}

export interface StatusBarHost {
  readonly showItem: () => void;
  readonly apply: (plan: StatusBarPlan) => void;
  readonly setTimeout: (handler: () => void, ms: number) => unknown;
  readonly clearTimeout: (handle: unknown) => void;
  readonly disposeItem: () => void;
}

/// Status-bar controller. Subscribes to the agent status stream on
/// activation, refreshes the badge per `StatusEvent`, and reconnects
/// with exponential backoff if the stream drops. Sends an explicit
/// `CancelSubscription` RPC on dispose so the agent can release its
/// subscriber slot promptly even if the closing socket is queued
/// behind other writes.
export class LocketStatusBarController implements vscode.Disposable {
  private stream: { dispose: () => void } | undefined;
  private disposed = false;
  private reconnectAttempts = 0;
  private reconnectHandle: unknown;
  private currentPlan: StatusBarPlan = connectingStatusBarPlan();

  public constructor(
    private readonly agentClient: AgentClient,
    private readonly host: StatusBarHost,
  ) {}

  public start(): void {
    this.applyPlan(connectingStatusBarPlan());
    this.host.showItem();
    this.subscribe();
  }

  public dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    if (this.reconnectHandle !== undefined) {
      this.host.clearTimeout(this.reconnectHandle);
      this.reconnectHandle = undefined;
    }
    this.stream?.dispose();
    this.stream = undefined;
    // Fire-and-forget: the agent should treat a vanished subscriber
    // socket as cancelled, but we send the typed RPC explicitly so the
    // subscriber slot is released without waiting on a TCP-level close
    // notification. Errors are swallowed because the extension is
    // shutting down.
    void this.agentClient.invoke('CancelSubscription', {}).catch(() => undefined);
    this.host.disposeItem();
  }

  private subscribe(): void {
    if (this.disposed) {
      return;
    }
    this.agentClient
      .subscribeStatus(
        (event) => this.onEvent(event),
        (error) => this.onStreamError(error),
      )
      .then((stream) => {
        if (this.disposed) {
          stream.dispose();
          return;
        }
        this.stream = stream;
        this.reconnectAttempts = 0;
      })
      .catch((error: unknown) => {
        this.onStreamError(toAgentClientError(error));
      });
  }

  private onEvent(event: StatusEvent): void {
    this.reconnectAttempts = 0;
    if (event.kind === 'heartbeat' && this.currentPlan.text !== '$(sync~spin) Locket') {
      // Refresh the "last seen" tooltip without recomputing the badge.
      this.applyPlan(heartbeatTooltipPlan(this.currentPlan, event));
      return;
    }
    this.applyPlan(statusEventBarPlan(event));
  }

  private onStreamError(error: AgentClientError): void {
    if (this.disposed) {
      return;
    }
    this.stream = undefined;
    this.applyPlan(unavailableStatusBarPlan(error));
    this.scheduleReconnect();
  }

  private scheduleReconnect(): void {
    if (this.disposed) {
      return;
    }
    this.reconnectAttempts += 1;
    const delay = reconnectDelayMs(this.reconnectAttempts);
    this.reconnectHandle = this.host.setTimeout(() => {
      this.reconnectHandle = undefined;
      this.subscribe();
    }, delay);
  }

  private applyPlan(plan: StatusBarPlan): void {
    this.currentPlan = plan;
    this.host.apply(plan);
  }
}

function applyPlanTo(item: vscode.StatusBarItem, plan: StatusBarPlan): void {
  item.text = plan.text;
  item.tooltip = plan.tooltip;
  item.backgroundColor =
    plan.background === 'warning'
      ? new vscode.ThemeColor('statusBarItem.warningBackground')
      : undefined;
}

function toAgentClientError(error: unknown): AgentClientError {
  if (error instanceof AgentClientError) {
    return error;
  }
  if (error instanceof Error) {
    return AgentClientError.unavailable(error.message);
  }
  return AgentClientError.unavailable('unknown agent status failure');
}
