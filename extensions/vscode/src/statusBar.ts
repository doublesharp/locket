import * as vscode from 'vscode';

import { AgentClient, AgentClientError } from './agentClient';
import {
  StatusBarPlan,
  connectingStatusBarPlan,
  statusEventBarPlan,
  unavailableStatusBarPlan,
} from './statusBarModel';

export function registerLocketStatusBar(agentClient: AgentClient): vscode.Disposable {
  const item = vscode.window.createStatusBarItem('locket.status', vscode.StatusBarAlignment.Left, 100);
  item.name = 'Locket Agent Status';
  item.command = 'locket.revealSecret';
  const controller = new LocketStatusBarController(agentClient, item);
  controller.start();
  return controller;
}

class LocketStatusBarController implements vscode.Disposable {
  private stream: vscode.Disposable | undefined;
  private disposed = false;

  public constructor(
    private readonly agentClient: AgentClient,
    private readonly item: vscode.StatusBarItem,
  ) {}

  public start(): void {
    this.apply(connectingStatusBarPlan());
    this.item.show();
    void this.agentClient
      .subscribeStatus(
        (event) => this.apply(statusEventBarPlan(event)),
        (error) => this.applyUnavailable(error),
      )
      .then((stream) => {
        if (this.disposed) {
          stream.dispose();
          return;
        }
        this.stream = stream;
      })
      .catch((error: unknown) => {
        this.applyUnavailable(toAgentClientError(error));
      });
  }

  public dispose(): void {
    this.disposed = true;
    this.stream?.dispose();
    this.item.dispose();
  }

  private applyUnavailable(error: AgentClientError): void {
    this.apply(unavailableStatusBarPlan(error));
  }

  private apply(plan: StatusBarPlan): void {
    this.item.text = plan.text;
    this.item.tooltip = plan.tooltip;
    this.item.backgroundColor =
      plan.background === 'warning'
        ? new vscode.ThemeColor('statusBarItem.warningBackground')
        : undefined;
  }
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
