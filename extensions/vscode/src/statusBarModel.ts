import { AgentClientError, StatusEvent, StatusPayload } from './agentClient';

export interface StatusBarPlan {
  readonly text: string;
  readonly tooltip: string;
  readonly background: 'none' | 'warning';
}

export function connectingStatusBarPlan(): StatusBarPlan {
  return {
    text: '$(sync~spin) Locket',
    tooltip: 'Locket agent status: connecting',
    background: 'none',
  };
}

export function statusEventBarPlan(event: StatusEvent): StatusBarPlan {
  return statusPayloadBarPlan(event, `sequence ${event.sequence}`);
}

export function statusPayloadBarPlan(status: StatusPayload, detail = 'snapshot'): StatusBarPlan {
  const grants = `${status.live_grant_count} live grant${status.live_grant_count === 1 ? '' : 's'}`;
  const ttl =
    status.unlock_ttl_seconds === null || status.unlock_ttl_seconds === undefined
      ? ''
      : `, unlock TTL ${status.unlock_ttl_seconds}s`;
  switch (status.lock_state) {
    case 'unlocked':
      return {
        text: '$(key) Locket',
        tooltip: `Locket agent status: unlocked (${grants}${ttl}, ${detail})`,
        background: 'none',
      };
    case 'locked':
      return {
        text: '$(lock) Locket',
        tooltip: `Locket agent status: locked (${grants}, ${detail})`,
        background: 'none',
      };
    case 'unknown':
      return {
        text: '$(question) Locket',
        tooltip: `Locket agent status: unknown (${grants}, ${detail})`,
        background: 'warning',
      };
  }
}

export function unavailableStatusBarPlan(error: AgentClientError | Error): StatusBarPlan {
  const message = error.message.trim();
  if (error instanceof AgentClientError && error.displayReason !== undefined) {
    return {
      text: '$(warning) Locket',
      tooltip: `${error.displayReason} ${error.nextAction ?? ''}`.trim(),
      background: 'warning',
    };
  }
  return {
    text: '$(warning) Locket',
    tooltip: `Locket agent unavailable${message.length > 0 ? `: ${message}` : ''}`,
    background: 'warning',
  };
}
