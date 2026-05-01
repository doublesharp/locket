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

/// Render a plan from a stream `StatusEvent`. Both `status` and
/// `heartbeat` events refresh the lock-state badge; the tooltip always
/// reflects the event kind so users can read the heartbeat timestamp.
export function statusEventBarPlan(event: StatusEvent): StatusBarPlan {
  const detail = event.kind === 'heartbeat'
    ? `last seen sequence ${event.sequence} (heartbeat)`
    : `sequence ${event.sequence}`;
  return statusPayloadBarPlan(event, detail);
}

/// Refresh just the tooltip on a heartbeat without recomputing the
/// badge. Returned plan reuses the most recent status snapshot's text
/// and background so the badge does not flicker between heartbeats.
export function heartbeatTooltipPlan(
  base: StatusBarPlan,
  event: StatusEvent,
): StatusBarPlan {
  return {
    text: base.text,
    background: base.background,
    tooltip: `${base.tooltip.split(' (last seen')[0]} (last seen sequence ${event.sequence})`,
  };
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

/// Reconnect-with-backoff schedule. The controller calls this with the
/// number of consecutive failed attempts (1-based) and gets the delay
/// before the next subscribe attempt. Exponential up to a 30 second
/// ceiling so transient agent restarts settle quickly while a hard-down
/// agent is not retried in a tight loop.
export function reconnectDelayMs(attempt: number): number {
  if (attempt <= 0) {
    return 0;
  }
  const base = 500;
  const ceiling = 30_000;
  const exp = base * 2 ** Math.min(attempt - 1, 10);
  return Math.min(exp, ceiling);
}
