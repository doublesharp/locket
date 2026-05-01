import test from 'node:test';
import assert from 'node:assert/strict';

import { AgentClientError } from './agentClient';
import {
  connectingStatusBarPlan,
  heartbeatTooltipPlan,
  reconnectDelayMs,
  statusEventBarPlan,
  statusPayloadBarPlan,
  unavailableStatusBarPlan,
} from './statusBarModel';

test('status bar model renders locked and unlocked agent states without names', () => {
  const locked = statusPayloadBarPlan({
    lock_state: 'locked',
    project_id: 'lk_proj_sensitive',
    profile_name: 'prod',
    live_grant_count: 0,
    agent_version: 'test-agent',
    unlock_ttl_seconds: null,
  });
  assert.equal(locked.text, '$(lock) Locket');
  assert.match(locked.tooltip, /locked/u);
  assert.doesNotMatch(locked.tooltip, /lk_proj_sensitive|prod/u);

  const unlocked = statusPayloadBarPlan({
    lock_state: 'unlocked',
    live_grant_count: 2,
    agent_version: 'test-agent',
    unlock_ttl_seconds: 42,
  });
  assert.equal(unlocked.text, '$(key) Locket');
  assert.match(unlocked.tooltip, /2 live grants, unlock TTL 42s/u);
});

test('status bar model renders stream events and unavailable state', () => {
  const event = statusEventBarPlan({
    kind: 'heartbeat',
    sequence: 7,
    lock_state: 'unknown',
    live_grant_count: 1,
    agent_version: 'test-agent',
  });
  assert.equal(event.text, '$(question) Locket');
  assert.equal(event.background, 'warning');
  assert.match(event.tooltip, /sequence 7/u);

  const connecting = connectingStatusBarPlan();
  assert.equal(connecting.text, '$(sync~spin) Locket');

  const unavailable = unavailableStatusBarPlan(new Error('socket missing'));
  assert.equal(unavailable.text, '$(warning) Locket');
  assert.equal(unavailable.background, 'warning');
  assert.match(unavailable.tooltip, /socket missing/u);

  const typedUnavailable = unavailableStatusBarPlan(AgentClientError.unavailable('socket missing'));
  assert.equal(typedUnavailable.tooltip, 'The local agent is unavailable. Run locket agent start, then retry.');
});

test('heartbeat events surface a "last seen" detail in the tooltip', () => {
  const heartbeat = statusEventBarPlan({
    kind: 'heartbeat',
    sequence: 11,
    lock_state: 'unlocked',
    live_grant_count: 0,
    agent_version: 'test-agent',
  });
  assert.match(heartbeat.tooltip, /last seen sequence 11/u);
});

test('heartbeatTooltipPlan refreshes the tooltip without changing the badge', () => {
  const base = statusPayloadBarPlan({
    lock_state: 'unlocked',
    live_grant_count: 1,
    agent_version: 'test-agent',
    unlock_ttl_seconds: 60,
  });
  const refreshed = heartbeatTooltipPlan(base, {
    kind: 'heartbeat',
    sequence: 9,
    lock_state: 'unlocked',
    live_grant_count: 1,
    agent_version: 'test-agent',
    unlock_ttl_seconds: 60,
  });
  assert.equal(refreshed.text, base.text, 'badge text must be preserved');
  assert.equal(refreshed.background, base.background);
  assert.match(refreshed.tooltip, /last seen sequence 9/u);
});

test('reconnect backoff schedule grows exponentially up to a 30 second ceiling', () => {
  assert.equal(reconnectDelayMs(0), 0);
  assert.equal(reconnectDelayMs(1), 500);
  assert.equal(reconnectDelayMs(2), 1_000);
  assert.equal(reconnectDelayMs(3), 2_000);
  assert.equal(reconnectDelayMs(8), 30_000, 'eighth attempt clamps at the ceiling');
  assert.equal(reconnectDelayMs(20), 30_000, 'long backoff stays at the ceiling');
});
