import test from 'node:test';
import assert from 'node:assert/strict';

import { ResolvedLocketProject } from './commandsModel';
import {
  TerminalAutobindContext,
  WarnOnceLatch,
  planTerminalAutobind,
} from './terminalAutobindModel';

const PROJECT: ResolvedLocketProject = {
  root: '/workspace/demo',
  projectId: 'lk_proj_demo',
  defaultProfileId: 'prof-dev',
};

test('planTerminalAutobind builds a ResolveReference grant when in a Locket project', () => {
  const context: TerminalAutobindContext = {
    resolveProject: (cwd) => (cwd === '/workspace/demo' ? PROJECT : undefined),
    pid: 4242,
    processStartTime: 'start-token',
    ttlSeconds: 60,
  };
  const plan = planTerminalAutobind('/workspace/demo', context);
  assert.notEqual(plan, undefined);
  assert.equal(plan!.project, PROJECT);
  assert.equal(plan!.grantPayload.action, 'ResolveReference');
  assert.equal(plan!.grantPayload.project_id, 'lk_proj_demo');
  assert.equal(plan!.grantPayload.profile_id, 'prof-dev');
  assert.equal(plan!.grantPayload.ttl_seconds, 60);
  assert.deepEqual(plan!.grantPayload.binding, { pid: 4242, process_start_time: 'start-token' });
});

test('planTerminalAutobind returns undefined when no Locket project resolves', () => {
  const context: TerminalAutobindContext = {
    resolveProject: () => undefined,
    pid: 1,
    processStartTime: 'start',
  };
  assert.equal(planTerminalAutobind('/elsewhere', context), undefined);
  assert.equal(planTerminalAutobind(undefined, context), undefined);
});

test('WarnOnceLatch fires exactly once until reset', () => {
  const latch = new WarnOnceLatch();
  assert.equal(latch.shouldFire(), true);
  assert.equal(latch.shouldFire(), false);
  assert.equal(latch.shouldFire(), false);
  latch.reset();
  assert.equal(latch.shouldFire(), true);
  assert.equal(latch.shouldFire(), false);
});
