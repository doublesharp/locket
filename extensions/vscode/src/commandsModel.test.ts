import * as fs from 'node:fs';
import * as path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { AgentClientError } from './agentClient';
import {
  LOCKET_COMMAND_ROUTES,
  agentErrorMessage,
  buildListAuditRequest,
  buildListPoliciesRequest,
  buildLockRequest,
  buildScanKnownValuesRequest,
  buildSetActiveProfileRequest,
} from './commandsModel';

test('lock request always reports the desktop session-lock source', () => {
  assert.deepEqual(buildLockRequest(), { source: 'desktop' });
});

test('switch profile request trims fields and uses agent payload shape', () => {
  assert.deepEqual(
    buildSetActiveProfileRequest(
      ' /tmp/locket.toml ',
      ' /tmp/store.db ',
      ' lk_proj_a ',
      ' dev ',
    ),
    {
      config_path: '/tmp/locket.toml',
      store_path: '/tmp/store.db',
      project_id: 'lk_proj_a',
      profile_name: 'dev',
      privacy_redact_names: false,
    },
  );
});

test('switch profile request rejects blank fields', () => {
  assert.throws(
    () => buildSetActiveProfileRequest('', '/tmp/store.db', 'lk_proj_a', 'dev'),
    /config path is required/u,
  );
  assert.throws(
    () => buildSetActiveProfileRequest('/tmp/locket.toml', '', 'lk_proj_a', 'dev'),
    /store path is required/u,
  );
  assert.throws(
    () => buildSetActiveProfileRequest('/tmp/locket.toml', '/tmp/store.db', '', 'dev'),
    /project id is required/u,
  );
  assert.throws(
    () => buildSetActiveProfileRequest('/tmp/locket.toml', '/tmp/store.db', 'lk_proj_a', ''),
    /profile name is required/u,
  );
});

test('list policies request requires a project id', () => {
  assert.deepEqual(buildListPoliciesRequest(' lk_proj_a '), {
    project_id: 'lk_proj_a',
    privacy_redact_names: false,
  });
  assert.throws(() => buildListPoliciesRequest(''), /project id is required/u);
});

test('scan workspace request filters blank paths and never sets require_known', () => {
  const request = buildScanKnownValuesRequest(['/repo/a', '   ', '/repo/b']);
  assert.deepEqual(request.paths, ['/repo/a', '/repo/b']);
  assert.equal(request.require_known, false);
  assert.equal(request.redact_names, false);
});

test('list audit request bounds the limit and trims fields', () => {
  const request = buildListAuditRequest(' /tmp/store.db ', ' lk_proj_a ');
  assert.equal(request.store_path, '/tmp/store.db');
  assert.equal(request.project_id, 'lk_proj_a');
  assert.equal(request.limit, 200);
  assert.equal(request.redact_names, false);
});

test('list audit request rejects blank required fields', () => {
  assert.throws(() => buildListAuditRequest('', 'lk_proj_a'), /store path is required/u);
  assert.throws(() => buildListAuditRequest('/tmp/store.db', ''), /project id is required/u);
});

test('command routing table covers every spec command and uses unique ids', () => {
  const expected = [
    { commandId: 'locket.unlock', agentMethod: 'Unlock' },
    { commandId: 'locket.lock', agentMethod: 'Lock' },
    { commandId: 'locket.switchProfile', agentMethod: 'SetActiveProfile' },
    { commandId: 'locket.runPolicy', agentMethod: 'ListPolicies' },
    { commandId: 'locket.scanWorkspace', agentMethod: 'ScanKnownValues' },
    { commandId: 'locket.revealSecret', agentMethod: 'Reveal' },
    { commandId: 'locket.copySecret', agentMethod: 'Copy' },
    { commandId: 'locket.openAuditView', agentMethod: 'ListAudit' },
  ];
  assert.deepEqual([...LOCKET_COMMAND_ROUTES], expected);

  const ids = LOCKET_COMMAND_ROUTES.map((row) => row.commandId);
  assert.equal(new Set(ids).size, ids.length, 'command ids must be unique');
});

test('package.json declares every routed command id and lists them in the palette', () => {
  // Compiled tests live in `out/`; the manifest is one level up.
  const manifestPath = path.resolve(__dirname, '..', 'package.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
    contributes?: {
      commands?: ReadonlyArray<{ command: string; title?: string; category?: string }>;
      menus?: { commandPalette?: ReadonlyArray<{ command: string; when?: string }> };
    };
  };
  const declared = new Set(
    (manifest.contributes?.commands ?? []).map((entry) => entry.command),
  );
  const palette = new Set(
    (manifest.contributes?.menus?.commandPalette ?? []).map((entry) => entry.command),
  );
  for (const route of LOCKET_COMMAND_ROUTES) {
    assert.ok(
      declared.has(route.commandId),
      `package.json missing contributes.commands entry for ${route.commandId}`,
    );
    assert.ok(
      palette.has(route.commandId),
      `package.json missing commandPalette entry for ${route.commandId}`,
    );
  }
});

test('agent error message uses typed display copy when available', () => {
  const unlockRequired = AgentClientError.agent({
    error: 'UnlockRequired',
    message: 'unlock required',
    retryable: false,
  });
  assert.equal(
    agentErrorMessage(unlockRequired),
    'The vault is locked. Run locket unlock or approve an agent unlock prompt.',
  );

  assert.equal(
    agentErrorMessage(AgentClientError.unavailable('socket gone')),
    'The local agent is unavailable. Run locket agent start, then retry.',
  );

  assert.equal(
    agentErrorMessage(AgentClientError.protocol('bad frame')),
    'Locket agent protocol error: bad frame',
  );

  assert.equal(agentErrorMessage('not an error object'), 'Locket command failed.');
});
