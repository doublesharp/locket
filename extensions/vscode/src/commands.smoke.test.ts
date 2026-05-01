// Manifest-consistency smoke test for the VS Code command-palette
// surface. This is *not* a live integration test — it walks every
// entry in `LOCKET_COMMAND_ROUTES`, constructs the wire payload via
// the `commandsModel.ts` builders, and asserts each one matches a
// known-good shape so the manifest, registrar, and agent contract
// cannot drift silently.
//
// The existing `commandsModel.test.ts` covers per-builder edge cases
// (trimming, blank-field rejection, palette presence). This file is
// the matrix-style sweep that complements it: one assertion per
// command id covering the full wire envelope.

import * as fs from 'node:fs';
import * as path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { AgentMethod, RequestEnvelope, encodeFrame } from './agentClient';
import {
  AUDIT_VIEW_LIMIT,
  IDE_SESSION_DEFAULT_TTL_SECONDS,
  LOCKET_COMMAND_ROUTES,
  LOCKET_EDITOR_COMMAND_IDS,
  buildListAuditRequest,
  buildListPoliciesRequest,
  buildLockRequest,
  buildScanKnownValuesRequest,
  buildSetActiveProfileRequest,
  buildUnlockRequest,
} from './commandsModel';
import { buildRevealRequest } from './revealWebview';

// Expected wire payload per command id. Built once with stable inputs
// so any drift in the builders surfaces as a test diff.
const STORE_PATH = '/tmp/locket-smoke/store.db';
const CONFIG_PATH = '/tmp/locket-smoke/locket.toml';
const PROJECT_ID = 'lk_proj_smoke';
const PROFILE_NAME = 'dev';
const PROFILE_ID = 'prof-dev';
const SECRET_NAME = 'DATABASE_URL';
const WORKSPACE_PATHS = ['/repo/main', '/repo/aux'];

const EXPECTED_COMMAND_PAYLOADS: ReadonlyArray<{
  readonly commandId: string;
  readonly agentMethod: AgentMethod | string;
  readonly payload: unknown;
}> = [
  {
    commandId: 'locket.unlock',
    agentMethod: 'Unlock',
    payload: {
      project_id: PROJECT_ID,
      passphrase: null,
      ttl_seconds: IDE_SESSION_DEFAULT_TTL_SECONDS,
      audit: { store_path: STORE_PATH, profile_id: PROFILE_ID },
    },
  },
  {
    commandId: 'locket.lock',
    agentMethod: 'Lock',
    payload: { source: 'desktop' },
  },
  {
    commandId: 'locket.switchProfile',
    agentMethod: 'SetActiveProfile',
    payload: {
      config_path: CONFIG_PATH,
      store_path: STORE_PATH,
      project_id: PROJECT_ID,
      profile_name: PROFILE_NAME,
      privacy_redact_names: false,
    },
  },
  {
    commandId: 'locket.runPolicy',
    agentMethod: 'ListPolicies',
    payload: { project_id: PROJECT_ID, privacy_redact_names: false },
  },
  {
    commandId: 'locket.scanWorkspace',
    agentMethod: 'ScanKnownValues',
    payload: {
      paths: WORKSPACE_PATHS,
      require_known: false,
      redact_names: false,
    },
  },
  {
    commandId: 'locket.revealSecret',
    agentMethod: 'Reveal',
    payload: { secret_name: SECRET_NAME, profile_id: PROFILE_ID },
  },
  {
    commandId: 'locket.copySecret',
    agentMethod: 'Copy',
    // `Copy` reuses the same builder as `Reveal` because the agent
    // contract for both gated-access flows is identical.
    payload: { secret_name: SECRET_NAME, profile_id: PROFILE_ID },
  },
  {
    commandId: 'locket.openAuditView',
    agentMethod: 'ListAudit',
    payload: {
      store_path: STORE_PATH,
      project_id: PROJECT_ID,
      limit: AUDIT_VIEW_LIMIT,
      redact_names: false,
    },
  },
];

// Construct the live payload for a given command id from the real
// `commandsModel.ts` builders. The dispatch table is intentionally
// flat so any new command id added to `LOCKET_COMMAND_ROUTES` without
// a smoke entry trips the exhaustive sweep below.
function buildPayloadForCommand(commandId: string): unknown {
  switch (commandId) {
    case 'locket.unlock':
      return buildUnlockRequest(PROJECT_ID, STORE_PATH, PROFILE_ID, null);
    case 'locket.lock':
      return buildLockRequest();
    case 'locket.switchProfile':
      return buildSetActiveProfileRequest(CONFIG_PATH, STORE_PATH, PROJECT_ID, PROFILE_NAME);
    case 'locket.runPolicy':
      return buildListPoliciesRequest(PROJECT_ID);
    case 'locket.scanWorkspace':
      return buildScanKnownValuesRequest(WORKSPACE_PATHS);
    case 'locket.revealSecret':
    case 'locket.copySecret':
      return buildRevealRequest(SECRET_NAME, PROFILE_ID);
    case 'locket.openAuditView':
      return buildListAuditRequest(STORE_PATH, PROJECT_ID);
    default:
      throw new Error(`smoke matrix missing payload builder for ${commandId}`);
  }
}

test('every routed command builds the expected agent payload shape', () => {
  // Per-command shape sweep. Order-stable comparisons make drift
  // diffs easy to read in CI.
  for (const expected of EXPECTED_COMMAND_PAYLOADS) {
    const actual = buildPayloadForCommand(expected.commandId);
    assert.deepEqual(
      actual,
      expected.payload,
      `payload shape drift for ${expected.commandId}`,
    );
  }

  // Cross-check: the smoke matrix must cover every route the
  // registrar exports and nothing more.
  const matrixIds = EXPECTED_COMMAND_PAYLOADS.map((entry) => entry.commandId).sort();
  const routeIds = LOCKET_COMMAND_ROUTES.map((route) => route.commandId).sort();
  assert.deepEqual(matrixIds, routeIds, 'smoke matrix must mirror LOCKET_COMMAND_ROUTES');

  // Cross-check: every smoke entry's agentMethod must agree with the
  // registrar's route table.
  for (const entry of EXPECTED_COMMAND_PAYLOADS) {
    const route = LOCKET_COMMAND_ROUTES.find((row) => row.commandId === entry.commandId);
    assert.ok(route, `route missing for ${entry.commandId}`);
    assert.equal(
      route.agentMethod,
      entry.agentMethod,
      `agentMethod mismatch for ${entry.commandId}`,
    );
  }
});

test('AgentMethod union covers every method id the registrar dispatches', () => {
  // The TypeScript compiler already enforces this for direct
  // `agentClient.invoke<...>(method, ...)` call sites, but
  // `LOCKET_COMMAND_ROUTES` stores the method as a plain string so the
  // table can survive lints across editor/agent boundaries. Here we
  // re-check at runtime that every routed method either exists in the
  // current `AgentMethod` union *or* is a server-side method the
  // extension still treats as a valid dispatch target via `invoke`.
  const knownAgentMethods: ReadonlySet<AgentMethod> = new Set<AgentMethod>([
    'Status',
    'Unlock',
    'Lock',
    'RegisterClient',
    'RevokeClient',
    'RequestGrant',
    'RevokeGrant',
    'ExpireGrant',
    'ResolveReference',
    'PrepareExec',
    'ScanKnownValues',
    'Reveal',
    'Copy',
    'SubscribeStatus',
    'CancelSubscription',
    'ClientHello',
  ]);
  // Server-side methods the registrar dispatches through `invoke` that
  // are not yet in the typed `AgentMethod` union. Any addition here
  // must be matched by a follow-up that widens the union.
  const acceptedExtraMethods: ReadonlySet<string> = new Set<string>([
    'SetActiveProfile',
    'ListPolicies',
    'ListAudit',
  ]);
  for (const route of LOCKET_COMMAND_ROUTES) {
    const known = (knownAgentMethods as ReadonlySet<string>).has(route.agentMethod);
    const extra = acceptedExtraMethods.has(route.agentMethod);
    assert.ok(
      known || extra,
      `route ${route.commandId} -> ${route.agentMethod} is not in AgentMethod nor the accepted-extra allowlist`,
    );
  }
});

test('every editor command id appears in package.json contributes.commands', () => {
  // Compiled tests live in `out/`; the manifest is one level up.
  const manifestPath = path.resolve(__dirname, '..', 'package.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
    contributes?: { commands?: ReadonlyArray<{ command: string }> };
  };
  const declared = new Set(
    (manifest.contributes?.commands ?? []).map((entry) => entry.command),
  );
  for (const commandId of LOCKET_EDITOR_COMMAND_IDS) {
    assert.ok(
      declared.has(commandId),
      `package.json missing contributes.commands entry for ${commandId}`,
    );
  }
  // Reverse direction: package.json must not contribute commands the
  // command or terminal registrars will ignore.
  for (const id of declared) {
    assert.ok(
      LOCKET_EDITOR_COMMAND_IDS.includes(id),
      `package.json contributes ${id} with no registrar route`,
    );
  }
});

test('AgentMethod values encode through the wire frame for every routed command', () => {
  // Build a request envelope per route and round-trip it through the
  // shared `encodeFrame` helper to prove the wire shape is well-formed.
  for (const route of LOCKET_COMMAND_ROUTES) {
    const envelope: RequestEnvelope = {
      v: 1,
      id: `smoke-${route.commandId}`,
      // The registry stores the method as a plain string (see
      // `LOCKET_COMMAND_ROUTES`); cast through `unknown` because some
      // server-side methods are not yet in the typed `AgentMethod`
      // union (`SetActiveProfile`, `ListPolicies`, `ListAudit`).
      kind: route.agentMethod as unknown as AgentMethod,
      payload: buildPayloadForCommand(route.commandId),
    };
    const frame = encodeFrame(envelope);
    assert.ok(frame.length > 4, `${route.commandId} frame must include a body`);
    const declaredLength = frame.readUInt32LE(0);
    assert.equal(
      declaredLength,
      frame.length - 4,
      `${route.commandId} length prefix must equal body length`,
    );
    const decoded = JSON.parse(
      frame.subarray(4, 4 + declaredLength).toString('utf8'),
    ) as RequestEnvelope;
    assert.equal(decoded.kind, route.agentMethod);
    assert.equal(decoded.id, envelope.id);
    assert.deepEqual(decoded.payload, envelope.payload);
  }
});
