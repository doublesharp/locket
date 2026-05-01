import { mkdtemp, rm } from 'node:fs/promises';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { AgentClient, RequestEnvelope } from './agentClient';
import { ResolvedLocketProject } from './commandsModel';
import { LOCKET_IDE_ENV_SESSION_VARIABLE } from './ideEnvSession';
import { WarnOnceLatch } from './terminalAutobindModel';
import {
  TerminalAutobindHandlerDeps,
  handleOpenTerminal,
  requestDirectoryGrant,
} from './terminalAutobindHandler';

const PROJECT: ResolvedLocketProject = {
  root: '/workspace/demo',
  projectId: 'lk_proj_demo',
  defaultProfileId: 'prof-dev',
};

test('handleOpenTerminal injects LOCKET_IDE_ENV_SESSION and fires a RequestGrant on terminal open', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const observed: RequestEnvelope[] = [];
  const grantBarrier = createBarrier();
  const server = net.createServer((socket) => {
    socket.on('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      observed.push(request);
      if (request.kind === 'ListPolicies') {
        socket.write(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: {
              rows: [
                {
                  id: 'p1',
                  name: 'deploy',
                  allowed_secrets: ['DATABASE_URL'],
                },
              ],
            },
          }),
        );
        return;
      }
      if (request.kind === 'RegisterIdeEnvSession') {
        socket.write(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: { session_id: 'session-uuid', ttl_seconds: 1800 },
          }),
        );
        return;
      }
      if (request.kind === 'RequestGrant') {
        socket.end(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: {
              grant_id: 'lk_grant_test',
              ttl_seconds: 1800,
              expires_at_unix_nanos: 1,
            },
          }),
        );
        grantBarrier.resolve();
      }
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const collectionMutations: Array<['replace', string, string]> = [];
    const warnings: string[] = [];
    const deps: TerminalAutobindHandlerDeps = {
      agentClient: client,
      environmentVariableCollection: {
        replace: (name, value) => collectionMutations.push(['replace', name, value]),
        delete: () => undefined,
      },
      autobindContext: {
        resolveProject: () => PROJECT,
        pid: 4242,
        processStartTime: 'start-token',
        ttlSeconds: 1800,
      },
      storePath: '/tmp/store.db',
      notifyDirectoryGrantRejected: (reason) => warnings.push(reason),
      warnOnce: new WarnOnceLatch(),
    };

    const outcome = await handleOpenTerminal('/workspace/demo', deps);
    await grantBarrier.promise;

    assert.equal(outcome.applied, true);
    assert.equal(outcome.sessionId, 'session-uuid');
    assert.deepEqual(collectionMutations, [
      ['replace', LOCKET_IDE_ENV_SESSION_VARIABLE, 'session-uuid'],
    ]);
    const grantRequest = observed.find((r) => r.kind === 'RequestGrant');
    assert.notEqual(grantRequest, undefined);
    const body = grantRequest!.payload as Record<string, unknown>;
    assert.equal(body.action, 'ResolveReference');
    assert.equal(body.project_id, 'lk_proj_demo');
    assert.equal(body.profile_id, 'prof-dev');
    assert.deepEqual(body.binding, { pid: 4242, process_start_time: 'start-token' });
    assert.equal(warnings.length, 0);
  } finally {
    server.close();
    await cleanup();
  }
});

test('handleOpenTerminal returns applied:false outside a Locket project', async () => {
  const deps: TerminalAutobindHandlerDeps = {
    agentClient: new AgentClient({ socketPath: '/dev/null', connectTimeoutMs: 100 }),
    environmentVariableCollection: { replace: () => undefined, delete: () => undefined },
    autobindContext: {
      resolveProject: () => undefined,
      pid: 1,
      processStartTime: 'x',
    },
    storePath: '/tmp/store.db',
    notifyDirectoryGrantRejected: () => undefined,
    warnOnce: new WarnOnceLatch(),
  };
  const outcome = await handleOpenTerminal('/elsewhere', deps);
  assert.deepEqual(outcome, { applied: false });
});

test('requestDirectoryGrant fires a once-per-session warning on agent rejection', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const server = net.createServer((socket) => {
    socket.on('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      socket.end(
        encodeResponse({
          v: 1,
          id: request.id,
          ok: false,
          error: 'ProjectRootUntrusted',
          message: 'directory not trusted',
          retryable: false,
        }),
      );
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const warnings: string[] = [];
    const warnOnce = new WarnOnceLatch();
    const baseDeps: TerminalAutobindHandlerDeps = {
      agentClient: client,
      environmentVariableCollection: { replace: () => undefined, delete: () => undefined },
      autobindContext: {
        resolveProject: () => PROJECT,
        pid: 1,
        processStartTime: 'x',
      },
      storePath: '/tmp/store.db',
      notifyDirectoryGrantRejected: (reason) => warnings.push(reason),
      warnOnce,
    };
    const grantPayload = {
      project_id: PROJECT.projectId,
      profile_id: PROJECT.defaultProfileId,
      action: 'ResolveReference' as const,
      ttl_seconds: 60,
      binding: { pid: 1, process_start_time: 'x' },
    };

    await requestDirectoryGrant(baseDeps, grantPayload);
    await requestDirectoryGrant(baseDeps, grantPayload);
    await requestDirectoryGrant(baseDeps, grantPayload);

    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /not trusted/u);
  } finally {
    server.close();
    await cleanup();
  }
});

function createBarrier(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolveFn: () => void = () => undefined;
  const promise = new Promise<void>((resolve) => {
    resolveFn = resolve;
  });
  return { promise, resolve: () => resolveFn() };
}

async function temporarySocketPath(): Promise<{ socketPath: string; cleanup: () => Promise<void> }> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'locket-vscode-autobind-'));
  return {
    socketPath: path.join(directory, 'agent.sock'),
    cleanup: () => rm(directory, { recursive: true, force: true }),
  };
}

function listen(server: net.Server, socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

function decodeRequest(frame: Buffer): RequestEnvelope {
  const length = frame.readUInt32LE(0);
  return JSON.parse(frame.subarray(4, 4 + length).toString('utf8')) as RequestEnvelope;
}

function encodeResponse(response: object): Buffer {
  const payload = Buffer.from(JSON.stringify(response), 'utf8');
  const frame = Buffer.allocUnsafe(4 + payload.length);
  frame.writeUInt32LE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}
