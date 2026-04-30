import { mkdtemp, rm } from 'node:fs/promises';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { AgentClient, AgentClientError, RequestEnvelope, resolveAgentSocketPath } from './agentClient';

test('status round trips over the agent socket frame protocol', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const server = net.createServer((socket) => {
    socket.once('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      assert.equal(request.kind, 'Status');
      socket.end(
        encodeResponse({
          v: 1,
          id: request.id,
          ok: true,
          payload: {
            lock_state: 'locked',
            project_id: null,
            profile_name: null,
            live_grant_count: 0,
            agent_version: 'test-agent',
            unlock_ttl_seconds: null,
          },
        }),
      );
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const status = await client.status();
    assert.equal(status.lock_state, 'locked');
    assert.equal(status.agent_version, 'test-agent');
    assert.equal(status.live_grant_count, 0);
  } finally {
    server.close();
    await cleanup();
  }
});

test('agent error envelopes become typed client errors', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const server = net.createServer((socket) => {
    socket.once('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      socket.end(
        encodeResponse({
          v: 1,
          id: request.id,
          ok: false,
          error: 'UnlockRequired',
          message: 'unlock required',
          retryable: false,
        }),
      );
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    await assert.rejects(
      () => client.invoke('Reveal', {}),
      (error: unknown) => {
        assert.ok(error instanceof AgentClientError);
        assert.equal(error.kind, 'agent');
        assert.equal(error.code, 'UnlockRequired');
        assert.equal(error.message, 'unlock required');
        assert.equal(error.retryable, false);
        return true;
      },
    );
  } finally {
    server.close();
    await cleanup();
  }
});

test('socket path honors LOCKET_AGENT_SOCKET override', () => {
  assert.equal(resolveAgentSocketPath({ LOCKET_AGENT_SOCKET: '/tmp/locket-test.sock' }), '/tmp/locket-test.sock');
});

async function temporarySocketPath(): Promise<{ socketPath: string; cleanup: () => Promise<void> }> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'locket-vscode-agent-'));
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
