import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';

const PROTOCOL_VERSION = 1;
const DEFAULT_MAX_MESSAGE_SIZE = 1024 * 1024;
const DEFAULT_CONNECT_TIMEOUT_MS = 2_000;

export type AgentMethod =
  | 'Status'
  | 'Unlock'
  | 'Lock'
  | 'RegisterClient'
  | 'RevokeClient'
  | 'RequestGrant'
  | 'RevokeGrant'
  | 'ExpireGrant'
  | 'ResolveReference'
  | 'PrepareExec'
  | 'ScanKnownValues'
  | 'Reveal'
  | 'Copy'
  | 'SubscribeStatus'
  | 'CancelSubscription'
  | 'ClientHello';

export type LockState = 'locked' | 'unlocked' | 'unknown';
export type StatusEventKind = 'status' | 'heartbeat';

export interface StatusPayload {
  readonly lock_state: LockState;
  readonly project_id?: string | null;
  readonly profile_name?: string | null;
  readonly live_grant_count: number;
  readonly agent_version: string;
  readonly unlock_ttl_seconds?: number | null;
}

export interface StatusEvent extends StatusPayload {
  readonly kind: StatusEventKind;
  readonly sequence: number;
}

export interface AgentClientOptions {
  readonly socketPath?: string;
  readonly connectTimeoutMs?: number;
  readonly maxMessageSize?: number;
}

export interface AgentProtocolErrorBody {
  readonly error: string;
  readonly message: string;
  readonly retryable: boolean;
}

export interface RequestEnvelope {
  readonly v: typeof PROTOCOL_VERSION;
  readonly id: string;
  readonly kind: AgentMethod;
  readonly payload: unknown;
}

export interface SuccessEnvelope {
  readonly v: typeof PROTOCOL_VERSION;
  readonly id: string;
  readonly ok: true;
  readonly payload: unknown;
}

export interface ErrorEnvelope {
  readonly v: typeof PROTOCOL_VERSION;
  readonly id: string;
  readonly ok: false;
  readonly error: string;
  readonly message: string;
  readonly retryable: boolean;
}

export type ResponseEnvelope = SuccessEnvelope | ErrorEnvelope;

type SocketFactory = (socketPath: string) => net.Socket;

export class AgentClientError extends Error {
  public readonly kind: 'unavailable' | 'protocol' | 'agent';
  public readonly code?: string;
  public readonly retryable: boolean;

  private constructor(
    kind: AgentClientError['kind'],
    message: string,
    retryable: boolean,
    code?: string,
  ) {
    super(message);
    this.name = 'AgentClientError';
    this.kind = kind;
    this.code = code;
    this.retryable = retryable;
  }

  public static unavailable(message: string): AgentClientError {
    return new AgentClientError('unavailable', message, true);
  }

  public static protocol(message: string): AgentClientError {
    return new AgentClientError('protocol', message, false);
  }

  public static agent(error: AgentProtocolErrorBody): AgentClientError {
    return new AgentClientError('agent', error.message, error.retryable, error.error);
  }
}

export class AgentClient {
  private readonly socketPath: string;
  private readonly connectTimeoutMs: number;
  private readonly maxMessageSize: number;
  private readonly socketFactory: SocketFactory;
  private nextRequestId = 1;

  public constructor(options: AgentClientOptions = {}, socketFactory: SocketFactory = connectSocket) {
    this.socketPath = options.socketPath ?? resolveAgentSocketPath();
    this.connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    this.maxMessageSize = options.maxMessageSize ?? DEFAULT_MAX_MESSAGE_SIZE;
    this.socketFactory = socketFactory;
  }

  public async status(): Promise<StatusPayload> {
    return this.invoke<StatusPayload>('Status', {});
  }

  public dispose(): void {
    // Connections are opened per request and closed immediately.
  }

  public async invoke<TPayload>(method: AgentMethod, payload: unknown): Promise<TPayload> {
    const request = this.requestEnvelope(method, payload);
    const socket = await this.openSocket();

    try {
      socket.write(encodeFrame(request, this.maxMessageSize));
      const response = await readOneResponse(socket, this.maxMessageSize);
      if (response.id !== request.id) {
        throw AgentClientError.protocol('agent response id did not match request id');
      }
      return unwrapResponse<TPayload>(response);
    } finally {
      socket.end();
      socket.destroy();
    }
  }

  public async subscribeStatus(
    onEvent: (event: StatusEvent) => void,
    onError: (error: AgentClientError) => void,
  ): Promise<{ dispose: () => void }> {
    const request = this.requestEnvelope('SubscribeStatus', {});
    const socket = await this.openSocket();
    let buffer = Buffer.alloc(0);
    let disposed = false;

    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      try {
        while (buffer.length >= 4) {
          const decoded = tryDecodeFrame(buffer, this.maxMessageSize);
          if (decoded === undefined) {
            return;
          }
          buffer = buffer.subarray(decoded.consumed);
          if (decoded.response.id !== request.id) {
            throw AgentClientError.protocol('agent stream response id did not match request id');
          }
          onEvent(unwrapResponse<StatusEvent>(decoded.response));
        }
      } catch (error) {
        onError(toClientError(error));
        socket.destroy();
      }
    });
    socket.on('error', (error: Error) => {
      if (!disposed) {
        onError(AgentClientError.unavailable(error.message));
      }
    });
    socket.write(encodeFrame(request, this.maxMessageSize));

    return {
      dispose: () => {
        disposed = true;
        socket.end();
        socket.destroy();
      },
    };
  }

  private requestEnvelope(method: AgentMethod, payload: unknown): RequestEnvelope {
    const id = `vscode-${Date.now()}-${this.nextRequestId}`;
    this.nextRequestId += 1;
    return { v: PROTOCOL_VERSION, id, kind: method, payload };
  }

  private async openSocket(): Promise<net.Socket> {
    const socket = this.socketFactory(this.socketPath);
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        socket.destroy();
        reject(AgentClientError.unavailable('agent socket connection timed out'));
      }, this.connectTimeoutMs);

      socket.once('connect', () => {
        clearTimeout(timeout);
        resolve(socket);
      });
      socket.once('error', (error: Error) => {
        clearTimeout(timeout);
        reject(AgentClientError.unavailable(error.message));
      });
    });
  }
}

export function resolveAgentSocketPath(environment: NodeJS.ProcessEnv = process.env): string {
  const override = environment.LOCKET_AGENT_SOCKET?.trim();
  if (override !== undefined && override.length > 0) {
    return override;
  }
  return path.join(os.homedir(), '.locket', 'agent.sock');
}

export function encodeFrame(envelope: RequestEnvelope, maxMessageSize = DEFAULT_MAX_MESSAGE_SIZE): Buffer {
  const payload = Buffer.from(JSON.stringify(envelope), 'utf8');
  if (payload.length > maxMessageSize) {
    throw AgentClientError.protocol('agent request frame exceeds maximum size');
  }
  const frame = Buffer.allocUnsafe(4 + payload.length);
  frame.writeUInt32LE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

function readOneResponse(socket: net.Socket, maxMessageSize: number): Promise<ResponseEnvelope> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      try {
        const decoded = tryDecodeFrame(buffer, maxMessageSize);
        if (decoded !== undefined) {
          resolve(decoded.response);
        }
      } catch (error) {
        reject(error);
      }
    });
    socket.once('error', (error: Error) => {
      reject(AgentClientError.unavailable(error.message));
    });
    socket.once('close', () => {
      reject(AgentClientError.unavailable('agent socket closed before response'));
    });
  });
}

function tryDecodeFrame(
  buffer: Buffer,
  maxMessageSize: number,
): { response: ResponseEnvelope; consumed: number } | undefined {
  if (buffer.length < 4) {
    return undefined;
  }
  const length = buffer.readUInt32LE(0);
  if (length > maxMessageSize) {
    throw AgentClientError.protocol('agent response frame exceeds maximum size');
  }
  const consumed = 4 + length;
  if (buffer.length < consumed) {
    return undefined;
  }
  let response: unknown;
  try {
    response = JSON.parse(buffer.subarray(4, consumed).toString('utf8')) as unknown;
  } catch (error) {
    throw AgentClientError.protocol(error instanceof Error ? error.message : 'agent response JSON is invalid');
  }
  return { response: parseResponseEnvelope(response), consumed };
}

function parseResponseEnvelope(value: unknown): ResponseEnvelope {
  if (!isRecord(value) || value.v !== PROTOCOL_VERSION || typeof value.id !== 'string') {
    throw AgentClientError.protocol('agent response envelope is invalid');
  }
  if (value.ok === true && 'payload' in value) {
    return { v: PROTOCOL_VERSION, id: value.id, ok: true, payload: value.payload };
  }
  if (
    value.ok === false &&
    typeof value.error === 'string' &&
    typeof value.message === 'string' &&
    typeof value.retryable === 'boolean'
  ) {
    return {
      v: PROTOCOL_VERSION,
      id: value.id,
      ok: false,
      error: value.error,
      message: value.message,
      retryable: value.retryable,
    };
  }
  throw AgentClientError.protocol('agent response envelope is invalid');
}

function unwrapResponse<TPayload>(response: ResponseEnvelope): TPayload {
  if (!response.ok) {
    throw AgentClientError.agent(response);
  }
  return response.payload as TPayload;
}

function connectSocket(socketPath: string): net.Socket {
  return net.createConnection(socketPath);
}

function toClientError(error: unknown): AgentClientError {
  if (error instanceof AgentClientError) {
    return error;
  }
  if (error instanceof Error) {
    return AgentClientError.protocol(error.message);
  }
  return AgentClientError.protocol('unknown agent client failure');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
