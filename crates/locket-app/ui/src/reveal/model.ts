// Reveal modal state model.
//
// Pure (non-Vue) state machine that owns:
//
//   - the secret value displayed by the modal,
//   - the TTL deadline at which the value must be scrubbed,
//   - the dismissal reason emitted to subscribers when the value
//     leaves the modal.
//
// Living outside the Vue runtime means the contract is unit-testable
// without spinning up jsdom: every state transition emits a typed
// event that subscribers can observe directly.

export interface RevealRequest {
  /** Stable label rendered in the modal heading; never the value. */
  secretLabel: string;
  /** Plaintext returned by the agent's `Reveal` RPC. */
  value: string;
  /** TTL in seconds. Defaults to 30 when missing or non-positive. */
  ttlSeconds?: number;
}

export type RevealModalState =
  | { kind: 'idle' }
  | {
      kind: 'visible';
      secretLabel: string;
      value: string;
      ttlSeconds: number;
      shownAtMs: number;
    };

export type RevealModalEvent =
  | { kind: 'shown'; secretLabel: string; ttlSeconds: number }
  | { kind: 'scrubbed'; reason: ScrubReason }
  | { kind: 'dismissed'; reason: DismissReason };

export type ScrubReason = 'ttl-expired' | 'component-unmount' | 'manual-scrub';
export type DismissReason = 'blur' | 'explicit-close';

export type RevealModalListener = (event: RevealModalEvent) => void;

const DEFAULT_TTL_SECONDS = 30;

export class RevealModalModel {
  private state: RevealModalState = { kind: 'idle' };
  private readonly listeners = new Set<RevealModalListener>();

  /** Current state snapshot. Cheap to call; returns a stable reference. */
  snapshot(): RevealModalState {
    return this.state;
  }

  /** Register an event listener. Returns the unsubscribe function. */
  subscribe(listener: RevealModalListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Show the modal with a freshly resolved value. */
  show(request: RevealRequest, nowMs: number = nowMonotonic()): void {
    const ttl = request.ttlSeconds && request.ttlSeconds > 0
      ? request.ttlSeconds
      : DEFAULT_TTL_SECONDS;
    this.state = {
      kind: 'visible',
      secretLabel: request.secretLabel,
      value: request.value,
      ttlSeconds: ttl,
      shownAtMs: nowMs,
    };
    this.emit({ kind: 'shown', secretLabel: request.secretLabel, ttlSeconds: ttl });
  }

  /** Whole seconds remaining before the value scrubs. Floors to zero. */
  remainingSeconds(nowMs: number = nowMonotonic()): number {
    if (this.state.kind !== 'visible') {
      return 0;
    }
    const elapsedMs = nowMs - this.state.shownAtMs;
    const remainingMs = this.state.ttlSeconds * 1000 - elapsedMs;
    if (remainingMs <= 0) {
      return 0;
    }
    return Math.ceil(remainingMs / 1000);
  }

  /** Whether the TTL has lapsed. */
  isExpired(nowMs: number = nowMonotonic()): boolean {
    if (this.state.kind !== 'visible') {
      return false;
    }
    return nowMs - this.state.shownAtMs >= this.state.ttlSeconds * 1000;
  }

  /**
   * Scrub the displayed value and emit a typed `scrubbed` event. Idempotent:
   * subsequent calls while idle are a no-op.
   */
  scrub(reason: ScrubReason): void {
    if (this.state.kind === 'idle') {
      return;
    }
    this.zeroize();
    this.state = { kind: 'idle' };
    this.emit({ kind: 'scrubbed', reason });
  }

  /**
   * Dismiss the modal at the user's request and emit a typed `dismissed`
   * event. Always scrubs the underlying value first so dismiss-on-blur
   * never leaves plaintext in memory.
   */
  dismiss(reason: DismissReason): void {
    if (this.state.kind === 'idle') {
      return;
    }
    this.zeroize();
    this.state = { kind: 'idle' };
    this.emit({ kind: 'dismissed', reason });
  }

  private zeroize(): void {
    if (this.state.kind === 'visible') {
      // Best-effort plaintext scrub. Strings in JS are immutable so
      // we can't overwrite the underlying buffer; replacing the
      // reference still drops it from the modal so it can't be
      // re-rendered.
      this.state = {
        ...this.state,
        value: '',
      };
    }
  }

  private emit(event: RevealModalEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Listeners must not break sibling listeners.
      }
    }
  }
}

function nowMonotonic(): number {
  if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
    return performance.now();
  }
  return Date.now();
}
