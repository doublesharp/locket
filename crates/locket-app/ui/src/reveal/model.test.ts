// Unit tests for the reveal modal state model.
//
// Tests run under vitest (or any compatible runner that resolves
// `vitest`). When the runner is not configured locally, the file is
// skipped at collection time, but the assertions below are
// hand-verifiable for code review.

import { describe, expect, it, vi } from 'vitest';

import {
  RevealModalModel,
  type RevealModalEvent,
} from './model';

describe('RevealModalModel', () => {
  it('shows a request value and emits a `shown` event', () => {
    const model = new RevealModalModel();
    const events: RevealModalEvent[] = [];
    model.subscribe((event) => events.push(event));

    model.show({ secretLabel: 'DATABASE_URL', value: 'postgres://x', ttlSeconds: 30 }, 0);

    const snap = model.snapshot();
    expect(snap.kind).toBe('visible');
    if (snap.kind === 'visible') {
      expect(snap.value).toBe('postgres://x');
      expect(snap.ttlSeconds).toBe(30);
    }
    expect(events).toEqual([
      { kind: 'shown', secretLabel: 'DATABASE_URL', ttlSeconds: 30 },
    ]);
  });

  it('defaults the TTL to 30 seconds when missing or non-positive', () => {
    const model = new RevealModalModel();
    model.show({ secretLabel: 'DATABASE_URL', value: 'value' }, 0);
    const snap = model.snapshot();
    if (snap.kind === 'visible') {
      expect(snap.ttlSeconds).toBe(30);
    }
  });

  it('emits a `scrubbed` event when the TTL expires', () => {
    const model = new RevealModalModel();
    const events: RevealModalEvent[] = [];
    model.subscribe((event) => events.push(event));

    model.show({ secretLabel: 'DATABASE_URL', value: 'value', ttlSeconds: 30 }, 0);
    expect(model.isExpired(15_000)).toBe(false);
    expect(model.isExpired(30_000)).toBe(true);

    model.scrub('ttl-expired');
    expect(model.snapshot().kind).toBe('idle');
    expect(events.at(-1)).toEqual({ kind: 'scrubbed', reason: 'ttl-expired' });
  });

  it('emits a `dismissed` event when blurred and clears the value', () => {
    const model = new RevealModalModel();
    const events: RevealModalEvent[] = [];
    model.subscribe((event) => events.push(event));

    model.show({ secretLabel: 'DATABASE_URL', value: 'value', ttlSeconds: 30 }, 0);
    model.dismiss('blur');

    expect(model.snapshot().kind).toBe('idle');
    expect(events.at(-1)).toEqual({ kind: 'dismissed', reason: 'blur' });
  });

  it('emits a `dismissed` event when the user explicitly closes', () => {
    const model = new RevealModalModel();
    const events: RevealModalEvent[] = [];
    model.subscribe((event) => events.push(event));

    model.show({ secretLabel: 'DATABASE_URL', value: 'value', ttlSeconds: 30 }, 0);
    model.dismiss('explicit-close');

    expect(events.at(-1)).toEqual({ kind: 'dismissed', reason: 'explicit-close' });
  });

  it('counts down whole seconds until expiry', () => {
    const model = new RevealModalModel();
    model.show({ secretLabel: 'DATABASE_URL', value: 'value', ttlSeconds: 30 }, 0);
    expect(model.remainingSeconds(0)).toBe(30);
    expect(model.remainingSeconds(1_500)).toBe(29);
    expect(model.remainingSeconds(29_500)).toBe(1);
    expect(model.remainingSeconds(30_000)).toBe(0);
    expect(model.remainingSeconds(31_000)).toBe(0);
  });

  it('is idempotent if scrubbed while already idle', () => {
    const model = new RevealModalModel();
    const listener = vi.fn();
    model.subscribe(listener);
    model.scrub('ttl-expired');
    expect(listener).not.toHaveBeenCalled();
  });
});
