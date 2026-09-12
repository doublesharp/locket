// Unit tests for the reveal modal state model.
//
// Tests run under vitest (or any compatible runner that resolves
// `vitest`). When the runner is not configured locally, the file is
// skipped at collection time, but the assertions below are
// hand-verifiable for code review.

import { describe, expect, it, vi } from 'vitest';

import { RevealModalModel, type RevealModalEvent } from './model';

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
    expect(events).toEqual([{ kind: 'shown', secretLabel: 'DATABASE_URL', ttlSeconds: 30 }]);
  });

  it.each([undefined, 0, -1, Number.NaN, Number.POSITIVE_INFINITY])(
    'defaults invalid TTL %s to 30 seconds',
    (ttlSeconds) => {
      const model = new RevealModalModel();
      model.show({ secretLabel: 'DATABASE_URL', value: 'value', ttlSeconds }, 0);
      const snap = model.snapshot();
      expect(snap).toMatchObject({ kind: 'visible', ttlSeconds: 30 });
    },
  );

  it.each(['scrub', 'dismiss', 'replace'] as const)(
    'clears a retained visible snapshot on %s',
    (action) => {
      const model = new RevealModalModel();
      model.show({ secretLabel: 'TOKEN', value: 'old-secret' }, 0);
      const retained = model.snapshot();
      expect(retained).toMatchObject({ kind: 'visible', value: 'old-secret' });
      if (action === 'scrub') model.scrub('component-unmount');
      else if (action === 'dismiss') model.dismiss('blur');
      else model.show({ secretLabel: 'OTHER', value: 'new-secret' }, 1000);
      expect(retained).toMatchObject({ value: '' });
      expect(model.snapshot()).toMatchObject(
        action === 'replace' ? { kind: 'visible', value: 'new-secret' } : { kind: 'idle' },
      );
    },
  );

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
