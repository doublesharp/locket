import { describe, expect, it, vi } from 'vitest';
import { captureSelection, withCurrentSelection, initialProjectSelection } from './selection';
import type { DesktopProjectContext } from '../agent/types';
const project = (name: string): DesktopProjectContext => ({
  root: '/fixture/' + name,
  project_id: name,
  project_name: name,
  profile_id: name + '-real-id',
  profile_name: 'development',
});
function deferred<T>() {
  let resolve!: (result: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
describe('pending environment switch ownership', () => {
  it('ignores a deferred project A response after connecting B', async () => {
    let selected = project('A');
    let generation = 1;
    const captured = captureSelection(selected, generation)!;
    const pending = deferred<{ profile_id: string; profile_name: string }>();
    const applied = vi.fn();
    const switching = withCurrentSelection(
      captured,
      () => captureSelection(selected, generation),
      () => pending.promise,
      (response) => {
        applied(response);
        selected = { ...selected, ...response };
      },
    );
    selected = project('B');
    generation++;
    pending.resolve({ profile_id: 'A-production-id', profile_name: 'production' });
    expect(await switching).toBe(false);
    expect(applied).not.toHaveBeenCalled();
    expect(selected).toEqual(project('B'));
  });
  it('rejects an old response after leaving and reselecting the same project', async () => {
    const selected = project('A');
    let generation = 1;
    const captured = captureSelection(selected, generation)!;
    const pending = deferred<string>();
    const applied = vi.fn();
    const switching = withCurrentSelection(
      captured,
      () => captureSelection(selected, generation),
      () => pending.promise,
      applied,
    );
    generation += 2;
    pending.resolve('old');
    expect(await switching).toBe(false);
    expect(applied).not.toHaveBeenCalled();
  });
  it('applies success or rejection only to its unchanged captured context', async () => {
    const captured = captureSelection(project('A'), 1)!;
    const applied = vi.fn();
    expect(
      await withCurrentSelection(
        captured,
        () => captured,
        async () => ({ ok: false, reason: 'Denied' }),
        applied,
      ),
    ).toBe(true);
    expect(applied).toHaveBeenCalledWith({ ok: false, reason: 'Denied' });
  });
});
describe('initial known-project selection', () => {
  it('selects the sole known project without global status identity', () => {
    expect(initialProjectSelection([project('A')], null)).toEqual(project('A'));
  });
  it('leaves multiple choices unselected and preserves explicit selection', () => {
    expect(initialProjectSelection([project('A'), project('B')], null)).toBeNull();
    expect(initialProjectSelection([project('A')], project('B'))).toEqual(project('B'));
  });
});

it('invalidates a switch as soon as a new connection starts, before its metadata arrives', async () => {
  const selected = project('A');
  let generation = 1;
  const captured = captureSelection(selected, generation)!;
  const pending = deferred<string>();
  const applied = vi.fn();
  const switching = withCurrentSelection(
    captured,
    () => captureSelection(selected, generation),
    () => pending.promise,
    applied,
  );
  generation++;
  pending.resolve('A-late');
  expect(await switching).toBe(false);
  expect(applied).not.toHaveBeenCalled();
});
