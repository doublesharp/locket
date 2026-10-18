import { describe, expect, it } from 'vitest';
import { startHereActions, type StartHereInput } from './startHere';
const input = (patch: Partial<StartHereInput> = {}): StartHereInput => ({
  projectConnected: true,
  connected: true,
  lockLabel: 'Unlocked',
  secrets: [],
  policies: [],
  sessions: [],
  auditRows: [],
  findings: [],
  auditChainOk: null,
  secretsLoaded: true,
  policiesLoaded: true,
  ...patch,
});
describe('the first useful setup action', () => {
  it('connects a project before starting the agent', () => {
    expect(
      startHereActions(input({ projectConnected: false, connected: false })).map((x) => x.id),
    ).toEqual(['open-project']);
  });
  it('starts a disconnected agent first', () => {
    expect(startHereActions(input({ connected: false })).map((x) => x.id)).toEqual(['start-agent']);
  });
  it('offers the unlock action', () => {
    expect(startHereActions(input({ lockLabel: 'Locked' }))[0]).toMatchObject({
      id: 'unlock',
      target: 'unlock',
    });
  });
  it('does not confuse an absent load with empty', () => {
    expect(startHereActions(input({ secretsLoaded: false }))[0]?.id).toBe('load-project');
  });
  it('offers only import/add for a checked empty project', () => {
    expect(startHereActions(input()).map((x) => x.id)).toEqual(['add-secret']);
  });
  it('keeps completed setup complete and sharing optional', () => {
    expect(
      startHereActions(
        input({ secrets: [{} as never], policies: [{} as never], sessions: [{} as never] }),
      ),
    ).toEqual([]);
  });
  it('offers the first run after configuration', () => {
    expect(
      startHereActions(input({ secrets: [{} as never], policies: [{} as never] }))[0]?.id,
    ).toBe('run-command');
  });
});

it('offers unlock after locking without repeating completed setup', () => {
  expect(
    startHereActions(input({ setupComplete: true, lockLabel: 'Locked', secretsLoaded: false })).map(
      (action) => action.id,
    ),
  ).toEqual(['unlock']);
});

it('offers agent start for an already configured disconnected project', () => {
  expect(
    startHereActions(input({ setupComplete: true, connected: false })).map((action) => action.id),
  ).toEqual(['start-agent']);
  expect(startHereActions(input({ setupComplete: true, secretsLoaded: false }))).toEqual([]);
});
