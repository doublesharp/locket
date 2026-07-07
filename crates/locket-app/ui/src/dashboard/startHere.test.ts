import { describe, expect, it } from 'vitest';

import { startHereActions, type StartHereInput } from './startHere';

function baseInput(overrides: Partial<StartHereInput> = {}): StartHereInput {
  return {
    lockLabel: 'Unlocked',
    secrets: [
      {
        id: 'db',
        name: 'DATABASE_URL',
        source: 'user-local',
        required: true,
        optional: false,
        createdAt: '2026-01-01T00:00:00Z',
        currentVersion: 1,
        hasDeprecatedGrace: false,
      },
    ],
    policies: [
      {
        id: 'dev',
        name: 'dev',
        commandKind: 'argv',
        commandPreview: 'npm run dev',
        requiredSecrets: ['DATABASE_URL'],
        optionalSecrets: [],
        allowedSecrets: ['DATABASE_URL'],
        confirm: false,
        requireUserVerification: false,
        allowRemoteDocker: false,
        ttlSeconds: 300,
        envMode: 'minimal',
        overrideMode: 'locket',
        updatedAt: '2026-01-01T00:00:00Z',
      },
    ],
    sessions: [],
    auditRows: [],
    findings: [],
    auditChainOk: true,
    lastScanAt: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('startHereActions', () => {
  it('starts with availability before setup work', () => {
    const actions = startHereActions(
      baseInput({ lockLabel: 'Unavailable', secrets: [], policies: [], lastScanAt: undefined }),
    );

    expect(actions.map((action) => action.id).slice(0, 3)).toEqual([
      'unlock',
      'add-secret',
      'create-policy',
    ]);
    expect(actions[0]).toMatchObject({ target: 'settings', tone: 'critical' });
  });

  it('guides empty projects through secrets, policies, and scanning', () => {
    const actions = startHereActions(
      baseInput({ secrets: [], policies: [], lastScanAt: undefined }),
    );

    expect(actions.map((action) => action.id)).toEqual([
      'add-secret',
      'create-policy',
      'scan-project',
    ]);
  });

  it('surfaces production health issues before optional sharing', () => {
    const actions = startHereActions(
      baseInput({
        auditChainOk: false,
        findings: [
          {
            id: 'finding-1',
            rule: 'entropy',
            severity: 'critical',
            path: '.env',
            line: 1,
            column: 1,
            redactedSummary: 'possible secret',
          },
        ],
        sessions: [
          {
            sessionId: 'run-1',
            profile: 'dev',
            policy: 'dev',
            pid: 123,
            processStartTime: '2026-01-01T00:00:00Z',
            startedAt: '2026-01-01T00:00:00Z',
            state: 'failed',
            secretNameCount: 1,
          },
        ],
      }),
    );

    expect(actions.map((action) => action.id)).toEqual([
      'review-scan',
      'review-audit',
      'review-runs',
      'share-access',
    ]);
  });

  it('offers sharing once a project can run', () => {
    expect(startHereActions(baseInput()).map((action) => action.id)).toEqual(['share-access']);
  });
});
