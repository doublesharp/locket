// Tests for the desktop policy editor form model.
//
// Tests run under vitest. When the runner is not configured locally,
// the file is skipped at collection time. The assertions below are
// hand-verifiable for code review.

import { describe, expect, it } from 'vitest';

import type { CommandPolicySnapshotWire } from '../agent/types';
import {
  applyPolicyMutation,
  defaultPolicyForm,
  parseSecretList,
  policyFormRequiresTypedConfirmation,
  policyFormToSnapshot,
  validatePolicyForm,
  type PolicyFormState,
} from './form';

function validForm(overrides: Partial<PolicyFormState> = {}): PolicyFormState {
  return {
    ...defaultPolicyForm(),
    name: 'deploy',
    commandPreview: 'kubectl apply -f manifest.yaml',
    requiredSecrets: 'KUBECONFIG, AWS_ACCESS_KEY_ID',
    optionalSecrets: '',
    allowedSecrets: '',
    ...overrides,
  };
}

describe('parseSecretList', () => {
  it('trims, dedupes, and skips blanks', () => {
    expect(parseSecretList(' A , B,A , ,C ')).toEqual(['A', 'B', 'C']);
  });

  it('returns an empty list for blank input', () => {
    expect(parseSecretList('')).toEqual([]);
    expect(parseSecretList('   ')).toEqual([]);
  });
});

describe('validatePolicyForm', () => {
  it('accepts a fully-populated form', () => {
    const result = validatePolicyForm(validForm());
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual({});
  });

  it('rejects a missing name', () => {
    const result = validatePolicyForm(validForm({ name: '' }));
    expect(result.valid).toBe(false);
    expect(result.errors.name).toBeDefined();
  });

  it('rejects an invalid name pattern', () => {
    const result = validatePolicyForm(validForm({ name: 'bad name!' }));
    expect(result.valid).toBe(false);
    expect(result.errors.name).toBeDefined();
  });

  it('rejects a missing command preview', () => {
    const result = validatePolicyForm(validForm({ commandPreview: '' }));
    expect(result.valid).toBe(false);
    expect(result.errors.commandPreview).toBeDefined();
  });

  it('rejects a non-uppercase secret name', () => {
    const result = validatePolicyForm(validForm({ requiredSecrets: 'kubeconfig' }));
    expect(result.valid).toBe(false);
    expect(result.errors.requiredSecrets).toBeDefined();
  });

  it('rejects negative or oversized TTLs', () => {
    expect(validatePolicyForm(validForm({ ttlSeconds: -1 })).errors.ttlSeconds).toBeDefined();
    expect(validatePolicyForm(validForm({ ttlSeconds: 100_000 })).errors.ttlSeconds).toBeDefined();
  });
});

describe('policyFormToSnapshot', () => {
  it('produces a wire snapshot with deduped allowed secrets', () => {
    const snapshot = policyFormToSnapshot(
      validForm({
        optionalSecrets: 'OPTIONAL_TOKEN',
        allowedSecrets: 'AWS_ACCESS_KEY_ID, EXTRA',
      }),
      'project-123',
      1_700_000_000_000_000_000,
    );
    expect(snapshot.project_id).toBe('project-123');
    expect(snapshot.required_secrets).toEqual(['KUBECONFIG', 'AWS_ACCESS_KEY_ID']);
    expect(snapshot.optional_secrets).toEqual(['OPTIONAL_TOKEN']);
    expect(snapshot.allowed_secrets).toEqual([
      'KUBECONFIG',
      'AWS_ACCESS_KEY_ID',
      'OPTIONAL_TOKEN',
      'EXTRA',
    ]);
    expect(snapshot.updated_at_unix_nanos).toBe(1_700_000_000_000_000_000);
  });

  it('truncates the TTL to a non-negative integer', () => {
    const snapshot = policyFormToSnapshot(
      validForm({ ttlSeconds: 30.7 }),
      'project-123',
      0,
    );
    expect(snapshot.ttl_seconds).toBe(30);
  });
});

describe('applyPolicyMutation', () => {
  const base: CommandPolicySnapshotWire[] = [
    snapshot('project-123', 'deploy'),
    snapshot('project-123', 'lint'),
  ];

  it('creates a new entry by appending it', () => {
    const next = snapshot('project-123', 'test');
    const result = applyPolicyMutation(base, 'create', next);
    expect(result.map((s) => s.name)).toEqual(['deploy', 'lint', 'test']);
  });

  it('replaces an existing entry on edit', () => {
    const next = { ...snapshot('project-123', 'deploy'), command_preview: 'kubectl rollout' };
    const result = applyPolicyMutation(base, 'edit', next, 'deploy');
    expect(result).toHaveLength(2);
    const updated = result.find((s) => s.name === 'deploy');
    expect(updated?.command_preview).toBe('kubectl rollout');
  });

  it('renames an entry on edit when the name changes', () => {
    const next = { ...snapshot('project-123', 'deploy-prod') };
    const result = applyPolicyMutation(base, 'edit', next, 'deploy');
    expect(result.map((s) => s.name).sort()).toEqual(['deploy-prod', 'lint']);
  });

  it('drops an entry on delete', () => {
    const result = applyPolicyMutation(base, 'delete', snapshot('project-123', 'lint'), 'lint');
    expect(result.map((s) => s.name)).toEqual(['deploy']);
  });
});

describe('policyFormRequiresTypedConfirmation', () => {
  it('gates every mutation when the active profile is dangerous', () => {
    expect(policyFormRequiresTypedConfirmation(true, 'create')).toBe(true);
    expect(policyFormRequiresTypedConfirmation(true, 'edit')).toBe(true);
    expect(policyFormRequiresTypedConfirmation(true, 'delete')).toBe(true);
  });

  it('does not gate mutations on a regular profile', () => {
    expect(policyFormRequiresTypedConfirmation(false, 'create')).toBe(false);
    expect(policyFormRequiresTypedConfirmation(false, 'edit')).toBe(false);
    expect(policyFormRequiresTypedConfirmation(false, 'delete')).toBe(false);
  });
});

function snapshot(projectId: string, name: string): CommandPolicySnapshotWire {
  return {
    project_id: projectId,
    name,
    command_kind: 'argv',
    command_preview: `${name} --run`,
    required_secrets: [],
    optional_secrets: [],
    allowed_secrets: [],
    confirm: false,
    require_user_verification: false,
    require_agent: false,
    allow_remote_docker: false,
    ttl_seconds: 60,
    env_mode: 'minimal',
    override_mode: 'fail',
    updated_at_unix_nanos: 0,
  };
}
