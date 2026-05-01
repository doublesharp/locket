// Tests for the desktop team-invite form models.
//
// Tests run under vitest. When the runner is not configured locally,
// the file is skipped at collection time. The assertions below are
// hand-verifiable for code review.

import { describe, expect, it } from 'vitest';

import type { AuditWireRow } from '../agent/types';
import {
  acceptFormToPayload,
  defaultAcceptForm,
  defaultIssueForm,
  defaultRevokeForm,
  issueDangerousConfirmationMatches,
  issueFormToPayload,
  issueRequiresDangerousConfirmation,
  parseProfileList,
  revokeFormToPayload,
  teamInviteRowsFromAudit,
  validateAcceptForm,
  validateIssueForm,
  validateRevokeForm,
} from './invite';

describe('parseProfileList', () => {
  it('trims, dedupes, and skips empties', () => {
    expect(parseProfileList(' dev , prod, dev ,, qa ')).toEqual(['dev', 'prod', 'qa']);
  });
});

describe('validateIssueForm', () => {
  it('accepts a well-formed invite with a developer role', () => {
    const result = validateIssueForm({
      ...defaultIssueForm(),
      recipientLabel: 'alice',
      deviceDescriptor: 'lkdev1_abcdef0123456789abcdef',
      role: 'developer',
      profiles: 'dev, qa',
      dangerousProfiles: 'prod',
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    });
    expect(result.valid).toBe(true);
    expect(result.dangerousMatches).toEqual([]);
  });

  it('rejects an invalid descriptor prefix', () => {
    const result = validateIssueForm({
      ...defaultIssueForm(),
      recipientLabel: 'alice',
      deviceDescriptor: 'badprefix_xxxx',
      profiles: 'dev',
    });
    expect(result.valid).toBe(false);
    expect(result.errors.deviceDescriptor).toMatch(/lkdev1_/);
  });

  it('flags dangerous profile inclusion', () => {
    const result = validateIssueForm({
      ...defaultIssueForm(),
      recipientLabel: 'alice',
      deviceDescriptor: 'lkdev1_abcdef0123456789abcdef',
      profiles: 'dev, prod',
      dangerousProfiles: 'prod',
    });
    expect(result.valid).toBe(true);
    expect(result.dangerousMatches).toEqual(['prod']);
    expect(issueRequiresDangerousConfirmation(result)).toBe(true);
    expect(issueDangerousConfirmationMatches(result, 'prod')).toBe(true);
    expect(issueDangerousConfirmationMatches(result, '')).toBe(false);
  });

  it('rejects past expiry', () => {
    const result = validateIssueForm({
      ...defaultIssueForm(),
      recipientLabel: 'alice',
      deviceDescriptor: 'lkdev1_abcdef0123456789abcdef',
      profiles: 'dev',
      expiresAt: new Date(Date.now() - 86_400_000).toISOString(),
    });
    expect(result.valid).toBe(false);
    expect(result.errors.expiresAt).toMatch(/future/);
  });
});

describe('issueFormToPayload', () => {
  it('echoes dangerous matches into the confirmation array', () => {
    const payload = issueFormToPayload({
      ...defaultIssueForm(),
      recipientLabel: 'bob',
      deviceDescriptor: 'lkdev1_abcdef0123456789abcdef',
      profiles: 'dev, prod, qa',
      dangerousProfiles: 'prod',
      role: 'maintainer',
      expiresAt: '',
    });
    expect(payload.profiles).toEqual(['dev', 'prod', 'qa']);
    expect(payload.dangerous_profile_confirmation).toEqual(['prod']);
    expect(payload.role).toBe('maintainer');
    expect(payload.expires_at_unix_nanos).toBeNull();
  });
});

describe('validateAcceptForm', () => {
  const longInvite = 'a'.repeat(80);

  it('accepts well-formed input with hex fingerprint', () => {
    const result = validateAcceptForm({
      inviteText: longInvite,
      fingerprintConfirmation: 'a'.repeat(64),
      requireUserVerification: false,
      userVerified: false,
    });
    expect(result.valid).toBe(true);
  });

  it('requires user verification when gated', () => {
    const result = validateAcceptForm({
      inviteText: longInvite,
      fingerprintConfirmation: 'b'.repeat(64),
      requireUserVerification: true,
      userVerified: false,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.userVerified).toMatch(/verification/);
  });

  it('rejects a non-hex fingerprint', () => {
    const result = validateAcceptForm({
      inviteText: longInvite,
      fingerprintConfirmation: 'not-hex',
      requireUserVerification: false,
      userVerified: false,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.fingerprintConfirmation).toMatch(/hexadecimal/);
  });
});

describe('acceptFormToPayload', () => {
  it('lowercases the fingerprint', () => {
    const payload = acceptFormToPayload({
      inviteText: 'a'.repeat(80),
      fingerprintConfirmation: 'A'.repeat(64),
      requireUserVerification: false,
      userVerified: true,
    });
    expect(payload.fingerprint_confirmation).toBe('a'.repeat(64));
    expect(payload.user_verified).toBe(true);
  });
});

describe('validateRevokeForm', () => {
  it('requires the typed confirmation to match the id exactly', () => {
    expect(
      validateRevokeForm({ ...defaultRevokeForm(), inviteId: 'inv-1', confirmation: '' }).valid,
    ).toBe(false);
    expect(
      validateRevokeForm({ ...defaultRevokeForm(), inviteId: 'inv-1', confirmation: 'inv-2' })
        .valid,
    ).toBe(false);
    expect(
      validateRevokeForm({ ...defaultRevokeForm(), inviteId: 'inv-1', confirmation: 'inv-1' })
        .valid,
    ).toBe(true);
  });
});

describe('revokeFormToPayload', () => {
  it('returns the typed invite id', () => {
    expect(
      revokeFormToPayload({ ...defaultRevokeForm(), inviteId: ' inv-99 ', confirmation: 'inv-99' }),
    ).toEqual({ invite_id: 'inv-99' });
  });
});

describe('teamInviteRowsFromAudit', () => {
  function row(overrides: Partial<AuditWireRow>): AuditWireRow {
    return {
      sequence: 0,
      timestamp: 1_700_000_000_000_000_000,
      profile_id: null,
      action: 'TEAM_INVITE',
      status: 'OK',
      secret_name: null,
      command: null,
      ...overrides,
    };
  }

  it('reconstructs metadata-only rows from audit metadata', () => {
    const future = Date.now() * 1_000_000 + 86_400_000_000_000;
    const rows = teamInviteRowsFromAudit([
      row({
        sequence: 1,
        command: JSON.stringify({
          invite_id: 'inv-1',
          recipient_label: 'alice',
          role: 'developer',
          profiles: ['dev'],
          direction: 'issued',
          expires_at_unix_nanos: future,
        }),
      }),
    ]);
    expect(rows).toHaveLength(1);
    const single = rows[0];
    expect(single?.id).toBe('inv-1');
    expect(single?.status).toBe('pending');
    expect(single?.role).toBe('developer');
    expect(single?.profiles).toEqual(['dev']);
    expect(single?.direction).toBe('issued');
  });

  it('marks revoked invites as revoked', () => {
    const rows = teamInviteRowsFromAudit([
      row({
        sequence: 2,
        command: JSON.stringify({ invite_id: 'inv-2', recipient_label: 'bob' }),
      }),
      row({
        sequence: 3,
        status: 'REVOKED',
        command: JSON.stringify({ invite_id: 'inv-2' }),
      }),
    ]);
    expect(rows[0]?.status).toBe('revoked');
  });

  it('marks expired invites as expired', () => {
    const past = 1_500_000_000_000_000_000;
    const rows = teamInviteRowsFromAudit(
      [
        row({
          sequence: 4,
          command: JSON.stringify({
            invite_id: 'inv-3',
            expires_at_unix_nanos: past,
            direction: 'received',
          }),
        }),
      ],
      { now_unix_nanos: past + 1_000_000_000 },
    );
    expect(rows[0]?.status).toBe('expired');
  });

  it('skips non-TEAM_INVITE rows', () => {
    const rows = teamInviteRowsFromAudit([
      row({ sequence: 5, action: 'REVEAL' }),
      row({
        sequence: 6,
        command: JSON.stringify({ invite_id: 'inv-only' }),
      }),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.id).toBe('inv-only');
  });
});

describe('defaults', () => {
  it('provide stable starting values', () => {
    expect(defaultIssueForm().role).toBe('developer');
    expect(defaultAcceptForm().requireUserVerification).toBe(false);
    expect(defaultRevokeForm().inviteId).toBe('');
  });
});
