// Lightweight desktop editor smoke coverage.
//
// This stays in the pure model layer so CI and local development can
// exercise the editor's set/rotate/delete wire shapes without building
// a packaged Tauri app or launching a webview.

import { describe, expect, it } from 'vitest';

import {
  defaultDeleteForm,
  defaultRotateForm,
  defaultSetForm,
  deleteFormToRequest,
  deleteUnavailableNotice,
  rotateFormToPayload,
  rotateSecretSuccessNotice,
  setFormToPayload,
  setSecretSuccessNotice,
  validateDeleteForm,
  validateRotateForm,
  validateSetForm,
} from './editor';

const PROJECT_ID = 'lk_proj_editor_smoke';
const PROFILE_ID = 'prof-editor';
const SECRET_NAME = 'DATABASE_URL';
const CANARY_VALUE = 'lk-canary-desktop-editor-value-1234567890abcdef';

describe('desktop editor smoke flow', () => {
  it('builds set, rotate, and delete requests without echoing values into notices', () => {
    const setForm = {
      ...defaultSetForm(),
      name: ` ${SECRET_NAME} `,
      value: CANARY_VALUE,
      description: 'Primary database URL',
      source: 'machine-local' as const,
    };
    expect(validateSetForm(setForm).valid).toBe(true);
    const setPayload = setFormToPayload(setForm, {
      projectId: PROJECT_ID,
      profileId: PROFILE_ID,
      grantId: 'grant-editor',
    });
    expect(setPayload).toEqual({
      project_id: PROJECT_ID,
      profile_id: PROFILE_ID,
      grant_id: 'grant-editor',
      secret_name: SECRET_NAME,
      value: CANARY_VALUE,
      source: 'machine-local',
    });
    expect(setSecretSuccessNotice(setPayload.secret_name, 7)).toBe('Created DATABASE_URL v7.');
    expect(setSecretSuccessNotice(setPayload.secret_name, 7)).not.toContain(CANARY_VALUE);

    const rotateForm = {
      ...defaultRotateForm(),
      name: SECRET_NAME,
      value: CANARY_VALUE,
      graceUntil: '2099-01-01T00:00:00.000Z',
    };
    expect(validateRotateForm(rotateForm).valid).toBe(true);
    const rotatePayload = rotateFormToPayload(rotateForm, {
      projectId: PROJECT_ID,
      profileId: PROFILE_ID,
      source: 'machine-local',
    });
    expect(rotatePayload.secret_name).toBe(SECRET_NAME);
    expect(rotatePayload.value).toBe(CANARY_VALUE);
    expect(rotatePayload.grace_until).toBeGreaterThan(4_000_000_000_000_000_000);
    expect(rotateSecretSuccessNotice(rotatePayload.secret_name, 8)).toBe(
      'Rotated DATABASE_URL to v8.',
    );
    expect(rotateSecretSuccessNotice(rotatePayload.secret_name, 8)).not.toContain(CANARY_VALUE);

    const deleteForm = {
      ...defaultDeleteForm(),
      name: SECRET_NAME,
      confirmation: SECRET_NAME,
    };
    expect(validateDeleteForm(deleteForm).valid).toBe(true);
    expect(
      deleteFormToRequest(deleteForm, { projectId: PROJECT_ID, profileId: PROFILE_ID }),
    ).toEqual({
        project_id: PROJECT_ID,
        profile_id: PROFILE_ID,
        secret_name: SECRET_NAME,
        typed_confirmation: SECRET_NAME,
    });
    expect(deleteUnavailableNotice(SECRET_NAME)).not.toContain(CANARY_VALUE);
  });
});
