<script setup lang="ts">
// Desktop view for issuing, accepting, and revoking team invites.
//
// The agent does not yet expose dedicated `ListTeamInvites`,
// `CreateTeamInvite`, `AcceptTeamInvite`, or `RevokeTeamInvite` RPCs
// (see `crates/locket-agent/src/method.rs`). Until those land:
//   - The list is reconstructed from `TEAM_INVITE` audit rows owned by
//     the active project. Rows include only metadata; no secret values
//     ever pass through the webview.
//   - Issue/accept/revoke submits are surfaced as typed
//     "agent surface missing" notices so the user is never silently
//     dropped on the floor and the desktop UX is reviewable today.
//
// The form models (`../team/invite.ts`) own validation, dangerous-
// profile gating, and payload construction so they stay testable
// without spinning up jsdom.

import { computed, ref, watch } from 'vue';

import {
  acceptFormToPayload,
  defaultAcceptForm,
  defaultIssueForm,
  defaultRevokeForm,
  issueDangerousConfirmationMatches,
  issueFormToPayload,
  issueRequiresDangerousConfirmation,
  revokeFormToPayload,
  teamInviteRowsFromAudit,
  validateAcceptForm,
  validateIssueForm,
  validateRevokeForm,
  type TeamInviteAcceptFormState,
  type TeamInviteIssueFormState,
  type TeamInviteRevokeFormState,
  type TeamInviteRow,
} from '../team/invite';
import type { AuditWireRow } from '../agent/types';

interface Props {
  /** Audit rows for the active project, used for invite reconstruction. */
  auditRows: ReadonlyArray<AuditWireRow>;
  /** Comma-separated list of dangerous-profile names from agent settings. */
  dangerousProfiles: string;
  /** Whether team_accept enforces fresh user-verification. */
  requireAcceptUserVerification: boolean;
  loading: boolean;
  errorMessage?: string | null;
  lastRefreshedAt?: string;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (event: 'refresh'): void;
  (event: 'issue', payload: ReturnType<typeof issueFormToPayload>): void;
  (event: 'accept', payload: ReturnType<typeof acceptFormToPayload>): void;
  (event: 'revoke', payload: ReturnType<typeof revokeFormToPayload>): void;
}>();

const issueForm = ref<TeamInviteIssueFormState>(defaultIssueForm());
const issueDangerousConfirmation = ref<string>('');
const issueSubmitError = ref<string | null>(null);

const acceptForm = ref<TeamInviteAcceptFormState>(defaultAcceptForm());
const acceptSubmitError = ref<string | null>(null);

const revokeForm = ref<TeamInviteRevokeFormState>(defaultRevokeForm());
const revokeSubmitError = ref<string | null>(null);

const searchQuery = ref<string>('');

watch(
  () => props.dangerousProfiles,
  (next) => {
    issueForm.value = { ...issueForm.value, dangerousProfiles: next };
  },
  { immediate: true },
);

watch(
  () => props.requireAcceptUserVerification,
  (next) => {
    acceptForm.value = { ...acceptForm.value, requireUserVerification: next };
  },
  { immediate: true },
);

const inviteRows = computed<TeamInviteRow[]>(() => teamInviteRowsFromAudit(props.auditRows));

const filteredRows = computed<TeamInviteRow[]>(() => {
  const query = searchQuery.value.trim().toLowerCase();
  if (query.length === 0) {
    return inviteRows.value;
  }
  return inviteRows.value.filter((row) =>
    [
      row.id,
      row.recipientLabel ?? '',
      row.issuerLabel ?? '',
      row.role ?? '',
      row.status,
      row.direction,
      row.profiles.join(' '),
    ]
      .join(' ')
      .toLowerCase()
      .includes(query),
  );
});

const issueValidation = computed(() => validateIssueForm(issueForm.value));
const issueRequiresConfirmation = computed<boolean>(() =>
  issueRequiresDangerousConfirmation(issueValidation.value),
);
const issueConfirmationMatches = computed<boolean>(() =>
  issueDangerousConfirmationMatches(issueValidation.value, issueDangerousConfirmation.value),
);
const issueCanSubmit = computed<boolean>(() => {
  if (!issueValidation.value.valid) {
    return false;
  }
  if (issueRequiresConfirmation.value && !issueConfirmationMatches.value) {
    return false;
  }
  return true;
});

const acceptValidation = computed(() => validateAcceptForm(acceptForm.value));
const acceptCanSubmit = computed<boolean>(() => acceptValidation.value.valid);

const revokeValidation = computed(() => validateRevokeForm(revokeForm.value));
const revokeCanSubmit = computed<boolean>(() => revokeValidation.value.valid);

function onIssue(): void {
  if (!issueCanSubmit.value) {
    return;
  }
  issueSubmitError.value = null;
  try {
    emit('issue', issueFormToPayload(issueForm.value));
  } catch (error) {
    issueSubmitError.value = error instanceof Error ? error.message : 'Issue failed.';
  }
}

function onAccept(): void {
  if (!acceptCanSubmit.value) {
    return;
  }
  acceptSubmitError.value = null;
  try {
    emit('accept', acceptFormToPayload(acceptForm.value));
  } catch (error) {
    acceptSubmitError.value = error instanceof Error ? error.message : 'Accept failed.';
  }
}

function onRevoke(): void {
  if (!revokeCanSubmit.value) {
    return;
  }
  revokeSubmitError.value = null;
  try {
    emit('revoke', revokeFormToPayload(revokeForm.value));
  } catch (error) {
    revokeSubmitError.value = error instanceof Error ? error.message : 'Revoke failed.';
  }
}

function refresh(): void {
  emit('refresh');
}

function statusBadge(status: TeamInviteRow['status']): string {
  switch (status) {
    case 'pending':
      return 'badge--info';
    case 'accepted':
      return 'badge--ok';
    case 'revoked':
      return 'badge--danger';
    case 'expired':
      return 'badge--warning';
    default:
      return 'badge--neutral';
  }
}
</script>

<template>
  <section class="view" aria-labelledby="team-invite-heading">
    <header class="view__header">
      <h2 id="team-invite-heading">Team invites</h2>
      <div class="view__actions">
        <span v-if="lastRefreshedAt" class="view__muted">
          <time :datetime="lastRefreshedAt">{{ lastRefreshedAt }}</time>
        </span>
        <button type="button" class="view__button" :disabled="loading" @click="refresh">
          Refresh
        </button>
      </div>
      <label class="view__search">
        <span class="view__search-label">Search invites</span>
        <input
          v-model="searchQuery"
          type="search"
          autocomplete="off"
          spellcheck="false"
          placeholder="Search by id, recipient, role, status, profile"
        />
      </label>
    </header>

    <p v-if="errorMessage" class="view__error">{{ errorMessage }}</p>

    <p class="view__notice" role="note">
      Agent invite RPCs (<code>ListTeamInvites</code>, <code>CreateTeamInvite</code>,
      <code>AcceptTeamInvite</code>, <code>RevokeTeamInvite</code>) are not yet wired.
      The list below is reconstructed from <code>TEAM_INVITE</code> audit rows. Submit buttons
      enqueue requests against the desktop bridge, which currently surfaces an
      <code>unsupported-method</code> response until the agent ships those RPCs.
    </p>

    <section aria-labelledby="team-invite-list-heading" class="view__panel">
      <h3 id="team-invite-list-heading" class="view__panel-heading">Pending and recent invites</h3>
      <p v-if="loading" class="view__loading" role="status">Loading invite history…</p>
      <p v-else-if="filteredRows.length === 0" class="view__empty">
        No matching invites in audit history.
      </p>
      <table v-else class="view__table" aria-describedby="team-invite-list-heading">
        <thead>
          <tr>
            <th scope="col">Invite id</th>
            <th scope="col">Direction</th>
            <th scope="col">Status</th>
            <th scope="col">Recipient / Issuer</th>
            <th scope="col">Role</th>
            <th scope="col">Profiles</th>
            <th scope="col">Created</th>
            <th scope="col">Expires</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in filteredRows" :key="row.id">
            <td>
              <code>{{ row.id }}</code>
            </td>
            <td>{{ row.direction }}</td>
            <td>
              <span class="badge" :class="statusBadge(row.status)">{{ row.status }}</span>
            </td>
            <td>
              <span v-if="row.direction === 'issued'">{{ row.recipientLabel ?? '—' }}</span>
              <span v-else>{{ row.issuerLabel ?? '—' }}</span>
            </td>
            <td>{{ row.role ?? '—' }}</td>
            <td>
              <span v-if="row.profiles.length > 0">{{ row.profiles.join(', ') }}</span>
              <span v-else class="view__muted">—</span>
            </td>
            <td>
              <time :datetime="row.createdAt">{{ row.createdAt }}</time>
            </td>
            <td>
              <time v-if="row.expiresAt" :datetime="row.expiresAt">{{ row.expiresAt }}</time>
              <span v-else class="view__muted">—</span>
            </td>
          </tr>
        </tbody>
      </table>
    </section>

    <section aria-labelledby="team-invite-issue-heading" class="view__panel">
      <h3 id="team-invite-issue-heading" class="view__panel-heading">Issue invite</h3>
      <form @submit.prevent="onIssue">
        <label class="view__field">
          <span>Recipient label</span>
          <input
            v-model="issueForm.recipientLabel"
            type="text"
            autocomplete="off"
            spellcheck="false"
            data-testid="team-invite-recipient"
          />
          <span v-if="issueValidation.errors.recipientLabel" class="view__error">
            {{ issueValidation.errors.recipientLabel }}
          </span>
        </label>
        <label class="view__field">
          <span>Recipient device descriptor</span>
          <textarea
            v-model="issueForm.deviceDescriptor"
            rows="2"
            autocomplete="off"
            spellcheck="false"
            data-testid="team-invite-descriptor"
          />
          <span v-if="issueValidation.errors.deviceDescriptor" class="view__error">
            {{ issueValidation.errors.deviceDescriptor }}
          </span>
        </label>
        <div class="view__row">
          <label class="view__field">
            <span>Role</span>
            <select v-model="issueForm.role">
              <option value="developer">developer</option>
              <option value="maintainer">maintainer</option>
              <option value="owner">owner</option>
              <option value="read-only">read-only</option>
            </select>
          </label>
          <label class="view__field">
            <span>Expiry (ISO 8601)</span>
            <input
              v-model="issueForm.expiresAt"
              type="datetime-local"
              autocomplete="off"
              spellcheck="false"
            />
            <span v-if="issueValidation.errors.expiresAt" class="view__error">
              {{ issueValidation.errors.expiresAt }}
            </span>
          </label>
        </div>
        <label class="view__field">
          <span>Profiles (comma-separated)</span>
          <input
            v-model="issueForm.profiles"
            type="text"
            autocomplete="off"
            spellcheck="false"
            data-testid="team-invite-profiles"
          />
          <span v-if="issueValidation.errors.profiles" class="view__error">
            {{ issueValidation.errors.profiles }}
          </span>
        </label>
        <p v-if="issueRequiresConfirmation" class="view__warn" role="status">
          This invite includes the dangerous profile(s):
          <strong>{{ issueValidation.dangerousMatches.join(', ') }}</strong>. Type each
          dangerous profile name to confirm.
        </p>
        <label v-if="issueRequiresConfirmation" class="view__field">
          <span>Type dangerous profile name(s)</span>
          <input
            v-model="issueDangerousConfirmation"
            type="text"
            autocomplete="off"
            spellcheck="false"
            data-testid="team-invite-dangerous-confirmation"
          />
        </label>
        <p v-if="issueSubmitError" class="view__error" role="alert">{{ issueSubmitError }}</p>
        <div class="view__form-actions">
          <button
            type="submit"
            class="view__button view__button--primary"
            :disabled="!issueCanSubmit"
            data-testid="team-invite-issue"
          >
            Issue invite
          </button>
        </div>
      </form>
    </section>

    <section aria-labelledby="team-invite-accept-heading" class="view__panel">
      <h3 id="team-invite-accept-heading" class="view__panel-heading">Accept invite</h3>
      <form @submit.prevent="onAccept">
        <label class="view__field">
          <span>Paste invite text</span>
          <textarea
            v-model="acceptForm.inviteText"
            rows="6"
            spellcheck="false"
            autocomplete="off"
            data-testid="team-invite-accept-text"
          />
          <span v-if="acceptValidation.errors.inviteText" class="view__error">
            {{ acceptValidation.errors.inviteText }}
          </span>
        </label>
        <label class="view__field">
          <span>Issuer device fingerprint (64 hex)</span>
          <input
            v-model="acceptForm.fingerprintConfirmation"
            type="text"
            autocomplete="off"
            spellcheck="false"
            data-testid="team-invite-accept-fingerprint"
          />
          <span v-if="acceptValidation.errors.fingerprintConfirmation" class="view__error">
            {{ acceptValidation.errors.fingerprintConfirmation }}
          </span>
        </label>
        <label v-if="acceptForm.requireUserVerification" class="view__check">
          <input v-model="acceptForm.userVerified" type="checkbox" />
          I have completed local user verification (platform prompt / hardware key /
          passphrase fallback).
          <span v-if="acceptValidation.errors.userVerified" class="view__error">
            {{ acceptValidation.errors.userVerified }}
          </span>
        </label>
        <p v-if="acceptSubmitError" class="view__error" role="alert">{{ acceptSubmitError }}</p>
        <div class="view__form-actions">
          <button
            type="submit"
            class="view__button view__button--primary"
            :disabled="!acceptCanSubmit"
            data-testid="team-invite-accept"
          >
            Accept invite
          </button>
        </div>
      </form>
    </section>

    <section aria-labelledby="team-invite-revoke-heading" class="view__panel">
      <h3 id="team-invite-revoke-heading" class="view__panel-heading">Revoke invite</h3>
      <p class="view__muted">Owners and the issuing maintainer may revoke an outstanding invite.</p>
      <form @submit.prevent="onRevoke">
        <label class="view__field">
          <span>Invite id</span>
          <input
            v-model="revokeForm.inviteId"
            type="text"
            autocomplete="off"
            spellcheck="false"
            data-testid="team-invite-revoke-id"
          />
          <span v-if="revokeValidation.errors.inviteId" class="view__error">
            {{ revokeValidation.errors.inviteId }}
          </span>
        </label>
        <label class="view__field">
          <span>Type the invite id again to confirm</span>
          <input
            v-model="revokeForm.confirmation"
            type="text"
            autocomplete="off"
            spellcheck="false"
            data-testid="team-invite-revoke-confirm"
          />
          <span v-if="revokeValidation.errors.confirmation" class="view__error">
            {{ revokeValidation.errors.confirmation }}
          </span>
        </label>
        <p v-if="revokeSubmitError" class="view__error" role="alert">{{ revokeSubmitError }}</p>
        <div class="view__form-actions">
          <button
            type="submit"
            class="view__button view__button--danger"
            :disabled="!revokeCanSubmit"
            data-testid="team-invite-revoke"
          >
            Revoke invite
          </button>
        </div>
      </form>
    </section>
  </section>
</template>

<style scoped>
.view {
  background: #0f1115;
  color: #e6e8ec;
  padding: 1rem;
  border-radius: 0.5rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.view__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
}
.view__header h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.view__actions {
  display: inline-flex;
  align-items: center;
  gap: 0.625rem;
  margin-left: auto;
}
.view__panel {
  background: #11141a;
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 0.5rem;
  padding: 0.875rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.view__panel-heading {
  margin: 0;
  font-size: 0.85rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: #9aa3b2;
}
.view__field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.85rem;
}
.view__field input,
.view__field select,
.view__field textarea {
  background: #0f1115;
  color: #e6e8ec;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 0.375rem;
  padding: 0.4rem 0.6rem;
  font: inherit;
  font-size: 0.85rem;
}
.view__row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.75rem;
}
.view__check {
  display: flex;
  gap: 0.5rem;
  align-items: flex-start;
  font-size: 0.85rem;
}
.view__warn {
  margin: 0;
  padding: 0.5rem 0.625rem;
  background: rgba(248, 215, 122, 0.08);
  border: 1px solid rgba(248, 215, 122, 0.32);
  color: #f8d77a;
  border-radius: 0.375rem;
  font-size: 0.8rem;
}
.view__notice {
  margin: 0;
  padding: 0.5rem 0.625rem;
  background: rgba(120, 170, 255, 0.06);
  border: 1px solid rgba(120, 170, 255, 0.2);
  color: #a8c6ff;
  border-radius: 0.375rem;
  font-size: 0.78rem;
}
.view__notice code {
  background: rgba(255, 255, 255, 0.04);
  padding: 0 0.25rem;
  border-radius: 0.25rem;
}
.view__form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}
.view__button {
  min-height: 2rem;
  border: 1px solid rgba(255, 255, 255, 0.14);
  border-radius: 0.375rem;
  background: rgba(255, 255, 255, 0.06);
  color: #e6e8ec;
  cursor: pointer;
  font: inherit;
  font-size: 0.8125rem;
  padding: 0.25rem 0.625rem;
}
.view__button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.view__button--primary {
  background: #f8d77a;
  color: #1a1a1a;
  border-color: transparent;
}
.view__button--danger {
  background: #d96570;
  color: #1a1a1a;
  border-color: transparent;
}
.view__loading,
.view__empty {
  margin: 0;
  font-size: 0.875rem;
  color: #9aa3b2;
}
.view__error {
  margin: 0;
  color: #f08a90;
  font-size: 0.8rem;
}
.view__muted {
  color: #9aa3b2;
}
.view__search {
  display: grid;
  gap: 0.25rem;
  min-width: min(18rem, 100%);
}
.view__search-label {
  color: #9aa3b2;
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.view__search input {
  box-sizing: border-box;
  width: 100%;
  min-height: 2rem;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 0.375rem;
  background: rgba(255, 255, 255, 0.05);
  color: #e6e8ec;
  font: inherit;
  padding: 0.375rem 0.625rem;
}
.view__table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}
.view__table th,
.view__table td {
  text-align: left;
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  vertical-align: top;
}
.view__table th {
  font-weight: 600;
  color: #9aa3b2;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.badge {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  border-radius: 0.375rem;
  font-size: 0.75rem;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
}
.badge--info {
  background: rgba(120, 170, 255, 0.12);
  border-color: rgba(120, 170, 255, 0.32);
  color: #a8c6ff;
}
.badge--ok {
  background: rgba(143, 209, 158, 0.12);
  border-color: rgba(143, 209, 158, 0.32);
  color: #8fd19e;
}
.badge--warning {
  background: rgba(248, 215, 122, 0.12);
  border-color: rgba(248, 215, 122, 0.32);
  color: #f8d77a;
}
.badge--danger {
  background: rgba(217, 101, 112, 0.12);
  border-color: rgba(217, 101, 112, 0.32);
  color: #f08a90;
}
.badge--neutral {
  color: #9aa3b2;
}
</style>
