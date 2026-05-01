<script setup lang="ts">
import { computed, ref, watch } from 'vue';

import {
  defaultPolicyForm,
  policyFormFromRow,
  policyFormRequiresTypedConfirmation,
  policyFormToSnapshot,
  validatePolicyForm,
  type PolicyFormMode,
  type PolicyFormState,
} from '../policy/form';
import type { CommandPolicySnapshotWire } from '../agent/types';
import type { CommandPolicyRow } from '../types/views';

interface Props {
  mode: PolicyFormMode;
  row?: CommandPolicyRow | null;
  projectId: string;
  /** Active profile is flagged dangerous in agent settings. */
  dangerousProfile: boolean;
  /** Display label of the active profile (used in confirmation copy). */
  profileLabel: string;
  submitting: boolean;
  errorMessage?: string | null;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (
    event: 'submit',
    payload: { mode: PolicyFormMode; snapshot: CommandPolicySnapshotWire; originalName: string },
  ): void;
  (event: 'dismiss'): void;
}>();

const form = ref<PolicyFormState>(initialState());
const confirmation = ref<string>('');

watch(
  () => [props.mode, props.row],
  () => {
    form.value = initialState();
    confirmation.value = '';
  },
);

function initialState(): PolicyFormState {
  if ((props.mode === 'edit' || props.mode === 'delete') && props.row) {
    return policyFormFromRow(props.row);
  }
  return defaultPolicyForm();
}

const validation = computed(() => validatePolicyForm(form.value));

const requiresConfirmation = computed<boolean>(() =>
  policyFormRequiresTypedConfirmation(props.dangerousProfile, props.mode),
);

const confirmationMatches = computed<boolean>(
  () => confirmation.value.trim() === props.profileLabel,
);

const canSubmit = computed<boolean>(() => {
  if (props.submitting) {
    return false;
  }
  if (props.mode !== 'delete' && !validation.value.valid) {
    return false;
  }
  if (requiresConfirmation.value && !confirmationMatches.value) {
    return false;
  }
  return true;
});

const heading = computed<string>(() => {
  switch (props.mode) {
    case 'create':
      return 'Create policy';
    case 'edit':
      return 'Edit policy';
    case 'delete':
      return 'Delete policy';
    default:
      return 'Policy';
  }
});

const submitLabel = computed<string>(() => {
  switch (props.mode) {
    case 'create':
      return 'Create';
    case 'edit':
      return 'Save changes';
    case 'delete':
      return 'Delete';
    default:
      return 'Submit';
  }
});

function nowUnixNanos(): number {
  return Date.now() * 1_000_000;
}

function onSubmit(): void {
  if (!canSubmit.value) {
    return;
  }
  const originalName = props.row?.name ?? form.value.name.trim();
  const snapshot = policyFormToSnapshot(form.value, props.projectId, nowUnixNanos());
  emit('submit', { mode: props.mode, snapshot, originalName });
}

function onDismiss(): void {
  emit('dismiss');
}
</script>

<template>
  <div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="policy-form-title">
    <form class="modal" data-testid="policy-form" @submit.prevent="onSubmit">
      <header>
        <h2 id="policy-form-title">{{ heading }}</h2>
        <p v-if="props.dangerousProfile" class="modal__warn" role="status">
          Active profile is flagged dangerous. Type the profile name to confirm.
        </p>
      </header>

      <template v-if="props.mode !== 'delete'">
        <label class="modal__field">
          <span>Name</span>
          <input
            v-model="form.name"
            type="text"
            required
            autocomplete="off"
            spellcheck="false"
            data-testid="policy-form-name"
          />
          <span v-if="validation.errors.name" class="modal__error">{{ validation.errors.name }}</span>
        </label>

        <label class="modal__field">
          <span>Command kind</span>
          <select v-model="form.commandKind" data-testid="policy-form-kind">
            <option value="argv">argv</option>
            <option value="shell">shell</option>
          </select>
        </label>

        <label class="modal__field">
          <span>Command</span>
          <textarea
            v-model="form.commandPreview"
            rows="3"
            spellcheck="false"
            data-testid="policy-form-command"
          />
          <span v-if="validation.errors.commandPreview" class="modal__error">
            {{ validation.errors.commandPreview }}
          </span>
        </label>

        <label class="modal__field">
          <span>Required secrets (comma-separated)</span>
          <input
            v-model="form.requiredSecrets"
            type="text"
            autocomplete="off"
            spellcheck="false"
            data-testid="policy-form-required"
          />
          <span v-if="validation.errors.requiredSecrets" class="modal__error">
            {{ validation.errors.requiredSecrets }}
          </span>
        </label>

        <label class="modal__field">
          <span>Optional secrets</span>
          <input v-model="form.optionalSecrets" type="text" autocomplete="off" spellcheck="false" />
          <span v-if="validation.errors.optionalSecrets" class="modal__error">
            {{ validation.errors.optionalSecrets }}
          </span>
        </label>

        <label class="modal__field">
          <span>Allowed extra secrets</span>
          <input v-model="form.allowedSecrets" type="text" autocomplete="off" spellcheck="false" />
          <span v-if="validation.errors.allowedSecrets" class="modal__error">
            {{ validation.errors.allowedSecrets }}
          </span>
        </label>

        <label class="modal__field">
          <span>TTL (seconds)</span>
          <input
            v-model.number="form.ttlSeconds"
            type="number"
            min="0"
            max="86400"
            data-testid="policy-form-ttl"
          />
          <span v-if="validation.errors.ttlSeconds" class="modal__error">
            {{ validation.errors.ttlSeconds }}
          </span>
        </label>

        <fieldset class="modal__fieldset">
          <legend>Gates</legend>
          <label class="modal__check">
            <input v-model="form.confirm" type="checkbox" /> Require typed confirmation
          </label>
          <label class="modal__check">
            <input v-model="form.requireUserVerification" type="checkbox" /> Require user verification
          </label>
          <label class="modal__check">
            <input v-model="form.allowRemoteDocker" type="checkbox" /> Allow remote Docker
          </label>
        </fieldset>

        <div class="modal__row">
          <label class="modal__field">
            <span>Environment</span>
            <select v-model="form.envMode">
              <option value="minimal">minimal</option>
              <option value="inherit">inherit</option>
              <option value="strict">strict</option>
            </select>
          </label>
          <label class="modal__field">
            <span>Override mode</span>
            <select v-model="form.overrideMode">
              <option value="locket">locket</option>
              <option value="preserve">preserve</option>
              <option value="fail">fail</option>
            </select>
          </label>
        </div>
      </template>

      <p v-else class="modal__caption">
        Delete <strong>{{ props.row?.name ?? form.name }}</strong>?
      </p>

      <label v-if="requiresConfirmation" class="modal__field" data-testid="policy-form-confirmation">
        <span>Type the active profile name ({{ props.profileLabel }}) to confirm</span>
        <input v-model="confirmation" type="text" autocomplete="off" spellcheck="false" />
      </label>

      <p v-if="props.errorMessage" class="modal__error" role="alert">{{ props.errorMessage }}</p>

      <div class="modal__actions">
        <button type="button" class="modal__btn modal__btn--ghost" @click="onDismiss">Cancel</button>
        <button
          type="submit"
          :class="['modal__btn', props.mode === 'delete' ? 'modal__btn--danger' : 'modal__btn--primary']"
          :disabled="!canSubmit"
          data-testid="policy-form-submit"
        >
          {{ submitLabel }}
        </button>
      </div>
    </form>
  </div>
</template>

<style scoped>
.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.55);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 150;
  overflow: auto;
}
.modal {
  background: #161a22;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 0.5rem;
  padding: 1.25rem 1.5rem;
  min-width: 400px;
  max-width: 560px;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin: 2rem 0;
}
.modal h2 {
  margin: 0;
  font-size: 1.05rem;
}
.modal__warn {
  margin: 0.25rem 0 0;
  color: #f2b879;
  font-size: 0.8rem;
}
.modal__field {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  font-size: 0.85rem;
}
.modal__field input,
.modal__field textarea,
.modal__field select {
  background: #0f1115;
  color: #e6e8ec;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 0.375rem;
  padding: 0.4rem 0.6rem;
  font-size: 0.85rem;
  font-family: inherit;
}
.modal__row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.5rem;
}
.modal__fieldset {
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 0.375rem;
  padding: 0.5rem 0.75rem;
}
.modal__fieldset legend {
  color: #9aa3b2;
  font-size: 0.75rem;
}
.modal__check {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  font-size: 0.8rem;
  margin: 0.25rem 0;
}
.modal__caption {
  margin: 0;
  font-size: 0.9rem;
  color: #c5cbd6;
}
.modal__error {
  color: #f08a90;
  font-size: 0.75rem;
}
.modal__actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}
.modal__btn {
  border: 0;
  border-radius: 0.375rem;
  padding: 0.4rem 0.85rem;
  font-size: 0.85rem;
  cursor: pointer;
}
.modal__btn--primary {
  background: #f8d77a;
  color: #1a1a1a;
}
.modal__btn--danger {
  background: #d96570;
  color: #1a1a1a;
}
.modal__btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.modal__btn--ghost {
  background: transparent;
  color: #c5cbd6;
  border: 1px solid rgba(255, 255, 255, 0.12);
}
</style>
