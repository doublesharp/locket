<script setup lang="ts">
import { computed } from 'vue';

import type { SettingsState } from '../types/views';

defineOptions({ name: 'AppSettings' });

interface Props {
  state: SettingsState;
  loading: boolean;
  errorMessage: string | null;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: 'update', patch: Partial<SettingsState>): void;
}>();

const redactNames = computed<boolean>(() => props.state.privacyRedactNames);

function onToggleRedact(event: Event): void {
  const target = event.target as HTMLInputElement;
  emit('update', { privacyRedactNames: target.checked });
}

function userVerificationLabel(value: boolean): string {
  return value ? 'required' : 'not required';
}

function dangerousProfileLabel(value: boolean): string {
  return value ? 'enabled' : 'disabled';
}
</script>

<template>
  <section class="view" aria-labelledby="settings-heading">
    <header class="view__header">
      <h2 id="settings-heading">Settings</h2>
    </header>

    <section class="view__section" aria-labelledby="settings-privacy-heading">
      <h3 id="settings-privacy-heading" class="view__section-heading">Privacy</h3>
      <p class="view__paragraph">Names are replaced with aliases when redaction is enabled.</p>

      <label class="view__field">
        <input
          type="checkbox"
          :checked="redactNames"
          :disabled="loading"
          aria-describedby="settings-privacy-help"
          @change="onToggleRedact"
        />
        <span>Redact names with local aliases</span>
      </label>
      <p v-if="errorMessage" class="view__error" role="status">{{ errorMessage }}</p>
      <p id="settings-privacy-help" class="view__help">
        Affects dashboard, tray, shell status, and notifications.
      </p>
    </section>

    <section class="view__section" aria-labelledby="settings-agent-heading">
      <h3 id="settings-agent-heading" class="view__section-heading">Agent &amp; vault</h3>
      <p class="view__paragraph">
        These values are owned by the CLI and agent. Use <code>locket</code> commands to change
        them.
      </p>

      <dl class="view__definitions">
        <div class="view__definition">
          <dt>Unlock TTL</dt>
          <dd>{{ state.unlockTtlSeconds }}s</dd>
        </div>
        <div class="view__definition">
          <dt>User verification</dt>
          <dd>{{ userVerificationLabel(state.requireUserVerification) }}</dd>
        </div>
        <div class="view__definition">
          <dt>Dangerous profile flag</dt>
          <dd>{{ dangerousProfileLabel(state.dangerousProfileFlag) }}</dd>
        </div>
      </dl>
    </section>

    <footer class="view__footer">
      <span class="view__muted">Agent version</span>
      <code class="view__version">{{ state.agentVersion }}</code>
      <span v-if="loading" class="view__muted">Syncing</span>
    </footer>
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

.view__header h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.view__section {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.75rem;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 0.5rem;
}

.view__section-heading {
  margin: 0;
  font-size: 0.8125rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: #9aa3b2;
}

.view__paragraph {
  margin: 0;
  font-size: 0.875rem;
  color: #e6e8ec;
}

.view__paragraph code {
  background: rgba(255, 255, 255, 0.06);
  padding: 0.125rem 0.25rem;
  border-radius: 0.25rem;
  font-size: 0.8125rem;
}

.view__field {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.875rem;
  cursor: pointer;
}

.view__field input[type='checkbox'] {
  width: 1rem;
  height: 1rem;
  accent-color: #f8d77a;
}

.view__field input[type='checkbox']:focus-visible {
  outline: 2px solid #f8d77a;
  outline-offset: 2px;
}

.view__help {
  margin: 0;
  font-size: 0.75rem;
  color: #9aa3b2;
}

.view__error {
  margin: 0;
  font-size: 0.75rem;
  color: #f2b879;
}

.view__definitions {
  margin: 0;
  display: grid;
  grid-template-columns: max-content 1fr;
  column-gap: 1rem;
  row-gap: 0.375rem;
  font-size: 0.875rem;
}

.view__definition {
  display: contents;
}

.view__definition dt {
  color: #9aa3b2;
}

.view__definition dd {
  margin: 0;
  color: #e6e8ec;
}

.view__footer {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.8125rem;
  border-top: 1px solid rgba(255, 255, 255, 0.08);
  padding-top: 0.75rem;
}

.view__muted {
  color: #9aa3b2;
}

.view__version {
  color: #e6e8ec;
}
</style>
