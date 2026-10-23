<script setup lang="ts">
interface Props {
  actionsEnabled: boolean;
  launching: boolean;
  errorMessage?: string | null;
  launchNotice?: string | null;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  (e: 'scan'): void;
}>();

function onScan(): void {
  if (props.actionsEnabled && !props.launching) emit('scan');
}
</script>

<template>
  <section class="view" aria-labelledby="scan-heading">
    <header class="view__header">
      <h2 id="scan-heading">Scan in terminal</h2>
      <button
        type="button"
        class="view__action"
        aria-label="Scan in terminal"
        :disabled="launching || !actionsEnabled"
        @click="onScan"
      >
        {{ launching ? 'Opening terminal…' : 'Scan in terminal' }}
      </button>
    </header>

    <p class="view__help">
      Run <code>locket scan --require-known</code> in this project's trusted folder. The CLI uses
      the project's ignore rules, scan rules, and known values. Complete any unlock or approval in
      the terminal.
    </p>
    <p class="view__help">
      Read the results in the terminal. This app does not receive findings or completion status.
    </p>
    <p v-if="!actionsEnabled" class="view__notice">
      Connect a project and wait for project selection to finish before opening a scan.
    </p>
    <p v-if="launching" class="view__notice" role="status">Opening your terminal…</p>
    <p v-else-if="errorMessage" class="view__error" role="alert">{{ errorMessage }}</p>
    <p v-else-if="launchNotice" class="view__notice" role="status">{{ launchNotice }}</p>
  </section>
</template>

<style scoped>
.view {
  background: #0f1115;
  color: #e6e8ec;
  padding: 1rem;
  border-radius: 0.5rem;
}

.view__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  margin-bottom: 0.75rem;
  gap: 0.75rem;
}

.view__header h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.view__action {
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 0.375rem;
  padding: 0.25rem 0.75rem;
  font-size: 0.8125rem;
  cursor: pointer;
}

.view__action:hover:not(:disabled) {
  background: rgba(255, 255, 255, 0.08);
}

.view__action:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}

.view__action:focus-visible {
  outline: 2px solid #f8d77a;
  outline-offset: 2px;
}

.view__help,
.view__notice,
.view__error {
  font-size: 0.875rem;
  color: #9aa3b2;
}

.view__notice {
  color: #f8d77a;
}

.view__error {
  color: #f4b3b3;
}
</style>
