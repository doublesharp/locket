<script setup lang="ts">
import { computed } from 'vue';

import AgentUnavailableBanner from './components/AgentUnavailableBanner.vue';
import { useAgent } from './composables/useAgent';

const { status, error, loading } = useAgent();

const lockLabel = computed<string>(() => {
  if (loading.value && status.value === null && error.value === null) {
    return 'Connecting to agent…';
  }
  if (status.value === null) {
    return 'Vault status unavailable';
  }
  switch (status.value.lock_state) {
    case 'unlocked':
      return 'Vault unlocked';
    case 'locked':
      return 'Vault locked';
    case 'unknown':
      return 'Vault status unknown';
    default:
      return 'Vault status unknown';
  }
});
</script>

<template>
  <main class="locket-shell">
    <header class="locket-shell__header">
      <h1>Locket</h1>
      <p class="locket-shell__state">
        {{ lockLabel }}
      </p>
    </header>

    <AgentUnavailableBanner v-if="error" :error="error" />
  </main>
</template>

<style>
:root {
  color-scheme: light dark;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
}

body {
  margin: 0;
  background: #0f1115;
  color: #e6e8ec;
}

.locket-shell {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 2rem;
  gap: 1.5rem;
}

.locket-shell__header {
  text-align: center;
}

.locket-shell__header h1 {
  margin: 0 0 0.5rem;
  font-size: 1.5rem;
  letter-spacing: 0.04em;
}

.locket-shell__state {
  margin: 0;
  font-size: 0.875rem;
  color: #9aa3b2;
}
</style>
