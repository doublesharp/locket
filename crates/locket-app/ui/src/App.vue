<script setup lang="ts">
// Empty shell. Real views (project dashboard, profile switcher, secret
// metadata list, etc.) land in their own slices on top of this shell.
// No agent IPC, no reveal/copy, no remote content.
</script>

<template>
  <main class="locket-shell">
    <header class="locket-shell__header">
      <h1>Locket</h1>
      <p class="locket-shell__state">vault status: pending agent connection</p>
    </header>
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
  align-items: center;
  justify-content: center;
  padding: 2rem;
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
