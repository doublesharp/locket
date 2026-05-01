<script setup lang="ts">
// Reveal modal entry point. The actual modal state lives in
// src/reveal/model.ts so it can be unit tested without the Vue
// runtime; this component subscribes to the typed events that the
// model emits and renders the short-lived plaintext panel with a
// per-second TTL countdown.

import { computed, onBeforeUnmount, onMounted, ref } from 'vue';

import {
  RevealModalModel,
  type RevealModalEvent,
  type RevealModalState,
  type RevealRequest,
} from '../reveal/model';

const model = new RevealModalModel();

defineExpose({
  /**
   * Imperative entry point used by App.vue to drive the reveal flow
   * from a tray menu action. The component still owns the modal state
   * and TTL countdown — this just forwards the resolved value into the
   * pure model.
   */
  show(request: RevealRequest): void {
    model.show(request);
  },
  /** Manually scrub the displayed value (e.g. on view switch). */
  scrub(reason: 'manual-scrub' | 'component-unmount' = 'manual-scrub'): void {
    model.scrub(reason);
  },
});

const state = ref<RevealModalState>(model.snapshot());
const remaining = ref<number>(0);

let unsubscribe: (() => void) | null = null;
let tick: ReturnType<typeof setInterval> | null = null;

function syncRemaining(): void {
  remaining.value = model.remainingSeconds(performance.now());
}

function startTicker(): void {
  stopTicker();
  syncRemaining();
  tick = setInterval(() => {
    syncRemaining();
    if (model.isExpired(performance.now())) {
      model.scrub('ttl-expired');
    }
  }, 1000);
}

function stopTicker(): void {
  if (tick !== null) {
    clearInterval(tick);
    tick = null;
  }
}

function onClose(): void {
  model.dismiss('explicit-close');
}

function onBlur(): void {
  if (state.value.kind === 'visible') {
    model.dismiss('blur');
  }
}

onMounted(() => {
  unsubscribe = model.subscribe((event: RevealModalEvent) => {
    state.value = model.snapshot();
    if (event.kind === 'shown') {
      startTicker();
    } else if (event.kind === 'scrubbed' || event.kind === 'dismissed') {
      stopTicker();
    }
  });
  window.addEventListener('blur', onBlur);
});

onBeforeUnmount(() => {
  unsubscribe?.();
  unsubscribe = null;
  stopTicker();
  window.removeEventListener('blur', onBlur);
  model.scrub('component-unmount');
});

const visible = computed<boolean>(() => state.value.kind === 'visible');
const value = computed<string>(() =>
  state.value.kind === 'visible' ? state.value.value : '',
);
const secretLabel = computed<string>(() =>
  state.value.kind === 'visible' ? state.value.secretLabel : '',
);
</script>

<template>
  <div
    v-if="visible"
    class="reveal-backdrop"
    role="dialog"
    aria-modal="true"
    aria-labelledby="reveal-title"
  >
    <div class="reveal">
      <header class="reveal__head">
        <h2 id="reveal-title">Reveal</h2>
        <span class="reveal__caption">{{ secretLabel }}</span>
      </header>
      <pre class="reveal__value" data-testid="reveal-value">{{ value }}</pre>
      <footer class="reveal__foot">
        <span class="reveal__ttl" aria-live="polite"
          >Hides in {{ remaining }}s</span
        >
        <button type="button" class="reveal__close" @click="onClose">Close</button>
      </footer>
    </div>
  </div>
</template>

<style scoped>
.reveal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.55);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 200;
}
.reveal {
  background: #161a22;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 0.5rem;
  padding: 1.25rem 1.5rem;
  min-width: 360px;
  max-width: 560px;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.reveal__head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.75rem;
}
.reveal__head h2 {
  margin: 0;
  font-size: 1.1rem;
}
.reveal__caption {
  color: #9aa3b2;
  font-size: 0.8rem;
}
.reveal__value {
  margin: 0;
  padding: 0.625rem 0.75rem;
  background: #0b0d11;
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 0.375rem;
  white-space: pre-wrap;
  word-break: break-all;
  color: #f8d77a;
  font-family: 'SF Mono', Menlo, monospace;
  font-size: 0.85rem;
}
.reveal__foot {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.75rem;
}
.reveal__ttl {
  color: #f2b879;
  font-size: 0.85rem;
}
.reveal__close {
  background: transparent;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 0.375rem;
  color: #c5cbd6;
  padding: 0.35rem 0.75rem;
  cursor: pointer;
}
</style>
