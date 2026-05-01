<script setup lang="ts">
import { ref } from 'vue';

defineProps<{
  projectLabel: string;
}>();

const emit = defineEmits<{
  (event: 'submit', passphrase: string): void;
  (event: 'dismiss'): void;
}>();

const passphrase = ref<string>('');

function onSubmit(): void {
  if (passphrase.value.length === 0) {
    return;
  }
  emit('submit', passphrase.value);
  passphrase.value = '';
}

function onDismiss(): void {
  passphrase.value = '';
  emit('dismiss');
}
</script>

<template>
  <div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="unlock-title">
    <form class="modal" @submit.prevent="onSubmit">
      <h2 id="unlock-title">Unlock vault</h2>
      <p class="modal__caption">Project: {{ projectLabel }}</p>
      <label class="modal__field">
        <span>Passphrase</span>
        <input
          v-model="passphrase"
          type="password"
          autocomplete="current-password"
          required
          autofocus
        />
      </label>
      <div class="modal__actions">
        <button type="button" class="modal__btn modal__btn--ghost" @click="onDismiss">
          Cancel
        </button>
        <button type="submit" class="modal__btn modal__btn--primary" :disabled="passphrase.length === 0">
          Unlock
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
  z-index: 100;
}
.modal {
  background: #161a22;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 0.5rem;
  padding: 1.5rem 1.75rem;
  min-width: 320px;
  max-width: 480px;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.modal h2 {
  margin: 0;
  font-size: 1.15rem;
}
.modal__caption {
  margin: 0;
  color: #9aa3b2;
  font-size: 0.85rem;
}
.modal__field {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  font-size: 0.85rem;
}
.modal__field input {
  background: #0f1115;
  color: #e6e8ec;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 0.375rem;
  padding: 0.5rem 0.625rem;
  font-size: 0.9rem;
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
.modal__btn--primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.modal__btn--ghost {
  background: transparent;
  color: #c5cbd6;
  border: 1px solid rgba(255, 255, 255, 0.12);
}
</style>
