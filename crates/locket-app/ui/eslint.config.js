import js from '@eslint/js';
import vue from 'eslint-plugin-vue';
import vueTs from '@vue/eslint-config-typescript';

export default [
  js.configs.recommended,
  ...vue.configs['flat/recommended'],
  ...vueTs(),
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
    },
    rules: {
      'no-console': 'warn',
      'no-debugger': 'error',
    },
  },
  {
    ignores: ['dist/**', 'node_modules/**'],
  },
];
