// Out-of-tree TypeScript linting for the Locket VS Code extension.
// Mirrors the workspace's posture: deny-by-default for unsafe and
// production-noise patterns. Matching the cli/agent crate clippy
// posture keeps developer feedback consistent across surfaces.
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
    project: ['./tsconfig.json'],
    tsconfigRootDir: __dirname,
  },
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
  ],
  env: {
    node: true,
    es2022: true,
  },
  rules: {
    'no-console': 'error',
    '@typescript-eslint/no-explicit-any': 'error',
    '@typescript-eslint/no-non-null-assertion': 'error',
    '@typescript-eslint/explicit-module-boundary-types': 'error',
  },
  ignorePatterns: ['out/**', 'node_modules/**'],
};
