import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';
import ts from 'typescript-eslint';

export default ts.config(
  {
    ignores: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/.svelte-kit/**'],
  },
  js.configs.recommended,
  ...ts.configs.recommended,
  ...svelte.configs.recommended,
  prettier,
  ...svelte.configs.prettier,
  {
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
    },
    rules: {
      // Crypto code must never fall back to a weak RNG.
      'no-restricted-properties': [
        'error',
        { object: 'Math', property: 'random', message: 'Use a CSPRNG (randomBytes) instead.' },
      ],
      'no-restricted-globals': [
        'error',
        { name: 'localStorage', message: 'Secrets must never touch localStorage (plan §2.3).' },
      ],
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
  {
    files: ['**/*.svelte', '**/*.svelte.ts'],
    languageOptions: {
      parserOptions: { parser: ts.parser, extraFileExtensions: ['.svelte'] },
    },
  },
);
