import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Argon2id at production parameters is deliberately slow.
    testTimeout: 30_000,
  },
});
