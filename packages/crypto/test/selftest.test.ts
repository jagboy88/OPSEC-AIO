import { expect, it } from 'vitest';
import { runSelfTest } from '../src/index.js';

it('the in-browser self-test passes in Node too', async () => {
  const results = await runSelfTest();
  expect(results.length).toBeGreaterThanOrEqual(9);
  expect(results.filter((r) => !r.ok)).toEqual([]);
});
