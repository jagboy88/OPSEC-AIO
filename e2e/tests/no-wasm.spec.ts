import { expect, test } from '@playwright/test';

/**
 * Without WebAssembly the crypto engine can't start. Every page must say so
 * plainly and explain how to allow it, never blame storage or fail silently.
 */
test('explains a disabled WebAssembly instead of failing confusingly', async ({ page }) => {
  await page.goto('/');
  expect(await page.evaluate(() => typeof WebAssembly)).toBe('undefined');
  await expect(page.getByTestId('wasm-notice')).toBeVisible();

  await page.goto('/chat');
  await expect(page.getByText('WebAssembly turned off').first()).toBeVisible();
  await expect(page.getByText('Lockdown Mode').first()).toBeVisible();
  await expect(page.getByText(/blocks local storage/)).toHaveCount(0);

  await page.goto('/selftest');
  await expect(page.getByTestId('selftest-status')).toHaveText(
    'Crypto failed to load in this browser.',
  );
  await expect(page.getByText('GrapheneOS (Vanadium)')).toBeVisible();
});
