import { test as base, expect, type Page } from '@playwright/test';

/**
 * Every page load is watched for CSP/SRI violations, uncaught errors and any
 * request leaving the origin. A privacy app that silently phones home, or whose
 * crypto is blocked by its own CSP, should fail the suite.
 */
export const test = base.extend<{ guard: void }>({
  guard: [
    async ({ page, baseURL }, use) => {
      const problems: string[] = [];
      const origin = new URL(baseURL!).origin;
      page.on('console', (m) => {
        if (m.type() === 'error' || /Content Security Policy|integrity/i.test(m.text())) {
          // Expected: the API's 404 for a burned note is logged by Chrome as a failed resource.
          if (/Failed to load resource: the server responded with a status of 404/.test(m.text()))
            return;
          problems.push(`console: ${m.text()}`);
        }
      });
      page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
      page.on('request', (r) => {
        const u = r.url();
        if (!u.startsWith(origin) && !u.startsWith('data:') && !u.startsWith('blob:')) {
          problems.push(`external request: ${u}`);
        }
      });
      await use();
      expect(problems, 'CSP violations, page errors or external requests').toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

export async function createNote(
  page: Page,
  text: string,
  opts: { views?: number; password?: string } = {},
): Promise<{ link: string; deleteLink: string }> {
  await page.goto('/burn');
  await page.getByLabel('Your note').fill(text);
  if (opts.views) await page.getByLabel('Destroy after').selectOption(String(opts.views));
  if (opts.password) {
    await page.getByLabel('Also require a password').check();
    await page.getByLabel('Password', { exact: true }).fill(opts.password);
  }
  await page.getByRole('button', { name: 'Create secure link' }).click();
  const link = await page.getByTestId('share-link').inputValue({ timeout: 30_000 });
  await page.getByText('Delete it early').click();
  const deleteLink = await page.getByTestId('delete-link').inputValue();
  return { link, deleteLink };
}
