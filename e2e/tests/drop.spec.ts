import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { Page } from '@playwright/test';
import { expect, test } from './fixtures.js';

interface UploadOpts {
  name?: string;
  content?: Buffer;
  downloads?: string;
  password?: string;
}

async function uploadDrop(page: Page, opts: UploadOpts = {}) {
  const name = opts.name ?? 'secret-plans.txt';
  const content = opts.content ?? Buffer.from(`top secret ${Date.now()} ✓\n`);
  await page.goto('/drop');
  await page.locator('#file').setInputFiles({ name, mimeType: 'text/plain', buffer: content });
  await expect(page.getByTestId('picked-name')).toHaveText(name);
  if (opts.downloads) await page.getByLabel('Downloads allowed').selectOption(opts.downloads);
  if (opts.password) {
    await page.getByLabel('Also require a password').check();
    await page.getByLabel('Password', { exact: true }).fill(opts.password);
  }
  await page.getByRole('button', { name: 'Encrypt & upload' }).click();
  const link = await page.getByTestId('share-link').inputValue({ timeout: 60_000 });
  await page.getByText('Delete it early').click();
  const deleteLink = await page.getByTestId('delete-link').inputValue();
  return { name, content, link, deleteLink };
}

async function downloadVia(page: Page): Promise<{ name: string; bytes: Buffer }> {
  const [dl] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download & decrypt' }).click(),
  ]);
  const path = await dl.path();
  return { name: dl.suggestedFilename(), bytes: await readFile(path) };
}

test.describe('Drop', () => {
  test('a file round-trips byte-for-byte and the key never reaches the server', async ({
    page,
    browser,
  }) => {
    const up = await uploadDrop(page);
    const url = new URL(up.link);
    expect(url.pathname).toMatch(/^\/d\/[A-Za-z0-9_-]{22}$/);

    const recipient = await browser.newContext({ ignoreHTTPSErrors: true });
    const rpage = await recipient.newPage();
    const sent: string[] = [];
    rpage.on('request', (r) => sent.push(`${r.url()} ${r.postData() ?? ''}`));

    await rpage.goto(up.link);
    await expect(rpage.getByTestId('file-name')).toHaveText(up.name);
    const got = await downloadVia(rpage);
    expect(got.name).toBe(up.name);
    expect(got.bytes.equals(up.content)).toBe(true);
    await expect(rpage.getByText('Decrypted and saved.')).toBeVisible();

    const key = url.hash.slice(1);
    expect(sent.filter((s) => s.includes(key))).toEqual([]);
    expect(new URL(rpage.url()).hash).toBe('');
    // Neither the name nor the contents were ever sent in the clear.
    expect(sent.filter((s) => s.includes(up.name) || s.includes('top secret'))).toEqual([]);
    await recipient.close();
  });

  test('multi-chunk files (2.5 MB, 3 chunks) decrypt correctly', async ({ page }) => {
    const content = randomBytes(2_500_000);
    const up = await uploadDrop(page, { name: 'big.bin', content });
    await page.goto(up.link);
    await expect(page.getByTestId('file-name')).toHaveText('big.bin');
    const got = await downloadVia(page);
    expect(got.bytes.length).toBe(content.length);
    expect(got.bytes.equals(content)).toBe(true);
  });

  test('a one-download file disappears after it is downloaded', async ({ page }) => {
    const up = await uploadDrop(page, { downloads: '1' });
    await page.goto(up.link);
    await expect(page.getByText('or after 1 more download')).toBeVisible();
    const got = await downloadVia(page);
    expect(got.bytes.equals(up.content)).toBe(true);
    await expect(page.getByText('That was the last allowed download.')).toBeVisible();

    await page.goto(up.link);
    await expect(page.getByText("There's nothing here.")).toBeVisible();
  });

  test('password-protected files need the password before even the name is shown', async ({
    page,
  }) => {
    const up = await uploadDrop(page, { name: 'locked.txt', password: 'open sesame' });
    expect(up.link.endsWith('.p')).toBe(true);
    await page.goto(up.link);
    await expect(page.getByText('This file is password-protected.')).toBeVisible();
    await expect(page.getByText('locked.txt')).toHaveCount(0);

    await page.getByLabel('Password', { exact: true }).fill('nope');
    await page.getByRole('button', { name: 'Unlock' }).click();
    await expect(page.getByRole('alert')).toContainText('Wrong password');

    await page.getByLabel('Password', { exact: true }).fill('open sesame');
    await page.getByRole('button', { name: 'Unlock' }).click();
    await expect(page.getByTestId('file-name')).toHaveText('locked.txt', { timeout: 15_000 });
    const got = await downloadVia(page);
    expect(got.bytes.equals(up.content)).toBe(true);
  });

  test('the deletion link removes the file', async ({ page }) => {
    const up = await uploadDrop(page);
    await page.goto(up.deleteLink);
    await page.getByRole('button', { name: 'Delete file' }).click();
    await expect(page.getByText('Deleted.')).toBeVisible();
    await page.goto(up.link);
    await expect(page.getByText("There's nothing here.")).toBeVisible();
  });

  test('a tampered key fails safely', async ({ page }) => {
    const up = await uploadDrop(page);
    const [base, key] = up.link.split('#') as [string, string];
    await page.goto(`${base}#${(key[0] === 'A' ? 'B' : 'A') + key.slice(1)}`);
    await expect(page.getByText('This file could not be decrypted.')).toBeVisible();
  });
});
