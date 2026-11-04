import { createNote, expect, test } from './fixtures.js';

test.describe('Burn', () => {
  test('a note is readable exactly once, and the key never reaches the server', async ({
    page,
    browser,
  }) => {
    const text = `Launch code ${Date.now()}\nline two ✓`;
    const { link } = await createNote(page, text);

    const url = new URL(link);
    expect(url.pathname).toMatch(/^\/n\/[A-Za-z0-9_-]{22}$/);
    expect(url.hash.length).toBe(44); // '#' + 43-char base64url key

    // The plaintext was cleared from the compose form's memory.
    await expect(page.getByText(text)).toHaveCount(0);

    // Recipient: fresh browser context, record every request sent.
    const recipient = await browser.newContext({ ignoreHTTPSErrors: true });
    const rpage = await recipient.newPage();
    const sent: string[] = [];
    rpage.on('request', (r) => sent.push(r.url() + ' ' + (r.postData() ?? '')));

    await rpage.goto(link);
    await expect(rpage.getByText('This note will be destroyed when you open it.')).toBeVisible();
    // Nothing has been fetched from the note API yet: link previews can't burn it.
    expect(sent.some((s) => s.includes('/api/v1/note/'))).toBe(false);

    await rpage.getByRole('button', { name: 'Open and destroy note' }).click();
    await expect(rpage.getByTestId('note-text')).toHaveText(text);
    await expect(rpage.getByText('This note has now been destroyed')).toBeVisible();

    // The key was removed from the address bar...
    expect(new URL(rpage.url()).hash).toBe('');
    // ...and was never sent to the server in any request.
    const key = url.hash.slice(1);
    expect(sent.filter((s) => s.includes(key))).toEqual([]);

    // Second visit: gone, indistinguishable from never-existed.
    const again = await recipient.newPage();
    await again.goto(link);
    await again.getByRole('button', { name: 'Open and destroy note' }).click();
    await expect(again.getByText("There's nothing here.")).toBeVisible();
    await recipient.close();
  });

  test('multi-view notes count down', async ({ page }) => {
    const { link } = await createNote(page, 'twice', { views: 2 });
    await page.goto(link);
    await page.getByRole('button', { name: 'Open and destroy note' }).click();
    await expect(
      page.getByText('It can be opened 1 more time before it is destroyed.'),
    ).toBeVisible();

    await page.goto(link);
    await page.getByRole('button', { name: 'Open and destroy note' }).click();
    await expect(page.getByTestId('note-text')).toHaveText('twice');
    await expect(page.getByText('This note has now been destroyed')).toBeVisible();
  });

  test('password-protected notes need the password, and wrong guesses can be retried', async ({
    page,
  }) => {
    const { link } = await createNote(page, 'behind a password', { password: 'hunter2!' });
    expect(link.endsWith('.p')).toBe(true);

    await page.goto(link);
    await expect(page.getByText('It is password-protected.')).toBeVisible();
    await page.getByRole('button', { name: 'Open and destroy note' }).click();

    await page.getByLabel('Password', { exact: true }).fill('wrong');
    await page.getByRole('button', { name: 'Unlock' }).click();
    await expect(page.getByRole('alert')).toContainText('Wrong password');

    await page.getByLabel('Password', { exact: true }).fill('hunter2!');
    await page.getByRole('button', { name: 'Unlock' }).click();
    await expect(page.getByTestId('note-text')).toHaveText('behind a password', {
      timeout: 15_000,
    });
  });

  test('the deletion link destroys an unread note', async ({ page }) => {
    const { link, deleteLink } = await createNote(page, 'never to be read');
    await page.goto(deleteLink);
    await page.getByRole('button', { name: 'Delete note' }).click();
    await expect(page.getByText('Deleted.')).toBeVisible();

    await page.goto(link);
    await page.getByRole('button', { name: 'Open and destroy note' }).click();
    await expect(page.getByText("There's nothing here.")).toBeVisible();
  });

  test('a link with the key cut off explains what happened', async ({ page }) => {
    const { link } = await createNote(page, 'x');
    await page.goto(link.split('#')[0]!);
    await expect(page.getByText('This link is incomplete.')).toBeVisible();
  });

  test('a tampered key fails safely', async ({ page }) => {
    const { link } = await createNote(page, 'y');
    const [base, key] = link.split('#') as [string, string];
    const flipped = (key[0] === 'A' ? 'B' : 'A') + key.slice(1);
    await page.goto(`${base}#${flipped}`);
    await page.getByRole('button', { name: 'Open and destroy note' }).click();
    await expect(page.getByText('This note could not be decrypted.')).toBeVisible();
  });
});

test('home page links to Burn and the self-test passes', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: /Write a note/ }).click();
  await expect(page).toHaveURL(/\/burn$/);
  await page.goto('/selftest');
  await expect(page.getByTestId('selftest-status')).toHaveText('All checks passed.', {
    timeout: 30_000,
  });
});
