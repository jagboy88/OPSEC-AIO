import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { Browser, Page } from '@playwright/test';
import { expect, test } from './fixtures.js';

const PASS = 'correct horse battery staple';
const uniq = () => randomBytes(3).toString('hex');

async function newUser(browser: Browser, name: string): Promise<Page> {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  await page.goto('/chat');
  await page.getByLabel('Username').fill(name);
  await page.getByLabel('Passphrase', { exact: true }).fill(PASS);
  await page.getByLabel('Repeat passphrase').fill(PASS);
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByTestId('me')).toHaveText(`@${name}`, { timeout: 30_000 });
  await expect(page.getByTitle('Connected')).toBeVisible({ timeout: 15_000 });
  return page;
}

async function startChat(page: Page, peer: string) {
  await page.getByRole('button', { name: 'New', exact: true }).click();
  await page.getByLabel('Username').fill(peer);
  await page.getByRole('button', { name: 'Start chat' }).click();
  await expect(page.getByTestId('conv-title')).toHaveText(`@${peer}`);
}

async function send(page: Page, text: string) {
  await page.getByLabel('Message', { exact: true }).fill(text);
  await page.getByRole('button', { name: 'Send' }).click();
  await expect(page.getByTestId('message-text').filter({ hasText: text })).toBeVisible();
}

async function open(page: Page, title: string) {
  await page.getByTestId('conversation-list').getByText(title, { exact: true }).click();
}

test.describe('Chat', () => {
  test.describe.configure({ timeout: 120_000 });

  test('two people chat in real time and see the same safety number', async ({ browser }) => {
    const a = `alice_${uniq()}`;
    const b = `bob_${uniq()}`;
    const alice = await newUser(browser, a);
    const bob = await newUser(browser, b);

    await startChat(alice, b);
    await send(alice, 'hello from alice ✓');

    // Arrives over the WebSocket without reloading.
    await open(bob, `@${a}`);
    await expect(bob.getByTestId('message-text')).toHaveText('hello from alice ✓');
    await send(bob, 'hi alice');
    await expect(alice.getByTestId('message-text').filter({ hasText: 'hi alice' })).toBeVisible();

    for (const p of [alice, bob]) {
      await p.getByRole('button', { name: 'Conversation menu' }).click();
      await p.getByRole('button', { name: 'Safety number' }).click();
    }
    const sa = await alice.getByTestId('safety-number').innerText();
    const sb = await bob.getByTestId('safety-number').innerText();
    expect(sa.replace(/\s/g, '')).toMatch(/^\d{60}$/);
    expect(sa.replace(/\s/g, '')).toBe(sb.replace(/\s/g, ''));
    await alice.getByRole('button', { name: 'Mark as verified' }).click();
    await expect(alice.getByText('· ✓ verified')).toBeVisible();
  });

  test('disappearing messages are synced and deleted when the timer runs out', async ({
    browser,
  }) => {
    const a = `alice_${uniq()}`;
    const b = `bob_${uniq()}`;
    const alice = await newUser(browser, a);
    const bob = await newUser(browser, b);
    await startChat(alice, b);
    await alice.getByLabel('Disappearing messages').selectOption('30');
    await send(alice, 'this will vanish');

    await open(bob, `@${a}`);
    await expect(bob.getByText(`@${a} set disappearing messages to 30 seconds.`)).toBeVisible();
    await expect(bob.getByTestId('message-text')).toHaveText('this will vanish');
    await expect(bob.getByLabel('Disappearing messages')).toHaveValue('30');

    // Sender's copy started at send; reader's at read. Both gone after 30 s.
    await expect(alice.getByTestId('message-text')).toHaveCount(0, { timeout: 45_000 });
    await expect(bob.getByTestId('message-text')).toHaveCount(0, { timeout: 45_000 });
  });

  test('groups fan out to every member', async ({ browser }) => {
    const [a, b, c] = [`alice_${uniq()}`, `bob_${uniq()}`, `carol_${uniq()}`];
    const alice = await newUser(browser, a);
    const bob = await newUser(browser, b);
    const carol = await newUser(browser, c);

    await alice.getByRole('button', { name: 'New', exact: true }).click();
    await alice.getByRole('tab', { name: 'Group' }).click();
    await alice.getByLabel('Group name').fill('Night shift');
    await alice.getByLabel('Members').fill(`${b}, ${c}`);
    await alice.getByRole('button', { name: 'Create group' }).click();
    await expect(alice.getByTestId('conv-title')).toHaveText('Night shift');

    await open(carol, '# Night shift');
    await expect(carol.getByText(`@${a} added you to “Night shift”.`)).toBeVisible();
    await send(carol, 'carol checking in');
    await expect(
      alice.getByTestId('message-text').filter({ hasText: 'carol checking in' }),
    ).toBeVisible();
    await open(bob, '# Night shift');
    await expect(bob.getByTestId('message-text')).toHaveText('carol checking in');

    // Only the creator manages members; every change is spelled out.
    await bob.getByRole('button', { name: 'Conversation menu' }).click();
    await bob.getByRole('button', { name: 'Members', exact: true }).click();
    await expect(bob.getByTestId('group-members')).toContainText(`@${a}`);
    await expect(bob.getByRole('button', { name: `Remove @${c}` })).toHaveCount(0);

    await alice.getByRole('button', { name: 'Conversation menu' }).click();
    await alice.getByRole('button', { name: 'Manage members' }).click();
    await alice.getByRole('button', { name: `Remove @${c}` }).click();
    await expect(alice.getByText(`You removed @${c}.`)).toBeVisible();
    await expect(bob.getByText(`@${a} removed @${c}.`)).toBeVisible();
    await expect(carol.getByText(`@${a} removed you.`)).toBeVisible();
    await send(alice, 'just us now');
    await expect(bob.getByTestId('message-text').filter({ hasText: 'just us now' })).toBeVisible();
    await expect(carol.getByTestId('message-text').filter({ hasText: 'just us now' })).toHaveCount(
      0,
    );

    await alice.getByLabel('Usernames to add').fill(`@${c}`);
    await alice.getByRole('button', { name: 'Add', exact: true }).click();
    await expect(alice.getByText(`You added @${c}.`)).toBeVisible();
    await expect(carol.getByText(`@${a} added you back.`)).toBeVisible();
    await send(carol, 'back again');
    await expect(alice.getByTestId('message-text').filter({ hasText: 'back again' })).toBeVisible();
  });

  test('files are shared as encrypted attachments', async ({ browser }) => {
    const a = `alice_${uniq()}`;
    const b = `bob_${uniq()}`;
    const alice = await newUser(browser, a);
    const bob = await newUser(browser, b);
    await startChat(alice, b);
    const content = randomBytes(200_000);
    await alice.locator('form input[type=file]').setInputFiles({
      name: 'evidence.bin',
      mimeType: 'application/octet-stream',
      buffer: content,
    });
    await expect(alice.getByText('📎 evidence.bin')).toBeVisible({ timeout: 30_000 });

    await open(bob, `@${a}`);
    await expect(bob.getByText('📎 evidence.bin')).toBeVisible();
    const [dl] = await Promise.all([
      bob.waitForEvent('download'),
      bob.getByRole('button', { name: 'Download' }).click(),
    ]);
    expect(dl.suggestedFilename()).toBe('evidence.bin');
    expect((await readFile(await dl.path())).equals(content)).toBe(true);
  });

  test('lock, wrong passphrase, unlock keeps history; account deletion wipes it', async ({
    browser,
  }) => {
    const a = `alice_${uniq()}`;
    const b = `bob_${uniq()}`;
    const alice = await newUser(browser, a);
    await newUser(browser, b);
    await startChat(alice, b);
    await send(alice, 'remember me');

    await alice.getByRole('button', { name: 'Settings' }).click();
    await alice.getByRole('button', { name: /^Lock/ }).click();
    await expect(alice.getByRole('heading', { name: 'Unlock chat' })).toBeVisible();
    await alice.getByLabel('Passphrase').fill('wrong passphrase');
    await alice.getByRole('button', { name: 'Unlock' }).click();
    await expect(alice.getByRole('alert')).toHaveText('Wrong passphrase.');
    await alice.getByLabel('Passphrase').fill(PASS);
    await alice.getByRole('button', { name: 'Unlock' }).click();
    await open(alice, `@${b}`);
    await expect(alice.getByTestId('message-text')).toHaveText('remember me');

    await alice.getByRole('button', { name: 'Settings' }).click();
    await alice.getByText('Delete account').click();
    await alice.getByLabel('Type your username to confirm').fill(a);
    await alice.getByRole('button', { name: 'Delete everything' }).click();
    await expect(alice.getByRole('heading', { name: 'Create a chat account' })).toBeVisible();
    await alice.reload();
    await expect(alice.getByRole('heading', { name: 'Create a chat account' })).toBeVisible();
  });
});
