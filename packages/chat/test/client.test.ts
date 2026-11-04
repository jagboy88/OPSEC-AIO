import { beforeEach, describe, expect, it } from 'vitest';
import { randomId, ready } from '@opsec-aio/crypto';
import {
  ChatClient,
  ChatInputError,
  IdentityChangedError,
  MemoryKV,
  UsernameTakenError,
  createVault,
  formatSafetyNumber,
  generateUsername,
  unlockVault,
  type FileRef,
} from '../src/index.js';
import { FakeChatServer } from './fake-server.js';

await ready();
const FAST = { opsLimit: 2, memLimitBytes: 8 * 1024 * 1024 };
const PASS = 'a long passphrase';

let server: FakeChatServer;
let clock: number;
const now = () => clock;

async function account(name: string, raw = new MemoryKV()) {
  const kv = await createVault(raw, PASS, FAST);
  const client = await ChatClient.create(server, kv, name, { preKeyBatch: 5, now });
  return { client, raw };
}

const texts = (c: ChatClient, convId: string) =>
  c
    .messages(convId)
    .filter((m) => m.kind !== 'system')
    .map((m) => `${m.from}: ${m.text}`);

beforeEach(() => {
  server = new FakeChatServer();
  clock = 1_000_000;
});

describe('1:1 chat', () => {
  it('exchanges messages both ways across ratchet steps', async () => {
    const { client: alice } = await account('alice');
    const { client: bob } = await account('bob');
    const conv = await alice.startDirect('@Bob');
    expect(conv.id).toBe('d:bob');

    await alice.sendText(conv.id, 'hi bob');
    await alice.sendText(conv.id, 'are you there?');
    expect(await bob.sync()).toBe(2);
    await bob.sendText('d:alice', 'yes!');
    await alice.sync();
    await alice.sendText(conv.id, 'great');
    await bob.sync();

    expect(texts(bob, 'd:alice')).toEqual([
      'alice: hi bob',
      'alice: are you there?',
      'bob: yes!',
      'alice: great',
    ]);
    expect(texts(alice, 'd:bob')).toEqual(texts(bob, 'd:alice'));
    expect(bob.conversation('d:alice')?.unread).toBe(3);
    expect(server.mailbox).toEqual([]); // everything ACKed and deleted
  });

  it('the server only ever sees ciphertext', async () => {
    const { client: alice } = await account('alice');
    await account('bob');
    await alice.startDirect('bob');
    await alice.sendText('d:bob', 'the eagle lands at midnight');
    const [m] = server.mailbox;
    expect(m!.type).toBe(3); // first message carries the X3DH prekey material
    expect(Buffer.from(m!.body, 'base64url').toString('latin1')).not.toContain('eagle');
    expect(JSON.stringify(server.mailbox)).not.toContain('midnight');
  });

  it('ignores duplicates (WebSocket push + pending fetch of the same message)', async () => {
    const { client: alice } = await account('alice');
    const { client: bob } = await account('bob');
    await alice.startDirect('bob');
    await alice.sendText('d:bob', 'once');
    const pending = [...server.mailbox].map(({ to: _to, ...m }) => m);
    await bob.receive(pending);
    await bob.receive(pending);
    expect(texts(bob, 'd:alice')).toEqual(['alice: once']);
    expect(bob.messages('d:alice').some((m) => /could not be decrypted/.test(m.text ?? ''))).toBe(
      false,
    );
  });

  it('survives a restart: state and sessions persist in the encrypted vault', async () => {
    const { client: alice } = await account('alice');
    const bobRaw = new MemoryKV();
    const { client: bob } = await account('bob', bobRaw);
    await alice.startDirect('bob');
    await alice.sendText('d:bob', 'before restart');
    await bob.sync();

    const bob2 = await ChatClient.open(server, await unlockVault(bobRaw, PASS), { now });
    expect(texts(bob2, 'd:alice')).toEqual(['alice: before restart']);
    await alice.sendText('d:bob', 'after restart');
    await bob2.sync();
    await bob2.sendText('d:alice', 'still here');
    await alice.sync();
    expect(texts(alice, 'd:bob').at(-1)).toBe('bob: still here');
  });

  it('validates inputs', async () => {
    const { client: alice } = await account('alice');
    await expect(alice.startDirect('alice')).rejects.toBeInstanceOf(ChatInputError);
    await expect(alice.startDirect('nobody')).rejects.toThrow(/No user/);
    await expect(alice.startDirect('Not Valid!')).rejects.toBeInstanceOf(ChatInputError);
    await expect(account('alice')).rejects.toBeInstanceOf(UsernameTakenError);
    expect(generateUsername()).toMatch(/^[a-z]+_[a-z]+_\d{4}$/);
  });
});

describe('prekeys', () => {
  it('consumes one-time prekeys and refills them', async () => {
    const { client: alice } = await account('alice');
    for (const name of ['bob', 'carol', 'dave', 'erin', 'frank']) {
      const { client } = await account(name);
      await client.startDirect('alice');
      await client.sendText('d:alice', `hi from ${name}`);
    }
    expect(server.users.get('alice')!.otpks).toHaveLength(0);
    await alice.sync();
    expect(alice.conversations()).toHaveLength(5);
    await alice.maintainKeys();
    expect(server.users.get('alice')!.otpks).toHaveLength(5);
    // A sender can still reach alice with no one-time prekey left (X3DH without OPK).
    server.users.get('alice')!.otpks = [];
    const { client: gina } = await account('gina');
    await gina.startDirect('alice');
    await gina.sendText('d:alice', 'no opk needed');
    await alice.sync();
    expect(texts(alice, 'd:gina')).toEqual(['gina: no opk needed']);
  });

  it('rotates the signed prekey weekly', async () => {
    const { client: alice } = await account('alice');
    const before = server.users.get('alice')!.spk.key_id;
    clock += 8 * 24 * 3600 * 1000;
    await alice.maintainKeys();
    expect(server.users.get('alice')!.spk.key_id).toBe(before + 1);
    const { client: bob } = await account('bob');
    await bob.startDirect('alice');
    await bob.sendText('d:alice', 'with the new signed prekey');
    await alice.sync();
    expect(texts(alice, 'd:bob')).toEqual(['bob: with the new signed prekey']);
  });
});

describe('disappearing messages', () => {
  it('syncs the timer, starts on read for recipients and on send for senders', async () => {
    const { client: alice } = await account('alice');
    const { client: bob } = await account('bob');
    await alice.startDirect('bob');
    await alice.setTimer('d:bob', 30);
    await alice.sendText('d:bob', 'self-destructs');
    await bob.sync();
    expect(bob.conversation('d:alice')?.timer).toBe(30);
    expect(
      bob
        .messages('d:alice')
        .some((m) => /set disappearing messages to 30 seconds/.test(m.text ?? '')),
    ).toBe(true);

    // Unread: survives past 30 s…
    clock += 40_000;
    await bob.purgeExpired();
    expect(texts(bob, 'd:alice')).toEqual(['alice: self-destructs']);
    // …the sender's copy expired 30 s after sending.
    await alice.purgeExpired();
    expect(texts(alice, 'd:bob')).toEqual([]);

    // Reading starts the 30 s timer.
    await bob.markRead('d:alice');
    clock += 29_000;
    await bob.purgeExpired();
    expect(texts(bob, 'd:alice')).toHaveLength(1);
    clock += 2_000;
    expect(await bob.purgeExpired()).toBe(1);
    expect(texts(bob, 'd:alice')).toEqual([]);
  });

  it('unread messages still expire at 2 × timer after arrival', async () => {
    const { client: alice } = await account('alice');
    const { client: bob } = await account('bob');
    await alice.startDirect('bob');
    await alice.setTimer('d:bob', 300);
    await alice.sendText('d:bob', 'never read');
    await bob.sync();
    clock += 599_000;
    await bob.purgeExpired();
    expect(texts(bob, 'd:alice')).toHaveLength(1);
    clock += 2_000;
    await bob.purgeExpired();
    expect(texts(bob, 'd:alice')).toEqual([]);
  });

  it('attachment keys vanish with their message', async () => {
    const { client: alice } = await account('alice');
    const { client: bob } = await account('bob');
    await alice.startDirect('bob');
    await alice.setTimer('d:bob', 30);
    const file: FileRef = {
      drop: randomId(),
      key: 'A'.repeat(43),
      name: 'x.pdf',
      size: 10,
      type: 'application/pdf',
    };
    await alice.sendFile('d:bob', file, 'see attached');
    await bob.sync();
    expect(bob.messages('d:alice').find((m) => m.kind === 'file')?.file).toEqual(file);
    await bob.markRead('d:alice');
    clock += 31_000;
    await bob.purgeExpired();
    expect(JSON.stringify(bob.messages('d:alice'))).not.toContain(file.key);
  });
});

describe('groups (pairwise fan-out)', () => {
  it('creates a group, fans out messages and timer changes, handles leaving', async () => {
    const { client: alice } = await account('alice');
    const { client: bob } = await account('bob');
    const { client: carol } = await account('carol');
    const g = await alice.createGroup('Plans', ['bob', 'carol']);
    await bob.sync();
    await carol.sync();
    expect(bob.conversation(g.id)?.members.sort()).toEqual(['alice', 'bob', 'carol']);
    expect(carol.conversation(g.id)?.title).toBe('Plans');

    await bob.sendText(g.id, 'hello group');
    expect(
      server.mailbox
        .filter((m) => m.from === 'bob')
        .map((m) => m.to)
        .sort(),
    ).toEqual(['alice', 'carol']);
    await alice.sync();
    await carol.sync();
    expect(texts(alice, g.id)).toEqual(['bob: hello group']);
    expect(texts(carol, g.id)).toEqual(['bob: hello group']);

    // Any member may change the timer (decision #9).
    await carol.setTimer(g.id, 3600);
    await alice.sync();
    await bob.sync();
    expect(alice.conversation(g.id)?.timer).toBe(3600);
    expect(bob.conversation(g.id)?.timer).toBe(3600);

    await carol.leaveGroup(g.id);
    await alice.sync();
    expect(alice.conversation(g.id)?.members.sort()).toEqual(['alice', 'bob']);
    await expect(carol.sendText(g.id, 'still here?')).rejects.toThrow(/left this group/);
  });

  it('ignores group messages from non-members', async () => {
    const { client: alice } = await account('alice');
    const { client: bob } = await account('bob');
    const { client: mallory } = await account('mallory');
    const g = await alice.createGroup('Private', ['bob']);
    await bob.sync();
    // Mallory forges a "group" conversation with the same id and posts into it.
    await mallory.startDirect('bob');
    // @ts-expect-error -- reaching into internals to forge a group conversation
    mallory.convs.set(g.id, { ...g, members: ['mallory', 'bob'] });
    await mallory.sendText(g.id, 'let me in');
    await bob.sync();
    expect(texts(bob, g.id)).toEqual([]);
  });
});

describe('safety numbers and key changes', () => {
  it('both sides compute the same 60-digit safety number', async () => {
    const { client: alice } = await account('alice');
    const { client: bob } = await account('bob');
    expect(await alice.safetyNumber('bob')).toBeNull();
    await alice.startDirect('bob');
    await alice.sendText('d:bob', 'hi');
    await bob.sync();
    const a = await alice.safetyNumber('bob');
    expect(a).toMatch(/^\d{60}$/);
    expect(await bob.safetyNumber('alice')).toBe(a);
    expect(formatSafetyNumber(a!).split(' ')).toHaveLength(12);
  });

  it('warns when a contact’s key changes, and blocks sending to a verified contact until accepted', async () => {
    const { client: alice } = await account('alice');
    const { client: bob } = await account('bob');
    await alice.startDirect('bob');
    await alice.sendText('d:bob', 'hi');
    await bob.sync();
    await alice.setVerified('bob', true);
    const oldNumber = await alice.safetyNumber('bob');

    // Bob reinstalls: new account, new identity key, same username.
    await bob.deleteAccount();
    const { client: bob2 } = await account('bob');

    // Alice resets the session; the fresh bundle has a different identity.
    await alice.resetSession('bob');
    await expect(alice.sendText('d:bob', 'is this you?')).rejects.toBeInstanceOf(
      IdentityChangedError,
    );
    await alice.acceptNewIdentity('bob');
    await alice.sendText('d:bob', 'is this you?');
    await bob2.sync();
    expect(texts(bob2, 'd:alice')).toEqual(['alice: is this you?']);
    expect(await alice.safetyNumber('bob')).not.toBe(oldNumber);
    expect((await alice.identity('bob'))?.verified).toBe(false);
  });

  it('flags a changed key when the contact messages first', async () => {
    const { client: alice } = await account('alice');
    const { client: bob } = await account('bob');
    await bob.startDirect('alice');
    await bob.sendText('d:alice', 'hi');
    await alice.sync();
    await bob.deleteAccount();
    const { client: bob2 } = await account('bob');
    await bob2.startDirect('alice');
    await bob2.sendText('d:alice', 'new phone');
    await alice.sync();
    expect(texts(alice, 'd:bob').at(-1)).toBe('bob: new phone');
    expect(
      alice.messages('d:bob').some((m) => /safety number with @bob changed/.test(m.text ?? '')),
    ).toBe(true);
    expect((await alice.identity('bob'))?.changed).toBe(true);
  });
});

describe('account deletion', () => {
  it('removes the account server-side and wipes the device', async () => {
    const { client: alice, raw } = await account('alice');
    await alice.deleteAccount();
    expect(server.users.has('alice')).toBe(false);
    expect(raw.map.size).toBe(0);
  });
});
