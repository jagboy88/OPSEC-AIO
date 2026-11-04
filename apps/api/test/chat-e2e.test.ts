/**
 * The real chat client (@opsec-aio/chat) talking to the real API over HTTP
 * and WebSocket, with a real Postgres (TEST_DATABASE_URL).
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { randomBytes, ready } from '@opsec-aio/crypto';
import { ChatClient, HttpChatServer, MemoryKV, createVault } from '@opsec-aio/chat';
import type { IncomingMessage } from '@opsec-aio/types';
import { buildApp } from '../src/app.js';
import { MIGRATIONS_DIR, createPool, migrate, type Pool } from '../src/db.js';

await ready();
const url = process.env.TEST_DATABASE_URL;
const FAST = { opsLimit: 2, memLimitBytes: 8 * 1024 * 1024 };

describe.skipIf(!url)('chat client ⇄ API (postgres)', () => {
  let pool: Pool;
  let app: FastifyInstance;
  let server: HttpChatServer;
  let n = 0;

  beforeAll(async () => {
    pool = createPool(url!);
    await migrate(pool, MIGRATIONS_DIR);
    app = await buildApp({
      config: { logLevel: 'silent', trustProxyHops: 0 },
      probes: {},
      data: { pool, tokenPepper: randomBytes(32) },
    });
    await app.ready();
    // fetch() adapter onto Fastify's in-process injector.
    server = new HttpChatServer(async (input, init) => {
      const res = await app.inject({
        method: (init?.method ?? 'GET') as 'GET',
        url: input,
        remoteAddress: `10.3.${Math.floor(++n / 250)}.${n % 250}`,
        headers: (init?.headers ?? {}) as Record<string, string>,
        ...(init?.body ? { payload: init.body as string } : {}),
      });
      const headers = new Headers();
      for (const [k, v] of Object.entries(res.headers))
        if (v !== undefined) headers.set(k, String(v));
      return new Response(res.statusCode === 204 ? null : res.body, {
        status: res.statusCode,
        headers,
      });
    });
  });
  afterAll(async () => {
    await app?.close();
    await pool?.end();
  });
  beforeEach(async () => {
    await pool.query('DELETE FROM users');
  });

  const account = async (name: string) =>
    ChatClient.create(server, await createVault(new MemoryKV(), 'passphrase!', FAST), name, {
      preKeyBatch: 10,
    });

  it('1:1 and group messages round-trip through the real relay; the database holds no plaintext', async () => {
    const alice = await account('alice');
    const bob = await account('bob');
    const carol = await account('carol');

    await alice.startDirect('bob');
    await alice.sendText('d:bob', 'meet at the usual place');
    await bob.sync();
    await bob.sendText('d:alice', 'ok');
    await alice.sync();
    expect(alice.messages('d:bob').map((m) => m.text)).toEqual(['meet at the usual place', 'ok']);

    const g = await alice.createGroup('crew', ['bob', 'carol']);
    await bob.sync();
    await carol.sync();
    await carol.sendText(g.id, 'carol here');
    const dump = JSON.stringify(
      (await pool.query('SELECT ciphertext FROM mailbox')).rows.map((r) =>
        Buffer.from(r.ciphertext).toString('latin1'),
      ),
    );
    expect(dump).not.toContain('carol here');
    expect(dump).not.toContain('crew');
    await alice.sync();
    await bob.sync();
    expect(
      alice
        .messages(g.id)
        .filter((m) => m.kind === 'text')
        .map((m) => m.text),
    ).toEqual(['carol here']);
    expect(
      bob
        .messages(g.id)
        .filter((m) => m.kind === 'text')
        .map((m) => m.text),
    ).toEqual(['carol here']);
    expect((await pool.query('SELECT 1 FROM mailbox')).rowCount).toBe(0);
  });

  it('delivers over the WebSocket and the pushed message decrypts', async () => {
    const alice = await account('alice');
    const bob = await account('bob');
    const ws = await app.injectWS('/api/v1/ws');
    const pushed: IncomingMessage[] = [];
    const ready = new Promise<void>((resolve) =>
      ws.on('message', (raw: Buffer) => {
        const m = JSON.parse(raw.toString());
        if (m.type === 'ready') resolve();
        if (m.type === 'message') pushed.push(m.message);
      }),
    );
    ws.send(JSON.stringify({ type: 'auth', token: await bob.sessionToken() }));
    await ready;
    await alice.startDirect('bob');
    await alice.sendText('d:bob', 'pushed in real time');
    await new Promise((r) => setTimeout(r, 100));
    expect(pushed).toHaveLength(1);
    await bob.receive(pushed);
    expect(bob.messages('d:alice').map((m) => m.text)).toEqual(['pushed in real time']);
    // Pending fetch afterwards finds nothing new (it was ACKed).
    expect(await bob.sync()).toBe(0);
    ws.terminate();
  });

  it('refills prekeys against the real server', async () => {
    const alice = await account('alice');
    for (const name of ['b1', 'b2', 'b3']) {
      const c = await account(`user_${name}`);
      await c.startDirect('alice');
      await c.sendText('d:alice', 'hi');
    }
    await alice.sync();
    const before = Number(
      (
        await pool.query(
          "SELECT count(*) AS n FROM one_time_prekeys k JOIN users u ON u.id = k.user_id WHERE u.username = 'alice'",
        )
      ).rows[0].n,
    );
    expect(before).toBe(7);
    await alice.maintainKeys();
    const after = Number(
      (
        await pool.query(
          "SELECT count(*) AS n FROM one_time_prekeys k JOIN users u ON u.id = k.user_id WHERE u.username = 'alice'",
        )
      ).rows[0].n,
    );
    expect(after).toBe(17);
  });
});
