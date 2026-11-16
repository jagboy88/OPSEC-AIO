/**
 * Chat server integration tests (accounts, prekeys, relay, WebSocket) against
 * a real Postgres (TEST_DATABASE_URL).
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import {
  authChallengeMessage,
  concatBytes,
  fromBase64Url,
  generateSigningKeyPair,
  randomBytes,
  ready,
  sign,
  toBase64Url,
  type SigningKeyPair,
} from '@opsec-aio/crypto';
import { CHAT_MESSAGE_MAX_BYTES, CHAT_PENDING_PAGE } from '@opsec-aio/types';
import { buildApp } from '../src/app.js';
import { OTPK_HANDOUTS_PER_HOUR } from '../src/routes/keys.js';
import { MIGRATIONS_DIR, createPool, migrate, type Pool } from '../src/db.js';
import { sweep } from '../src/sweeper.js';

await ready();

const url = process.env.TEST_DATABASE_URL;
const pubKey = () => toBase64Url(concatBytes(new Uint8Array([5]), randomBytes(32)));

describe.skipIf(!url)('Chat API (postgres)', () => {
  let pool: Pool;
  let app: FastifyInstance;
  let n = 0;
  const ip = () => `10.2.${Math.floor(++n / 250)}.${n % 250}`;

  const pepper = randomBytes(32);
  async function makeApp(extra: { mailboxMaxBytes?: number } = {}) {
    const a = await buildApp({
      config: { logLevel: 'silent', trustProxyHops: 0 },
      probes: {},
      data: { pool, tokenPepper: pepper, ...extra },
    });
    await a.ready();
    return a;
  }

  beforeAll(async () => {
    pool = createPool(url!);
    await migrate(pool, MIGRATIONS_DIR);
    app = await makeApp();
  });
  afterAll(async () => {
    await app?.close();
    await pool?.end();
  });
  beforeEach(async () => {
    await pool.query('DELETE FROM users');
  });

  const call = (
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    opts: { token?: string; body?: unknown } = {},
  ) =>
    app.inject({
      method,
      url: `/api/v1${path}`,
      remoteAddress: ip(),
      ...(opts.token ? { headers: { authorization: `Bearer ${opts.token}` } } : {}),
      ...(opts.body !== undefined ? { payload: opts.body as object } : {}),
    });

  interface Account {
    username: string;
    keys: SigningKeyPair;
    token: string;
  }

  async function register(username: string, prekeys = 5): Promise<Account> {
    const keys = generateSigningKeyPair();
    const res = await call('POST', '/auth/register', {
      body: {
        username,
        auth_pub: toBase64Url(keys.publicKey),
        identity_pub: pubKey(),
        registration_id: 1234,
        signed_prekey: { key_id: 1, pub: pubKey(), sig: toBase64Url(randomBytes(64)) },
        one_time_prekeys: Array.from({ length: prekeys }, (_, i) => ({
          key_id: i + 1,
          pub: pubKey(),
        })),
      },
    });
    expect(res.statusCode, res.body).toBe(201);
    return { username, keys, token: await login(username, keys) };
  }

  async function login(username: string, keys: SigningKeyPair): Promise<string> {
    const { nonce } = (await call('POST', '/auth/challenge', { body: { username } })).json();
    const signature = sign(authChallengeMessage(username, fromBase64Url(nonce)), keys.privateKey);
    const res = await call('POST', '/auth/login', {
      body: { username, nonce, signature: toBase64Url(signature) },
    });
    expect(res.statusCode, res.body).toBe(200);
    return res.json().session_token;
  }

  describe('accounts', () => {
    it('registers, rejects duplicates and invalid usernames', async () => {
      await register('alice');
      const dup = await call('POST', '/auth/register', {
        body: {
          username: 'alice',
          auth_pub: toBase64Url(randomBytes(32)),
          identity_pub: pubKey(),
          registration_id: 1,
          signed_prekey: { key_id: 1, pub: pubKey(), sig: toBase64Url(randomBytes(64)) },
          one_time_prekeys: [],
        },
      });
      expect(dup.statusCode).toBe(409);
      expect(dup.json()).toEqual({ error: 'conflict' });
      for (const username of ['Al', 'ALICE', 'a b', 'x'.repeat(33), '../etc']) {
        const res = await call('POST', '/auth/register', { body: { username } });
        expect(res.statusCode).toBe(400);
      }
    });

    it('logs in only with a valid signature over a fresh, single-use challenge', async () => {
      const a = await register('alice');
      const { nonce } = (
        await call('POST', '/auth/challenge', { body: { username: 'alice' } })
      ).json();
      const forged = toBase64Url(
        sign(
          authChallengeMessage('alice', fromBase64Url(nonce)),
          generateSigningKeyPair().privateKey,
        ),
      );
      expect(
        (
          await call('POST', '/auth/login', {
            body: { username: 'alice', nonce, signature: forged },
          })
        ).statusCode,
      ).toBe(401);
      // The failed attempt consumed the challenge: even a valid signature now fails.
      const good = toBase64Url(
        sign(authChallengeMessage('alice', fromBase64Url(nonce)), a.keys.privateKey),
      );
      expect(
        (await call('POST', '/auth/login', { body: { username: 'alice', nonce, signature: good } }))
          .statusCode,
      ).toBe(401);
    });

    it('does not reveal whether a username exists at the challenge step', async () => {
      await register('alice');
      const real = await call('POST', '/auth/challenge', { body: { username: 'alice' } });
      const fake = await call('POST', '/auth/challenge', { body: { username: 'nobody_here' } });
      expect(real.statusCode).toBe(fake.statusCode);
      expect(Object.keys(real.json())).toEqual(Object.keys(fake.json()));
      const sig = toBase64Url(randomBytes(64));
      expect(
        (
          await call('POST', '/auth/login', {
            body: { username: 'nobody_here', nonce: fake.json().nonce, signature: sig },
          })
        ).statusCode,
      ).toBe(401);
    });

    it('a challenge for one user cannot be used to log in as another', async () => {
      const a = await register('alice');
      await register('bob');
      const { nonce } = (
        await call('POST', '/auth/challenge', { body: { username: 'bob' } })
      ).json();
      const sig = toBase64Url(
        sign(authChallengeMessage('alice', fromBase64Url(nonce)), a.keys.privateKey),
      );
      expect(
        (await call('POST', '/auth/login', { body: { username: 'alice', nonce, signature: sig } }))
          .statusCode,
      ).toBe(401);
    });

    it('requires a session for keys and messages; logout revokes it', async () => {
      const a = await register('alice');
      expect((await call('GET', '/keys/count')).statusCode).toBe(401);
      expect((await call('GET', '/messages/pending', { token: 'x'.repeat(43) })).statusCode).toBe(
        401,
      );
      expect((await call('GET', '/keys/count', { token: a.token })).statusCode).toBe(200);
      expect((await call('POST', '/auth/logout', { token: a.token })).statusCode).toBe(204);
      expect((await call('GET', '/keys/count', { token: a.token })).statusCode).toBe(401);
    });

    it('stores only a hash of session tokens', async () => {
      const a = await register('alice');
      const { rows } = await pool.query('SELECT token_hash FROM sessions');
      const raw = Buffer.from(fromBase64Url(a.token)).toString('hex');
      expect(rows.every((r) => !Buffer.from(r.token_hash).toString('hex').includes(raw))).toBe(
        true,
      );
    });
  });

  describe('prekeys', () => {
    it('hands out each one-time prekey exactly once, then none', async () => {
      await register('alice', 3);
      const b = await register('bob', 0);
      const seen = new Set<number>();
      for (let i = 0; i < 3; i++) {
        const bundle = (await call('GET', '/keys/bundle/alice', { token: b.token })).json();
        expect(bundle.signed_prekey.key_id).toBe(1);
        seen.add(bundle.one_time_prekey.key_id);
      }
      expect(seen.size).toBe(3);
      const last = (await call('GET', '/keys/bundle/alice', { token: b.token })).json();
      expect(last.one_time_prekey).toBeNull();
      expect((await call('GET', '/keys/bundle/nobody', { token: b.token })).statusCode).toBe(404);
    });

    it('never hands the same prekey to concurrent requests', async () => {
      await register('alice', 10);
      const b = await register('bob', 0);
      const res = await Promise.all(
        Array.from({ length: 10 }, () => call('GET', '/keys/bundle/alice', { token: b.token })),
      );
      const ids = res.map((r) => r.json().one_time_prekey?.key_id);
      expect(new Set(ids).size).toBe(10);
    });

    it('hands out at most 30 one-time prekeys per user per hour, but keeps serving bundles', async () => {
      await register('alice', 40);
      const b = await register('bob', 0);
      const got: (number | null)[] = [];
      for (let i = 0; i < OTPK_HANDOUTS_PER_HOUR + 5; i++) {
        const r = await call('GET', '/keys/bundle/alice', { token: b.token });
        expect(r.statusCode).toBe(200);
        got.push(r.json().one_time_prekey?.key_id ?? null);
      }
      expect(got.filter((k) => k !== null)).toHaveLength(OTPK_HANDOUTS_PER_HOUR);
      expect(got.slice(OTPK_HANDOUTS_PER_HOUR)).toEqual([null, null, null, null, null]);
      const { rows } = await pool.query(
        "SELECT count(*)::int AS n FROM one_time_prekeys k JOIN users u ON u.id = k.user_id WHERE u.username = 'alice'",
      );
      expect(rows[0].n).toBe(40 - OTPK_HANDOUTS_PER_HOUR);
      // A new hour window hands them out again.
      await pool.query(
        "UPDATE users SET otpk_window_start = now() - interval '61 minutes' WHERE username = 'alice'",
      );
      expect(
        (await call('GET', '/keys/bundle/alice', { token: b.token })).json().one_time_prekey,
      ).not.toBeNull();
    });

    it('replenishes up to the cap and rotates signed prekeys keeping two', async () => {
      const a = await register('alice', 0);
      const batch = (start: number, count: number) =>
        Array.from({ length: count }, (_, i) => ({ key_id: start + i, pub: pubKey() }));
      for (const start of [1, 101, 201]) {
        const r = await call('POST', '/keys/prekeys', {
          token: a.token,
          body: { one_time_prekeys: batch(start, 100) },
        });
        expect(r.statusCode).toBe(200);
      }
      expect((await call('GET', '/keys/count', { token: a.token })).json()).toEqual({
        one_time_prekeys: 300,
      });
      expect(
        (
          await call('POST', '/keys/prekeys', {
            token: a.token,
            body: { one_time_prekeys: batch(301, 1) },
          })
        ).statusCode,
      ).toBe(400);

      for (const id of [2, 3, 4]) {
        const r = await call('PUT', '/keys/signed-prekey', {
          token: a.token,
          body: { key_id: id, pub: pubKey(), sig: toBase64Url(randomBytes(64)) },
        });
        expect(r.statusCode).toBe(204);
      }
      const { rows } = await pool.query('SELECT key_id FROM signed_prekeys ORDER BY key_id');
      expect(rows.map((r) => r.key_id)).toEqual([3, 4]);
    });
  });

  describe('relay', () => {
    const body = () => toBase64Url(randomBytes(200));

    it('delivers, lists and deletes on ACK; only the recipient can ACK', async () => {
      const a = await register('alice');
      const b = await register('bob');
      const msg = body();
      const sent = await call('POST', '/messages', {
        token: a.token,
        body: { messages: [{ to: 'bob', type: 3, body: msg }] },
      });
      expect(sent.statusCode).toBe(201);

      const pending = (await call('GET', '/messages/pending', { token: b.token })).json().messages;
      expect(pending).toHaveLength(1);
      expect(pending[0]).toMatchObject({ from: 'alice', type: 3, body: msg });
      expect((await call('GET', '/messages/pending', { token: a.token })).json().messages).toEqual(
        [],
      );

      // Alice cannot delete Bob's mail.
      await call('POST', '/messages/ack', { token: a.token, body: { ids: [pending[0].id] } });
      expect(
        (await call('GET', '/messages/pending', { token: b.token })).json().messages,
      ).toHaveLength(1);
      expect(
        (await call('POST', '/messages/ack', { token: b.token, body: { ids: [pending[0].id] } }))
          .statusCode,
      ).toBe(204);
      expect((await call('GET', '/messages/pending', { token: b.token })).json().messages).toEqual(
        [],
      );
      expect((await pool.query('SELECT 1 FROM mailbox')).rowCount).toBe(0);
    });

    it('pages pending messages, and ACKs a full page in one request', async () => {
      const a = await register('alice');
      const b = await register('bob');
      for (let i = 0; i < 15; i++) {
        await call('POST', '/messages', {
          token: a.token,
          body: {
            messages: Array.from({ length: 20 }, () => ({ to: 'bob', type: 1, body: body() })),
          },
        });
      }
      const pending = (await call('GET', '/messages/pending', { token: b.token })).json().messages;
      expect(pending).toHaveLength(CHAT_PENDING_PAGE);
      const ack = await call('POST', '/messages/ack', {
        token: b.token,
        body: { ids: pending.map((m: { id: string }) => m.id) },
      });
      expect(ack.statusCode).toBe(204);
      expect((await pool.query('SELECT 1 FROM mailbox')).rowCount).toBe(300 - CHAT_PENDING_PAGE);
    });

    it('refuses messages over 16 KiB, and new mail once all mailboxes hold the global cap', async () => {
      const a = await register('alice');
      await register('bob');
      const big = toBase64Url(randomBytes(CHAT_MESSAGE_MAX_BYTES + 1));
      const tooBig = await call('POST', '/messages', {
        token: a.token,
        body: { messages: [{ to: 'bob', type: 1, body: big }] },
      });
      expect(tooBig.statusCode).toBe(400);

      const small = await makeApp({ mailboxMaxBytes: 3 * CHAT_MESSAGE_MAX_BYTES });
      try {
        const full = toBase64Url(randomBytes(CHAT_MESSAGE_MAX_BYTES));
        const send = () =>
          small.inject({
            method: 'POST',
            url: '/api/v1/messages',
            remoteAddress: ip(),
            headers: { authorization: `Bearer ${a.token}` },
            payload: { messages: [{ to: 'bob', type: 1, body: full }] },
          });
        expect((await send()).statusCode).toBe(201);
        expect((await send()).statusCode).toBe(201);
        expect((await send()).statusCode).toBe(201);
        const res = await send();
        expect(res.statusCode).toBe(507);
        expect(res.json()).toEqual({ error: 'storage_full' });
      } finally {
        await small.close();
      }
    });

    it('fans out a batch, and rejects the whole batch if any recipient is unknown', async () => {
      const a = await register('alice');
      const b = await register('bob');
      const c = await register('carol');
      const ok = await call('POST', '/messages', {
        token: a.token,
        body: {
          messages: [
            { to: 'bob', type: 1, body: body() },
            { to: 'carol', type: 1, body: body() },
          ],
        },
      });
      expect(ok.json()).toEqual({ sent: 2 });
      const bad = await call('POST', '/messages', {
        token: a.token,
        body: {
          messages: [
            { to: 'bob', type: 1, body: body() },
            { to: 'nobody', type: 1, body: body() },
          ],
        },
      });
      expect(bad.statusCode).toBe(404);
      for (const t of [b.token, c.token]) {
        expect((await call('GET', '/messages/pending', { token: t })).json().messages).toHaveLength(
          1,
        );
      }
    });

    it('validates message shape and size', async () => {
      const a = await register('alice');
      await register('bob');
      for (const m of [
        { to: 'bob', type: 2, body: body() },
        { to: 'bob', type: 1, body: 'not base64!' },
        { to: 'bob', type: 1, body: toBase64Url(randomBytes(64 * 1024 + 1)) },
      ]) {
        const r = await call('POST', '/messages', { token: a.token, body: { messages: [m] } });
        expect([400, 413]).toContain(r.statusCode);
      }
    });

    it('pushes messages over the WebSocket after token auth', async () => {
      const a = await register('alice');
      const b = await register('bob');
      const ws = await app.injectWS('/api/v1/ws');
      const inbox: unknown[] = [];
      const readyP = new Promise<void>((resolve) =>
        ws.on('message', (raw: Buffer) => {
          const m = JSON.parse(raw.toString());
          if (m.type === 'ready') resolve();
          else inbox.push(m);
        }),
      );
      ws.send(JSON.stringify({ type: 'auth', token: b.token }));
      await readyP;
      const msg = body();
      await call('POST', '/messages', {
        token: a.token,
        body: { messages: [{ to: 'bob', type: 1, body: msg }] },
      });
      await new Promise((r) => setTimeout(r, 50));
      expect(inbox).toEqual([
        { type: 'message', message: expect.objectContaining({ from: 'alice', body: msg }) },
      ]);
      ws.terminate();
    });

    it('closes a WebSocket that presents a bad token', async () => {
      const ws = await app.injectWS('/api/v1/ws');
      const closed = new Promise<number>((resolve) =>
        ws.on('close', (code: number) => resolve(code)),
      );
      ws.send(JSON.stringify({ type: 'auth', token: 'A'.repeat(43) }));
      expect(await closed).toBe(4401);
    });

    it('answers garbage WebSocket frames with an error instead of crashing', async () => {
      const b = await register('bob');
      const ws = await app.injectWS('/api/v1/ws');
      const replies: unknown[] = [];
      ws.on('message', (raw: Buffer) => replies.push(JSON.parse(raw.toString())));
      for (const frame of [
        'null',
        '42',
        '"auth"',
        '[]',
        '{}',
        '{"type":7}',
        'not json',
        '{"type":"auth"}',
      ]) {
        ws.send(frame);
      }
      ws.send(JSON.stringify({ type: 'auth', token: { not: 'a string' } }));
      ws.send(JSON.stringify({ type: 'ping' }));
      await new Promise((r) => setTimeout(r, 100));
      expect(replies).toHaveLength(10);
      expect(
        replies.slice(0, 9).every((m) => (m as { error?: string }).error === 'bad_request'),
      ).toBe(true);
      expect(replies[9]).toEqual({ type: 'pong' });
      // The process and this socket are still fine: auth still works.
      const ready = new Promise<void>((resolve) =>
        ws.on('message', (raw: Buffer) => {
          if (JSON.parse(raw.toString()).type === 'ready') resolve();
        }),
      );
      ws.send(JSON.stringify({ type: 'auth', token: b.token }));
      await ready;
      ws.terminate();
    });

    it('caps open WebSockets per client', async () => {
      // A real listener: injected sockets never report the server-side close.
      const addr = await app.listen({ port: 0, host: '127.0.0.1' });
      const url = `${addr.replace('http', 'ws')}/api/v1/ws`;
      const connect = () =>
        new Promise<WebSocket>((resolve, reject) => {
          const ws = new WebSocket(url);
          ws.addEventListener('open', () => resolve(ws));
          ws.addEventListener('error', () => reject(new Error('connect failed')));
        });
      const closed = (ws: WebSocket) =>
        new Promise<number>((resolve) => ws.addEventListener('close', (e) => resolve(e.code)));

      const open = await Promise.all(Array.from({ length: 20 }, connect));
      const extra = await connect();
      expect(await closed(extra)).toBe(4429);
      // Closing one frees a slot.
      const first = open[0]!;
      const firstClosed = closed(first);
      first.close();
      await firstClosed;
      await new Promise((r) => setTimeout(r, 50));
      const again = await connect();
      const pong = new Promise<unknown>((resolve) =>
        again.addEventListener('message', (e) => resolve(JSON.parse(String(e.data)))),
      );
      again.send(JSON.stringify({ type: 'ping' }));
      expect(await pong).toEqual({ type: 'pong' });
      for (const ws of [...open.slice(1), again]) ws.close();
    });

    it('account deletion removes keys, sessions and queued mail; senders become anonymous', async () => {
      const a = await register('alice');
      const b = await register('bob');
      await call('POST', '/messages', {
        token: a.token,
        body: { messages: [{ to: 'bob', type: 1, body: body() }] },
      });
      await call('POST', '/messages', {
        token: b.token,
        body: { messages: [{ to: 'alice', type: 1, body: body() }] },
      });
      expect((await call('DELETE', '/auth/account', { token: a.token })).statusCode).toBe(204);
      for (const t of ['users', 'one_time_prekeys', 'signed_prekeys', 'sessions']) {
        const { rows } = await pool.query(
          `SELECT count(*)::int AS n FROM ${t} WHERE ${t === 'users' ? 'username' : 'user_id'} = ${t === 'users' ? "'alice'" : "(SELECT id FROM users WHERE username = 'alice')"}`,
        );
        expect(rows[0].n).toBe(0);
      }
      const pending = (await call('GET', '/messages/pending', { token: b.token })).json().messages;
      expect(pending[0].from).toBeNull();
      expect((await call('GET', '/keys/count', { token: a.token })).statusCode).toBe(401);
    });

    it('sweeps expired challenges and sessions', async () => {
      await register('alice');
      await call('POST', '/auth/challenge', { body: { username: 'alice' } });
      await pool.query("UPDATE auth_challenges SET expires_at = now() - interval '1 second'");
      await pool.query("UPDATE sessions SET expires_at = now() - interval '1 second'");
      const r = await sweep(pool);
      expect(r.sessions).toBe(1);
      expect((await pool.query('SELECT 1 FROM auth_challenges')).rowCount).toBe(0);
    });
  });
});
