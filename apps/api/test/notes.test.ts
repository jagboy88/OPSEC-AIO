/**
 * Burn API integration tests against a real Postgres (TEST_DATABASE_URL).
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import {
  encryptNote,
  fromBase64Url,
  randomBytes,
  randomId,
  ready,
  toBase64Url,
} from '@opsec-aio/crypto';
import { NOTE_MAX_CIPHERTEXT_BYTES, NOTE_TEXT_MAX_BYTES_CHECK } from './helpers.js';
import { buildApp } from '../src/app.js';
import { MIGRATIONS_DIR, createPool, migrate, type Pool } from '../src/db.js';
import { sweep } from '../src/sweeper.js';

await ready();

const url = process.env.TEST_DATABASE_URL;
const HOUR = 3600;

describe.skipIf(!url)('Burn API (postgres)', () => {
  let pool: Pool;
  let app: FastifyInstance;
  let ipCounter = 0;
  /** Fresh client IP per request so rate limits don't interfere with functional tests. */
  const ip = () => `10.0.${Math.floor(++ipCounter / 250)}.${ipCounter % 250}`;

  beforeAll(async () => {
    pool = createPool(url!);
    await migrate(pool, MIGRATIONS_DIR);
    app = await buildApp({
      config: { logLevel: 'silent', trustProxyHops: 0 },
      probes: {},
      data: { pool, tokenPepper: randomBytes(32) },
    });
    await app.ready();
  });
  afterAll(async () => {
    await app?.close();
    await pool?.end();
  });
  beforeEach(async () => {
    await pool.query('DELETE FROM notes');
  });

  async function create(body: Record<string, unknown> = {}) {
    return app.inject({
      method: 'POST',
      url: '/api/v1/note',
      remoteAddress: ip(),
      payload: {
        ciphertext: toBase64Url(randomBytes(1068)),
        expires_in: HOUR,
        max_views: 1,
        ...body,
      },
    });
  }
  const openNote = (id: string) =>
    app.inject({ method: 'POST', url: `/api/v1/note/${id}/open`, remoteAddress: ip() });
  const del = (id: string, token: string) =>
    app.inject({
      method: 'DELETE',
      url: `/api/v1/note/${id}`,
      remoteAddress: ip(),
      payload: { deletion_token: token },
    });

  it('creates a note and returns id, deletion token and expiry', async () => {
    const before = Date.now();
    const res = await create({ expires_in: 24 * HOUR });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.note_id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(body.deletion_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const exp = Date.parse(body.expires_at);
    expect(exp - before).toBeGreaterThan(24 * HOUR * 1000 - 5000);
    expect(exp - before).toBeLessThan(24 * HOUR * 1000 + 5000);
  });

  it('stores only a hash of the deletion token', async () => {
    const { note_id, deletion_token } = (await create()).json();
    const { rows } = await pool.query('SELECT deletion_token_hash FROM notes WHERE id = $1', [
      note_id,
    ]);
    const stored = Buffer.from(rows[0].deletion_token_hash).toString('hex');
    expect(stored).not.toContain(Buffer.from(fromBase64Url(deletion_token)).toString('hex'));
  });

  it('burns a single-view note on first open; afterwards it is indistinguishable from never-existed', async () => {
    const ciphertext = toBase64Url(randomBytes(1068));
    const { note_id } = (await create({ ciphertext })).json();

    const first = await openNote(note_id);
    expect(first.statusCode).toBe(200);
    expect(first.json()).toEqual({ ciphertext, views_remaining: 0 });

    const second = await openNote(note_id);
    const never = await openNote(randomId());
    expect(second.statusCode).toBe(404);
    expect(never.statusCode).toBe(404);
    expect(second.body).toBe(never.body);
    expect(second.headers['content-length']).toBe(never.headers['content-length']);
    const { rowCount } = await pool.query('SELECT 1 FROM notes WHERE id = $1', [note_id]);
    expect(rowCount).toBe(0);
  });

  it('serves a multi-view note exactly max_views times', async () => {
    const { note_id } = (await create({ max_views: 3 })).json();
    expect((await openNote(note_id)).json().views_remaining).toBe(2);
    expect((await openNote(note_id)).json().views_remaining).toBe(1);
    expect((await openNote(note_id)).json().views_remaining).toBe(0);
    expect((await openNote(note_id)).statusCode).toBe(404);
  });

  it('never over-serves under concurrent opens', async () => {
    for (const maxViews of [1, 3]) {
      const { note_id } = (await create({ max_views: maxViews })).json();
      const results = await Promise.all(Array.from({ length: 12 }, () => openNote(note_id)));
      const ok = results.filter((r) => r.statusCode === 200);
      expect(ok.length).toBe(maxViews);
      expect(results.filter((r) => r.statusCode === 404).length).toBe(12 - maxViews);
      expect(ok.map((r) => r.json().views_remaining).sort()).toEqual(
        Array.from({ length: maxViews }, (_, i) => i),
      );
    }
  });

  it('refuses expired notes even before the sweeper runs, then the sweeper deletes them', async () => {
    const { note_id } = (await create()).json();
    const keep = (await create()).json().note_id;
    await pool.query(
      "UPDATE notes SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 second' WHERE id = $1",
      [note_id],
    );
    expect((await openNote(note_id)).statusCode).toBe(404);
    const swept = await sweep(pool);
    expect(swept.notes).toBe(1);
    const { rows } = await pool.query('SELECT id FROM notes');
    expect(rows.map((r) => r.id)).toEqual([keep]);
  });

  it('deletes with the right token only', async () => {
    const { note_id, deletion_token } = (await create()).json();
    const other = (await create()).json();
    expect((await del(note_id, other.deletion_token)).statusCode).toBe(404);
    expect((await del(randomId(), deletion_token)).statusCode).toBe(404);
    const ok = await del(note_id, deletion_token);
    expect(ok.statusCode).toBe(204);
    expect(ok.body).toBe('');
    expect((await openNote(note_id)).statusCode).toBe(404);
    expect((await del(note_id, deletion_token)).statusCode).toBe(404);
  });

  it.each([
    ['expiry not in the allowed list', { expires_in: 100 }],
    ['expiry beyond 30 days', { expires_in: 31 * 24 * HOUR }],
    ['zero views', { max_views: 0 }],
    ['six views', { max_views: 6 }],
    ['non-base64url ciphertext', { ciphertext: 'not base64!' }],
    ['padded base64', { ciphertext: toBase64Url(randomBytes(100)) + '==' }],
    ['ciphertext below one envelope', { ciphertext: toBase64Url(randomBytes(20)) }],
    ['non-canonical base64url', { ciphertext: toBase64Url(randomBytes(1067)).slice(0, -1) + 'B' }],
  ])('rejects %s with a generic 400', async (_name, body) => {
    const res = await create(body);
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: 'bad_request' });
  });

  it('rejects ciphertext above the cap', async () => {
    const res = await create({
      ciphertext: toBase64Url(randomBytes(NOTE_MAX_CIPHERTEXT_BYTES + 1)),
    });
    expect([400, 413]).toContain(res.statusCode);
    expect(await pool.query('SELECT 1 FROM notes').then((r) => r.rowCount)).toBe(0);
  });

  it('accepts the largest note the client can produce (64 KiB text + password)', async () => {
    const { ciphertext } = await encryptNote('x'.repeat(NOTE_TEXT_MAX_BYTES_CHECK), {
      password: 'pw',
      kdfParams: { opsLimit: 2, memLimitBytes: 8 * 1024 * 1024 },
    });
    expect(ciphertext.length).toBeLessThanOrEqual(NOTE_MAX_CIPHERTEXT_BYTES);
    const res = await create({ ciphertext: toBase64Url(ciphertext), max_views: 5 });
    expect(res.statusCode).toBe(201);
  });

  it('rate-limits opens per client (60/min) with a generic 429', async () => {
    const attacker = '203.0.113.7';
    let last = 0;
    for (let i = 0; i < 61; i++) {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/note/${randomId()}/open`,
        remoteAddress: attacker,
      });
      last = res.statusCode;
      if (i < 60) expect(res.statusCode).toBe(404);
      else expect(res.json()).toEqual({ error: 'rate_limited' });
    }
    expect(last).toBe(429);
    // A different client is unaffected.
    expect((await openNote(randomId())).statusCode).toBe(404);
  });
});
