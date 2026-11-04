/**
 * Drop API integration tests against a real Postgres (TEST_DATABASE_URL) and a
 * temporary blob directory.
 */
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { randomBytes, randomId, randomToken, ready, toBase64Url } from '@opsec-aio/crypto';
import { DROP_CHUNK_BYTES, DROP_CHUNK_OVERHEAD } from '@opsec-aio/types';
import { buildApp } from '../src/app.js';
import { DiskBlobStore } from '../src/blobs.js';
import { MIGRATIONS_DIR, createPool, migrate, type Pool } from '../src/db.js';
import { sweep } from '../src/sweeper.js';

await ready();

const url = process.env.TEST_DATABASE_URL;
const FULL = DROP_CHUNK_BYTES + DROP_CHUNK_OVERHEAD;
const HOUR = 3600;

describe.skipIf(!url)('Drop API (postgres + disk)', () => {
  let pool: Pool;
  let app: FastifyInstance;
  let blobDir: string;
  let blobs: DiskBlobStore;
  let n = 0;
  const ip = () => `10.1.${Math.floor(++n / 250)}.${n % 250}`;

  async function makeApp(storageMax?: number) {
    const a = await buildApp({
      config: { logLevel: 'silent', trustProxyHops: 0 },
      probes: {},
      data: {
        pool,
        tokenPepper: randomBytes(32),
        blobs,
        ...(storageMax !== undefined ? { dropStorageMaxBytes: storageMax } : {}),
      },
    });
    await a.ready();
    return a;
  }

  beforeAll(async () => {
    pool = createPool(url!);
    await migrate(pool, MIGRATIONS_DIR);
    blobDir = mkdtempSync(join(tmpdir(), 'blobs-'));
    blobs = new DiskBlobStore(blobDir);
    app = await makeApp();
  });
  afterAll(async () => {
    await app?.close();
    await pool?.end();
    rmSync(blobDir, { recursive: true, force: true });
  });
  beforeEach(async () => {
    await pool.query('DELETE FROM drops');
    for (const id of await blobs.list()) await blobs.remove(id);
  });

  const init = (body: Record<string, unknown> = {}, a = app) =>
    a.inject({
      method: 'POST',
      url: '/api/v1/drop/init',
      remoteAddress: ip(),
      payload: {
        chunk_count: 3,
        expires_in: 24 * HOUR,
        header_blob: toBase64Url(randomBytes(466)),
        ...body,
      },
    });
  const putChunk = (id: string, i: number, data: Uint8Array, token: string) =>
    app.inject({
      method: 'PUT',
      url: `/api/v1/drop/${id}/chunk/${i}`,
      remoteAddress: ip(),
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/octet-stream' },
      payload: Buffer.from(data),
    });
  const finalize = (id: string, token: string) =>
    app.inject({
      method: 'POST',
      url: `/api/v1/drop/${id}/finalize`,
      remoteAddress: ip(),
      headers: { authorization: `Bearer ${token}` },
    });
  const meta = (id: string) =>
    app.inject({ method: 'GET', url: `/api/v1/drop/${id}/meta`, remoteAddress: ip() });
  const startDownload = (id: string) =>
    app.inject({ method: 'POST', url: `/api/v1/drop/${id}/download`, remoteAddress: ip() });
  const getChunk = (id: string, i: number, token: string) =>
    app.inject({
      method: 'GET',
      url: `/api/v1/drop/${id}/chunk/${i}`,
      remoteAddress: ip(),
      headers: { authorization: `Bearer ${token}` },
    });
  const del = (id: string, body: Record<string, string>) =>
    app.inject({ method: 'DELETE', url: `/api/v1/drop/${id}`, remoteAddress: ip(), payload: body });

  /** Upload a complete drop with random chunk contents. */
  async function upload(chunkCount = 3, extra: Record<string, unknown> = {}) {
    const res = await init({ chunk_count: chunkCount, ...extra });
    expect(res.statusCode).toBe(201);
    const { drop_id: id, upload_token: uploadToken } = res.json();
    const chunks = Array.from({ length: chunkCount }, (_, i) =>
      randomBytes(i === chunkCount - 1 ? 4113 : FULL),
    );
    for (const [i, c] of chunks.entries()) {
      expect((await putChunk(id, i, c, uploadToken)).statusCode).toBe(204);
    }
    const fin = await finalize(id, uploadToken);
    expect(fin.statusCode).toBe(200);
    return { id, uploadToken, deletionToken: fin.json().deletion_token as string, chunks };
  }

  it('uploads, finalizes and serves a multi-chunk drop byte-for-byte', async () => {
    const { id, chunks } = await upload(3);
    const m = await meta(id);
    expect(m.statusCode).toBe(200);
    expect(m.json()).toMatchObject({ chunk_count: 3, downloads_remaining: null });

    const { download_token } = (await startDownload(id)).json();
    for (const [i, c] of chunks.entries()) {
      const res = await getChunk(id, i, download_token);
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toBe('application/octet-stream');
      expect(Buffer.compare(res.rawPayload, Buffer.from(c))).toBe(0);
    }
    // Unlimited drops stay available.
    expect((await meta(id)).statusCode).toBe(200);
    const { rows } = await pool.query('SELECT size, finalized FROM drops WHERE id = $1', [id]);
    expect(rows[0]).toEqual({ size: String(2 * FULL + 4113), finalized: true });
  });

  it('is invisible until finalized, and finalize needs every chunk', async () => {
    const res = await init({ chunk_count: 2 });
    const { drop_id: id, upload_token: t } = res.json();
    expect((await meta(id)).statusCode).toBe(404);
    await putChunk(id, 0, randomBytes(FULL), t);
    expect((await finalize(id, t)).statusCode).toBe(400);
    await putChunk(id, 1, randomBytes(100), t);
    expect((await finalize(id, t)).statusCode).toBe(200);
    expect((await meta(id)).statusCode).toBe(200);
  });

  it('guards chunk uploads: token, index, size, and no writes after finalize', async () => {
    const { drop_id: id, upload_token: t } = (await init({ chunk_count: 2 })).json();
    expect((await putChunk(id, 0, randomBytes(FULL), randomToken())).statusCode).toBe(404);
    expect((await putChunk(id, 2, randomBytes(100), t)).statusCode).toBe(400);
    expect((await putChunk(id, 0, randomBytes(FULL - 1), t)).statusCode).toBe(400); // non-final must be full
    expect((await putChunk(id, 1, randomBytes(16), t)).statusCode).toBe(400); // below one tag
    expect([400, 413]).toContain((await putChunk(id, 1, randomBytes(FULL + 1), t)).statusCode);
    await putChunk(id, 0, randomBytes(FULL), t);
    await putChunk(id, 1, randomBytes(17), t); // empty final chunk is valid
    expect((await finalize(id, t)).statusCode).toBe(200);
    expect((await putChunk(id, 0, randomBytes(FULL), t)).statusCode).toBe(404);
    expect((await finalize(id, t)).statusCode).toBe(404);
  });

  it('enforces max downloads and deletes the drop after the last allowed download completes', async () => {
    const { id, chunks } = await upload(2, { max_downloads: 1 });
    expect((await meta(id)).json().downloads_remaining).toBe(1);
    const start = (await startDownload(id)).json();
    expect(start.downloads_remaining).toBe(0);

    // No new downloads can start, and it already looks like it never existed.
    const gone = await meta(id);
    const never = await meta(randomId());
    expect(gone.statusCode).toBe(404);
    expect(gone.body).toBe(never.body);
    expect((await startDownload(id)).statusCode).toBe(404);

    // The download already in progress can finish…
    expect((await getChunk(id, 0, start.download_token)).statusCode).toBe(200);
    expect(readdirSync(blobDir)).toContain(id);
    expect((await getChunk(id, chunks.length - 1, start.download_token)).statusCode).toBe(200);
    // …and then everything is gone immediately, without waiting for the sweeper.
    expect((await pool.query('SELECT 1 FROM drops WHERE id = $1', [id])).rowCount).toBe(0);
    expect(readdirSync(blobDir)).not.toContain(id);
    expect((await getChunk(id, 0, start.download_token)).statusCode).toBe(404);
  });

  it('never exceeds max downloads under concurrent starts', async () => {
    const { id } = await upload(1, { max_downloads: 2 });
    const results = await Promise.all(Array.from({ length: 10 }, () => startDownload(id)));
    expect(results.filter((r) => r.statusCode === 200).length).toBe(2);
    expect(results.filter((r) => r.statusCode === 404).length).toBe(8);
  });

  it('only serves chunks to a live download token for that drop', async () => {
    const a = await upload(1);
    const b = await upload(1);
    const tokenA = (await startDownload(a.id)).json().download_token;
    expect((await getChunk(b.id, 0, tokenA)).statusCode).toBe(404);
    expect((await getChunk(a.id, 0, randomToken())).statusCode).toBe(404);
    expect(
      (await app.inject({ method: 'GET', url: `/api/v1/drop/${a.id}/chunk/0` })).statusCode,
    ).toBe(404);
    expect((await getChunk(a.id, 0, tokenA)).statusCode).toBe(200);
  });

  it('expired drops are refused at once and removed (row and files) by the sweeper', async () => {
    const { id } = await upload(2);
    const keep = await upload(1);
    const token = (await startDownload(id)).json().download_token;
    await pool.query(
      "UPDATE drops SET created_at = now() - interval '24 hours', expires_at = now() - interval '1 second' WHERE id = $1",
      [id],
    );
    expect((await meta(id)).statusCode).toBe(404);
    expect((await getChunk(id, 0, token)).statusCode).toBe(404);

    // An orphaned directory (no row) is also cleaned up.
    const orphan = randomId();
    await blobs.put(orphan, 0, randomBytes(10));

    const swept = await sweep(pool, blobs);
    expect(swept.drops).toBe(1);
    expect(swept.orphanBlobs).toBe(1);
    expect(readdirSync(blobDir).sort()).toEqual([keep.id]);
  });

  it('accepts only the allowed expiries (24 h is the hard ceiling)', async () => {
    for (const s of [HOUR, 6 * HOUR, 12 * HOUR, 24 * HOUR]) {
      expect((await init({ expires_in: s })).statusCode).toBe(201);
    }
    for (const s of [25 * HOUR, 48 * HOUR, 0, 100]) {
      expect((await init({ expires_in: s })).statusCode).toBe(400);
    }
  });

  it('deletes with the deletion token (after finalize) or upload token (to abort)', async () => {
    const done = await upload(1);
    expect((await del(done.id, { upload_token: done.uploadToken })).statusCode).toBe(404);
    expect((await del(done.id, { deletion_token: randomToken() })).statusCode).toBe(404);
    expect((await del(done.id, { deletion_token: done.deletionToken })).statusCode).toBe(204);
    expect(readdirSync(blobDir)).not.toContain(done.id);
    expect((await meta(done.id)).statusCode).toBe(404);

    const { drop_id: id, upload_token: t } = (await init({ chunk_count: 2 })).json();
    await putChunk(id, 0, randomBytes(FULL), t);
    expect((await del(id, { upload_token: t })).statusCode).toBe(204);
    expect(readdirSync(blobDir)).not.toContain(id);
  });

  it('rejects malformed init requests', async () => {
    for (const body of [
      { chunk_count: 0 },
      { chunk_count: 2049 },
      { max_downloads: 0 },
      { max_downloads: 101 },
      { header_blob: 'not base64!' },
      { header_blob: toBase64Url(randomBytes(10)) },
      { header_blob: toBase64Url(randomBytes(5000)) },
    ]) {
      const res = await init(body);
      expect(res.statusCode, JSON.stringify(body)).toBe(400);
    }
  });

  it('refuses new uploads with a 507 when the storage cap would be exceeded', async () => {
    const small = await makeApp(3 * FULL);
    try {
      expect((await init({ chunk_count: 2 }, small)).statusCode).toBe(201);
      const full = await init({ chunk_count: 2 }, small);
      expect(full.statusCode).toBe(507);
      expect(full.json()).toEqual({ error: 'storage_full' });
      expect((await init({ chunk_count: 1 }, small)).statusCode).toBe(201);
    } finally {
      await small.close();
    }
  });
});
