import type { FastifyPluginAsync, FastifyRequest } from 'fastify';
import {
  constantTimeEqual,
  fromBase64Url,
  hashToken,
  randomBytes,
  randomId,
  randomToken,
  toBase64Url,
} from '@opsec-aio/crypto';
import {
  DROP_CHUNK_BYTES,
  DROP_CHUNK_OVERHEAD,
  DROP_DOWNLOAD_WINDOW_SECONDS,
  DROP_EXPIRY_OPTIONS_SECONDS,
  DROP_HEADER_BLOB_MAX_BYTES,
  DROP_MAX_CHUNKS,
  DROP_MAX_DOWNLOADS_LIMIT,
  RATE_LIMITS,
  type DeleteDropRequest,
  type DropMetaResponse,
  type FinalizeDropResponse,
  type InitDropRequest,
  type InitDropResponse,
  type StartDownloadResponse,
} from '@opsec-aio/types';
import type { BlobStore } from '../blobs.js';
import type { Pool } from '../db.js';
import { rl } from '../http.js';

export interface DropRouteOptions {
  pool: Pool;
  pepper: Uint8Array;
  blobs: BlobStore;
  /** Soft cap on reserved ciphertext bytes across all live drops. */
  storageMaxBytes: number;
}

const MAX_CHUNK_CIPHERTEXT = DROP_CHUNK_BYTES + DROP_CHUNK_OVERHEAD;
const MIN_HEADER_BLOB = 42; // one bare AEAD envelope
const b64Len = (n: number) => Math.ceil((n * 4) / 3);

const idParams = {
  type: 'object',
  required: ['id'],
  properties: { id: { type: 'string', pattern: '^[A-Za-z0-9_-]{22}$' } },
} as const;
const chunkParams = {
  type: 'object',
  required: ['id', 'n'],
  properties: {
    id: { type: 'string', pattern: '^[A-Za-z0-9_-]{22}$' },
    n: { type: 'integer', minimum: 0, maximum: DROP_MAX_CHUNKS - 1 },
  },
} as const;

const httpError = (statusCode: number) =>
  Object.assign(new Error(String(statusCode)), { statusCode });
const notFound = () => httpError(404);
const badRequest = () => httpError(400);

function bearer(req: FastifyRequest): string | null {
  const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization ?? '');
  return m?.[1] ?? null;
}

function tokenMatches(token: string | null | undefined, stored: Buffer, pepper: Uint8Array) {
  return !!token && constantTimeEqual(hashToken(token, pepper), new Uint8Array(stored));
}

/** Expected ciphertext length of chunk n (0 = any valid final-chunk length). */
function chunkLengthOk(n: number, chunkCount: number, length: number): boolean {
  if (n < chunkCount - 1) return length === MAX_CHUNK_CIPHERTEXT;
  return length >= DROP_CHUNK_OVERHEAD && length <= MAX_CHUNK_CIPHERTEXT;
}

/**
 * Drop API (docs/PLAN.md §4.2, §5). The server stores opaque encrypted chunks
 * and enforces lifetime and download limits; it never sees names, types,
 * exact sizes or keys. Every "not available" answer is the same 404.
 */
export const dropRoutes: FastifyPluginAsync<DropRouteOptions> = async (app, opts) => {
  const { pool, pepper, blobs, storageMaxBytes } = opts;

  app.addContentTypeParser(
    'application/octet-stream',
    { parseAs: 'buffer', bodyLimit: MAX_CHUNK_CIPHERTEXT },
    (_req, body, done) => done(null, body),
  );

  // ── Upload ────────────────────────────────────────────────────────────────
  app.post<{ Body: InitDropRequest }>(
    '/drop/init',
    {
      config: rl(RATE_LIMITS.dropUpload),
      schema: {
        body: {
          type: 'object',
          required: ['chunk_count', 'expires_in', 'header_blob'],
          additionalProperties: false,
          properties: {
            chunk_count: { type: 'integer', minimum: 1, maximum: DROP_MAX_CHUNKS },
            expires_in: { type: 'integer', enum: [...DROP_EXPIRY_OPTIONS_SECONDS] },
            // A single nullable type (not anyOf): with anyOf, Ajv's type
            // coercion would turn 0 into null, i.e. "unlimited".
            max_downloads: {
              type: ['integer', 'null'],
              minimum: 1,
              maximum: DROP_MAX_DOWNLOADS_LIMIT,
            },
            header_blob: {
              type: 'string',
              pattern: '^[A-Za-z0-9_-]+$',
              minLength: b64Len(MIN_HEADER_BLOB),
              maxLength: b64Len(DROP_HEADER_BLOB_MAX_BYTES),
            },
          },
        },
      },
    },
    async (req, reply): Promise<InitDropResponse> => {
      let headerBlob: Uint8Array;
      try {
        headerBlob = fromBase64Url(req.body.header_blob);
      } catch {
        throw badRequest();
      }
      if (headerBlob.length < MIN_HEADER_BLOB || headerBlob.length > DROP_HEADER_BLOB_MAX_BYTES) {
        throw badRequest();
      }

      // Storage cap: reserve worst-case space for every live drop.
      const reserveBytes = req.body.chunk_count * MAX_CHUNK_CIPHERTEXT;
      const { rows: used } = await pool.query<{ reserved: string }>(
        'SELECT COALESCE(SUM(chunk_count::bigint), 0) * $1 AS reserved FROM drops WHERE expires_at > now()',
        [MAX_CHUNK_CIPHERTEXT],
      );
      if (Number(used[0]!.reserved) + reserveBytes > storageMaxBytes) throw httpError(507);

      const uploadToken = randomToken();
      for (let attempt = 0; attempt < 3; attempt++) {
        const id = randomId();
        try {
          const { rows } = await pool.query<{ expires_at: Date }>(
            `INSERT INTO drops (id, chunk_count, header_blob, expires_at, max_downloads,
                                upload_token_hash, deletion_token_hash)
             VALUES ($1, $2, $3, now() + make_interval(secs => $4), $5, $6, $7)
             RETURNING expires_at`,
            [
              id,
              req.body.chunk_count,
              headerBlob,
              req.body.expires_in,
              req.body.max_downloads ?? null,
              hashToken(uploadToken, pepper),
              // Placeholder: the real deletion token is issued at finalize.
              randomBytes(32),
            ],
          );
          reply.code(201);
          return {
            drop_id: id,
            upload_token: uploadToken,
            expires_at: rows[0]!.expires_at.toISOString(),
          };
        } catch (e) {
          if ((e as { code?: string }).code !== '23505') throw e;
        }
      }
      throw new Error('could not allocate drop id');
    },
  );

  app.put<{ Params: { id: string; n: number }; Body: Buffer }>(
    '/drop/:id/chunk/:n',
    { bodyLimit: MAX_CHUNK_CIPHERTEXT, schema: { params: chunkParams } },
    async (req, reply) => {
      const { rows } = await pool.query<{
        chunk_count: number;
        finalized: boolean;
        upload_token_hash: Buffer;
      }>(
        `SELECT chunk_count, finalized, upload_token_hash FROM drops
         WHERE id = $1 AND expires_at > now()`,
        [req.params.id],
      );
      const drop = rows[0];
      if (!drop || drop.finalized || !tokenMatches(bearer(req), drop.upload_token_hash, pepper)) {
        throw notFound();
      }
      const body = req.body;
      if (!Buffer.isBuffer(body) || req.params.n >= drop.chunk_count) throw badRequest();
      if (!chunkLengthOk(req.params.n, drop.chunk_count, body.length)) throw badRequest();
      await blobs.put(req.params.id, req.params.n, body);
      return reply.code(204).send();
    },
  );

  app.post<{ Params: { id: string } }>(
    '/drop/:id/finalize',
    { schema: { params: idParams } },
    async (req): Promise<FinalizeDropResponse> => {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const { rows } = await client.query<{
          chunk_count: number;
          finalized: boolean;
          upload_token_hash: Buffer;
          expires_at: Date;
        }>(
          `SELECT chunk_count, finalized, upload_token_hash, expires_at FROM drops
           WHERE id = $1 AND expires_at > now() FOR UPDATE`,
          [req.params.id],
        );
        const drop = rows[0];
        if (!drop || drop.finalized || !tokenMatches(bearer(req), drop.upload_token_hash, pepper)) {
          throw notFound();
        }
        let total = 0;
        for (let n = 0; n < drop.chunk_count; n++) {
          const size = await blobs.size(req.params.id, n);
          if (size === null || !chunkLengthOk(n, drop.chunk_count, size)) throw badRequest();
          total += size;
        }
        const deletionToken = randomToken();
        await client.query(
          'UPDATE drops SET finalized = true, size = $2, deletion_token_hash = $3 WHERE id = $1',
          [req.params.id, total, hashToken(deletionToken, pepper)],
        );
        await client.query('COMMIT');
        return { deletion_token: deletionToken, expires_at: drop.expires_at.toISOString() };
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    },
  );

  // ── Download ──────────────────────────────────────────────────────────────
  const AVAILABLE = `finalized AND expires_at > now()
    AND (max_downloads IS NULL OR downloads < max_downloads)`;

  app.get<{ Params: { id: string } }>(
    '/drop/:id/meta',
    { config: rl(RATE_LIMITS.dropMeta), schema: { params: idParams } },
    async (req): Promise<DropMetaResponse> => {
      const { rows } = await pool.query<{
        chunk_count: number;
        expires_at: Date;
        header_blob: Buffer;
        max_downloads: number | null;
        downloads: number;
      }>(
        `SELECT chunk_count, expires_at, header_blob, max_downloads, downloads FROM drops
         WHERE id = $1 AND ${AVAILABLE}`,
        [req.params.id],
      );
      const d = rows[0];
      if (!d) throw notFound();
      return {
        chunk_count: d.chunk_count,
        expires_at: d.expires_at.toISOString(),
        header_blob: toBase64Url(d.header_blob),
        downloads_remaining: d.max_downloads === null ? null : d.max_downloads - d.downloads,
      };
    },
  );

  app.post<{ Params: { id: string } }>(
    '/drop/:id/download',
    { config: rl(RATE_LIMITS.dropDownload), schema: { params: idParams } },
    async (req): Promise<StartDownloadResponse> => {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const { rows } = await client.query<{ max_downloads: number | null; downloads: number }>(
          `SELECT max_downloads, downloads FROM drops WHERE id = $1 AND ${AVAILABLE} FOR UPDATE`,
          [req.params.id],
        );
        const d = rows[0];
        if (!d) {
          await client.query('ROLLBACK');
          throw notFound();
        }
        const token = randomToken();
        await client.query('UPDATE drops SET downloads = downloads + 1 WHERE id = $1', [
          req.params.id,
        ]);
        await client.query(
          `INSERT INTO drop_downloads (token_hash, drop_id, expires_at)
           SELECT $1, id, LEAST(expires_at, now() + make_interval(secs => $3)) FROM drops WHERE id = $2`,
          [hashToken(token, pepper), req.params.id, DROP_DOWNLOAD_WINDOW_SECONDS],
        );
        await client.query('COMMIT');
        return {
          download_token: token,
          downloads_remaining: d.max_downloads === null ? null : d.max_downloads - d.downloads - 1,
        };
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    },
  );

  app.get<{ Params: { id: string; n: number } }>(
    '/drop/:id/chunk/:n',
    { schema: { params: chunkParams } },
    async (req, reply) => {
      const token = bearer(req);
      if (!token) throw notFound();
      const tokenHash = hashToken(token, pepper);
      // Looked up by keyed hash: comparing HMAC outputs leaks nothing useful.
      const { rows } = await pool.query<{
        chunk_count: number;
        max_downloads: number | null;
        downloads: number;
      }>(
        `SELECT d.chunk_count, d.max_downloads, d.downloads
         FROM drop_downloads t JOIN drops d ON d.id = t.drop_id
         WHERE t.token_hash = $1 AND t.drop_id = $2 AND t.expires_at > now() AND d.expires_at > now()`,
        [tokenHash, req.params.id],
      );
      const d = rows[0];
      if (!d) throw notFound();
      if (req.params.n >= d.chunk_count) throw badRequest();
      let data: Buffer;
      try {
        data = await blobs.get(req.params.id, req.params.n);
      } catch {
        throw notFound();
      }

      if (req.params.n === d.chunk_count - 1) {
        // Last chunk served: this download is complete.
        await pool.query('DELETE FROM drop_downloads WHERE token_hash = $1', [tokenHash]);
        if (d.max_downloads !== null && d.downloads >= d.max_downloads) {
          // Limit reached and no other download in flight: delete right now.
          const { rowCount } = await pool.query(
            `DELETE FROM drops WHERE id = $1 AND NOT EXISTS
               (SELECT 1 FROM drop_downloads WHERE drop_id = $1 AND expires_at > now())`,
            [req.params.id],
          );
          if (rowCount) await blobs.remove(req.params.id);
        }
      }
      return reply.type('application/octet-stream').send(data);
    },
  );

  // ── Delete ────────────────────────────────────────────────────────────────
  app.delete<{ Params: { id: string }; Body: DeleteDropRequest }>(
    '/drop/:id',
    {
      config: rl(RATE_LIMITS.dropDelete),
      schema: {
        params: idParams,
        body: {
          type: 'object',
          additionalProperties: false,
          minProperties: 1,
          maxProperties: 1,
          properties: {
            deletion_token: { type: 'string', pattern: '^[A-Za-z0-9_-]{43}$' },
            upload_token: { type: 'string', pattern: '^[A-Za-z0-9_-]{43}$' },
          },
        },
      },
    },
    async (req, reply) => {
      const { rows } = await pool.query<{
        finalized: boolean;
        upload_token_hash: Buffer;
        deletion_token_hash: Buffer;
      }>('SELECT finalized, upload_token_hash, deletion_token_hash FROM drops WHERE id = $1', [
        req.params.id,
      ]);
      const d = rows[0];
      const ok =
        !!d &&
        (d.finalized
          ? tokenMatches(req.body.deletion_token, d.deletion_token_hash, pepper)
          : tokenMatches(req.body.upload_token, d.upload_token_hash, pepper));
      if (!ok) throw notFound();
      await pool.query('DELETE FROM drops WHERE id = $1', [req.params.id]);
      await blobs.remove(req.params.id);
      return reply.code(204).send();
    },
  );
};
