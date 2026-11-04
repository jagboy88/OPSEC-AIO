import type { FastifyPluginAsync } from 'fastify';
import {
  constantTimeEqual,
  fromBase64Url,
  hashToken,
  randomId,
  randomToken,
  toBase64Url,
} from '@opsec-aio/crypto';
import {
  NOTE_EXPIRY_OPTIONS_SECONDS,
  NOTE_MAX_CIPHERTEXT_BYTES,
  NOTE_MAX_VIEWS,
  NOTE_MIN_CIPHERTEXT_BYTES,
  RATE_LIMITS,
  type CreateNoteRequest,
  type CreateNoteResponse,
  type DeleteWithTokenRequest,
  type OpenNoteResponse,
} from '@opsec-aio/types';
import type { Pool } from '../db.js';

export interface NoteRouteOptions {
  pool: Pool;
  pepper: Uint8Array;
}

const B64URL = '^[A-Za-z0-9_-]+$';
const idParams = {
  type: 'object',
  required: ['id'],
  properties: { id: { type: 'string', pattern: '^[A-Za-z0-9_-]{22}$' } },
} as const;

/** base64url length for n bytes, unpadded. */
const b64Len = (n: number) => Math.ceil((n * 4) / 3);

function badRequest(): Error {
  return Object.assign(new Error('bad request'), { statusCode: 400 });
}
function notFound(): Error {
  return Object.assign(new Error('not found'), { statusCode: 404 });
}

const rl = (r: { max: number; windowSeconds: number }) => ({
  rateLimit: { max: r.max, timeWindow: r.windowSeconds * 1000 },
});

/**
 * Burn API (docs/PLAN.md §4.3, §5). The server stores an opaque ciphertext and
 * hands it out exactly `max_views` times. Every "not there" case — never
 * existed, already burned, expired, wrong deletion token — is the same 404.
 */
export const noteRoutes: FastifyPluginAsync<NoteRouteOptions> = async (app, { pool, pepper }) => {
  app.post<{ Body: CreateNoteRequest }>(
    '/note',
    {
      config: rl(RATE_LIMITS.noteCreate),
      bodyLimit: 96 * 1024,
      schema: {
        body: {
          type: 'object',
          required: ['ciphertext', 'expires_in', 'max_views'],
          additionalProperties: false,
          properties: {
            ciphertext: {
              type: 'string',
              pattern: B64URL,
              minLength: b64Len(NOTE_MIN_CIPHERTEXT_BYTES),
              maxLength: b64Len(NOTE_MAX_CIPHERTEXT_BYTES),
            },
            expires_in: { type: 'integer', enum: [...NOTE_EXPIRY_OPTIONS_SECONDS] },
            max_views: { type: 'integer', minimum: 1, maximum: NOTE_MAX_VIEWS },
          },
        },
      },
    },
    async (req, reply): Promise<CreateNoteResponse> => {
      let ciphertext: Uint8Array;
      try {
        ciphertext = fromBase64Url(req.body.ciphertext);
      } catch {
        throw badRequest();
      }
      if (
        ciphertext.length < NOTE_MIN_CIPHERTEXT_BYTES ||
        ciphertext.length > NOTE_MAX_CIPHERTEXT_BYTES
      ) {
        throw badRequest();
      }

      const deletionToken = randomToken();
      const tokenHash = hashToken(deletionToken, pepper);
      // 128-bit random ids: a collision is astronomically unlikely, but retry
      // rather than surface a 500 if it ever happens.
      for (let attempt = 0; attempt < 3; attempt++) {
        const id = randomId();
        try {
          const { rows } = await pool.query<{ expires_at: Date }>(
            `INSERT INTO notes (id, ciphertext, expires_at, max_views, deletion_token_hash)
             VALUES ($1, $2, now() + make_interval(secs => $3), $4, $5)
             RETURNING expires_at`,
            [id, ciphertext, req.body.expires_in, req.body.max_views, tokenHash],
          );
          reply.code(201);
          return {
            note_id: id,
            deletion_token: deletionToken,
            expires_at: rows[0]!.expires_at.toISOString(),
          };
        } catch (e) {
          if ((e as { code?: string }).code !== '23505') throw e;
        }
      }
      throw new Error('could not allocate note id');
    },
  );

  app.post<{ Params: { id: string } }>(
    '/note/:id/open',
    { config: rl(RATE_LIMITS.noteOpen), schema: { params: idParams } },
    async (req): Promise<OpenNoteResponse> => {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        // Row lock serialises concurrent opens, so a note can never be served
        // more than max_views times.
        const { rows } = await client.query<{
          ciphertext: Buffer;
          views: number;
          max_views: number;
        }>(
          `SELECT ciphertext, views, max_views FROM notes
           WHERE id = $1 AND expires_at > now() FOR UPDATE`,
          [req.params.id],
        );
        const note = rows[0];
        if (!note) {
          await client.query('ROLLBACK');
          throw notFound();
        }
        const remaining = note.max_views - note.views - 1;
        if (remaining <= 0) {
          await client.query('DELETE FROM notes WHERE id = $1', [req.params.id]);
        } else {
          await client.query('UPDATE notes SET views = views + 1 WHERE id = $1', [req.params.id]);
        }
        await client.query('COMMIT');
        return { ciphertext: toBase64Url(note.ciphertext), views_remaining: remaining };
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    },
  );

  app.delete<{ Params: { id: string }; Body: DeleteWithTokenRequest }>(
    '/note/:id',
    {
      config: rl(RATE_LIMITS.noteDelete),
      schema: {
        params: idParams,
        body: {
          type: 'object',
          required: ['deletion_token'],
          additionalProperties: false,
          properties: { deletion_token: { type: 'string', pattern: '^[A-Za-z0-9_-]{43}$' } },
        },
      },
    },
    async (req, reply) => {
      const presented = hashToken(req.body.deletion_token, pepper);
      const { rows } = await pool.query<{ deletion_token_hash: Buffer }>(
        'SELECT deletion_token_hash FROM notes WHERE id = $1',
        [req.params.id],
      );
      const stored = rows[0]?.deletion_token_hash;
      if (!stored || !constantTimeEqual(new Uint8Array(stored), presented)) throw notFound();
      await pool.query('DELETE FROM notes WHERE id = $1 AND deletion_token_hash = $2', [
        req.params.id,
        presented,
      ]);
      return reply.code(204).send();
    },
  );
};
