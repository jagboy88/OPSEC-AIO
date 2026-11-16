import type { FastifyPluginAsync } from 'fastify';
import { toBase64Url } from '@opsec-aio/crypto';
import {
  ONE_TIME_PREKEY_MAX,
  RATE_LIMITS,
  type KeyBundleResponse,
  type PreKeyCountResponse,
  type SignedPreKeyUpload,
  type UploadPreKeysRequest,
} from '@opsec-aio/types';
import type { Pool } from '../db.js';
import { USERNAME_SCHEMA, b64Exact, decodeB64, httpError, rl } from '../http.js';
import { requireSession } from '../session.js';

export interface KeyRouteOptions {
  pool: Pool;
  pepper: Uint8Array;
}

const keyId = { type: 'integer', minimum: 0, maximum: 0x7fffffff } as const;

/**
 * One-time prekeys handed out per user per hour. Beyond this, bundles carry no
 * one-time prekey, so a stranger cannot drain someone's supply (forcing every
 * new contact onto the signed prekey alone) and yet cannot block contact either.
 */
export const OTPK_HANDOUTS_PER_HOUR = 30;

/** Prekey distribution for X3DH (docs/PLAN.md §4.1). Only signed-in users can fetch bundles. */
export const keyRoutes: FastifyPluginAsync<KeyRouteOptions> = async (app, { pool, pepper }) => {
  app.addHook('preHandler', requireSession(pool, pepper));

  app.get<{ Params: { username: string } }>(
    '/keys/bundle/:username',
    {
      config: rl(RATE_LIMITS.keyBundle),
      schema: {
        params: {
          type: 'object',
          required: ['username'],
          properties: { username: USERNAME_SCHEMA },
        },
      },
    },
    async (req): Promise<KeyBundleResponse> => {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const { rows: users } = await client.query<{
          id: string;
          identity_pub: Buffer;
          registration_id: number;
        }>('SELECT id, identity_pub, registration_id FROM users WHERE username = $1', [
          req.params.username,
        ]);
        const u = users[0];
        if (!u) throw httpError(404);
        const { rows: spk } = await client.query<{ key_id: number; pub: Buffer; sig: Buffer }>(
          `SELECT key_id, pub, sig FROM signed_prekeys WHERE user_id = $1
           ORDER BY created_at DESC, key_id DESC LIMIT 1`,
          [u.id],
        );
        const { rows: win } = await client.query<{ n: number }>(
          `UPDATE users SET
             otpk_window_count = CASE WHEN otpk_window_start > now() - interval '1 hour'
                                      THEN otpk_window_count + 1 ELSE 1 END,
             otpk_window_start = CASE WHEN otpk_window_start > now() - interval '1 hour'
                                      THEN otpk_window_start ELSE now() END
           WHERE id = $1 RETURNING otpk_window_count AS n`,
          [u.id],
        );
        // Each one-time prekey is handed out exactly once.
        const { rows: otpk } =
          win[0]!.n > OTPK_HANDOUTS_PER_HOUR
            ? { rows: [] }
            : await client.query<{ key_id: number; pub: Buffer }>(
                `DELETE FROM one_time_prekeys WHERE (user_id, key_id) = (
                   SELECT user_id, key_id FROM one_time_prekeys WHERE user_id = $1
                   ORDER BY key_id LIMIT 1 FOR UPDATE SKIP LOCKED)
                 RETURNING key_id, pub`,
                [u.id],
              );
        await client.query('COMMIT');
        const s = spk[0];
        if (!s) throw httpError(404);
        const one = otpk[0];
        return {
          username: req.params.username,
          identity_pub: toBase64Url(u.identity_pub),
          registration_id: u.registration_id,
          signed_prekey: { key_id: s.key_id, pub: toBase64Url(s.pub), sig: toBase64Url(s.sig) },
          one_time_prekey: one ? { key_id: one.key_id, pub: toBase64Url(one.pub) } : null,
        };
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    },
  );

  const count = async (userId: string) =>
    Number(
      (
        await pool.query<{ n: string }>(
          'SELECT count(*) AS n FROM one_time_prekeys WHERE user_id = $1',
          [userId],
        )
      ).rows[0]!.n,
    );

  app.get('/keys/count', async (req): Promise<PreKeyCountResponse> => ({
    one_time_prekeys: await count(req.user!.id),
  }));

  app.post<{ Body: UploadPreKeysRequest }>(
    '/keys/prekeys',
    {
      bodyLimit: 32 * 1024,
      schema: {
        body: {
          type: 'object',
          required: ['one_time_prekeys'],
          additionalProperties: false,
          properties: {
            one_time_prekeys: {
              type: 'array',
              minItems: 1,
              maxItems: 100,
              items: {
                type: 'object',
                required: ['key_id', 'pub'],
                additionalProperties: false,
                properties: { key_id: keyId, pub: b64Exact(33) },
              },
            },
          },
        },
      },
    },
    async (req): Promise<PreKeyCountResponse> => {
      const keys = req.body.one_time_prekeys.map((k) => ({
        id: k.key_id,
        pub: decodeB64(k.pub, 33),
      }));
      const existing = await count(req.user!.id);
      if (existing + keys.length > ONE_TIME_PREKEY_MAX) throw httpError(400);
      await pool.query(
        `INSERT INTO one_time_prekeys (user_id, key_id, pub)
         SELECT $1, * FROM unnest($2::int[], $3::bytea[]) ON CONFLICT DO NOTHING`,
        [req.user!.id, keys.map((k) => k.id), keys.map((k) => k.pub)],
      );
      return { one_time_prekeys: await count(req.user!.id) };
    },
  );

  app.put<{ Body: SignedPreKeyUpload }>(
    '/keys/signed-prekey',
    {
      schema: {
        body: {
          type: 'object',
          required: ['key_id', 'pub', 'sig'],
          additionalProperties: false,
          properties: { key_id: keyId, pub: b64Exact(33), sig: b64Exact(64) },
        },
      },
    },
    async (req, reply) => {
      const pub = decodeB64(req.body.pub, 33);
      const sig = decodeB64(req.body.sig, 64);
      await pool.query(
        `INSERT INTO signed_prekeys (user_id, key_id, pub, sig) VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, key_id) DO UPDATE SET pub = $3, sig = $4, created_at = now()`,
        [req.user!.id, req.body.key_id, pub, sig],
      );
      // Keep the newest two, so sessions started from the previous one still work.
      await pool.query(
        `DELETE FROM signed_prekeys WHERE user_id = $1 AND key_id NOT IN (
           SELECT key_id FROM signed_prekeys WHERE user_id = $1
           ORDER BY created_at DESC, key_id DESC LIMIT 2)`,
        [req.user!.id],
      );
      return reply.code(204).send();
    },
  );
};
