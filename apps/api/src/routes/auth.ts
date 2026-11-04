import type { FastifyPluginAsync } from 'fastify';
import {
  authChallengeMessage,
  hashToken,
  randomBytes,
  randomToken,
  toBase64Url,
  verify,
} from '@opsec-aio/crypto';
import {
  AUTH_CHALLENGE_TTL_SECONDS,
  RATE_LIMITS,
  SESSION_TTL_SECONDS,
  type ChallengeRequest,
  type ChallengeResponse,
  type LoginRequest,
  type LoginResponse,
  type RegisterRequest,
  type RegisterResponse,
} from '@opsec-aio/types';
import type { Pool } from '../db.js';
import { USERNAME_SCHEMA, b64Exact, decodeB64, httpError, rl } from '../http.js';
import { bearerToken, requireSession } from '../session.js';

export interface AuthRouteOptions {
  pool: Pool;
  pepper: Uint8Array;
}

const keyId = { type: 'integer', minimum: 0, maximum: 0x7fffffff } as const;
const preKeySchema = {
  type: 'object',
  required: ['key_id', 'pub'],
  additionalProperties: false,
  properties: { key_id: keyId, pub: b64Exact(33) },
} as const;

/**
 * Accounts (docs/PLAN.md §4.1). No email, no phone, no password on the
 * server: a username plus an Ed25519 public key. Login is a signed,
 * single-use server challenge.
 */
export const authRoutes: FastifyPluginAsync<AuthRouteOptions> = async (app, { pool, pepper }) => {
  const session = requireSession(pool, pepper);

  app.post<{ Body: RegisterRequest }>(
    '/auth/register',
    {
      config: rl(RATE_LIMITS.register),
      bodyLimit: 32 * 1024,
      schema: {
        body: {
          type: 'object',
          required: [
            'username',
            'auth_pub',
            'identity_pub',
            'registration_id',
            'signed_prekey',
            'one_time_prekeys',
          ],
          additionalProperties: false,
          properties: {
            username: USERNAME_SCHEMA,
            auth_pub: b64Exact(32),
            identity_pub: b64Exact(33),
            registration_id: { type: 'integer', minimum: 1, maximum: 16383 },
            signed_prekey: {
              type: 'object',
              required: ['key_id', 'pub', 'sig'],
              additionalProperties: false,
              properties: { key_id: keyId, pub: b64Exact(33), sig: b64Exact(64) },
            },
            one_time_prekeys: { type: 'array', maxItems: 100, items: preKeySchema },
          },
        },
      },
    },
    async (req, reply): Promise<RegisterResponse> => {
      const b = req.body;
      const authPub = decodeB64(b.auth_pub, 32);
      const identityPub = decodeB64(b.identity_pub, 33);
      const spk = {
        pub: decodeB64(b.signed_prekey.pub, 33),
        sig: decodeB64(b.signed_prekey.sig, 64),
      };
      const otpks = b.one_time_prekeys.map((k) => ({ id: k.key_id, pub: decodeB64(k.pub, 33) }));

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        let userId: string;
        try {
          const { rows } = await client.query<{ id: string }>(
            `INSERT INTO users (username, auth_pub, identity_pub, registration_id)
             VALUES ($1, $2, $3, $4) RETURNING id`,
            [b.username, authPub, identityPub, b.registration_id],
          );
          userId = rows[0]!.id;
        } catch (e) {
          if ((e as { code?: string }).code === '23505') throw httpError(409);
          throw e;
        }
        await client.query(
          'INSERT INTO signed_prekeys (user_id, key_id, pub, sig) VALUES ($1, $2, $3, $4)',
          [userId, b.signed_prekey.key_id, spk.pub, spk.sig],
        );
        if (otpks.length) {
          await client.query(
            `INSERT INTO one_time_prekeys (user_id, key_id, pub)
             SELECT $1, * FROM unnest($2::int[], $3::bytea[]) ON CONFLICT DO NOTHING`,
            [userId, otpks.map((k) => k.id), otpks.map((k) => k.pub)],
          );
        }
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
      reply.code(201);
      return { username: b.username };
    },
  );

  app.post<{ Body: ChallengeRequest }>(
    '/auth/challenge',
    {
      config: rl(RATE_LIMITS.authChallenge),
      schema: {
        body: {
          type: 'object',
          required: ['username'],
          additionalProperties: false,
          properties: { username: USERNAME_SCHEMA },
        },
      },
    },
    async (req): Promise<ChallengeResponse> => {
      const nonce = randomBytes(32);
      // Same response whether or not the user exists; only real users get a
      // stored (usable) challenge.
      await pool.query(
        `INSERT INTO auth_challenges (nonce, user_id, expires_at)
         SELECT $1, id, now() + make_interval(secs => $3) FROM users WHERE username = $2`,
        [nonce, req.body.username, AUTH_CHALLENGE_TTL_SECONDS],
      );
      return { nonce: toBase64Url(nonce) };
    },
  );

  app.post<{ Body: LoginRequest }>(
    '/auth/login',
    {
      config: rl(RATE_LIMITS.authLogin),
      schema: {
        body: {
          type: 'object',
          required: ['username', 'nonce', 'signature'],
          additionalProperties: false,
          properties: {
            username: USERNAME_SCHEMA,
            nonce: b64Exact(32),
            signature: b64Exact(64),
          },
        },
      },
    },
    async (req): Promise<LoginResponse> => {
      const nonce = decodeB64(req.body.nonce, 32);
      const signature = decodeB64(req.body.signature, 64);
      // Consume the challenge whatever happens next: single use.
      const { rows } = await pool.query<{ id: string; auth_pub: Buffer }>(
        `DELETE FROM auth_challenges c USING users u
         WHERE c.nonce = $1 AND c.user_id = u.id AND u.username = $2 AND c.expires_at > now()
         RETURNING u.id, u.auth_pub`,
        [nonce, req.body.username],
      );
      const user = rows[0];
      if (
        !user ||
        !verify(
          signature,
          authChallengeMessage(req.body.username, nonce),
          new Uint8Array(user.auth_pub),
        )
      ) {
        throw httpError(401);
      }
      const token = randomToken();
      const { rows: s } = await pool.query<{ expires_at: Date }>(
        `INSERT INTO sessions (token_hash, user_id, expires_at)
         VALUES ($1, $2, now() + make_interval(secs => $3)) RETURNING expires_at`,
        [hashToken(token, pepper), user.id, SESSION_TTL_SECONDS],
      );
      return { session_token: token, expires_at: s[0]!.expires_at.toISOString() };
    },
  );

  app.post('/auth/logout', { preHandler: session }, async (req, reply) => {
    await pool.query('DELETE FROM sessions WHERE token_hash = $1', [
      hashToken(bearerToken(req)!, pepper),
    ]);
    return reply.code(204).send();
  });

  /** Deletes the account and, by cascade, its keys, sessions and undelivered mail. */
  app.delete('/auth/account', { preHandler: session }, async (req, reply) => {
    await pool.query('DELETE FROM users WHERE id = $1', [req.user!.id]);
    return reply.code(204).send();
  });
};
