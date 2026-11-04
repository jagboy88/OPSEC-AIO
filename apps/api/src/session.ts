import type { FastifyReply, FastifyRequest } from 'fastify';
import { hashToken } from '@opsec-aio/crypto';
import type { Pool } from './db.js';

export interface SessionUser {
  id: string;
  username: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: SessionUser;
  }
}

const unauthorized = () => Object.assign(new Error('unauthorized'), { statusCode: 401 });

/** Look up a live session by its bearer token. Tokens are stored only as keyed hashes. */
export async function sessionUser(
  pool: Pool,
  pepper: Uint8Array,
  token: string | null | undefined,
): Promise<SessionUser | null> {
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const { rows } = await pool.query<SessionUser>(
    `SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1 AND s.expires_at > now()`,
    [hashToken(token, pepper)],
  );
  return rows[0] ?? null;
}

export function bearerToken(req: FastifyRequest): string | null {
  const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization ?? '');
  return m?.[1] ?? null;
}

/** preHandler: require a valid session, exposing it as `req.user`. */
export function requireSession(pool: Pool, pepper: Uint8Array) {
  return async (req: FastifyRequest, _reply: FastifyReply) => {
    const user = await sessionUser(pool, pepper, bearerToken(req));
    if (!user) throw unauthorized();
    req.user = user;
  };
}
