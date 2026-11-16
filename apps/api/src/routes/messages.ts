import type { FastifyPluginAsync } from 'fastify';
import { toBase64Url } from '@opsec-aio/crypto';
import {
  CHAT_BATCH_MAX,
  CHAT_MAILBOX_MAX,
  CHAT_MESSAGE_MAX_BYTES,
  CHAT_PENDING_PAGE,
  RATE_LIMITS,
  type AckRequest,
  type IncomingMessage,
  type PendingMessagesResponse,
  type SendMessagesRequest,
  type SendMessagesResponse,
  type SignalMessageType,
  type WsClientMessage,
  type WsServerMessage,
} from '@opsec-aio/types';
import type { Pool } from '../db.js';
import { UUID_PATTERN, USERNAME_SCHEMA, b64Len, decodeB64, httpError, rl } from '../http.js';
import type { Notifier } from '../notifier.js';
import { ONION_KEY_PREFIX, rateLimitKey } from '../ratelimit.js';
import { requireSession, sessionUser } from '../session.js';

export interface MessageRouteOptions {
  pool: Pool;
  pepper: Uint8Array;
  notifier: Notifier;
  /** Cap on queued ciphertext across all mailboxes (bytes). */
  mailboxMaxBytes: number;
}

const PENDING_LIMIT = CHAT_PENDING_PAGE;
/** How long a measured mailbox total is reused before measuring again. */
const MAILBOX_USAGE_TTL_MS = 30_000;
const WS_AUTH_TIMEOUT_MS = 10_000;
const WS_SESSION_RECHECK_MS = 5 * 60_000;
const WS_MAX_PER_CLIENT = 20;
const WS_MAX_PER_ONION = 500;

/**
 * Message relay (docs/PLAN.md §4.1). The server is a mailbox, not an archive:
 * it stores sender, recipient, time and an opaque Signal ciphertext, pushes it
 * over WebSocket if the recipient is online, and deletes it on ACK.
 */
export const messageRoutes: FastifyPluginAsync<MessageRouteOptions> = async (app, opts) => {
  const { pool, pepper, notifier, mailboxMaxBytes } = opts;
  const session = requireSession(pool, pepper);

  // Total queued ciphertext, measured at most every 30 s (octet_length reads
  // the TOAST header, not the data) plus what this process queued since. Not
  // pg_total_relation_size: the table file doesn't shrink after deletes, so it
  // would stay "full" forever once it got there.
  let usage = { bytes: 0, at: -Infinity };
  async function mailboxBytes(): Promise<number> {
    if (Date.now() - usage.at > MAILBOX_USAGE_TTL_MS) {
      const { rows } = await pool.query<{ bytes: string }>(
        'SELECT COALESCE(SUM(octet_length(ciphertext)), 0) AS bytes FROM mailbox',
      );
      usage = { bytes: Number(rows[0]!.bytes), at: Date.now() };
    }
    return usage.bytes;
  }

  app.post<{ Body: SendMessagesRequest }>(
    '/messages',
    {
      preHandler: session,
      config: rl(RATE_LIMITS.messageSend),
      bodyLimit: CHAT_BATCH_MAX * (b64Len(CHAT_MESSAGE_MAX_BYTES) + 256),
      schema: {
        body: {
          type: 'object',
          required: ['messages'],
          additionalProperties: false,
          properties: {
            messages: {
              type: 'array',
              minItems: 1,
              maxItems: CHAT_BATCH_MAX,
              items: {
                type: 'object',
                required: ['to', 'type', 'body'],
                additionalProperties: false,
                properties: {
                  to: USERNAME_SCHEMA,
                  type: { type: 'integer', enum: [1, 3] },
                  body: {
                    type: 'string',
                    pattern: '^[A-Za-z0-9_-]+$',
                    maxLength: b64Len(CHAT_MESSAGE_MAX_BYTES),
                  },
                },
              },
            },
          },
        },
      },
    },
    async (req, reply): Promise<SendMessagesResponse> => {
      const msgs = req.body.messages.map((m) => ({ ...m, bytes: decodeB64(m.body) }));
      const names = [...new Set(msgs.map((m) => m.to))];
      const { rows: users } = await pool.query<{ id: string; username: string; queued: string }>(
        `SELECT u.id, u.username,
                (SELECT count(*) FROM mailbox m WHERE m.to_user = u.id) AS queued
         FROM users u WHERE u.username = ANY($1::text[])`,
        [names],
      );
      if (users.length !== names.length) throw httpError(404);
      const byName = new Map(users.map((u) => [u.username, u]));
      if (users.some((u) => Number(u.queued) + msgs.length > CHAT_MAILBOX_MAX)) {
        throw httpError(507);
      }
      const batchBytes = msgs.reduce((n, m) => n + m.bytes.length, 0);
      if ((await mailboxBytes()) + batchBytes > mailboxMaxBytes) throw httpError(507);

      const toIds = msgs.map((m) => byName.get(m.to)!.id);
      const { rows } = await pool.query<{
        id: string;
        to_user: string;
        msg_type: SignalMessageType;
        ciphertext: Buffer;
        created_at: Date;
      }>(
        `INSERT INTO mailbox (to_user, from_user, msg_type, ciphertext)
         SELECT t, $1, k, c FROM unnest($2::uuid[], $3::smallint[], $4::bytea[]) AS x(t, k, c)
         RETURNING id, to_user, msg_type, ciphertext, created_at`,
        [req.user!.id, toIds, msgs.map((m) => m.type), msgs.map((m) => m.bytes)],
      );
      usage.bytes += batchBytes;
      for (const r of rows) {
        const message: IncomingMessage = {
          id: r.id,
          from: req.user!.username,
          type: r.msg_type,
          body: toBase64Url(r.ciphertext),
          sent_at: r.created_at.toISOString(),
        };
        void notifier.publish(r.to_user, JSON.stringify(message)).catch(() => {});
      }
      reply.code(201);
      return { sent: rows.length };
    },
  );

  app.get(
    '/messages/pending',
    { preHandler: session, config: rl(RATE_LIMITS.messagePending) },
    async (req): Promise<PendingMessagesResponse> => {
      const { rows } = await pool.query<{
        id: string;
        from: string | null;
        msg_type: SignalMessageType;
        ciphertext: Buffer;
        created_at: Date;
      }>(
        `SELECT m.id, u.username AS "from", m.msg_type, m.ciphertext, m.created_at
         FROM mailbox m LEFT JOIN users u ON u.id = m.from_user
         WHERE m.to_user = $1 ORDER BY m.created_at, m.id LIMIT $2`,
        [req.user!.id, PENDING_LIMIT],
      );
      return {
        messages: rows.map((r) => ({
          id: r.id,
          from: r.from,
          type: r.msg_type,
          body: toBase64Url(r.ciphertext),
          sent_at: r.created_at.toISOString(),
        })),
      };
    },
  );

  app.post<{ Body: AckRequest }>(
    '/messages/ack',
    {
      preHandler: session,
      // A full page of 500 UUIDs is ~20 KiB, over the 16 KiB default.
      bodyLimit: 32 * 1024,
      schema: {
        body: {
          type: 'object',
          required: ['ids'],
          additionalProperties: false,
          properties: {
            ids: {
              type: 'array',
              minItems: 1,
              maxItems: PENDING_LIMIT,
              items: { type: 'string', pattern: UUID_PATTERN },
            },
          },
        },
      },
    },
    async (req, reply) => {
      // Only the recipient can delete, and only their own mail.
      await pool.query('DELETE FROM mailbox WHERE to_user = $1 AND id = ANY($2::uuid[])', [
        req.user!.id,
        req.body.ids,
      ]);
      return reply.code(204).send();
    },
  );

  // Open sockets per client bucket (this process). Onion visitors share one bucket.
  const sockets = new Map<string, number>();

  app.get('/ws', { websocket: true }, (socket, req) => {
    const bucket = rateLimitKey(req, pepper);
    const cap = bucket.startsWith(ONION_KEY_PREFIX) ? WS_MAX_PER_ONION : WS_MAX_PER_CLIENT;
    const open = (sockets.get(bucket) ?? 0) + 1;
    if (open > cap) {
      socket.close(4429, 'too many connections');
      return;
    }
    sockets.set(bucket, open);
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      const n = (sockets.get(bucket) ?? 1) - 1;
      if (n > 0) sockets.set(bucket, n);
      else sockets.delete(bucket);
    };

    let unsubscribe: (() => void) | null = null;
    let authenticating = false;
    let recheck: ReturnType<typeof setInterval> | undefined;
    const send = (m: WsServerMessage) => {
      if (socket.readyState === socket.OPEN) socket.send(JSON.stringify(m));
    };
    const authTimer = setTimeout(() => socket.close(4401, 'unauthorized'), WS_AUTH_TIMEOUT_MS);

    const onMessage = async (raw: Buffer) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw.toString('utf8'));
      } catch {
        parsed = null;
      }
      // Anything that isn't {type: string, ...} is rejected (JSON `null` used
      // to crash the process here).
      if (
        typeof parsed !== 'object' ||
        parsed === null ||
        typeof (parsed as { type?: unknown }).type !== 'string'
      ) {
        send({ type: 'error', error: 'bad_request' });
        return;
      }
      const msg = parsed as WsClientMessage;
      if (msg.type === 'ping') {
        send({ type: 'pong' });
        return;
      }
      if (msg.type !== 'auth' || typeof msg.token !== 'string' || unsubscribe || authenticating) {
        send({ type: 'error', error: 'bad_request' });
        return;
      }
      authenticating = true;
      const token = msg.token;
      const user = await sessionUser(pool, pepper, token).catch(() => null);
      if (!user) {
        send({ type: 'error', error: 'unauthorized' });
        socket.close(4401, 'unauthorized');
        return;
      }
      clearTimeout(authTimer);
      unsubscribe = await notifier.subscribe(user.id, (payload) => {
        send({ type: 'message', message: JSON.parse(payload) as IncomingMessage });
      });
      if (socket.readyState !== socket.OPEN) {
        unsubscribe();
        return;
      }
      // Stop pushing once the session is logged out or expires.
      recheck = setInterval(() => {
        sessionUser(pool, pepper, token)
          .then((still) => {
            if (!still) socket.close(4401, 'session ended');
          })
          .catch(() => {});
      }, WS_SESSION_RECHECK_MS);
      send({ type: 'ready' });
    };

    socket.on('message', (raw: Buffer) => {
      // Never let a handler error become an unhandled rejection (which would
      // take the whole process down): drop just this socket instead.
      onMessage(raw).catch(() => socket.close(1011, 'error'));
    });

    socket.on('close', () => {
      clearTimeout(authTimer);
      clearInterval(recheck);
      unsubscribe?.();
      release();
    });
  });

  // Look up whether a username exists (to start a chat). Requires a session.
  app.get<{ Params: { username: string } }>(
    '/users/:username',
    {
      preHandler: session,
      config: rl(RATE_LIMITS.keyBundle),
      schema: {
        params: {
          type: 'object',
          required: ['username'],
          properties: { username: USERNAME_SCHEMA },
        },
      },
    },
    async (req) => {
      const { rowCount } = await pool.query('SELECT 1 FROM users WHERE username = $1', [
        req.params.username,
      ]);
      if (!rowCount) throw httpError(404);
      return { username: req.params.username };
    },
  );
};
