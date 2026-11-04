import type { FastifyPluginAsync } from 'fastify';
import { toBase64Url } from '@opsec-aio/crypto';
import {
  CHAT_BATCH_MAX,
  CHAT_MAILBOX_MAX,
  CHAT_MESSAGE_MAX_BYTES,
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
import { requireSession, sessionUser } from '../session.js';

export interface MessageRouteOptions {
  pool: Pool;
  pepper: Uint8Array;
  notifier: Notifier;
}

const PENDING_LIMIT = 500;
const WS_AUTH_TIMEOUT_MS = 10_000;

/**
 * Message relay (docs/PLAN.md §4.1). The server is a mailbox, not an archive:
 * it stores sender, recipient, time and an opaque Signal ciphertext, pushes it
 * over WebSocket if the recipient is online, and deletes it on ACK.
 */
export const messageRoutes: FastifyPluginAsync<MessageRouteOptions> = async (app, opts) => {
  const { pool, pepper, notifier } = opts;
  const session = requireSession(pool, pepper);

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

  app.get('/ws', { websocket: true }, (socket) => {
    let unsubscribe: (() => void) | null = null;
    let authenticating = false;
    const send = (m: WsServerMessage) => {
      if (socket.readyState === socket.OPEN) socket.send(JSON.stringify(m));
    };
    const authTimer = setTimeout(() => socket.close(4401, 'unauthorized'), WS_AUTH_TIMEOUT_MS);

    socket.on('message', async (raw: Buffer) => {
      let msg: WsClientMessage;
      try {
        msg = JSON.parse(raw.toString('utf8')) as WsClientMessage;
      } catch {
        send({ type: 'error', error: 'bad_request' });
        return;
      }
      if (msg.type === 'ping') {
        send({ type: 'pong' });
        return;
      }
      if (msg.type !== 'auth' || unsubscribe || authenticating) {
        send({ type: 'error', error: 'bad_request' });
        return;
      }
      authenticating = true;
      const user = await sessionUser(pool, pepper, msg.token).catch(() => null);
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
      send({ type: 'ready' });
    });

    socket.on('close', () => {
      clearTimeout(authTimer);
      unsubscribe?.();
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
