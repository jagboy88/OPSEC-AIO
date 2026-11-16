import websocket from '@fastify/websocket';
import Fastify, { LogController, type FastifyError, type FastifyInstance } from 'fastify';
import { API_PREFIX, type ErrorResponse } from '@opsec-aio/types';
import type { Redis } from 'ioredis';
import type { BlobStore } from './blobs.js';
import type { Config } from './config.js';
import type { Pool } from './db.js';
import { serializeError } from './log.js';
import { setRateLimitMultiplier } from './http.js';
import { MemoryNotifier, type Notifier } from './notifier.js';
import { registerRateLimit } from './ratelimit.js';
import { healthRoutes, type Probe } from './routes/health.js';
import { authRoutes } from './routes/auth.js';
import { dropRoutes } from './routes/drops.js';
import { keyRoutes } from './routes/keys.js';
import { messageRoutes } from './routes/messages.js';
import { noteRoutes } from './routes/notes.js';

export interface AppDeps {
  config: Pick<Config, 'logLevel' | 'trustProxyHops'> &
    Partial<Pick<Config, 'rateLimitMultiplier'>>;
  /** Named readiness checks (database, redis, storage…). */
  probes: Record<string, Probe>;
  /**
   * Data layer. When absent (unit tests of the shell) only health routes exist.
   * Callers must have awaited `ready()` from @opsec-aio/crypto.
   */
  data?: {
    pool: Pool;
    tokenPepper: Uint8Array;
    /** Rate-limit store; in-process memory when absent. */
    redis?: Redis;
    /** Drop storage; Drop routes are only registered when present. */
    blobs?: BlobStore;
    dropStorageMaxBytes?: number;
    dropMinFreeBytes?: number;
    /** Cap on queued chat ciphertext across all mailboxes. */
    mailboxMaxBytes?: number;
    /** Cross-process WebSocket fan-out; in-process when absent. */
    notifier?: Notifier;
  };
}

/** Default cap on stored Drop ciphertext: 20 GiB. Override with DROP_STORAGE_MAX_BYTES. */
export const DEFAULT_DROP_STORAGE_MAX_BYTES = 20 * 1024 ** 3;
/** Default free-space floor on the blob volume: 2 GiB. Override with DROP_MIN_FREE_BYTES. */
export const DEFAULT_DROP_MIN_FREE_BYTES = 2 * 1024 ** 3;
/** Default cap on queued chat ciphertext: 2 GiB. Override with MAILBOX_MAX_BYTES. */
export const DEFAULT_MAILBOX_MAX_BYTES = 2 * 1024 ** 3;

/** Default JSON body limit; endpoints that accept more opt in explicitly. */
const DEFAULT_BODY_LIMIT = 16 * 1024;

function errorCode(status: number): ErrorResponse['error'] {
  if (status === 404) return 'not_found';
  if (status === 413) return 'payload_too_large';
  if (status === 429) return 'rate_limited';
  if (status === 507) return 'storage_full';
  if (status === 401) return 'unauthorized';
  if (status === 409) return 'conflict';
  if (status >= 400 && status < 500) return 'bad_request';
  return 'internal';
}

export async function buildApp(deps: AppDeps): Promise<FastifyInstance> {
  setRateLimitMultiplier(deps.config.rateLimitMultiplier ?? 1);
  const app = Fastify({
    // Privacy-preserving logging (plan §7): no request lines, no IPs, no URLs,
    // no user agents. Only errors and lifecycle events are logged.
    logger: {
      level: deps.config.logLevel,
      base: null,
      serializers: {
        req: () => ({}),
        res: () => ({}),
        err: serializeError,
      },
    },
    logController: new LogController({ disableRequestLogging: true }),
    // Trust exactly N proxy hops (Caddy) so per-IP rate limits see the real client.
    trustProxy: (_addr: string, hop: number) => hop < deps.config.trustProxyHops,
    bodyLimit: DEFAULT_BODY_LIMIT,
    // Opaque ids only — never reflect anything derived from the client.
    genReqId: () => '-',
    return503OnClosing: true,
  });

  // Defence in depth: Caddy sets the full header set, but the API must be
  // safe even if it is ever reached directly.
  app.addHook('onSend', async (_req, reply, payload) => {
    reply.header('Cache-Control', 'no-store');
    reply.header('Referrer-Policy', 'no-referrer');
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Cross-Origin-Resource-Policy', 'same-origin');
    reply.header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    return payload;
  });

  app.setErrorHandler((err: FastifyError, req, reply) => {
    const status = err.statusCode && err.statusCode >= 400 ? err.statusCode : 500;
    if (status >= 500 && status !== 507) req.log.error({ err }, 'request failed');
    const body: ErrorResponse = { error: errorCode(status) };
    return reply.code(status).send(body);
  });

  // Same response for "never existed" and "already burned" (plan §5).
  app.setNotFoundHandler((_req, reply) => {
    const body: ErrorResponse = { error: 'not_found' };
    return reply.code(404).send(body);
  });

  await app.register(healthRoutes, { prefix: API_PREFIX, probes: deps.probes });

  if (deps.data) {
    const { pool, tokenPepper, redis } = deps.data;
    await registerRateLimit(app, { pepper: tokenPepper, ...(redis ? { redis } : {}) });
    await app.register(noteRoutes, { prefix: API_PREFIX, pool, pepper: tokenPepper });
    // Chat (Phase 3). WebSocket frames from clients are tiny control messages.
    await app.register(websocket, {
      options: { maxPayload: 4096 },
      // Covers both handler errors and broken connections: drop the socket,
      // log only what kind of error it was.
      errorHandler: (err, socket, req) => {
        // Errors with a code are connection-level (ECONNRESET, WS_ERR_*) and
        // routine on mobile networks; anything else is a bug worth seeing.
        if ((err as { code?: unknown }).code) req.log.debug({ err }, 'websocket closed on error');
        else req.log.warn({ err }, 'websocket handler failed');
        socket.terminate();
      },
    });
    await app.register(authRoutes, { prefix: API_PREFIX, pool, pepper: tokenPepper });
    await app.register(keyRoutes, { prefix: API_PREFIX, pool, pepper: tokenPepper });
    await app.register(messageRoutes, {
      prefix: API_PREFIX,
      pool,
      pepper: tokenPepper,
      notifier: deps.data.notifier ?? new MemoryNotifier(),
      mailboxMaxBytes: deps.data.mailboxMaxBytes ?? DEFAULT_MAILBOX_MAX_BYTES,
    });
    if (deps.data.blobs) {
      await app.register(dropRoutes, {
        prefix: API_PREFIX,
        pool,
        pepper: tokenPepper,
        blobs: deps.data.blobs,
        storageMaxBytes: deps.data.dropStorageMaxBytes ?? DEFAULT_DROP_STORAGE_MAX_BYTES,
        minFreeBytes: deps.data.dropMinFreeBytes ?? DEFAULT_DROP_MIN_FREE_BYTES,
      });
    }
  }

  return app;
}
