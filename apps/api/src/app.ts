import Fastify, { LogController, type FastifyError, type FastifyInstance } from 'fastify';
import { API_PREFIX, type ErrorResponse } from '@opsec-aio/types';
import type { Config } from './config.js';
import { healthRoutes, type Probe } from './routes/health.js';

export interface AppDeps {
  config: Pick<Config, 'logLevel' | 'trustProxyHops'>;
  /** Named readiness checks (database, redis, storage…). */
  probes: Record<string, Probe>;
}

/** Default JSON body limit; endpoints that accept more opt in explicitly. */
const DEFAULT_BODY_LIMIT = 16 * 1024;

function errorCode(status: number): ErrorResponse['error'] {
  if (status === 404) return 'not_found';
  if (status === 413) return 'payload_too_large';
  if (status === 429) return 'rate_limited';
  if (status >= 400 && status < 500) return 'bad_request';
  return 'internal';
}

export async function buildApp(deps: AppDeps): Promise<FastifyInstance> {
  const app = Fastify({
    // Privacy-preserving logging (plan §7): no request lines, no IPs, no URLs,
    // no user agents. Only errors and lifecycle events are logged.
    logger: {
      level: deps.config.logLevel,
      base: null,
      serializers: {
        req: () => ({}),
        res: () => ({}),
        err: (err: Error) => ({ type: err.name, message: err.message, stack: err.stack ?? '' }),
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
    if (status >= 500) req.log.error({ err }, 'request failed');
    const body: ErrorResponse = { error: errorCode(status) };
    return reply.code(status).send(body);
  });

  // Same response for "never existed" and "already burned" (plan §5).
  app.setNotFoundHandler((_req, reply) => {
    const body: ErrorResponse = { error: 'not_found' };
    return reply.code(404).send(body);
  });

  await app.register(healthRoutes, { prefix: API_PREFIX, probes: deps.probes });

  return app;
}
