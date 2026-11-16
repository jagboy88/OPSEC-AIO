import rateLimit, { normalizeIP } from '@fastify/rate-limit';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';
import { blake2b, toBase64Url, utf8Encode } from '@opsec-aio/crypto';

const DAY_MS = 86_400_000;

/**
 * Rate-limit bucket key for a client. Raw IPs never reach Redis: the key is a
 * BLAKE2b MAC of (day, IP) under the server pepper, so it changes every UTC day
 * and cannot be reversed or linked across days without the pepper. IPv6
 * addresses are grouped by /64 so one host cannot rotate through its subnet.
 */
export function clientKey(ip: string, pepper: Uint8Array, now = Date.now()): string {
  const day = Math.floor(now / DAY_MS);
  const subject = `${day}|${normalizeIP(ip, 64)}`;
  return toBase64Url(blake2b(utf8Encode(subject), 16, pepper));
}

/** Bucket key prefix for traffic that arrived through the Tor onion service. */
export const ONION_KEY_PREFIX = 'onion:';

/**
 * Onion visitors all reach Caddy from 127.0.0.1, so they can't be told apart
 * by IP. Caddy's onion site sets `X-Opsec-Via: onion` (the clearnet site
 * strips any client-supplied value, and the API is not reachable directly),
 * and those requests share one daily bucket with larger limits (see rl()).
 */
export function rateLimitKey(req: FastifyRequest, pepper: Uint8Array, now = Date.now()): string {
  if (req.headers['x-opsec-via'] === 'onion') return `${ONION_KEY_PREFIX}${Math.floor(now / DAY_MS)}`;
  return clientKey(req.ip, pepper, now);
}

export interface RateLimitDeps {
  /** Shared store across API replicas. Falls back to in-process memory when absent (tests). */
  redis?: Redis;
  pepper: Uint8Array;
}

/** Registers the plugin with no global limit; routes opt in via `config.rateLimit`. */
export async function registerRateLimit(app: FastifyInstance, deps: RateLimitDeps): Promise<void> {
  await app.register(rateLimit, {
    global: false,
    ...(deps.redis ? { redis: deps.redis } : {}),
    nameSpace: 'rl:',
    // If Redis is down, serve requests rather than fail closed: availability of
    // reading a note matters more than perfect abuse protection.
    skipOnError: true,
    keyGenerator: (req) => rateLimitKey(req, deps.pepper),
    errorResponseBuilder: (_req, ctx) =>
      Object.assign(new Error('rate limited'), { statusCode: ctx.statusCode }),
  });
}
