import rateLimit, { normalizeIP } from '@fastify/rate-limit';
import type { FastifyInstance } from 'fastify';
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
    keyGenerator: (req) => clientKey(req.ip, deps.pepper),
    errorResponseBuilder: (_req, ctx) =>
      Object.assign(new Error('rate limited'), { statusCode: ctx.statusCode }),
  });
}
