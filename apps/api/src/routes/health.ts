import type { FastifyPluginAsync } from 'fastify';
import type { HealthResponse, ReadyResponse } from '@opsec-aio/types';

export type Probe = () => Promise<void>;

const PROBE_TIMEOUT_MS = 2_000;

function withTimeout(p: Promise<void>): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('probe timeout')), PROBE_TIMEOUT_MS);
    p.then(
      () => {
        clearTimeout(t);
        resolve();
      },
      (e: unknown) => {
        clearTimeout(t);
        reject(e instanceof Error ? e : new Error('probe failed'));
      },
    );
  });
}

export const healthRoutes: FastifyPluginAsync<{ probes: Record<string, Probe> }> = async (
  app,
  opts,
) => {
  /** Liveness: the process is up. */
  app.get('/health', async (): Promise<HealthResponse> => ({ status: 'ok' }));

  /** Readiness: dependencies reachable. Used by the container healthcheck. */
  app.get('/ready', async (req, reply): Promise<ReadyResponse> => {
    const names = Object.keys(opts.probes);
    const results = await Promise.allSettled(names.map((n) => withTimeout(opts.probes[n]!())));
    const checks: ReadyResponse['checks'] = {};
    results.forEach((r, i) => {
      checks[names[i]!] = r.status === 'fulfilled' ? 'ok' : 'fail';
      if (r.status === 'rejected') req.log.warn({ probe: names[i] }, 'readiness probe failed');
    });
    const ok = results.every((r) => r.status === 'fulfilled');
    reply.code(ok ? 200 : 503);
    return { status: ok ? 'ok' : 'degraded', checks };
  });
};
