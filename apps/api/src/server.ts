import { constants } from 'node:fs';
import { access } from 'node:fs/promises';
import { Redis } from 'ioredis';
import { ready as cryptoReady } from '@opsec-aio/crypto';
import { buildApp } from './app.js';
import { DiskBlobStore } from './blobs.js';
import { RedisNotifier } from './notifier.js';
import { loadConfig } from './config.js';
import { MIGRATIONS_DIR, createPool, migrate } from './db.js';
import { startSweeper } from './sweeper.js';

async function main(): Promise<void> {
  const config = loadConfig();
  await cryptoReady();

  const pool = createPool(config.databaseUrl);
  const redis = new Redis(config.redisUrl, { maxRetriesPerRequest: 2, enableOfflineQueue: false });
  redis.on('error', () => {
    /* surfaced via /ready; avoid log spam that could include hostnames */
  });

  const notifier = new RedisNotifier(redis);
  const blobs = config.blobDir ? new DiskBlobStore(config.blobDir) : undefined;

  const probes: Record<string, () => Promise<void>> = {
    database: async () => {
      await pool.query('SELECT 1');
    },
    redis: async () => {
      if ((await redis.ping()) !== 'PONG') throw new Error('bad ping');
    },
  };
  if (config.blobDir) {
    const dir = config.blobDir;
    probes.storage = () => access(dir, constants.R_OK | constants.W_OK);
  }

  const app = await buildApp({
    config,
    probes,
    data: {
      pool,
      tokenPepper: config.tokenPepper,
      redis,
      notifier,
      mailboxMaxBytes: config.mailboxMaxBytes,
      ...(blobs
        ? {
            blobs,
            dropStorageMaxBytes: config.dropStorageMaxBytes,
            dropMinFreeBytes: config.dropMinFreeBytes,
          }
        : {}),
    },
  });

  if (config.migrateOnStart) {
    const applied = await migrate(pool, MIGRATIONS_DIR);
    if (applied.length) app.log.info({ applied }, 'migrations applied');
  }

  const stopSweeper = startSweeper(pool, app.log, blobs);

  // Last line of defence: log (without details that could carry ids) and keep
  // serving instead of letting one bug take every user offline.
  process.on('unhandledRejection', (e) => {
    app.log.error({ type: e instanceof Error ? e.name : typeof e }, 'unhandled rejection');
  });

  const shutdown = async (signal: string): Promise<void> => {
    app.log.info({ signal }, 'shutting down');
    stopSweeper();
    await app.close();
    await pool.end();
    await notifier.close();
    redis.disconnect();
    process.exit(0);
  };
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));

  await app.listen({ host: config.host, port: config.port });
}

main().catch((err: unknown) => {
  // Config errors must be readable; they never contain secrets (we only name the variable).
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
