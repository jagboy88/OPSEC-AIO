import { readFileSync } from 'node:fs';
import { fromBase64Url } from '@opsec-aio/crypto';

export interface Config {
  env: 'production' | 'development' | 'test';
  host: string;
  port: number;
  logLevel: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'silent';
  /** Number of trusted reverse-proxy hops (Caddy = 1). Used only for rate limiting. */
  trustProxyHops: number;
  databaseUrl: string;
  redisUrl: string;
  /**
   * Directory for encrypted Drop blobs (a dedicated volume, excluded from
   * backups, on a LUKS-encrypted host disk). Empty = storage disabled.
   */
  blobDir: string;
  /** Cap on reserved Drop ciphertext across live drops. */
  dropStorageMaxBytes: number;
  /** Server-side pepper for hashing deletion/upload/session tokens (≥ 32 bytes). */
  tokenPepper: Uint8Array;
  migrateOnStart: boolean;
}

type Env = Record<string, string | undefined>;

/**
 * Reads `NAME`, or the contents of the file at `NAME_FILE` (Docker secrets).
 */
function read(env: Env, name: string): string | undefined {
  const file = env[`${name}_FILE`];
  if (file) return readFileSync(file, 'utf8').trim();
  const v = env[name];
  return v === undefined || v === '' ? undefined : v;
}

function required(env: Env, name: string): string {
  const v = read(env, name);
  if (v === undefined) throw new Error(`missing required configuration: ${name}`);
  return v;
}

/** Inject a password (from a Docker secret) into a connection URL. */
function withPassword(url: string, password: string | undefined, name: string): string {
  if (password === undefined) return url;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error(`invalid ${name}`);
  }
  u.password = encodeURIComponent(password);
  return u.toString();
}

const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'silent'] as const;

export function loadConfig(env: Env = process.env): Config {
  const nodeEnv =
    env.NODE_ENV === 'production' || env.NODE_ENV === 'test' ? env.NODE_ENV : 'development';
  const logLevel = (read(env, 'LOG_LEVEL') ?? 'info') as Config['logLevel'];
  if (!LOG_LEVELS.includes(logLevel)) throw new Error('invalid LOG_LEVEL');

  const port = Number(read(env, 'PORT') ?? '3000');
  if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error('invalid PORT');
  const hops = Number(read(env, 'TRUST_PROXY_HOPS') ?? '0');
  if (!Number.isInteger(hops) || hops < 0 || hops > 5) throw new Error('invalid TRUST_PROXY_HOPS');

  const dropStorageMaxBytes = Number(read(env, 'DROP_STORAGE_MAX_BYTES') ?? 20 * 1024 ** 3);
  if (!Number.isSafeInteger(dropStorageMaxBytes) || dropStorageMaxBytes < 0) {
    throw new Error('invalid DROP_STORAGE_MAX_BYTES');
  }

  let tokenPepper: Uint8Array;
  try {
    tokenPepper = fromBase64Url(required(env, 'TOKEN_PEPPER'));
  } catch (e) {
    if (e instanceof Error && e.message.startsWith('missing')) throw e;
    throw new Error('TOKEN_PEPPER must be base64url', { cause: e });
  }
  if (tokenPepper.length < 32) throw new Error('TOKEN_PEPPER must decode to at least 32 bytes');

  return {
    env: nodeEnv,
    host: read(env, 'HOST') ?? '0.0.0.0',
    port,
    logLevel,
    trustProxyHops: hops,
    databaseUrl: withPassword(
      required(env, 'DATABASE_URL'),
      read(env, 'DATABASE_PASSWORD'),
      'DATABASE_URL',
    ),
    redisUrl: withPassword(required(env, 'REDIS_URL'), read(env, 'REDIS_PASSWORD'), 'REDIS_URL'),
    blobDir: read(env, 'BLOB_DIR') ?? '',
    dropStorageMaxBytes,
    tokenPepper,
    migrateOnStart: (read(env, 'MIGRATE_ON_START') ?? 'true') === 'true',
  };
}
