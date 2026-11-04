import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';

const PEPPER = 'A'.repeat(43); // 32 bytes base64url

const base = {
  DATABASE_URL: 'postgres://u:p@localhost/db',
  REDIS_URL: 'redis://localhost:6379',
  TOKEN_PEPPER: PEPPER,
};

describe('loadConfig', () => {
  it('loads defaults', () => {
    const c = loadConfig(base);
    expect(c.port).toBe(3000);
    expect(c.trustProxyHops).toBe(0);
    expect(c.tokenPepper.length).toBe(32);
    expect(c.migrateOnStart).toBe(true);
  });

  it('names missing variables without echoing values', () => {
    expect(() => loadConfig({ ...base, DATABASE_URL: undefined })).toThrow(/DATABASE_URL/);
    expect(() => loadConfig({ ...base, TOKEN_PEPPER: undefined })).toThrow(/TOKEN_PEPPER/);
  });

  it('rejects a weak pepper', () => {
    expect(() => loadConfig({ ...base, TOKEN_PEPPER: 'AAAA' })).toThrow(/32 bytes/);
    expect(() => loadConfig({ ...base, TOKEN_PEPPER: 'not base64!' })).toThrow(/base64url/);
  });

  it('injects passwords from *_FILE secrets into connection URLs', async () => {
    const { mkdtempSync, writeFileSync } = await import('node:fs');
    const { join } = await import('node:path');
    const { tmpdir } = await import('node:os');
    const dir = mkdtempSync(join(tmpdir(), 'cfg-'));
    writeFileSync(join(dir, 'pg'), 'p@ss/word\n');
    const c = loadConfig({
      ...base,
      DATABASE_URL: 'postgres://opsec@postgres:5432/opsec',
      DATABASE_PASSWORD_FILE: join(dir, 'pg'),
      REDIS_PASSWORD: 'r3dis',
    });
    expect(new URL(c.databaseUrl).password).toBe('p%40ss%2Fword');
    expect(new URL(c.redisUrl).password).toBe('r3dis');
  });

  it('validates numeric settings', () => {
    expect(() => loadConfig({ ...base, PORT: '99999' })).toThrow(/PORT/);
    expect(() => loadConfig({ ...base, TRUST_PROXY_HOPS: '-1' })).toThrow(/TRUST_PROXY_HOPS/);
  });
});
