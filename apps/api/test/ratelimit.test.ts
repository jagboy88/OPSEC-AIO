import { describe, expect, it } from 'vitest';
import { randomBytes, ready } from '@opsec-aio/crypto';
import { clientKey } from '../src/ratelimit.js';

await ready();
const pepper = randomBytes(32);
const DAY = 86_400_000;

describe('rate-limit client keys', () => {
  it('never contain the raw IP', () => {
    for (const ip of ['198.51.100.23', '2001:db8::1']) {
      const k = clientKey(ip, pepper);
      expect(k).not.toContain(ip);
      expect(k).toMatch(/^[A-Za-z0-9_-]{22}$/);
    }
  });

  it('are stable within a day and rotate across days', () => {
    const t = Date.UTC(2026, 10, 4, 12);
    expect(clientKey('198.51.100.23', pepper, t)).toBe(
      clientKey('198.51.100.23', pepper, t + 1000),
    );
    expect(clientKey('198.51.100.23', pepper, t)).not.toBe(
      clientKey('198.51.100.23', pepper, t + DAY),
    );
  });

  it('depend on the pepper', () => {
    expect(clientKey('198.51.100.23', pepper)).not.toBe(
      clientKey('198.51.100.23', randomBytes(32)),
    );
  });

  it('group an IPv6 /64 together but separate different /64s', () => {
    expect(clientKey('2001:db8:1:2::1', pepper)).toBe(clientKey('2001:db8:1:2:ffff::9', pepper));
    expect(clientKey('2001:db8:1:2::1', pepper)).not.toBe(clientKey('2001:db8:1:3::1', pepper));
  });
});

describe('onion traffic', () => {
  it('shares one daily bucket, distinct from any IP bucket', async () => {
    const { rateLimitKey } = await import('../src/ratelimit.js');
    const t = Date.UTC(2026, 10, 16, 12);
    const onion = (ip: string) =>
      rateLimitKey({ headers: { 'x-opsec-via': 'onion' }, ip } as never, pepper, t);
    expect(onion('127.0.0.1')).toBe(onion('10.0.0.9'));
    expect(onion('127.0.0.1')).toMatch(/^onion:\d+$/);
    expect(rateLimitKey({ headers: {}, ip: '127.0.0.1' } as never, pepper, t)).not.toMatch(/^onion:/);
  });
});
