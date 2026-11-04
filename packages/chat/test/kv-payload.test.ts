import { describe, expect, it } from 'vitest';
import { DecryptionError, randomId, ready, utf8Encode } from '@opsec-aio/crypto';
import {
  MemoryKV,
  createVault,
  decodePayload,
  encodePayload,
  hasVault,
  unlockVault,
  PayloadError,
  type Payload,
} from '../src/index.js';

await ready();
const FAST = { opsLimit: 2, memLimitBytes: 8 * 1024 * 1024 };

describe('encrypted vault', () => {
  it('stores records under hashed names with sealed values', async () => {
    const raw = new MemoryKV();
    const kv = await createVault(raw, 'correct horse battery', FAST);
    await kv.setJSON('identity:alice', { secret: 'value-xyz' });
    const dump = JSON.stringify(
      [...raw.map.entries()].map(([k, v]) => [k, Buffer.from(v).toString()]),
    );
    expect(dump).not.toContain('alice');
    expect(dump).not.toContain('value-xyz');
    expect(await kv.getJSON('identity:alice')).toEqual({ secret: 'value-xyz' });
  });

  it('unlocks only with the right passphrase', async () => {
    const raw = new MemoryKV();
    const kv = await createVault(raw, 'right passphrase', FAST);
    await kv.setJSON('k', 1);
    expect(await hasVault(raw)).toBe(true);
    await expect(unlockVault(raw, 'wrong passphrase')).rejects.toBeInstanceOf(DecryptionError);
    expect(await (await unlockVault(raw, 'right passphrase')).getJSON('k')).toBe(1);
    await expect(createVault(raw, 'again', FAST)).rejects.toThrow(/already exists/);
  });

  it('detects records moved between keys', async () => {
    const raw = new MemoryKV();
    const kv = await createVault(raw, 'pw-pw-pw-pw', FAST);
    await kv.set('a', utf8Encode('A'));
    await kv.set('b', utf8Encode('B'));
    const [ka, kb] = [...raw.map.keys()].filter((k) => k.startsWith('e:'));
    raw.map.set(kb!, raw.map.get(ka!)!);
    await expect(Promise.all([kv.get('a'), kv.get('b')])).rejects.toBeInstanceOf(DecryptionError);
  });

  it('destroy() wipes the device', async () => {
    const raw = new MemoryKV();
    const kv = await createVault(raw, 'pw-pw-pw-pw', FAST);
    await kv.setJSON('x', 1);
    await kv.destroy();
    expect(raw.map.size).toBe(0);
  });
});

describe('payloads', () => {
  const base = { v: 1 as const, id: randomId(), ts: 1 };

  it('round-trips and pads to 160-byte blocks', () => {
    const p: Payload = { ...base, kind: 'text', text: 'hi', timer: 0 };
    const bytes = encodePayload(p);
    expect(bytes.length % 160).toBe(0);
    expect(encodePayload({ ...p, text: 'hello there' }).length).toBe(bytes.length);
    expect(decodePayload(bytes)).toEqual(p);
  });

  it('rejects malformed or out-of-range payloads', () => {
    const bad: unknown[] = [
      { ...base, kind: 'text', text: '', timer: 0 },
      { ...base, kind: 'text', text: 'x', timer: 42 },
      { ...base, kind: 'group', group: randomId(), name: 'g', members: ['alice'] },
      { ...base, kind: 'group', group: randomId(), name: 'g', members: ['alice', 'BOB'] },
      { ...base, kind: 'nope' },
      { ...base, id: 'short', kind: 'timer', timer: 0 },
    ];
    for (const p of bad) expect(() => encodePayload(p as Payload)).toThrow(PayloadError);
    expect(() => decodePayload(new Uint8Array(160))).toThrow(PayloadError);
  });
});
