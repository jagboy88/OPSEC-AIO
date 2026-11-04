import { beforeAll, describe, expect, it } from 'vitest';
import {
  ARGON2ID_DEFAULT,
  DecryptionError,
  FormatError,
  WRAPPED_KEY_LENGTH,
  deriveKeyFromPassword,
  generateKey,
  ready,
  unwrapKeyWithPassword,
  utf8Encode,
  wrapKeyWithPassword,
} from '../src/index.js';

beforeAll(ready);

// Fast params for behavioural tests; production defaults are exercised once below.
const FAST = { opsLimit: 2, memLimitBytes: 8 * 1024 * 1024 };

describe('password key wrapping', () => {
  it('round-trips with the production defaults (64 MiB, t=3)', () => {
    const key = generateKey();
    const wrapped = wrapKeyWithPassword(key, 'hunter2 but longer', ARGON2ID_DEFAULT);
    expect(wrapped.length).toBe(WRAPPED_KEY_LENGTH);
    expect(unwrapKeyWithPassword(wrapped, 'hunter2 but longer')).toEqual(key);
  });

  it('rejects the wrong password', () => {
    const wrapped = wrapKeyWithPassword(generateKey(), 'right', FAST);
    expect(() => unwrapKeyWithPassword(wrapped, 'wrong')).toThrow(DecryptionError);
  });

  it('normalises Unicode so composed and decomposed forms match', () => {
    const key = generateKey();
    const wrapped = wrapKeyWithPassword(key, 'café', FAST);
    expect(unwrapKeyWithPassword(wrapped, 'café')).toEqual(key);
  });

  it('authenticates the stored KDF parameters', () => {
    const wrapped = wrapKeyWithPassword(generateKey(), 'pw', FAST);
    const bad = wrapped.slice();
    bad[5] = 3; // opsLimit 2 → 3: still in bounds, but AD no longer matches
    expect(() => unwrapKeyWithPassword(bad, 'pw')).toThrow(DecryptionError);
  });

  it('refuses out-of-bounds parameters before running Argon2 (DoS / downgrade guard)', () => {
    const wrapped = wrapKeyWithPassword(generateKey(), 'pw', FAST);
    const huge = wrapped.slice();
    new DataView(huge.buffer).setUint32(6, 0xffffffff); // ~4 TiB
    expect(() => unwrapKeyWithPassword(huge, 'pw')).toThrow(FormatError);
    const weak = wrapped.slice();
    new DataView(weak.buffer).setUint32(2, 1); // t = 1
    expect(() => unwrapKeyWithPassword(weak, 'pw')).toThrow(FormatError);
  });

  it('rejects malformed blobs', () => {
    expect(() => unwrapKeyWithPassword(new Uint8Array(10), 'pw')).toThrow(DecryptionError);
  });

  it('requires a 16-byte salt', () => {
    expect(() => deriveKeyFromPassword('pw', utf8Encode('short'), FAST)).toThrow(FormatError);
  });
});
