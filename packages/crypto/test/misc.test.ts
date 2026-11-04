import { describe, expect, it } from 'vitest';
import {
  buildShareLink,
  constantTimeEqual,
  fromBase64Url,
  generateKey,
  generateSigningKeyPair,
  hashToken,
  isValidId,
  isValidToken,
  keyFromFragment,
  randomBytes,
  randomId,
  randomToken,
  ready,
  sign,
  toBase64Url,
  utf8Decode,
  utf8Encode,
  verify,
  wipe,
} from '../src/index.js';

await ready();

describe('base64url', () => {
  it('matches RFC 4648 test vectors (no padding)', () => {
    const vectors: [string, string][] = [
      ['', ''],
      ['f', 'Zg'],
      ['fo', 'Zm8'],
      ['foo', 'Zm9v'],
      ['foob', 'Zm9vYg'],
      ['fooba', 'Zm9vYmE'],
      ['foobar', 'Zm9vYmFy'],
    ];
    for (const [plain, enc] of vectors) {
      expect(toBase64Url(utf8Encode(plain))).toBe(enc);
      expect(utf8Decode(fromBase64Url(enc))).toBe(plain);
    }
    expect(toBase64Url(new Uint8Array([0xfb, 0xff]))).toBe('-_8');
  });

  it('rejects padding, standard alphabet, whitespace and non-canonical input', () => {
    for (const bad of ['Zg==', '+/8', 'Zm 9v', 'Z', 'Zh']) {
      expect(() => fromBase64Url(bad)).toThrow();
    }
  });
});

describe('ids and tokens', () => {
  it('ids are 128-bit, 22 chars, and unique', () => {
    const ids = new Set(Array.from({ length: 1000 }, randomId));
    expect(ids.size).toBe(1000);
    for (const id of ids) expect(isValidId(id)).toBe(true);
    expect(fromBase64Url(randomId()).length).toBe(16);
  });

  it('validates shape strictly', () => {
    expect(isValidId('../../etc/passwd')).toBe(false);
    expect(isValidId('AAAAAAAAAAAAAAAAAAAAAB')).toBe(false); // non-canonical trailing bits
    expect(isValidId(42)).toBe(false);
    expect(isValidToken(randomToken())).toBe(true);
    expect(isValidToken(randomId())).toBe(false);
  });
});

describe('share links', () => {
  it('puts the key only in the fragment', () => {
    const key = generateKey();
    const id = randomId();
    const link = buildShareLink('https://opsec.example/', 'n', id, key);
    const url = new URL(link);
    expect(url.pathname).toBe(`/n/${id}`);
    expect(url.search).toBe('');
    expect(keyFromFragment(url.hash)).toEqual(key);
  });

  it('rejects fragments that are not a 32-byte key', () => {
    expect(() => keyFromFragment('#abc')).toThrow();
    expect(() => keyFromFragment(toBase64Url(randomBytes(31)))).toThrow();
  });
});

describe('signatures', () => {
  it('verify() returns false rather than throwing on garbage', () => {
    const kp = generateSigningKeyPair();
    const msg = utf8Encode('challenge');
    const sig = sign(msg, kp.privateKey);
    expect(verify(sig, msg, kp.publicKey)).toBe(true);
    expect(verify(sig, msg, generateSigningKeyPair().publicKey)).toBe(false);
    expect(verify(sig.subarray(1), msg, kp.publicKey)).toBe(false);
    expect(verify(new Uint8Array(64), msg, new Uint8Array(32))).toBe(false);
  });
});

describe('token hashing and comparison', () => {
  const pepper = randomBytes(32);

  it('is deterministic per pepper and differs across peppers', () => {
    const t = randomToken();
    expect(hashToken(t, pepper)).toEqual(hashToken(t, pepper));
    expect(constantTimeEqual(hashToken(t, pepper), hashToken(t, randomBytes(32)))).toBe(false);
  });

  it('refuses a short pepper', () => {
    expect(() => hashToken('x', randomBytes(8))).toThrow();
  });

  it('constantTimeEqual handles lengths', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });

  it('wipe zeroes buffers', () => {
    const k = generateKey();
    wipe(k, null, undefined);
    expect(k.every((b) => b === 0)).toBe(true);
  });
});
