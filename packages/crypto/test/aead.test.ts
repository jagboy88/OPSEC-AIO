import { beforeAll, describe, expect, it } from 'vitest';
import {
  Alg,
  DecryptionError,
  concatBytes,
  fromHex,
  generateKey,
  open,
  ready,
  seal,
  sealedLength,
  toHex,
  utf8Encode,
  type AeadAlgorithm,
} from '../src/index.js';
import { sealWithNonce } from '../src/aead.js';
import { sodium } from '../src/sodium.js';

beforeAll(ready);

const KEY = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const PT = utf8Encode('OpSec AIO golden vector');
const AAD = utf8Encode('opsec-aio/test');

describe('envelope format v1 (pinned regression vectors)', () => {
  // If either vector changes, the wire format changed: previously stored data
  // would become undecryptable. Bump FORMAT_VERSION instead of editing these.
  const X_NONCE = fromHex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7');
  const X_ENVELOPE =
    '0101a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70a9c5978d47de5e52e4f4ae61d54c6ae1bdcfa4fde' +
    '69b8a3a608e6c7100f4f64de2e1db1e32e80';
  const G_NONCE = fromHex('c0c1c2c3c4c5c6c7c8c9cacb');
  const G_ENVELOPE =
    '0102c0c1c2c3c4c5c6c7c8c9cacb4f3874021458d717d7f99acd5ec88d386c05865c488d6dde17bef2003bfadd0e14' +
    '52d4806ef30b';

  it('XChaCha20-Poly1305 envelope = header || nonce || AEAD(ad = header || aad)', async () => {
    const env = await sealWithNonce(KEY, PT, X_NONCE, Alg.XCHACHA20_POLY1305, AAD);
    expect(toHex(env)).toBe(X_ENVELOPE);
    const header = new Uint8Array([0x01, Alg.XCHACHA20_POLY1305]);
    const raw = sodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
      PT,
      concatBytes(header, AAD),
      null,
      X_NONCE,
      KEY,
    );
    expect(env).toEqual(concatBytes(header, X_NONCE, raw));
    expect(await open(KEY, fromHex(X_ENVELOPE), { aad: AAD })).toEqual(PT);
  });

  it('AES-256-GCM envelope', async () => {
    const env = await sealWithNonce(KEY, PT, G_NONCE, Alg.AES_256_GCM, AAD);
    expect(toHex(env)).toBe(G_ENVELOPE);
    expect(await open(KEY, fromHex(G_ENVELOPE), { aad: AAD })).toEqual(PT);
  });
});

describe.each<AeadAlgorithm>(['xchacha20poly1305', 'aes256gcm'])(
  'seal/open with %s',
  (algorithm) => {
    it('round-trips, including empty plaintext', async () => {
      const key = generateKey();
      for (const pt of [new Uint8Array(0), PT, new Uint8Array(100_000).fill(7)]) {
        const env = await seal(key, pt, { algorithm });
        expect(env.length).toBe(sealedLength(pt.length, algorithm));
        expect(await open(key, env)).toEqual(pt);
      }
    });

    it('uses a fresh random nonce every time', async () => {
      const key = generateKey();
      const a = await seal(key, PT, { algorithm });
      const b = await seal(key, PT, { algorithm });
      expect(toHex(a)).not.toBe(toHex(b));
    });

    it('rejects any single flipped bit', async () => {
      const key = generateKey();
      const env = await seal(key, PT, { algorithm, aad: AAD });
      for (let i = 0; i < env.length; i++) {
        const bad = env.slice();
        bad[i]! ^= 0x01;
        await expect(open(key, bad, { aad: AAD })).rejects.toBeInstanceOf(DecryptionError);
      }
    });

    it('rejects the wrong key, wrong/missing AAD and truncation', async () => {
      const key = generateKey();
      const env = await seal(key, PT, { algorithm, aad: AAD });
      await expect(open(generateKey(), env, { aad: AAD })).rejects.toBeInstanceOf(DecryptionError);
      await expect(open(key, env)).rejects.toBeInstanceOf(DecryptionError);
      await expect(open(key, env, { aad: utf8Encode('other') })).rejects.toBeInstanceOf(
        DecryptionError,
      );
      for (const len of [0, 1, 2, 10, env.length - 1]) {
        await expect(open(key, env.subarray(0, len), { aad: AAD })).rejects.toBeInstanceOf(
          DecryptionError,
        );
      }
    });
  },
);

describe('header binding', () => {
  it('rejects an unknown format version', async () => {
    const key = generateKey();
    const env = await seal(key, PT);
    env[0] = 0x02;
    await expect(open(key, env)).rejects.toBeInstanceOf(DecryptionError);
  });

  it('rejects an envelope whose algorithm byte was swapped', async () => {
    const key = generateKey();
    const env = await seal(key, PT, { algorithm: 'aes256gcm' });
    env[1] = Alg.XCHACHA20_POLY1305;
    await expect(open(key, env)).rejects.toBeInstanceOf(DecryptionError);
  });

  it('rejects keys of the wrong length', async () => {
    await expect(seal(new Uint8Array(16), PT)).rejects.toThrow(/32 bytes/);
  });
});
