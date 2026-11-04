import { open, seal } from './aead.js';
import { fromHex, toHex, utf8Encode } from './encoding.js';
import { blake2b, sha256 } from './hash.js';
import { deriveKeyFromPassword } from './kdf.js';
import { kxPublicKey, x25519 } from './kx.js';
import { decryptNote, encryptNote } from './note.js';
import { generateKey } from './random.js';
import { sign, signingKeyPairFromSeed, verify } from './sign.js';
import { ready } from './sodium.js';
import { STREAM_CHUNK_SIZE, StreamDecryptor, StreamEncryptor } from './stream.js';

export interface SelfTestResult {
  name: string;
  ok: boolean;
}

/**
 * Known-answer self-test, run in the user's browser before any secret is
 * handled. It proves the WASM backend and WebCrypto loaded and behave per
 * spec on *this* device — a cheap guard against broken builds or engines.
 * Uses only the public API.
 */
export async function runSelfTest(): Promise<SelfTestResult[]> {
  await ready();
  const results: SelfTestResult[] = [];
  const check = async (name: string, fn: () => boolean | Promise<boolean>) => {
    const ok = await Promise.resolve()
      .then(fn)
      .catch(() => false);
    results.push({ name, ok });
  };

  const key = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const pt = utf8Encode('OpSec AIO golden vector');
  const aad = utf8Encode('opsec-aio/test');

  await check('XChaCha20-Poly1305 envelope (pinned vector)', async () => {
    const env = fromHex(
      '0101a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b70a9c5978d47de5e52e4f4ae61d54c6ae1bdcfa4fde' +
        '69b8a3a608e6c7100f4f64de2e1db1e32e80',
    );
    return toHex(await open(key, env, { aad })) === toHex(pt);
  });

  await check('AES-256-GCM envelope (pinned vector)', async () => {
    const env = fromHex(
      '0102c0c1c2c3c4c5c6c7c8c9cacb4f3874021458d717d7f99acd5ec88d386c05865c488d6dde17bef2003bfadd0e14' +
        '52d4806ef30b',
    );
    return toHex(await open(key, env, { aad })) === toHex(pt);
  });

  await check('AEAD round-trip and tamper rejection', async () => {
    const k = generateKey();
    const env = await seal(k, pt);
    if (toHex(await open(k, env)) !== toHex(pt)) return false;
    env[env.length - 1]! ^= 1;
    try {
      await open(k, env);
      return false;
    } catch {
      return true;
    }
  });

  await check('Ed25519 (RFC 8032 test 1)', () => {
    const kp = signingKeyPairFromSeed(
      fromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
    );
    const sig = sign(new Uint8Array(0), kp.privateKey);
    return (
      toHex(sig) ===
        'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b' &&
      verify(sig, new Uint8Array(0), kp.publicKey)
    );
  });

  await check('X25519 (RFC 7748 §6.1)', () => {
    const a = fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const b = fromHex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
    return (
      toHex(x25519(a, kxPublicKey(b))) ===
      '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'
    );
  });

  await check('BLAKE2b-512 (RFC 7693)', () =>
    toHex(blake2b(utf8Encode('abc'), 64)).startsWith('ba80a53f981c4d0d6a2797b69f12f6e9'),
  );

  await check('SHA-256 (FIPS 180-2)', async () =>
    toHex(await sha256(utf8Encode('abc'))).startsWith('ba7816bf8f01cfea414140de5dae2223'),
  );

  await check(
    'Argon2id v1.3 (8 MiB vector)',
    () =>
      toHex(
        deriveKeyFromPassword('password', utf8Encode('somesaltsomesalt'), {
          opsLimit: 3,
          memLimitBytes: 8 * 1024 * 1024,
        }),
      ) === '02950b5580d9c4909f78967fb3a6bfe9f0839ed64b932b118aba21ec89705b29',
  );

  await check('File stream round-trip and truncation detection', () => {
    const k = generateKey();
    const enc = new StreamEncryptor(k);
    const c1 = enc.push(new Uint8Array(STREAM_CHUNK_SIZE).fill(1), false);
    const c2 = enc.push(utf8Encode('tail'), true);
    const dec = new StreamDecryptor(k, enc.header);
    dec.pull(c1);
    try {
      dec.finish(); // must refuse: final chunk not seen yet
      return false;
    } catch {
      /* expected */
    }
    const tail = dec.pull(c2);
    dec.finish();
    return toHex(tail) === toHex(utf8Encode('tail'));
  });

  await check('Burn note round-trip', async () => {
    const { key, ciphertext } = await encryptNote('self-test ✓');
    const n = await decryptNote(key, ciphertext);
    return !n.locked && n.text === 'self-test ✓';
  });

  return results;
}
