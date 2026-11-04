/**
 * Known-answer tests against published vectors. These pin the *primitives*
 * (libsodium WASM build + WebCrypto) to their specifications, so a broken or
 * substituted backend fails CI rather than silently producing bad ciphertext.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import {
  blake2b,
  deriveKeyFromPassword,
  fromHex,
  ready,
  sha256,
  sign,
  signingKeyPairFromSeed,
  toHex,
  utf8Encode,
  verify,
  x25519,
  kxPublicKey,
} from '../src/index.js';
import { asBufferSource } from '../src/encoding.js';
import { sodium } from '../src/sodium.js';

beforeAll(ready);

describe('XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03 §A.3.1)', () => {
  const plaintext = utf8Encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  );
  const aad = fromHex('50515253c0c1c2c3c4c5c6c7');
  const key = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
  const nonce = fromHex('404142434445464748494a4b4c4d4e4f5051525354555657');
  const expectedCt =
    'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
    '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
    '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
    '21f9664c97637da9768812f615c68b13b52e';
  const expectedTag = 'c0875924c1c7987947deafd8780acf49';

  it('encrypts to the published ciphertext and tag', () => {
    const out = sodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext,
      aad,
      null,
      nonce,
      key,
    );
    expect(toHex(out)).toBe(expectedCt + expectedTag);
  });

  it('decrypts the published ciphertext', () => {
    const pt = sodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fromHex(expectedCt + expectedTag),
      aad,
      nonce,
      key,
    );
    expect(pt).toEqual(plaintext);
  });
});

describe('AES-256-GCM via WebCrypto (McGrew & Viega GCM spec)', () => {
  async function gcm(key: string, iv: string, pt: string, aad: string): Promise<string> {
    const k = await crypto.subtle.importKey('raw', asBufferSource(fromHex(key)), 'AES-GCM', false, [
      'encrypt',
    ]);
    const ct = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: asBufferSource(fromHex(iv)),
        additionalData: asBufferSource(fromHex(aad)),
      },
      k,
      asBufferSource(fromHex(pt)),
    );
    return toHex(new Uint8Array(ct));
  }

  it('test case 13 (zero key, empty plaintext)', async () => {
    expect(await gcm('00'.repeat(32), '00'.repeat(12), '', '')).toBe(
      '530f8afbc74536b9a963b4f1c4cb738b',
    );
  });

  it('test case 14 (zero key, zero block)', async () => {
    expect(await gcm('00'.repeat(32), '00'.repeat(12), '00'.repeat(16), '')).toBe(
      'cea7403d4d606b6e074ec5d3baf39d18' + 'd0d1c8a799996bf0265b98b5d48ab919',
    );
  });

  it('test case 16 (with AAD)', async () => {
    const out = await gcm(
      'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
      'cafebabefacedbaddecaf888',
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
        '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
      'feedfacedeadbeeffeedfacedeadbeefabaddad2',
    );
    expect(out).toBe(
      '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa' +
        '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662' +
        '76fc6ece0f4e1768cddf8853bb2d551b',
    );
  });
});

describe('Ed25519 (RFC 8032 §7.1)', () => {
  it('TEST 1 (empty message)', () => {
    const kp = signingKeyPairFromSeed(
      fromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
    );
    expect(toHex(kp.publicKey)).toBe(
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    );
    const sig = sign(new Uint8Array(0), kp.privateKey);
    expect(toHex(sig)).toBe(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' +
        '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    );
    expect(verify(sig, new Uint8Array(0), kp.publicKey)).toBe(true);
  });

  it('TEST 2 (one-byte message)', () => {
    const kp = signingKeyPairFromSeed(
      fromHex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'),
    );
    expect(toHex(kp.publicKey)).toBe(
      '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    );
    const msg = fromHex('72');
    const sig = sign(msg, kp.privateKey);
    expect(toHex(sig)).toBe(
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da' +
        '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
    );
    expect(verify(sig, msg, kp.publicKey)).toBe(true);
    expect(verify(sig, fromHex('73'), kp.publicKey)).toBe(false);
  });
});

describe('X25519 (RFC 7748 §6.1)', () => {
  const aliceSk = fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
  const alicePk = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
  const bobSk = fromHex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
  const bobPk = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';
  const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

  it('derives public keys', () => {
    expect(toHex(kxPublicKey(aliceSk))).toBe(alicePk);
    expect(toHex(kxPublicKey(bobSk))).toBe(bobPk);
  });

  it('agrees on the shared secret', () => {
    expect(toHex(x25519(aliceSk, fromHex(bobPk)))).toBe(shared);
    expect(toHex(x25519(bobSk, fromHex(alicePk)))).toBe(shared);
  });

  it('rejects a low-order (all-zero) public key', () => {
    expect(() => x25519(aliceSk, new Uint8Array(32))).toThrow();
  });
});

describe('BLAKE2b (RFC 7693 Appendix A)', () => {
  it('BLAKE2b-512("abc")', () => {
    expect(toHex(blake2b(utf8Encode('abc'), 64))).toBe(
      'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1' +
        '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923',
    );
  });
});

describe('SHA-256 (FIPS 180-2)', () => {
  it('SHA-256("abc")', async () => {
    expect(toHex(await sha256(utf8Encode('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});

describe('Argon2id v1.3', () => {
  // Cross-implementation vectors computed with OpenSSL's Argon2id (python
  // `cryptography` 50), which was first checked against RFC 9106 §5.3.
  it('password / 16-byte salt, t=3, m=8 MiB', () => {
    const out = deriveKeyFromPassword('password', utf8Encode('somesaltsomesalt'), {
      opsLimit: 3,
      memLimitBytes: 8192 * 1024,
    });
    expect(toHex(out)).toBe('02950b5580d9c4909f78967fb3a6bfe9f0839ed64b932b118aba21ec89705b29');
  });

  it('t=2, m=64 MiB', () => {
    const out = deriveKeyFromPassword(
      'correct horse battery staple',
      fromHex('000102030405060708090a0b0c0d0e0f'),
      { opsLimit: 2, memLimitBytes: 64 * 1024 * 1024 },
    );
    expect(toHex(out)).toBe('c05ce4c4dd7e0e45ee6011cc59d068ade47df1b01fc0cf9cd4678bdf68a5b7b0');
  });
});
