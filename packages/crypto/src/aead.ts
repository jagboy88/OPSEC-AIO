import { asBufferSource, concatBytes } from './encoding.js';
import { DecryptionError, FormatError } from './errors.js';
import { Alg, FORMAT_VERSION, HEADER_LENGTH, KEY_LENGTH } from './format.js';
import { randomBytes } from './random.js';
import { sodium } from './sodium.js';

/**
 * Versioned AEAD envelope.
 *
 *   envelope = version(1) || alg(1) || nonce(24 | 12) || ciphertext || tag(16)
 *   AD       = version || alg || caller-supplied aad
 *
 * Binding the header into the AD means flipping the algorithm byte or the
 * version byte makes decryption fail instead of silently changing semantics.
 */

export type AeadAlgorithm = 'xchacha20poly1305' | 'aes256gcm';

export interface SealOptions {
  /** Defaults to XChaCha20-Poly1305. */
  algorithm?: AeadAlgorithm;
  /** Associated data, e.g. a purpose label. Must be supplied identically to open(). */
  aad?: Uint8Array;
}

export interface OpenOptions {
  aad?: Uint8Array;
}

const XCHACHA_NONCE = 24;
const GCM_NONCE = 12;
export const TAG_LENGTH = 16;

const ALG_BY_NAME = {
  xchacha20poly1305: Alg.XCHACHA20_POLY1305,
  aes256gcm: Alg.AES_256_GCM,
} as const;

function nonceLength(alg: number): number {
  if (alg === Alg.XCHACHA20_POLY1305) return XCHACHA_NONCE;
  if (alg === Alg.AES_256_GCM) return GCM_NONCE;
  throw new FormatError('unsupported algorithm');
}

function assertKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length !== KEY_LENGTH) {
    throw new FormatError('key must be 32 bytes');
  }
}

async function importAesKey(key: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  // Non-extractable: once imported, script cannot read the raw key back out.
  return crypto.subtle.importKey('raw', asBufferSource(key), { name: 'AES-GCM' }, false, [usage]);
}

/** Encrypt `plaintext` under a 32-byte key. Returns a self-describing envelope. */
export async function seal(
  key: Uint8Array,
  plaintext: Uint8Array,
  options: SealOptions = {},
): Promise<Uint8Array> {
  const alg = ALG_BY_NAME[options.algorithm ?? 'xchacha20poly1305'];
  return sealWithNonce(key, plaintext, randomBytes(nonceLength(alg)), alg, options.aad);
}

/**
 * @internal Deterministic-nonce variant used ONLY by known-answer tests.
 * Reusing a nonce with the same key is catastrophic; production code must call {@link seal}.
 */
export async function sealWithNonce(
  key: Uint8Array,
  plaintext: Uint8Array,
  nonce: Uint8Array,
  alg: number,
  aad: Uint8Array | undefined,
): Promise<Uint8Array> {
  assertKey(key);
  if (nonce.length !== nonceLength(alg)) throw new FormatError('bad nonce length');
  const header = new Uint8Array([FORMAT_VERSION, alg]);
  const ad = aad ? concatBytes(header, aad) : header;

  let ct: Uint8Array;
  if (alg === Alg.XCHACHA20_POLY1305) {
    ct = sodium().crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, null, nonce, key);
  } else {
    const k = await importAesKey(key, 'encrypt');
    ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: asBufferSource(nonce), additionalData: asBufferSource(ad) },
        k,
        asBufferSource(plaintext),
      ),
    );
  }
  return concatBytes(header, nonce, ct);
}

/** Decrypt and authenticate an envelope produced by {@link seal}. */
export async function open(
  key: Uint8Array,
  envelope: Uint8Array,
  options: OpenOptions = {},
): Promise<Uint8Array> {
  assertKey(key);
  if (envelope.length < HEADER_LENGTH) throw new DecryptionError();
  const version = envelope[0];
  const alg = envelope[1]!;
  if (version !== FORMAT_VERSION) throw new DecryptionError();
  if (alg !== Alg.XCHACHA20_POLY1305 && alg !== Alg.AES_256_GCM) throw new DecryptionError();

  const nLen = nonceLength(alg);
  if (envelope.length < HEADER_LENGTH + nLen + TAG_LENGTH) throw new DecryptionError();
  const header = envelope.subarray(0, HEADER_LENGTH);
  const nonce = envelope.subarray(HEADER_LENGTH, HEADER_LENGTH + nLen);
  const ct = envelope.subarray(HEADER_LENGTH + nLen);
  const ad = options.aad ? concatBytes(header, options.aad) : header;

  try {
    if (alg === Alg.XCHACHA20_POLY1305) {
      return sodium().crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, ad, nonce, key);
    }
    const k = await importAesKey(key, 'decrypt');
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: asBufferSource(nonce), additionalData: asBufferSource(ad) },
        k,
        asBufferSource(ct),
      ),
    );
  } catch {
    throw new DecryptionError();
  }
}

/** Size of the envelope produced for a plaintext of `plaintextLength` bytes. */
export function sealedLength(
  plaintextLength: number,
  algorithm: AeadAlgorithm = 'xchacha20poly1305',
): number {
  return HEADER_LENGTH + nonceLength(ALG_BY_NAME[algorithm]) + plaintextLength + TAG_LENGTH;
}
