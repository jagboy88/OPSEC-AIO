import { concatBytes, utf8Encode } from './encoding.js';
import { DecryptionError, FormatError } from './errors.js';
import { Alg, FORMAT_VERSION, KEY_LENGTH } from './format.js';
import { randomBytes } from './random.js';
import { sodium } from './sodium.js';

/**
 * Argon2id password-based key derivation and password-wrapping of content keys
 * (optional extra password on Drop / Burn links; local keystore encryption).
 */

export interface Argon2idParams {
  /** Iterations (t). */
  opsLimit: number;
  /** Memory in bytes (m). libsodium always uses parallelism p = 1. */
  memLimitBytes: number;
}

/** Plan §2.1: 64–128 MiB, t = 3, p = 1. */
export const ARGON2ID_DEFAULT: Readonly<Argon2idParams> = Object.freeze({
  opsLimit: 3,
  memLimitBytes: 64 * 1024 * 1024,
});

/**
 * Bounds enforced when *reading* params from a stored blob. The lower bound
 * stops a tampered blob from silently weakening derivation; the upper bound
 * stops it from exhausting memory/CPU on the client.
 */
export const ARGON2ID_BOUNDS = Object.freeze({
  minOpsLimit: 2,
  maxOpsLimit: 10,
  minMemLimitBytes: 8 * 1024 * 1024,
  maxMemLimitBytes: 1024 * 1024 * 1024,
});

export const ARGON2ID_SALT_LENGTH = 16;

function passwordBytes(password: string | Uint8Array): Uint8Array {
  // NFKC so the same visible password typed on different platforms derives the same key.
  return typeof password === 'string' ? utf8Encode(password.normalize('NFKC')) : password;
}

function checkParams(p: Argon2idParams): void {
  const b = ARGON2ID_BOUNDS;
  if (
    !Number.isInteger(p.opsLimit) ||
    !Number.isInteger(p.memLimitBytes) ||
    p.opsLimit < b.minOpsLimit ||
    p.opsLimit > b.maxOpsLimit ||
    p.memLimitBytes < b.minMemLimitBytes ||
    p.memLimitBytes > b.maxMemLimitBytes ||
    p.memLimitBytes % 1024 !== 0
  ) {
    throw new FormatError('Argon2id parameters out of bounds');
  }
}

/** Derive `length` bytes from a password with Argon2id (v1.3). */
export function deriveKeyFromPassword(
  password: string | Uint8Array,
  salt: Uint8Array,
  params: Argon2idParams = ARGON2ID_DEFAULT,
  length: number = KEY_LENGTH,
): Uint8Array {
  if (salt.length !== ARGON2ID_SALT_LENGTH) throw new FormatError('salt must be 16 bytes');
  checkParams(params);
  const s = sodium();
  return s.crypto_pwhash(
    length,
    passwordBytes(password),
    salt,
    params.opsLimit,
    params.memLimitBytes,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
}

/*
 * Wrapped key layout (all integers big-endian):
 *   version(1) || alg=0x10(1) || opsLimit(u32) || memLimitKiB(u32) || salt(16) || nonce(24) || ct(32+16)
 * AD = everything before the nonce, so the KDF parameters are authenticated.
 */
const WRAP_PREFIX_LENGTH = 2 + 4 + 4 + ARGON2ID_SALT_LENGTH;
const WRAP_NONCE_LENGTH = 24;
export const WRAPPED_KEY_LENGTH = WRAP_PREFIX_LENGTH + WRAP_NONCE_LENGTH + KEY_LENGTH + 16;

/** Encrypt a 32-byte content key under a password. */
export function wrapKeyWithPassword(
  key: Uint8Array,
  password: string | Uint8Array,
  params: Argon2idParams = ARGON2ID_DEFAULT,
): Uint8Array {
  if (key.length !== KEY_LENGTH) throw new FormatError('key must be 32 bytes');
  checkParams(params);
  const salt = randomBytes(ARGON2ID_SALT_LENGTH);
  const prefix = new Uint8Array(WRAP_PREFIX_LENGTH);
  const view = new DataView(prefix.buffer);
  prefix[0] = FORMAT_VERSION;
  prefix[1] = Alg.ARGON2ID_XCHACHA20_POLY1305_WRAP;
  view.setUint32(2, params.opsLimit);
  view.setUint32(6, params.memLimitBytes / 1024);
  prefix.set(salt, 10);

  const s = sodium();
  const kek = deriveKeyFromPassword(password, salt, params);
  try {
    const nonce = randomBytes(WRAP_NONCE_LENGTH);
    const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(key, prefix, null, nonce, kek);
    return concatBytes(prefix, nonce, ct);
  } finally {
    s.memzero(kek);
  }
}

/** Recover a content key wrapped by {@link wrapKeyWithPassword}. */
export function unwrapKeyWithPassword(
  wrapped: Uint8Array,
  password: string | Uint8Array,
): Uint8Array {
  if (
    wrapped.length !== WRAPPED_KEY_LENGTH ||
    wrapped[0] !== FORMAT_VERSION ||
    wrapped[1] !== Alg.ARGON2ID_XCHACHA20_POLY1305_WRAP
  ) {
    throw new DecryptionError();
  }
  const view = new DataView(wrapped.buffer, wrapped.byteOffset, wrapped.byteLength);
  const params: Argon2idParams = {
    opsLimit: view.getUint32(2),
    memLimitBytes: view.getUint32(6) * 1024,
  };
  checkParams(params); // throws FormatError before spending any CPU/memory
  const prefix = wrapped.subarray(0, WRAP_PREFIX_LENGTH);
  const salt = wrapped.subarray(10, WRAP_PREFIX_LENGTH);
  const nonce = wrapped.subarray(WRAP_PREFIX_LENGTH, WRAP_PREFIX_LENGTH + WRAP_NONCE_LENGTH);
  const ct = wrapped.subarray(WRAP_PREFIX_LENGTH + WRAP_NONCE_LENGTH);

  const s = sodium();
  const kek = deriveKeyFromPassword(password, salt, params);
  try {
    return s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, prefix, nonce, kek);
  } catch {
    throw new DecryptionError();
  } finally {
    s.memzero(kek);
  }
}
