import { fromBase64Url, toBase64Url } from './encoding.js';
import { KEY_LENGTH } from './format.js';

/** WebCrypto refuses more than 65 536 bytes per getRandomValues call. */
const MAX_GRV = 65_536;

/**
 * Cryptographically secure random bytes from the platform CSPRNG
 * (`crypto.getRandomValues`, the same source libsodium's JS build uses).
 * Called directly because libsodium's WASM wrapper is ~1000× slower for large
 * buffers. Never use Math.random.
 */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) throw new RangeError('invalid length');
  const out = new Uint8Array(length);
  for (let off = 0; off < length; off += MAX_GRV) {
    crypto.getRandomValues(out.subarray(off, Math.min(off + MAX_GRV, length)));
  }
  return out;
}

/** Fresh random 256-bit symmetric key. */
export function generateKey(): Uint8Array {
  return randomBytes(KEY_LENGTH);
}

/** 128-bit random identifier, base64url (22 chars). Used for drop and note ids. */
export function randomId(): string {
  return toBase64Url(randomBytes(16));
}

/** 256-bit random bearer token, base64url (43 chars). Used for deletion/upload tokens. */
export function randomToken(): string {
  return toBase64Url(randomBytes(32));
}

const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

function isCanonical(s: string): boolean {
  try {
    fromBase64Url(s);
    return true;
  } catch {
    return false;
  }
}

export function isValidId(s: unknown): s is string {
  return typeof s === 'string' && ID_RE.test(s) && isCanonical(s);
}

export function isValidToken(s: unknown): s is string {
  return typeof s === 'string' && TOKEN_RE.test(s) && isCanonical(s);
}
