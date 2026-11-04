import { fromBase64Url, toBase64Url } from './encoding.js';
import { sodium } from './sodium.js';
import { KEY_LENGTH } from './format.js';

/** Cryptographically secure random bytes. Never use Math.random. */
export function randomBytes(length: number): Uint8Array {
  return sodium().randombytes_buf(length);
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
