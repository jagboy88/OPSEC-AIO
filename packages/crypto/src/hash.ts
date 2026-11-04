import { asBufferSource } from './encoding.js';
import { FormatError } from './errors.js';
import { sodium } from './sodium.js';

/** BLAKE2b (RFC 7693). Optional key turns it into a MAC / keyed hash. */
export function blake2b(data: Uint8Array, outputLength = 32, key?: Uint8Array): Uint8Array {
  if (outputLength < 16 || outputLength > 64)
    throw new FormatError('BLAKE2b output must be 16–64 bytes');
  if (key && (key.length < 16 || key.length > 64))
    throw new FormatError('BLAKE2b key must be 16–64 bytes');
  return sodium().crypto_generichash(outputLength, data, key ?? null);
}

/** SHA-512 (libsodium, synchronous). */
export function sha512(data: Uint8Array): Uint8Array {
  return sodium().crypto_hash_sha512(data);
}

/** SHA-256 via WebCrypto. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', asBufferSource(data)));
}

/**
 * Hash a bearer token (deletion / upload token) for storage, keyed with a
 * server-side pepper so a database leak alone does not allow offline guessing.
 * Tokens are 256-bit random, so a fast keyed hash is sufficient (no Argon2 needed).
 */
export function hashToken(token: string, pepper: Uint8Array): Uint8Array {
  if (pepper.length < 32) throw new FormatError('pepper must be at least 32 bytes');
  return blake2b(new TextEncoder().encode(token), 32, pepper);
}

/** Constant-time equality. Different lengths return false. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  if (a.length === 0) return true;
  return sodium().memcmp(a, b);
}

/** Best-effort zeroisation of key material (plan §2.3 rule 6). */
export function wipe(...buffers: (Uint8Array | null | undefined)[]): void {
  const s = sodium();
  for (const b of buffers) if (b && b.length) s.memzero(b);
}
