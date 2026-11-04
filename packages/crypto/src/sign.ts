import { FormatError } from './errors.js';
import { sodium } from './sodium.js';

/** Ed25519 identity keys and signatures (RFC 8032). */

export interface SigningKeyPair {
  publicKey: Uint8Array; // 32 bytes
  /** 64 bytes (libsodium format: seed || publicKey). Keep encrypted at rest. */
  privateKey: Uint8Array;
}

export function generateSigningKeyPair(): SigningKeyPair {
  const kp = sodium().crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/** Deterministic key pair from a 32-byte seed. */
export function signingKeyPairFromSeed(seed: Uint8Array): SigningKeyPair {
  if (seed.length !== 32) throw new FormatError('seed must be 32 bytes');
  const kp = sodium().crypto_sign_seed_keypair(seed);
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export function sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== 64) throw new FormatError('private key must be 64 bytes');
  return sodium().crypto_sign_detached(message, privateKey);
}

/** Returns false (never throws) for any invalid signature, key or length. */
export function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  try {
    return sodium().crypto_sign_verify_detached(signature, message, publicKey);
  } catch {
    return false;
  }
}
