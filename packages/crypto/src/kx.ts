import { FormatError } from './errors.js';
import { sodium } from './sodium.js';

/** X25519 Diffie–Hellman (RFC 7748). */

export interface KxKeyPair {
  publicKey: Uint8Array; // 32 bytes
  privateKey: Uint8Array; // 32 bytes
}

export function generateKxKeyPair(): KxKeyPair {
  const kp = sodium().crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export function kxPublicKey(privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== 32) throw new FormatError('private key must be 32 bytes');
  return sodium().crypto_scalarmult_base(privateKey);
}

/**
 * Raw X25519 shared secret. Throws on low-order public keys (all-zero output).
 * Never use the raw output directly as a key — feed it through a KDF.
 */
export function x25519(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (privateKey.length !== 32 || publicKey.length !== 32) {
    throw new FormatError('X25519 keys must be 32 bytes');
  }
  try {
    return sodium().crypto_scalarmult(privateKey, publicKey);
  } catch {
    throw new FormatError('invalid X25519 public key');
  }
}
