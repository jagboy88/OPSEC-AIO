/**
 * Wire-format identifiers. Every ciphertext produced by this package starts
 * with a 2-byte header: [FORMAT_VERSION, algorithm id]. The header is always
 * bound into the AEAD associated data, so it cannot be altered (e.g. to
 * downgrade the algorithm) without decryption failing.
 *
 * NEVER renumber existing values — only append. Data encrypted today must stay
 * decryptable after algorithms are rotated.
 */
export const FORMAT_VERSION = 0x01;

export const Alg = {
  /** XChaCha20-Poly1305 (IETF), 24-byte random nonce. Default. */
  XCHACHA20_POLY1305: 0x01,
  /** AES-256-GCM via WebCrypto, 12-byte random nonce. */
  AES_256_GCM: 0x02,
  /** libsodium secretstream (XChaCha20-Poly1305), chunked files. */
  SECRETSTREAM_XCHACHA20_POLY1305: 0x03,
  /** Content key wrapped under an Argon2id password-derived key (XChaCha20-Poly1305). */
  ARGON2ID_XCHACHA20_POLY1305_WRAP: 0x10,
} as const;

export type AlgId = (typeof Alg)[keyof typeof Alg];

export const HEADER_LENGTH = 2;
export const KEY_LENGTH = 32;
