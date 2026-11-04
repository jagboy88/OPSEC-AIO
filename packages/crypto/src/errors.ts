/**
 * Thrown for any failure to authenticate or decrypt. The message is
 * deliberately generic: callers (and attackers) learn nothing about *why*
 * decryption failed (wrong key vs. tampered data vs. truncated input).
 */
export class DecryptionError extends Error {
  constructor() {
    super('decryption failed');
    this.name = 'DecryptionError';
  }
}

/** Thrown when an input has the wrong shape (length, version, encoding). */
export class FormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FormatError';
  }
}
