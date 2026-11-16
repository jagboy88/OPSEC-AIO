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
/**
 * The browser can't run the crypto engine at all, almost always because
 * WebAssembly is disabled (iOS Lockdown Mode, JIT turned off in GrapheneOS /
 * Vanadium, Tor Browser "Safer"/"Safest", hardened Firefox/Brave settings).
 */
export class CryptoUnavailableError extends Error {
  constructor(readonly reason: 'webassembly' | 'failed') {
    super(
      reason === 'webassembly'
        ? 'WebAssembly is disabled in this browser'
        : 'crypto engine failed to start',
    );
    this.name = 'CryptoUnavailableError';
  }
}

export class FormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FormatError';
  }
}
