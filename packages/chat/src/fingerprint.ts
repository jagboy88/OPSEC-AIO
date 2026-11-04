import { concatBytes, sha512 } from '@opsec-aio/crypto';

const VERSION = new Uint8Array([0, 0]);

function displayString(identifier: string, key: Uint8Array, iterations: number): string {
  // Identifiers are usernames ([a-z0-9_]): one byte per character.
  const id = Uint8Array.from(identifier, (c) => c.charCodeAt(0) & 0xff);
  let hash = sha512(concatBytes(VERSION, key, id, key));
  for (let i = 1; i < iterations; i++) hash = sha512(concatBytes(hash, key));
  let out = '';
  for (let offset = 0; offset < 30; offset += 5) {
    const chunk =
      (hash[offset]! * 2 ** 32 +
        hash[offset + 1]! * 2 ** 24 +
        hash[offset + 2]! * 2 ** 16 +
        hash[offset + 3]! * 2 ** 8 +
        hash[offset + 4]!) %
      100000;
    out += String(chunk).padStart(5, '0');
  }
  return out;
}

/**
 * Signal's numeric safety number (v0), byte-for-byte compatible with the
 * library's FingerprintGenerator, but computed with native-speed SHA-512
 * (the library's pure-JS fallback takes many seconds in a browser).
 */
export function safetyNumber(
  localId: string,
  localKey: Uint8Array,
  remoteId: string,
  remoteKey: Uint8Array,
  iterations = 5200,
): string {
  return [
    displayString(localId, localKey, iterations),
    displayString(remoteId, remoteKey, iterations),
  ]
    .sort()
    .join('');
}
