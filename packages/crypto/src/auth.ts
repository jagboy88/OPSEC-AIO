import { concatBytes, utf8Encode } from './encoding.js';

const AUTH_CONTEXT = utf8Encode('opsec-aio:auth:v1');

/**
 * The exact bytes a client signs (Ed25519, `auth` key) to log in:
 *   "opsec-aio:auth:v1" || 0x00 || utf8(username) || 0x00 || nonce
 * The context label stops the signature being valid for anything else; the
 * username binds it to one account; the server-issued, single-use nonce stops
 * replay.
 */
export function authChallengeMessage(username: string, nonce: Uint8Array): Uint8Array {
  return concatBytes(
    AUTH_CONTEXT,
    new Uint8Array([0]),
    utf8Encode(username),
    new Uint8Array([0]),
    nonce,
  );
}
