import { open, seal } from './aead.js';
import { concatBytes, utf8Decode, utf8Encode } from './encoding.js';
import { DecryptionError, FormatError } from './errors.js';
import {
  ARGON2ID_DEFAULT,
  WRAPPED_KEY_LENGTH,
  unwrapKeyWithPassword,
  wrapKeyWithPassword,
  type Argon2idParams,
} from './kdf.js';
import { generateKey, randomBytes } from './random.js';
import { sodium } from './sodium.js';

/**
 * Burn note format (docs/PLAN.md §4.3).
 *
 *   stored  = seal(K, inner, aad = "opsec-aio:note:v1")        ← all the server ever sees
 *   inner v2 (written now):
 *             version(1)=0x02 || flags(1) || slot(98) || seal(B, payload, aad = "opsec-aio:note:body:v2")
 *               flags bit 0: password-protected
 *               password:    slot = wrap(C, password), B = C (random content key)
 *               no password: slot = 98 random bytes,  B = K
 *             Both cases have the same length, so the size doesn't reveal
 *             whether a password was used (v1 leaked it).
 *   inner v1 (still read):
 *             version(1)=0x01 || flags(1) || (payload | wrap(C, pw) || seal(C, payload, aad = "opsec-aio:note:pw:v1"))
 *   payload = ISO/IEC 7816-4 pad( kind(1)=0x01 || utf8(text), 1 KiB )
 *
 * K travels only in the link fragment. The password-wrapped key sits *inside*
 * the K envelope, so someone holding the database cannot even start guessing
 * passwords offline without also having the link. Padding to 1 KiB blocks
 * means the server learns only the note's size bucket, not its exact length.
 */

export const NOTE_TEXT_MAX_BYTES = 64 * 1024;
export const NOTE_PADDING_BLOCK = 1024;

const NOTE_V1 = 0x01;
const NOTE_V2 = 0x02;
const FLAG_PASSWORD = 0x01;
const KIND_TEXT = 0x01;
const AAD_OUTER = utf8Encode('opsec-aio:note:v1');
const AAD_PASSWORD = utf8Encode('opsec-aio:note:pw:v1');
const AAD_BODY_V2 = utf8Encode('opsec-aio:note:body:v2');

export interface EncryptNoteOptions {
  /** Optional second factor: the link alone is then not enough to read the note. */
  password?: string;
  /** Argon2id cost for the password wrap. Defaults to {@link ARGON2ID_DEFAULT}. */
  kdfParams?: Argon2idParams;
}

export interface EncryptedNote {
  /** Link key (goes in the URL fragment, never to the server). */
  key: Uint8Array;
  /** Opaque blob to upload. */
  ciphertext: Uint8Array;
}

export type OpenedNote =
  | { locked: false; text: string }
  | {
      locked: true;
      /** Throws {@link DecryptionError} on a wrong password; may be retried. */
      unlock(password: string): Promise<string>;
    };

function encodePayload(text: string): Uint8Array {
  if (text.length === 0) throw new FormatError('note is empty');
  const bytes = utf8Encode(text);
  if (bytes.length > NOTE_TEXT_MAX_BYTES) throw new FormatError('note is too long');
  return sodium().pad(concatBytes(new Uint8Array([KIND_TEXT]), bytes), NOTE_PADDING_BLOCK);
}

function decodePayload(padded: Uint8Array): string {
  let raw: Uint8Array;
  try {
    raw = sodium().unpad(padded, NOTE_PADDING_BLOCK);
  } catch {
    throw new DecryptionError();
  }
  if (raw[0] !== KIND_TEXT) throw new FormatError('unsupported note content — update the app');
  try {
    return utf8Decode(raw.subarray(1));
  } catch {
    throw new DecryptionError();
  }
}

/** Encrypt a note in the browser. Upload `ciphertext`; put `key` in the link. */
export async function encryptNote(
  text: string,
  options: EncryptNoteOptions = {},
): Promise<EncryptedNote> {
  const payload = encodePayload(text);
  const key = generateKey();
  let inner: Uint8Array;
  if (options.password !== undefined) {
    if (options.password.length === 0) throw new FormatError('password is empty');
    const contentKey = generateKey();
    try {
      const wrapped = wrapKeyWithPassword(
        contentKey,
        options.password,
        options.kdfParams ?? ARGON2ID_DEFAULT,
      );
      const body = await seal(contentKey, payload, { aad: AAD_BODY_V2 });
      inner = concatBytes(new Uint8Array([NOTE_V2, FLAG_PASSWORD]), wrapped, body);
    } finally {
      sodium().memzero(contentKey);
    }
  } else {
    const body = await seal(key, payload, { aad: AAD_BODY_V2 });
    inner = concatBytes(new Uint8Array([NOTE_V2, 0]), randomBytes(WRAPPED_KEY_LENGTH), body);
  }
  const ciphertext = await seal(key, inner, { aad: AAD_OUTER });
  return { key, ciphertext };
}

/** Decrypt a note fetched from the server with the key from the link. */
export async function decryptNote(key: Uint8Array, ciphertext: Uint8Array): Promise<OpenedNote> {
  const inner = await open(key, ciphertext, { aad: AAD_OUTER });
  if (inner.length < 2 || (inner[0] !== NOTE_V1 && inner[0] !== NOTE_V2)) {
    throw new FormatError('unsupported note version — update the app');
  }
  const v2 = inner[0] === NOTE_V2;
  const flags = inner[1]!;
  if (flags !== 0 && flags !== FLAG_PASSWORD) {
    throw new FormatError('unsupported note flags — update the app');
  }
  if (flags === 0 && !v2) return { locked: false, text: decodePayload(inner.subarray(2)) };

  const wrapped = inner.slice(2, 2 + WRAPPED_KEY_LENGTH);
  const body = inner.slice(2 + WRAPPED_KEY_LENGTH);
  if (wrapped.length !== WRAPPED_KEY_LENGTH) throw new DecryptionError();
  const bodyAad = v2 ? AAD_BODY_V2 : AAD_PASSWORD;
  if (flags === 0) {
    // v2 without a password: the slot is padding; the body is sealed under K.
    return { locked: false, text: decodePayload(await open(key, body, { aad: bodyAad })) };
  }
  return {
    locked: true,
    async unlock(password: string): Promise<string> {
      const contentKey = unwrapKeyWithPassword(wrapped, password);
      try {
        return decodePayload(await open(contentKey, body, { aad: bodyAad }));
      } finally {
        sodium().memzero(contentKey);
      }
    },
  };
}
