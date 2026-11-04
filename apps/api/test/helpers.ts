import { NOTE_TEXT_MAX_BYTES } from '@opsec-aio/crypto';
import { NOTE_MAX_CIPHERTEXT_BYTES, NOTE_MAX_PLAINTEXT_BYTES } from '@opsec-aio/types';

// The client (crypto package) and server (types package) must agree on the
// note size limit; fail loudly here if they ever drift.
if (NOTE_TEXT_MAX_BYTES !== NOTE_MAX_PLAINTEXT_BYTES) {
  throw new Error('crypto and types disagree on the maximum note size');
}

export const NOTE_TEXT_MAX_BYTES_CHECK = NOTE_TEXT_MAX_BYTES;
export { NOTE_MAX_CIPHERTEXT_BYTES };
