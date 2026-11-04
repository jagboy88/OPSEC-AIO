import { concatBytes } from './encoding.js';
import { DecryptionError, FormatError } from './errors.js';
import { Alg, FORMAT_VERSION, HEADER_LENGTH, KEY_LENGTH } from './format.js';
import { sodium, type Sodium } from './sodium.js';

/**
 * Chunked file encryption (Drop module) built on libsodium's
 * crypto_secretstream_xchacha20poly1305.
 *
 *   streamHeader = version(1) || alg(1) || secretstreamHeader(24)
 *   chunk_i      = secretstream_push(plaintext_i, ad = version || alg)
 *
 * secretstream authenticates chunk order and marks the last chunk with
 * TAG_FINAL, so reordering, dropping, duplicating or truncating chunks is
 * detected. Each chunk adds {@link STREAM_CHUNK_OVERHEAD} bytes.
 */

/** Plaintext bytes per chunk (1 MiB). Only the final chunk may be shorter. */
export const STREAM_CHUNK_SIZE = 1024 * 1024;
export const STREAM_CHUNK_OVERHEAD = 17;
export const STREAM_HEADER_LENGTH = HEADER_LENGTH + 24;

type StreamState = ReturnType<Sodium['crypto_secretstream_xchacha20poly1305_init_pull']>;

const FORMAT_AD = new Uint8Array([FORMAT_VERSION, Alg.SECRETSTREAM_XCHACHA20_POLY1305]);

function assertKey(key: Uint8Array): void {
  if (key.length !== KEY_LENGTH) throw new FormatError('key must be 32 bytes');
}

export class StreamEncryptor {
  /** Must be stored alongside the ciphertext chunks (it is not secret). */
  readonly header: Uint8Array;
  #state: StreamState;
  #finished = false;

  constructor(key: Uint8Array) {
    assertKey(key);
    const s = sodium();
    const init = s.crypto_secretstream_xchacha20poly1305_init_push(key);
    this.#state = init.state;
    this.header = concatBytes(FORMAT_AD, init.header);
  }

  /** Encrypt one chunk. Pass `final = true` for the last chunk (which may be empty). */
  push(chunk: Uint8Array, final: boolean): Uint8Array {
    if (this.#finished) throw new Error('stream already finalised');
    if (chunk.length > STREAM_CHUNK_SIZE) throw new FormatError('chunk too large');
    if (!final && chunk.length !== STREAM_CHUNK_SIZE) {
      throw new FormatError('only the final chunk may be shorter than STREAM_CHUNK_SIZE');
    }
    const s = sodium();
    const tag = final
      ? s.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      : s.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    const out = s.crypto_secretstream_xchacha20poly1305_push(this.#state, chunk, FORMAT_AD, tag);
    if (final) this.#finished = true;
    return out;
  }

  get finished(): boolean {
    return this.#finished;
  }
}

export class StreamDecryptor {
  #state: StreamState;
  #finished = false;

  constructor(key: Uint8Array, header: Uint8Array) {
    assertKey(key);
    if (
      header.length !== STREAM_HEADER_LENGTH ||
      header[0] !== FORMAT_VERSION ||
      header[1] !== Alg.SECRETSTREAM_XCHACHA20_POLY1305
    ) {
      throw new DecryptionError();
    }
    try {
      this.#state = sodium().crypto_secretstream_xchacha20poly1305_init_pull(
        header.subarray(HEADER_LENGTH),
        key,
      );
    } catch {
      throw new DecryptionError();
    }
  }

  /** Decrypt the next chunk. Throws {@link DecryptionError} on any tampering. */
  pull(chunk: Uint8Array): Uint8Array {
    if (this.#finished) throw new DecryptionError(); // data after the FINAL chunk
    if (
      chunk.length < STREAM_CHUNK_OVERHEAD ||
      chunk.length > STREAM_CHUNK_SIZE + STREAM_CHUNK_OVERHEAD
    ) {
      throw new DecryptionError();
    }
    const s = sodium();
    let res: { message: Uint8Array; tag: number } | false;
    try {
      res = s.crypto_secretstream_xchacha20poly1305_pull(this.#state, chunk, FORMAT_AD);
    } catch {
      throw new DecryptionError();
    }
    if (!res) throw new DecryptionError();
    if (res.tag === s.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
      this.#finished = true;
    } else if (res.tag !== s.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) {
      throw new DecryptionError();
    }
    return res.message;
  }

  get finished(): boolean {
    return this.#finished;
  }

  /**
   * Call after the last chunk. Throws if the stream was truncated (no FINAL
   * chunk seen) — without this check an attacker could silently cut a file short.
   */
  finish(): void {
    if (!this.#finished) throw new DecryptionError();
  }
}

/** Number of chunks for a plaintext of `size` bytes (an empty file is one empty final chunk). */
export function streamChunkCount(size: number): number {
  return Math.max(1, Math.ceil(size / STREAM_CHUNK_SIZE));
}

/** Total ciphertext bytes (excluding header) for a plaintext of `size` bytes. */
export function streamCiphertextLength(size: number): number {
  return size + streamChunkCount(size) * STREAM_CHUNK_OVERHEAD;
}
