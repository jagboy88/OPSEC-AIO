import { open, seal } from './aead.js';
import { concatBytes, utf8Decode, utf8Encode } from './encoding.js';
import { DecryptionError, FormatError } from './errors.js';
import { KEY_LENGTH } from './format.js';
import {
  ARGON2ID_DEFAULT,
  WRAPPED_KEY_LENGTH,
  unwrapKeyWithPassword,
  wrapKeyWithPassword,
  type Argon2idParams,
} from './kdf.js';
import { generateKey, randomBytes } from './random.js';
import { sodium } from './sodium.js';
import { STREAM_CHUNK_SIZE, STREAM_HEADER_LENGTH, StreamEncryptor } from './stream.js';

/**
 * Drop file format (docs/PLAN.md §4.2).
 *
 *   header_blob = seal(L, inner, aad = "opsec-aio:drop:v1")       ← stored by the server
 *   inner       = version(1)=0x01 || flags(1) || wrapSlot(98) || streamHeader(26) || metaEnvelope
 *                   flags bit 0: password-protected
 *                   wrapSlot: wrap(K, password), or 98 random bytes when there is no password
 *                             (always present, so the blob size does not reveal password use)
 *   metaEnvelope = seal(K, pad(json{v,name,type,size}, 256), aad = "opsec-aio:drop:meta:v1")
 *   chunks      = secretstream(K) over  file bytes || zero padding  up to padme(size)
 *
 * L is the link key (URL fragment). Without a password K = L; with one, K is
 * random and only recoverable with L *and* the password. The server sees the
 * chunk count (a coarse size bucket), never the exact size, name or type.
 */

export const DROP_META_PADDING_BLOCK = 256;
export const DROP_NAME_MAX_LENGTH = 255;

const DROP_VERSION = 0x01;
const FLAG_PASSWORD = 0x01;
const AAD_HEADER = utf8Encode('opsec-aio:drop:v1');
const AAD_META = utf8Encode('opsec-aio:drop:meta:v1');
const INNER_FIXED = 2 + WRAPPED_KEY_LENGTH + STREAM_HEADER_LENGTH;

export interface DropMeta {
  /** Original file name (no path). */
  name: string;
  /** MIME type as reported by the browser; may be empty. */
  type: string;
  /** Exact file size in bytes. */
  size: number;
}

/**
 * PADMÉ padding (Nikitin et al., 2019): rounds a length up so that it leaks
 * only O(log log n) bits, with at most ~12% overhead. Lengths below 4 KiB are
 * rounded up to 4 KiB.
 */
export function padme(length: number): number {
  if (!Number.isSafeInteger(length) || length < 0) throw new FormatError('invalid length');
  const l = Math.max(length, 4096);
  const e = Math.floor(Math.log2(l));
  const s = Math.floor(Math.log2(e)) + 1;
  const unit = 2 ** (e - s);
  return Math.ceil(l / unit) * unit;
}

export interface DropLayout {
  /** Plaintext bytes to stream, including padding. */
  paddedSize: number;
  chunkCount: number;
}

export function dropLayout(size: number): DropLayout {
  const paddedSize = padme(size);
  return { paddedSize, chunkCount: Math.max(1, Math.ceil(paddedSize / STREAM_CHUNK_SIZE)) };
}

export interface CreateDropOptions {
  password?: string;
  kdfParams?: Argon2idParams;
}

export interface NewDrop extends DropLayout {
  /** Goes in the link fragment only. */
  linkKey: Uint8Array;
  /** Upload to the server as-is. */
  headerBlob: Uint8Array;
  /** Encrypts the chunks, in order; the last one with `final = true`. */
  encryptor: StreamEncryptor;
}

function sanitizeName(name: string): string {
  // Strip any path components and control characters; keep it short.
  // eslint-disable-next-line no-control-regex
  const base = (name.split(/[\\/]/).pop() ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return Array.from(base || 'file')
    .slice(0, DROP_NAME_MAX_LENGTH)
    .join('');
}

/** Prepare a new drop for a file. Call `encryptor.push` on each plaintext chunk afterwards. */
export async function createDrop(
  meta: DropMeta,
  options: CreateDropOptions = {},
): Promise<NewDrop> {
  if (!Number.isSafeInteger(meta.size) || meta.size < 0) throw new FormatError('invalid size');
  const s = sodium();
  const linkKey = generateKey();
  let contentKey = linkKey;
  let flags = 0;
  let wrapSlot: Uint8Array;
  if (options.password !== undefined) {
    if (options.password.length === 0) throw new FormatError('password is empty');
    contentKey = generateKey();
    wrapSlot = wrapKeyWithPassword(
      contentKey,
      options.password,
      options.kdfParams ?? ARGON2ID_DEFAULT,
    );
    flags |= FLAG_PASSWORD;
  } else {
    wrapSlot = randomBytes(WRAPPED_KEY_LENGTH);
  }

  const encryptor = new StreamEncryptor(contentKey);
  const metaJson = JSON.stringify({
    v: 1,
    name: sanitizeName(meta.name),
    type: meta.type.slice(0, 255),
    size: meta.size,
  });
  const metaEnvelope = await seal(
    contentKey,
    s.pad(utf8Encode(metaJson), DROP_META_PADDING_BLOCK),
    {
      aad: AAD_META,
    },
  );
  const inner = concatBytes(
    new Uint8Array([DROP_VERSION, flags]),
    wrapSlot,
    encryptor.header,
    metaEnvelope,
  );
  const headerBlob = await seal(linkKey, inner, { aad: AAD_HEADER });
  if (contentKey !== linkKey) s.memzero(contentKey);
  return { linkKey, headerBlob, encryptor, ...dropLayout(meta.size) };
}

export interface OpenedDrop {
  meta: DropMeta;
  /** Key for {@link StreamDecryptor}. Wipe it when done. */
  contentKey: Uint8Array;
  streamHeader: Uint8Array;
  layout: DropLayout;
}

export type DropHeader =
  | ({ locked: false } & OpenedDrop)
  | {
      locked: true;
      /** Throws {@link DecryptionError} on a wrong password; may be retried. */
      unlock(password: string): Promise<OpenedDrop>;
    };

async function readMeta(contentKey: Uint8Array, inner: Uint8Array): Promise<OpenedDrop> {
  const streamHeader = inner.slice(2 + WRAPPED_KEY_LENGTH, INNER_FIXED);
  const padded = await open(contentKey, inner.subarray(INNER_FIXED), { aad: AAD_META });
  let raw: Uint8Array;
  try {
    raw = sodium().unpad(padded, DROP_META_PADDING_BLOCK);
  } catch {
    throw new DecryptionError();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(raw));
  } catch {
    throw new DecryptionError();
  }
  const m = parsed as Partial<DropMeta> & { v?: unknown };
  if (
    m.v !== 1 ||
    typeof m.name !== 'string' ||
    typeof m.type !== 'string' ||
    typeof m.size !== 'number' ||
    !Number.isSafeInteger(m.size) ||
    m.size < 0
  ) {
    throw new FormatError('unsupported file metadata — update the app');
  }
  const meta: DropMeta = { name: sanitizeName(m.name), type: m.type, size: m.size };
  return { meta, contentKey, streamHeader, layout: dropLayout(meta.size) };
}

/** Decrypt a drop's header blob with the link key. */
export async function openDropHeader(
  linkKey: Uint8Array,
  headerBlob: Uint8Array,
): Promise<DropHeader> {
  if (linkKey.length !== KEY_LENGTH) throw new FormatError('key must be 32 bytes');
  const inner = await open(linkKey, headerBlob, { aad: AAD_HEADER });
  if (inner.length <= INNER_FIXED || inner[0] !== DROP_VERSION) {
    throw new FormatError('unsupported file format — update the app');
  }
  const flags = inner[1]!;
  if (flags === 0) {
    return { locked: false, ...(await readMeta(linkKey.slice(), inner)) };
  }
  if (flags !== FLAG_PASSWORD) throw new FormatError('unsupported file format — update the app');
  const wrapped = inner.slice(2, 2 + WRAPPED_KEY_LENGTH);
  return {
    locked: true,
    async unlock(password: string) {
      const contentKey = unwrapKeyWithPassword(wrapped, password);
      return readMeta(contentKey, inner);
    },
  };
}

/**
 * Byte range [start, end) of chunk `index` in the padded plaintext. Bytes at
 * or beyond the real file size are zero padding.
 */
export function dropChunkBounds(index: number, layout: DropLayout): { start: number; end: number } {
  if (!Number.isInteger(index) || index < 0 || index >= layout.chunkCount) {
    throw new FormatError('chunk index out of range');
  }
  const start = index * STREAM_CHUNK_SIZE;
  return { start, end: Math.min(start + STREAM_CHUNK_SIZE, layout.paddedSize) };
}

/**
 * Plaintext for one chunk: `fileBytes` (the file's bytes in this chunk's range,
 * possibly shorter than the range) followed by zero padding.
 */
export function padChunk(
  fileBytes: Uint8Array,
  bounds: { start: number; end: number },
): Uint8Array {
  const length = bounds.end - bounds.start;
  if (fileBytes.length === length) return fileBytes;
  if (fileBytes.length > length) throw new FormatError('chunk overflow');
  const out = new Uint8Array(length);
  out.set(fileBytes);
  return out;
}
