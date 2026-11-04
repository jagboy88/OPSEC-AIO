import {
  StreamDecryptor,
  createDrop,
  dropChunkBounds,
  fromBase64Url,
  openDropHeader,
  padChunk,
  parseFragment,
  ready,
  toBase64Url,
  wipe,
  type OpenedDrop,
} from '@opsec-aio/crypto';
import { api, withRetry } from './api.js';

export interface UploadOptions {
  expiresIn: number;
  maxDownloads: number | null;
  password?: string;
  signal?: AbortSignal;
  onProgress?: (doneBytes: number, totalBytes: number) => void;
  /** Called once the server has allocated the drop, so the caller can abort it. */
  onStarted?: (id: string, uploadToken: string) => void;
}

export interface UploadResult {
  id: string;
  linkKey: Uint8Array;
  deletionToken: string;
  expiresAt: string;
}

const MAX_IN_FLIGHT = 3;

/**
 * Encrypt and upload a file chunk by chunk. Chunks are encrypted strictly in
 * order (secretstream is sequential) while up to three encrypted chunks upload
 * in parallel. Plaintext never leaves this function unencrypted.
 */
export async function uploadFile(file: File, opts: UploadOptions): Promise<UploadResult> {
  await ready();
  const drop = await createDrop(
    { name: file.name, type: file.type, size: file.size },
    opts.password ? { password: opts.password } : {},
  );
  const init = await api.initDrop({
    chunk_count: drop.chunkCount,
    expires_in: opts.expiresIn,
    max_downloads: opts.maxDownloads,
    header_blob: toBase64Url(drop.headerBlob),
  });
  opts.onStarted?.(init.drop_id, init.upload_token);

  const total = drop.paddedSize;
  let done = 0;
  const inFlight = new Set<Promise<void>>();
  for (let i = 0; i < drop.chunkCount; i++) {
    opts.signal?.throwIfAborted();
    const bounds = dropChunkBounds(i, drop);
    const fileEnd = Math.min(bounds.end, file.size);
    const plain =
      bounds.start < file.size
        ? new Uint8Array(await file.slice(bounds.start, fileEnd).arrayBuffer())
        : new Uint8Array(0);
    const sealed = drop.encryptor.push(padChunk(plain, bounds), i === drop.chunkCount - 1);
    wipe(plain);

    const index = i;
    const p: Promise<void> = withRetry(() =>
      api.putChunk(init.drop_id, index, sealed, init.upload_token, opts.signal),
    ).then(() => {
      done += bounds.end - bounds.start;
      opts.onProgress?.(done, total);
    });
    inFlight.add(p);
    void p.finally(() => inFlight.delete(p)).catch(() => {});
    if (inFlight.size >= MAX_IN_FLIGHT) await Promise.race(inFlight);
  }
  await Promise.all(inFlight);
  const fin = await withRetry(() => api.finalizeDrop(init.drop_id, init.upload_token));
  return {
    id: init.drop_id,
    linkKey: drop.linkKey,
    deletionToken: fin.deletion_token,
    expiresAt: fin.expires_at,
  };
}

/** Where decrypted bytes go. */
export interface FileSink {
  write(chunk: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(): Promise<void>;
}

/** Above this size, prefer streaming straight to disk where the browser allows it. */
export const STREAM_TO_DISK_THRESHOLD = 256 * 1024 * 1024;
/** Above this size, warn that an in-memory download may fail on low-memory devices. */
export const MEMORY_WARNING_THRESHOLD = 512 * 1024 * 1024;

interface SaveFilePickerWindow {
  showSaveFilePicker?: (opts: { suggestedName?: string }) => Promise<{
    createWritable(): Promise<{
      write(data: Uint8Array): Promise<void>;
      close(): Promise<void>;
      abort(): Promise<void>;
    }>;
  }>;
}

export function canStreamToDisk(): boolean {
  return typeof (window as SaveFilePickerWindow).showSaveFilePicker === 'function';
}

/**
 * File System Access API sink (desktop Chromium): writes straight to disk, so
 * a 2 GB file never has to fit in memory. Must be called from a click handler.
 */
export async function diskSink(name: string): Promise<FileSink> {
  const handle = await (window as SaveFilePickerWindow).showSaveFilePicker!({
    suggestedName: name,
  });
  const w = await handle.createWritable();
  return { write: (c) => w.write(c), close: () => w.close(), abort: () => w.abort() };
}

/** In-memory sink: assembles a Blob and triggers a normal browser download. */
export function memorySink(name: string, type: string): FileSink {
  let parts: BlobPart[] = [];
  return {
    async write(c) {
      parts.push(c as Uint8Array<ArrayBuffer>);
    },
    async close() {
      const url = URL.createObjectURL(
        new Blob(parts, { type: type || 'application/octet-stream' }),
      );
      parts = [];
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      a.rel = 'noopener';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    },
    async abort() {
      parts = [];
    },
  };
}

/**
 * Fetch, decrypt and write every chunk. Strips the PADMÉ padding and refuses
 * truncated or tampered streams. Returns the server's remaining-download count.
 */
export async function downloadDrop(
  id: string,
  opened: OpenedDrop,
  sink: FileSink,
  onProgress?: (doneBytes: number, totalBytes: number) => void,
): Promise<number | null> {
  const { download_token: token, downloads_remaining } = await api.startDownload(id);
  const { chunkCount } = opened.layout;
  const dec = new StreamDecryptor(opened.contentKey, opened.streamHeader);
  const size = opened.meta.size;
  let written = 0;
  try {
    // Keep one chunk in flight while decrypting the previous one.
    let next = withRetry(() => api.getChunk(id, 0, token));
    for (let i = 0; i < chunkCount; i++) {
      const sealed = await next;
      if (i + 1 < chunkCount) {
        const n = i + 1;
        next = withRetry(() => api.getChunk(id, n, token));
      }
      const plain = dec.pull(sealed);
      const take = Math.min(plain.length, size - written);
      if (take > 0) await sink.write(plain.subarray(0, take));
      written += take;
      onProgress?.(written, size);
    }
    dec.finish();
    if (written !== size) throw new Error('size mismatch');
    await sink.close();
    return downloads_remaining;
  } catch (e) {
    await sink.abort().catch(() => {});
    throw e;
  } finally {
    wipe(opened.contentKey);
  }
}

// ── Chat attachments (plan §4.1: "attachments inside chat reuse the Drop module") ──

export interface AttachmentRef {
  drop: string;
  /** Drop link fragment (key). Travels only inside the E2EE chat message. */
  key: string;
  name: string;
  size: number;
  type: string;
}

/** Encrypt and upload a file as a 24-hour Drop; returns what the chat message carries. */
export async function uploadAttachment(
  file: File,
  onProgress?: (done: number, total: number) => void,
): Promise<AttachmentRef> {
  const res = await uploadFile(file, {
    expiresIn: 24 * 3600,
    maxDownloads: null,
    ...(onProgress ? { onProgress } : {}),
  });
  const key = toBase64Url(res.linkKey);
  wipe(res.linkKey);
  return { drop: res.id, key, name: file.name, size: file.size, type: file.type };
}

/** Fetch, decrypt and save an attachment. Must be called from a click handler. */
export async function downloadAttachment(
  ref: AttachmentRef,
  onProgress?: (done: number, total: number) => void,
): Promise<void> {
  await ready();
  const meta = await api.dropMeta(ref.drop);
  const header = await openDropHeader(parseFragment(ref.key).key, fromBase64Url(meta.header_blob));
  if (header.locked) throw new Error('attachment unexpectedly password-protected');
  const sink =
    header.meta.size > STREAM_TO_DISK_THRESHOLD && canStreamToDisk()
      ? await diskSink(header.meta.name)
      : memorySink(header.meta.name, header.meta.type);
  await downloadDrop(ref.drop, header, sink, onProgress);
}
