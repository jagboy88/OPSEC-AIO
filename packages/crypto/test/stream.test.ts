import { describe, expect, it } from 'vitest';
import {
  DecryptionError,
  STREAM_CHUNK_OVERHEAD,
  STREAM_CHUNK_SIZE,
  STREAM_HEADER_LENGTH,
  StreamDecryptor,
  StreamEncryptor,
  generateKey,
  randomBytes,
  ready,
  streamChunkCount,
  streamCiphertextLength,
} from '../src/index.js';

await ready();

function encryptFile(key: Uint8Array, data: Uint8Array) {
  const enc = new StreamEncryptor(key);
  const n = streamChunkCount(data.length);
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    const part = data.subarray(i * STREAM_CHUNK_SIZE, (i + 1) * STREAM_CHUNK_SIZE);
    chunks.push(enc.push(part, i === n - 1));
  }
  return { header: enc.header, chunks };
}

function decryptFile(key: Uint8Array, header: Uint8Array, chunks: Uint8Array[]): Uint8Array {
  const dec = new StreamDecryptor(key, header);
  const parts = chunks.map((c) => dec.pull(c));
  dec.finish();
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

describe('secretstream file encryption', () => {
  it('round-trips files of awkward sizes', () => {
    const key = generateKey();
    for (const size of [
      0,
      1,
      STREAM_CHUNK_SIZE - 1,
      STREAM_CHUNK_SIZE,
      2 * STREAM_CHUNK_SIZE + 123,
    ]) {
      const data = randomBytes(size);
      const { header, chunks } = encryptFile(key, data);
      expect(header.length).toBe(STREAM_HEADER_LENGTH);
      expect(chunks.length).toBe(streamChunkCount(size));
      expect(chunks.reduce((n, c) => n + c.length, 0)).toBe(streamCiphertextLength(size));
      expect(decryptFile(key, header, chunks)).toEqual(data);
    }
  });

  it('adds exactly STREAM_CHUNK_OVERHEAD bytes per chunk', () => {
    const { chunks } = encryptFile(generateKey(), randomBytes(10));
    expect(chunks[0]!.length).toBe(10 + STREAM_CHUNK_OVERHEAD);
  });

  const key = generateKey();
  const data = randomBytes(3 * STREAM_CHUNK_SIZE + 5);
  const { header, chunks } = encryptFile(key, data);

  it('detects truncation (final chunk missing)', () => {
    expect(() => decryptFile(key, header, chunks.slice(0, -1))).toThrow(DecryptionError);
  });

  it('detects reordered chunks', () => {
    const swapped = [chunks[1]!, chunks[0]!, chunks[2]!, chunks[3]!];
    expect(() => decryptFile(key, header, swapped)).toThrow(DecryptionError);
  });

  it('detects a dropped middle chunk', () => {
    expect(() => decryptFile(key, header, [chunks[0]!, chunks[2]!, chunks[3]!])).toThrow(
      DecryptionError,
    );
  });

  it('detects data appended after the final chunk', () => {
    expect(() => decryptFile(key, header, [...chunks, chunks[3]!])).toThrow(DecryptionError);
  });

  it('detects a flipped bit in a chunk', () => {
    const bad = chunks.map((c) => c.slice());
    bad[2]![1000]! ^= 0x80;
    expect(() => decryptFile(key, header, bad)).toThrow(DecryptionError);
  });

  it('rejects the wrong key or a tampered header', () => {
    expect(() => decryptFile(generateKey(), header, chunks)).toThrow(DecryptionError);
    const h = header.slice();
    h[1] = 0x01; // claim a different algorithm
    expect(() => new StreamDecryptor(key, h)).toThrow(DecryptionError);
    const h2 = header.slice();
    h2[10]! ^= 1;
    expect(() => decryptFile(key, h2, chunks)).toThrow(DecryptionError);
  });

  it('refuses short non-final chunks and pushes after finalisation', () => {
    const enc = new StreamEncryptor(generateKey());
    expect(() => enc.push(new Uint8Array(10), false)).toThrow();
    enc.push(new Uint8Array(10), true);
    expect(() => enc.push(new Uint8Array(0), true)).toThrow();
  });
});
