import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  DecryptionError,
  FormatError,
  STREAM_CHUNK_OVERHEAD,
  STREAM_CHUNK_SIZE,
  StreamDecryptor,
  createDrop,
  dropChunkBounds,
  dropLayout,
  fromHex,
  generateKey,
  openDropHeader,
  padChunk,
  padme,
  randomBytes,
  ready,
  type DropHeader,
  type OpenedDrop,
} from '../src/index.js';

await ready();

const FAST = { opsLimit: 2, memLimitBytes: 8 * 1024 * 1024 };

/** Encrypt a whole in-memory file the way the web client does, chunk by chunk. */
async function encryptFile(file: Uint8Array, opts: { password?: string } = {}) {
  const drop = await createDrop(
    { name: 'report.pdf', type: 'application/pdf', size: file.length },
    opts.password ? { password: opts.password, kdfParams: FAST } : {},
  );
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < drop.chunkCount; i++) {
    const b = dropChunkBounds(i, drop);
    const bytes = file.subarray(Math.min(b.start, file.length), Math.min(b.end, file.length));
    chunks.push(drop.encryptor.push(padChunk(bytes, b), i === drop.chunkCount - 1));
  }
  return { drop, chunks };
}

function decryptFile(opened: OpenedDrop, chunks: Uint8Array[]): Uint8Array {
  const dec = new StreamDecryptor(opened.contentKey, opened.streamHeader);
  const out = new Uint8Array(opened.meta.size);
  let written = 0;
  for (const c of chunks) {
    const pt = dec.pull(c);
    const take = Math.min(pt.length, opened.meta.size - written);
    out.set(pt.subarray(0, take), written);
    written += take;
  }
  dec.finish();
  return out;
}

function unlocked(h: DropHeader): OpenedDrop {
  if (h.locked) throw new Error('expected unlocked header');
  return h;
}

describe('padme', () => {
  it('never shrinks, rounds small files to 4 KiB, and keeps overhead under 12%', () => {
    expect(padme(0)).toBe(4096);
    expect(padme(1)).toBe(4096);
    expect(padme(4096)).toBe(4096);
    for (const n of [4097, 10_000, 123_456, 1_000_000, 50_000_000, 2 ** 31 - 1]) {
      const p = padme(n);
      expect(p).toBeGreaterThanOrEqual(n);
      expect((p - n) / n).toBeLessThan(0.12);
    }
  });

  it('maps many sizes onto few buckets (that is the point)', () => {
    const buckets = new Set<number>();
    for (let n = 1_000_000; n < 1_100_000; n += 100) buckets.add(padme(n));
    expect(buckets.size).toBeLessThan(10);
  });

  it('the 2 GiB maximum fits in exactly 2048 chunks', () => {
    expect(padme(2 ** 31)).toBe(2 ** 31);
    expect(dropLayout(2 ** 31).chunkCount).toBe(2048);
  });
});

describe('drop format v1 (pinned vectors)', () => {
  const vectors = JSON.parse(
    readFileSync(new URL('./fixtures/drop-vectors.json', import.meta.url), 'utf8'),
  ) as Record<
    'plain' | 'password',
    {
      linkKey: string;
      headerBlob: string;
      chunks: string[];
      name: string;
      type: string;
      content: string;
      password?: string;
    }
  >;

  for (const kind of ['plain', 'password'] as const) {
    it(`decrypts a ${kind} drop created by an earlier client`, async () => {
      const v = vectors[kind];
      const header = await openDropHeader(fromHex(v.linkKey), fromHex(v.headerBlob));
      const opened = header.locked ? await header.unlock(v.password!) : header;
      expect(opened.meta.name).toBe(v.name);
      expect(opened.meta.type).toBe(v.type);
      const bytes = decryptFile(opened, v.chunks.map(fromHex));
      expect(new TextDecoder().decode(bytes)).toBe(v.content);
    });
  }
});

describe('createDrop / openDropHeader', () => {
  it('round-trips files across chunk boundaries', async () => {
    for (const size of [0, 1, 5000, STREAM_CHUNK_SIZE, 2 * STREAM_CHUNK_SIZE + 7]) {
      const file = randomBytes(size);
      const { drop, chunks } = await encryptFile(file);
      expect(chunks.length).toBe(drop.chunkCount);
      const opened = unlocked(await openDropHeader(drop.linkKey, drop.headerBlob));
      expect(opened.meta).toEqual({ name: 'report.pdf', type: 'application/pdf', size });
      expect(decryptFile(opened, chunks)).toEqual(file);
    }
  });

  it('ciphertext size depends only on the padded bucket', async () => {
    const a = await encryptFile(randomBytes(1_000_000));
    const b = await encryptFile(randomBytes(1_010_000)); // same 16 KiB bucket as 1_000_000
    const total = (c: Uint8Array[]) => c.reduce((n, x) => n + x.length, 0);
    expect(total(a.chunks)).toBe(total(b.chunks));
    expect(total(a.chunks)).toBe(a.drop.paddedSize + a.drop.chunkCount * STREAM_CHUNK_OVERHEAD);
  });

  it('header size does not reveal whether a password is used', async () => {
    const plain = await createDrop({ name: 'a', type: '', size: 1 });
    const locked = await createDrop(
      { name: 'a', type: '', size: 1 },
      { password: 'x', kdfParams: FAST },
    );
    expect(plain.headerBlob.length).toBe(locked.headerBlob.length);
  });

  it('password drops: link alone reveals nothing, wrong passwords can be retried', async () => {
    const file = randomBytes(3000);
    const { drop, chunks } = await encryptFile(file, { password: 'pa55' });
    const header = await openDropHeader(drop.linkKey, drop.headerBlob);
    expect(header.locked).toBe(true);
    if (!header.locked) return;
    await expect(header.unlock('wrong')).rejects.toBeInstanceOf(DecryptionError);
    const opened = await header.unlock('pa55');
    expect(decryptFile(opened, chunks)).toEqual(file);
    // The link key alone cannot decrypt the content.
    expect(() => decryptFile({ ...opened, contentKey: drop.linkKey }, chunks)).toThrow(
      DecryptionError,
    );
  });

  it('sanitises file names (no paths, no control characters, bounded length)', async () => {
    const d = await createDrop({ name: '../../etc/pass\nwd', type: '', size: 0 });
    const opened = unlocked(await openDropHeader(d.linkKey, d.headerBlob));
    expect(opened.meta.name).toBe('passwd');
    const long = await createDrop({ name: 'x'.repeat(1000), type: '', size: 0 });
    expect(unlocked(await openDropHeader(long.linkKey, long.headerBlob)).meta.name.length).toBe(
      255,
    );
  });

  it('rejects the wrong link key, a tampered header and truncated chunks', async () => {
    const { drop, chunks } = await encryptFile(randomBytes(2 * STREAM_CHUNK_SIZE));
    await expect(openDropHeader(generateKey(), drop.headerBlob)).rejects.toBeInstanceOf(
      DecryptionError,
    );
    const bad = drop.headerBlob.slice();
    bad[100]! ^= 1;
    await expect(openDropHeader(drop.linkKey, bad)).rejects.toBeInstanceOf(DecryptionError);
    const opened = unlocked(await openDropHeader(drop.linkKey, drop.headerBlob));
    expect(() => decryptFile(opened, chunks.slice(0, -1))).toThrow(DecryptionError);
  });

  it('rejects invalid sizes and empty passwords', async () => {
    await expect(createDrop({ name: 'a', type: '', size: -1 })).rejects.toBeInstanceOf(FormatError);
    await expect(
      createDrop({ name: 'a', type: '', size: 1 }, { password: '' }),
    ).rejects.toBeInstanceOf(FormatError);
  });

  it('chunk bounds cover the padded file exactly once', () => {
    const layout = dropLayout(3 * STREAM_CHUNK_SIZE + 1);
    let expected = 0;
    for (let i = 0; i < layout.chunkCount; i++) {
      const b = dropChunkBounds(i, layout);
      expect(b.start).toBe(expected);
      expected = b.end;
    }
    expect(expected).toBe(layout.paddedSize);
    expect(() => dropChunkBounds(layout.chunkCount, layout)).toThrow(FormatError);
  });
});
