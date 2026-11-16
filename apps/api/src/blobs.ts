import { randomBytes } from 'node:crypto';
import { mkdir, readFile, readdir, rename, rm, stat, statfs, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Storage for encrypted Drop chunks. Everything stored here is already
 * client-encrypted; the server never has the keys.
 *
 * Layout: <root>/<drop id>/<chunk index>. Ids are validated before they reach
 * this module, and are re-checked here so a path can never escape the root.
 */
export interface BlobStore {
  put(id: string, index: number, data: Uint8Array): Promise<void>;
  get(id: string, index: number): Promise<Buffer>;
  /** Size of a stored chunk, or null if it is missing. */
  size(id: string, index: number): Promise<number | null>;
  /** Remove every chunk of a drop. Idempotent. */
  remove(id: string): Promise<void>;
  /** Ids that currently have any stored data (for orphan cleanup). */
  list(): Promise<string[]>;
  /** Free space for new chunks in bytes, or null if unknown. */
  freeBytes?(): Promise<number | null>;
}

const ID_RE = /^[A-Za-z0-9_-]{22}$/;

function check(id: string, index?: number): void {
  if (!ID_RE.test(id)) throw new Error('invalid blob id');
  if (index !== undefined && (!Number.isInteger(index) || index < 0 || index > 4096)) {
    throw new Error('invalid chunk index');
  }
}

export class DiskBlobStore implements BlobStore {
  constructor(private readonly root: string) {}

  async put(id: string, index: number, data: Uint8Array): Promise<void> {
    check(id, index);
    const dir = join(this.root, id);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    // Write-then-rename: a reader never sees a half-written chunk, and a
    // retried upload of the same chunk simply replaces it.
    const tmp = join(dir, `.${index}.${randomBytes(6).toString('hex')}.tmp`);
    await writeFile(tmp, data, { mode: 0o600 });
    await rename(tmp, join(dir, String(index)));
  }

  async get(id: string, index: number): Promise<Buffer> {
    check(id, index);
    return readFile(join(this.root, id, String(index)));
  }

  async size(id: string, index: number): Promise<number | null> {
    check(id, index);
    try {
      return (await stat(join(this.root, id, String(index)))).size;
    } catch {
      return null;
    }
  }

  async remove(id: string): Promise<void> {
    check(id);
    await rm(join(this.root, id), { recursive: true, force: true });
  }

  async list(): Promise<string[]> {
    try {
      return (await readdir(this.root)).filter((n) => ID_RE.test(n));
    } catch {
      return [];
    }
  }

  async freeBytes(): Promise<number | null> {
    try {
      const s = await statfs(this.root);
      return s.bavail * s.bsize;
    } catch {
      return null;
    }
  }
}
