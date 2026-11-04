import type { KV } from '@opsec-aio/chat';

const DB_NAME = 'opsec-aio-chat';
const STORE = 'kv';

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

/**
 * IndexedDB-backed KV. It only ever holds the passphrase-wrapped master key
 * and records sealed by EncryptedKV (plan §2.3: "keys that must persist are
 * stored in IndexedDB, encrypted"; nothing in localStorage).
 */
export class IndexedDbKV implements KV {
  private constructor(private readonly db: IDBDatabase) {}

  static async open(): Promise<IndexedDbKV> {
    const r = indexedDB.open(DB_NAME, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    return new IndexedDbKV(await req(r));
  }

  private store(mode: IDBTransactionMode) {
    return this.db.transaction(STORE, mode).objectStore(STORE);
  }

  async get(key: string): Promise<Uint8Array | undefined> {
    const v = await req(this.store('readonly').get(key));
    return v instanceof Uint8Array ? v : undefined;
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    await req(this.store('readwrite').put(value, key));
  }

  async delete(key: string): Promise<void> {
    await req(this.store('readwrite').delete(key));
  }

  async clear(): Promise<void> {
    await req(this.store('readwrite').clear());
  }

  /** Every raw (already encrypted) record, for moving the account to another device. */
  async exportAll(): Promise<[string, Uint8Array][]> {
    const s = this.store('readonly');
    const [keys, values] = await Promise.all([req(s.getAllKeys()), req(s.getAll())]);
    return keys.map((k, i) => [String(k), values[i] as Uint8Array]);
  }

  async importAll(entries: [string, Uint8Array][]): Promise<void> {
    await this.clear();
    for (const [k, v] of entries) await this.set(k, v);
  }
}
