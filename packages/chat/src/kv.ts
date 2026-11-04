import {
  ARGON2ID_DEFAULT,
  blake2b,
  generateKey,
  open,
  seal,
  toBase64Url,
  unwrapKeyWithPassword,
  utf8Decode,
  utf8Encode,
  wipe,
  wrapKeyWithPassword,
  type Argon2idParams,
} from '@opsec-aio/crypto';

/** Minimal async key–value store (IndexedDB in browsers, memory in tests). */
export interface KV {
  get(key: string): Promise<Uint8Array | undefined>;
  set(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  /** Remove everything (account deletion / "forget this device"). */
  clear(): Promise<void>;
}

export class MemoryKV implements KV {
  readonly map = new Map<string, Uint8Array>();
  async get(key: string) {
    return this.map.get(key);
  }
  async set(key: string, value: Uint8Array) {
    this.map.set(key, value.slice());
  }
  async delete(key: string) {
    this.map.delete(key);
  }
  async clear() {
    this.map.clear();
  }
}

const VAULT_KEY = 'vault';

/**
 * Encrypted view over a KV (plan §2.3 rule 2). Both record names and values
 * are protected: the physical key is a keyed BLAKE2b hash of the logical name
 * (so contact usernames don't appear on disk), and the value is sealed with
 * XChaCha20-Poly1305 bound to that physical key (so records can't be swapped).
 */
export class EncryptedKV {
  private constructor(
    private readonly inner: KV,
    private readonly nameKey: Uint8Array,
    private readonly dataKey: Uint8Array,
  ) {}

  static fromMasterKey(inner: KV, masterKey: Uint8Array): EncryptedKV {
    return new EncryptedKV(
      inner,
      blake2b(utf8Encode('opsec-aio:kv:name:v1'), 32, masterKey),
      blake2b(utf8Encode('opsec-aio:kv:data:v1'), 32, masterKey),
    );
  }

  private physical(name: string): string {
    return 'e:' + toBase64Url(blake2b(utf8Encode(name), 16, this.nameKey));
  }

  async get(name: string): Promise<Uint8Array | undefined> {
    const key = this.physical(name);
    const sealed = await this.inner.get(key);
    return sealed ? open(this.dataKey, sealed, { aad: utf8Encode(key) }) : undefined;
  }

  async set(name: string, value: Uint8Array): Promise<void> {
    const key = this.physical(name);
    await this.inner.set(key, await seal(this.dataKey, value, { aad: utf8Encode(key) }));
  }

  async delete(name: string): Promise<void> {
    await this.inner.delete(this.physical(name));
  }

  async getJSON<T>(name: string): Promise<T | undefined> {
    const v = await this.get(name);
    return v ? (JSON.parse(utf8Decode(v)) as T) : undefined;
  }

  async setJSON(name: string, value: unknown): Promise<void> {
    await this.set(name, utf8Encode(JSON.stringify(value)));
  }

  /** Wipe the device: every record, including the passphrase-wrapped master key. */
  async destroy(): Promise<void> {
    await this.inner.clear();
    this.lock();
  }

  /** Forget the in-memory keys (the store becomes unusable). */
  lock(): void {
    wipe(this.nameKey, this.dataKey);
  }
}

export async function hasVault(inner: KV): Promise<boolean> {
  return (await inner.get(VAULT_KEY)) !== undefined;
}

/**
 * Create a new vault: a random master key, wrapped under the passphrase with
 * Argon2id. Changing the passphrase later only rewraps this one key.
 */
export async function createVault(
  inner: KV,
  passphrase: string,
  kdf: Argon2idParams = ARGON2ID_DEFAULT,
): Promise<EncryptedKV> {
  if (await hasVault(inner)) throw new Error('a vault already exists on this device');
  const master = generateKey();
  try {
    await inner.set(VAULT_KEY, wrapKeyWithPassword(master, passphrase, kdf));
    return EncryptedKV.fromMasterKey(inner, master);
  } finally {
    wipe(master);
  }
}

/** Unlock with the passphrase. Throws DecryptionError on a wrong passphrase. */
export async function unlockVault(inner: KV, passphrase: string): Promise<EncryptedKV> {
  const wrapped = await inner.get(VAULT_KEY);
  if (!wrapped) throw new Error('no vault on this device');
  const master = unwrapKeyWithPassword(wrapped, passphrase);
  try {
    return EncryptedKV.fromMasterKey(inner, master);
  } finally {
    wipe(master);
  }
}

/** Raw wrapped master key + all records, for moving an account to another device. */
export const VAULT_RECORD = VAULT_KEY;
