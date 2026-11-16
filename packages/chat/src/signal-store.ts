import {
  Direction,
  type KeyPairType,
  type SessionRecordType,
  type StorageType,
} from '@privacyresearch/libsignal-protocol-typescript';
import { abToB64, b64ToAB } from './bytes.js';
import type { EncryptedKV } from './kv.js';

export interface IdentityRecord {
  key: string; // base64url
  verified: boolean;
  /** Set when a contact's key changed; cleared when the user acknowledges it. */
  changed: boolean;
  firstSeen: number;
}

interface StoredKeyPair {
  pub: string;
  priv: string;
}

/** "alice.1" → "alice": identities are per user; sessions are per device. */
const userOf = (address: string) => address.replace(/\.\d+$/, '');

const toPair = (s: StoredKeyPair): KeyPairType => ({
  pubKey: b64ToAB(s.pub),
  privKey: b64ToAB(s.priv),
});
const fromPair = (k: KeyPairType): StoredKeyPair => ({
  pub: abToB64(k.pubKey),
  priv: abToB64(k.privKey),
});

function sameKey(a: ArrayBuffer, b64: string): boolean {
  return abToB64(a) === b64;
}

/**
 * Signal Protocol storage over the encrypted vault.
 *
 * Identity policy (trust on first use, like Signal):
 *  - first contact: remember the key;
 *  - a contact's key changes: accept it, but flag the conversation ("safety
 *    number changed") so the user is told;
 *  - if the user had *verified* that contact, refuse to send to the new key
 *    until they look at the new safety number and accept it.
 */
export class SignalStore implements StorageType {
  constructor(
    private readonly kv: EncryptedKV,
    private readonly identity: KeyPairType,
    private readonly registrationId: number,
    private readonly onIdentityChanged: (username: string) => void = () => {},
  ) {}

  async getIdentityKeyPair() {
    return this.identity;
  }

  async getLocalRegistrationId() {
    return this.registrationId;
  }

  async getIdentity(username: string): Promise<IdentityRecord | undefined> {
    return this.kv.getJSON<IdentityRecord>(`identity:${username}`);
  }

  async putIdentity(username: string, rec: IdentityRecord): Promise<void> {
    await this.kv.setJSON(`identity:${username}`, rec);
  }

  async isTrustedIdentity(identifier: string, identityKey: ArrayBuffer, direction: Direction) {
    const rec = await this.getIdentity(userOf(identifier));
    if (!rec || sameKey(identityKey, rec.key)) return true;
    // Key differs. Receiving: accept (saveIdentity will flag it). Sending:
    // only blocked if the user had explicitly verified the old key.
    return direction === Direction.RECEIVING ? true : !rec.verified;
  }

  async saveIdentity(encodedAddress: string, publicKey: ArrayBuffer): Promise<boolean> {
    const username = userOf(encodedAddress);
    const rec = await this.getIdentity(username);
    if (rec && sameKey(publicKey, rec.key)) return false;
    if (rec?.verified) {
      // A verified contact's key is never replaced silently, even by an
      // incoming message (the library calls this after decrypting a first
      // message from a new identity). Keep the verified key, so sending stays
      // blocked by isTrustedIdentity(SENDING), and park the new key until the
      // user checks it and calls acceptNewIdentity().
      await this.kv.setJSON(`pending-identity:${username}`, abToB64(publicKey));
      if (!rec.changed) {
        await this.putIdentity(username, { ...rec, changed: true });
        this.onIdentityChanged(username);
      }
      return true;
    }
    await this.putIdentity(username, {
      key: abToB64(publicKey),
      verified: false,
      changed: !!rec,
      firstSeen: rec?.firstSeen ?? Date.now(),
    });
    if (rec) this.onIdentityChanged(username);
    return !!rec;
  }

  async loadPreKey(keyId: string | number) {
    const s = await this.kv.getJSON<StoredKeyPair>(`prekey:${keyId}`);
    return s ? toPair(s) : undefined;
  }

  async storePreKey(keyId: string | number, keyPair: KeyPairType) {
    await this.kv.setJSON(`prekey:${keyId}`, fromPair(keyPair));
  }

  async removePreKey(keyId: string | number) {
    await this.kv.delete(`prekey:${keyId}`);
  }

  async loadSignedPreKey(keyId: string | number) {
    const s = await this.kv.getJSON<StoredKeyPair>(`signedprekey:${keyId}`);
    return s ? toPair(s) : undefined;
  }

  async storeSignedPreKey(keyId: string | number, keyPair: KeyPairType) {
    await this.kv.setJSON(`signedprekey:${keyId}`, fromPair(keyPair));
  }

  async removeSignedPreKey(keyId: string | number) {
    await this.kv.delete(`signedprekey:${keyId}`);
  }

  async loadSession(encodedAddress: string): Promise<SessionRecordType | undefined> {
    return this.kv.getJSON<string>(`session:${encodedAddress}`);
  }

  async storeSession(encodedAddress: string, record: SessionRecordType) {
    await this.kv.setJSON(`session:${encodedAddress}`, record);
  }

  async removeSession(encodedAddress: string) {
    await this.kv.delete(`session:${encodedAddress}`);
  }
}
