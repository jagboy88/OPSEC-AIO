import {
  KeyHelper,
  SessionBuilder,
  SessionCipher,
  SignalProtocolAddress,
  type KeyPairType,
} from '@privacyresearch/libsignal-protocol-typescript';
import {
  authChallengeMessage,
  fromBase64Url,
  generateSigningKeyPair,
  randomId,
  sign,
  toBase64Url,
} from '@opsec-aio/crypto';
import {
  DISAPPEARING_DEFAULT_SECONDS,
  DISAPPEARING_TIMER_OPTIONS_SECONDS,
  GROUP_MAX_MEMBERS,
  ONE_TIME_PREKEY_BATCH,
  USERNAME_PATTERN,
  type IncomingMessage,
  type OutgoingMessage,
  type PreKeyUpload,
} from '@opsec-aio/types';
import { abToB64, b64ToAB, binToBytes, bytesToBin, toAB } from './bytes.js';
import { safetyNumber } from './fingerprint.js';
import type { EncryptedKV } from './kv.js';
import {
  PayloadTooLargeError,
  TEXT_MAX_CHARS,
  decodePayload,
  encodePayload,
  type FileRef,
  type Payload,
} from './payload.js';
import { ChatServerError, type ChatServer } from './server.js';
import { SignalStore, type IdentityRecord } from './signal-store.js';

// ── Public types ─────────────────────────────────────────────────────────────

export interface Conversation {
  /** "d:<username>" or "g:<group id>". */
  id: string;
  kind: 'direct' | 'group';
  title: string;
  peer?: string;
  group?: string;
  /** Group members including me; for direct chats [me, peer]. */
  members: string[];
  /** Disappearing-message timer in seconds; 0 = off. */
  timer: number;
  updatedAt: number;
  unread: number;
  /** I left this group (read-only). */
  left?: boolean;
  /** Group creator: the only member who may change membership or the name. */
  admin?: string;
  /** Per sender: timestamp of the last control message applied (replay guard). */
  controlTs?: Record<string, number>;
}

export interface StoredMessage {
  id: string;
  convId: string;
  /** Sender username; for system notices, "". */
  from: string;
  kind: 'text' | 'file' | 'system';
  text?: string;
  file?: FileRef;
  sentAt: number;
  receivedAt: number;
  /** Timer that applied when the message was sent (seconds; 0 = never expires). */
  timer: number;
  readAt?: number;
  /** When it will be deleted from this device. */
  expiresAt?: number;
}

export class IdentityChangedError extends Error {
  constructor(readonly username: string) {
    super(`safety number with ${username} changed`);
    this.name = 'IdentityChangedError';
  }
}

export class UsernameTakenError extends Error {
  constructor() {
    super('username taken');
    this.name = 'UsernameTakenError';
  }
}

export class ChatInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ChatInputError';
  }
}

export interface ChatClientOptions {
  /** One-time prekeys to generate at registration / per refill. */
  preKeyBatch?: number;
  /** Clock override for tests. */
  now?: () => number;
}

// ── Internals ────────────────────────────────────────────────────────────────

interface AccountState {
  v: 1;
  username: string;
  authPub: string;
  authPriv: string;
  identityPub: string;
  identityPriv: string;
  registrationId: number;
  signedPreKeyId: number;
  signedPreKeyCreatedAt: number;
  nextPreKeyId: number;
}

const DEVICE_ID = 1;
const MAX_MESSAGES_PER_CONVERSATION = 2000;
const SEEN_IDS_KEPT = 1000;
const SEEN_PAYLOADS_PER_SENDER = 2000;
const PREKEY_REFILL_BELOW = 20;
const SIGNED_PREKEY_ROTATE_MS = 7 * 24 * 3600 * 1000;
const FINGERPRINT_ITERATIONS = 5200;

const directId = (u: string) => `d:${u}`;
const groupId = (g: string) => `g:${g}`;

export function timerLabel(seconds: number): string {
  if (seconds === 0) return 'off';
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds < 3600) return `${seconds / 60} minutes`;
  if (seconds < 86400) return `${seconds / 3600} hour${seconds === 3600 ? '' : 's'}`;
  return `${seconds / 86400} day${seconds === 86400 ? '' : 's'}`;
}

/** "12345 67890 …" — 12 groups of 5 digits, as Signal displays safety numbers. */
export function formatSafetyNumber(digits: string): string {
  return digits.replace(/(\d{5})(?=\d)/g, '$1 ');
}

/**
 * End-to-end encrypted chat client (docs/PLAN.md §4.1).
 *
 * - Signal Protocol (X3DH + Double Ratchet) per contact; groups are pairwise
 *   fan-out (one ciphertext per member).
 * - All state lives in an {@link EncryptedKV}; plaintext never touches the
 *   server or unencrypted storage.
 * - Disappearing messages: per-conversation timer, synced by an encrypted
 *   control message. Incoming messages start their timer when read, with a
 *   hard ceiling of 2 × timer after arrival; my own start when sent.
 */
export class ChatClient {
  private token: string | null = null;
  private tokenValidUntil = 0;
  private readonly convs = new Map<string, Conversation>();
  private readonly msgs = new Map<string, StoredMessage[]>();
  private seen: string[] = [];
  /** Per sender: recently applied payload ids, so a replayed message is ignored. */
  private seenPayloads: Record<string, string[]> = {};
  private readonly dirty = new Set<string>();
  private chain: Promise<unknown> = Promise.resolve();
  private readonly listeners = new Set<() => void>();
  private readonly store: SignalStore;
  private readonly now: () => number;
  private readonly preKeyBatch: number;

  private constructor(
    private readonly server: ChatServer,
    private readonly kv: EncryptedKV,
    private account: AccountState,
    opts: ChatClientOptions,
  ) {
    this.now = opts.now ?? Date.now;
    this.preKeyBatch = opts.preKeyBatch ?? ONE_TIME_PREKEY_BATCH;
    const identity: KeyPairType = {
      pubKey: b64ToAB(account.identityPub),
      privKey: b64ToAB(account.identityPriv),
    };
    this.store = new SignalStore(kv, identity, account.registrationId, (u) =>
      this.onIdentityChanged(u),
    );
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  /** Generate keys, register `username`, store everything in `kv`, and log in. */
  static async create(
    server: ChatServer,
    kv: EncryptedKV,
    username: string,
    opts: ChatClientOptions = {},
  ): Promise<ChatClient> {
    if (!USERNAME_PATTERN.test(username)) {
      throw new ChatInputError('Usernames are 3–32 characters: a–z, 0–9 and _.');
    }
    const batch = opts.preKeyBatch ?? ONE_TIME_PREKEY_BATCH;
    const auth = generateSigningKeyPair();
    const identity = await KeyHelper.generateIdentityKeyPair();
    const registrationId = 1 + (KeyHelper.generateRegistrationId() % 16383);
    const spk = await KeyHelper.generateSignedPreKey(identity, 1);
    const preKeys = await Promise.all(
      Array.from({ length: batch }, (_, i) => KeyHelper.generatePreKey(i + 1)),
    );

    try {
      await server.register({
        username,
        auth_pub: toBase64Url(auth.publicKey),
        identity_pub: abToB64(identity.pubKey),
        registration_id: registrationId,
        signed_prekey: {
          key_id: spk.keyId,
          pub: abToB64(spk.keyPair.pubKey),
          sig: abToB64(spk.signature),
        },
        one_time_prekeys: preKeys.map((k) => ({ key_id: k.keyId, pub: abToB64(k.keyPair.pubKey) })),
      });
    } catch (e) {
      if (e instanceof ChatServerError && e.status === 409) throw new UsernameTakenError();
      throw e;
    }

    const account: AccountState = {
      v: 1,
      username,
      authPub: toBase64Url(auth.publicKey),
      authPriv: toBase64Url(auth.privateKey),
      identityPub: abToB64(identity.pubKey),
      identityPriv: abToB64(identity.privKey),
      registrationId,
      signedPreKeyId: spk.keyId,
      signedPreKeyCreatedAt: (opts.now ?? Date.now)(),
      nextPreKeyId: batch + 1,
    };
    const client = new ChatClient(server, kv, account, opts);
    await client.store.storeSignedPreKey(spk.keyId, spk.keyPair);
    for (const k of preKeys) await client.store.storePreKey(k.keyId, k.keyPair);
    await kv.setJSON('account', account);
    await client.persist();
    await client.login();
    return client;
  }

  /** Load an existing account from an unlocked vault and log in. */
  static async open(
    server: ChatServer,
    kv: EncryptedKV,
    opts: ChatClientOptions = {},
  ): Promise<ChatClient> {
    const account = await kv.getJSON<AccountState>('account');
    if (!account) throw new Error('no account in this vault');
    const client = new ChatClient(server, kv, account, opts);
    for (const c of (await kv.getJSON<Conversation[]>('conversations')) ?? []) {
      client.convs.set(c.id, c);
      client.msgs.set(c.id, (await kv.getJSON<StoredMessage[]>(`messages:${c.id}`)) ?? []);
    }
    client.seen = (await kv.getJSON<string[]>('seen')) ?? [];
    client.seenPayloads = (await kv.getJSON<Record<string, string[]>>('seen-payloads')) ?? {};
    client.dropExpired(); // messages that expired while the app was closed
    await client.login();
    return client;
  }

  get username(): string {
    return this.account.username;
  }

  async login(): Promise<string> {
    const nonce = await this.server.challenge(this.username);
    const signature = sign(
      authChallengeMessage(this.username, fromBase64Url(nonce)),
      fromBase64Url(this.account.authPriv),
    );
    const res = await this.server.login({
      username: this.username,
      nonce,
      signature: toBase64Url(signature),
    });
    this.token = res.session_token;
    this.tokenValidUntil = Date.parse(res.expires_at) - 60_000;
    return this.token;
  }

  /** A valid session token (for the WebSocket handshake). */
  async sessionToken(): Promise<string> {
    if (!this.token || Date.now() > this.tokenValidUntil) return this.login();
    return this.token;
  }

  private async authed<T>(fn: (token: string) => Promise<T>): Promise<T> {
    const token = await this.sessionToken();
    try {
      return await fn(token);
    } catch (e) {
      if (e instanceof ChatServerError && e.status === 401) return fn(await this.login());
      throw e;
    }
  }

  async logout(): Promise<void> {
    if (this.token) await this.server.logout(this.token).catch(() => {});
    this.token = null;
    this.kv.lock();
  }

  /** Delete the account on the server and wipe everything on this device. */
  async deleteAccount(): Promise<void> {
    await this.authed((t) => this.server.deleteAccount(t));
    this.token = null;
    await this.kv.destroy();
    this.convs.clear();
    this.msgs.clear();
  }

  onChange(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit() {
    for (const l of this.listeners) l();
  }

  /** Serialise everything that touches Signal session state or the store. */
  private lock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => {});
    return run.finally(() => this.emit());
  }

  private async persist(): Promise<void> {
    await this.kv.setJSON('conversations', [...this.convs.values()]);
    for (const id of this.dirty) {
      if (this.convs.has(id)) await this.kv.setJSON(`messages:${id}`, this.msgs.get(id) ?? []);
      else await this.kv.delete(`messages:${id}`);
    }
    this.dirty.clear();
    await this.kv.setJSON('seen', this.seen);
    await this.kv.setJSON('seen-payloads', this.seenPayloads);
  }

  // ── Reading state ──────────────────────────────────────────────────────────

  conversations(): Conversation[] {
    return [...this.convs.values()].sort((a, b) => b.updatedAt - a.updatedAt);
  }

  conversation(id: string): Conversation | undefined {
    return this.convs.get(id);
  }

  messages(convId: string): StoredMessage[] {
    const now = this.now();
    return (this.msgs.get(convId) ?? []).filter(
      (m) => m.expiresAt === undefined || m.expiresAt > now,
    );
  }

  /** Remove expired messages from memory (persisted on the next write). */
  private dropExpired(): number {
    const now = this.now();
    let removed = 0;
    for (const [id, list] of this.msgs) {
      const kept = list.filter((m) => m.expiresAt === undefined || m.expiresAt > now);
      if (kept.length !== list.length) {
        removed += list.length - kept.length;
        this.msgs.set(id, kept);
        this.dirty.add(id);
      }
    }
    return removed;
  }

  // ── Conversations ──────────────────────────────────────────────────────────

  private ensureDirect(peer: string): Conversation {
    const id = directId(peer);
    let c = this.convs.get(id);
    if (!c) {
      c = {
        id,
        kind: 'direct',
        title: peer,
        peer,
        members: [this.username, peer],
        timer: DISAPPEARING_DEFAULT_SECONDS,
        updatedAt: this.now(),
        unread: 0,
      };
      this.convs.set(id, c);
      this.msgs.set(id, []);
      this.dirty.add(id);
    }
    return c;
  }

  async startDirect(username: string): Promise<Conversation> {
    const peer = username.trim().toLowerCase().replace(/^@/, '');
    if (!USERNAME_PATTERN.test(peer)) throw new ChatInputError('That is not a valid username.');
    if (peer === this.username) throw new ChatInputError("You can't start a chat with yourself.");
    if (!(await this.authed((t) => this.server.userExists(t, peer)))) {
      throw new ChatInputError(`No user called @${peer}.`);
    }
    return this.lock(async () => {
      const c = this.ensureDirect(peer);
      await this.persist();
      return c;
    });
  }

  async createGroup(name: string, memberNames: string[]): Promise<Conversation> {
    const title = name.trim();
    if (!title || title.length > 64) throw new ChatInputError('Group names are 1–64 characters.');
    const others = [
      ...new Set(memberNames.map((m) => m.trim().toLowerCase().replace(/^@/, ''))),
    ].filter((m) => m && m !== this.username);
    if (others.length < 1) throw new ChatInputError('Add at least one other member.');
    if (others.length + 1 > GROUP_MAX_MEMBERS) {
      throw new ChatInputError(`Groups have at most ${GROUP_MAX_MEMBERS} members.`);
    }
    for (const m of others) {
      if (!USERNAME_PATTERN.test(m)) throw new ChatInputError(`@${m} is not a valid username.`);
      if (!(await this.authed((t) => this.server.userExists(t, m)))) {
        throw new ChatInputError(`No user called @${m}.`);
      }
    }
    return this.lock(async () => {
      const gid = randomId();
      const conv: Conversation = {
        id: groupId(gid),
        kind: 'group',
        title,
        group: gid,
        members: [this.username, ...others],
        timer: DISAPPEARING_DEFAULT_SECONDS,
        updatedAt: this.now(),
        unread: 0,
        admin: this.username,
      };
      await this.sendPayload(conv, {
        v: 1,
        id: randomId(),
        ts: this.now(),
        kind: 'group',
        group: gid,
        name: title,
        members: conv.members,
      });
      this.convs.set(conv.id, conv);
      this.msgs.set(conv.id, []);
      this.notice(conv, `You created “${title}”.`);
      await this.persist();
      return conv;
    });
  }

  async leaveGroup(convId: string): Promise<void> {
    await this.lock(async () => {
      const conv = this.mustConv(convId);
      if (conv.kind !== 'group' || conv.left) return;
      await this.sendPayload(conv, {
        v: 1,
        id: randomId(),
        ts: this.now(),
        kind: 'leave',
        group: conv.group!,
      });
      conv.left = true;
      this.notice(conv, 'You left the group.');
      await this.persist();
    });
  }

  /**
   * Change a group's members (creator only). Everyone in the old *and* new
   * list is told, so removed members know they're out; each change shows up
   * as an explicit notice on every member's device.
   */
  async updateGroupMembers(convId: string, add: string[], remove: string[]): Promise<void> {
    const norm = (l: string[]) =>
      [...new Set(l.map((m) => m.trim().toLowerCase().replace(/^@/, '')))].filter(Boolean);
    const toAdd = norm(add);
    const toRemove = norm(remove);
    for (const m of toAdd) {
      if (!USERNAME_PATTERN.test(m)) throw new ChatInputError(`@${m} is not a valid username.`);
      if (!(await this.authed((t) => this.server.userExists(t, m)))) {
        throw new ChatInputError(`No user called @${m}.`);
      }
    }
    await this.lock(async () => {
      const conv = this.mustConv(convId);
      if (conv.kind !== 'group' || conv.left) throw new ChatInputError('Not an active group.');
      if (conv.admin !== this.username) {
        throw new ChatInputError('Only the person who created the group can change its members.');
      }
      if (toRemove.includes(this.username)) {
        throw new ChatInputError('Use “Leave group” to leave.');
      }
      const next = [...new Set([...conv.members.filter((m) => !toRemove.includes(m)), ...toAdd])];
      if (next.length > GROUP_MAX_MEMBERS) {
        throw new ChatInputError(`Groups have at most ${GROUP_MAX_MEMBERS} members.`);
      }
      if (next.length < 2) throw new ChatInputError('A group needs at least one other member.');
      const ts = this.now();
      const notify: Conversation = {
        ...conv,
        members: [...new Set([...conv.members, ...next])],
      };
      await this.sendPayload(notify, {
        v: 1,
        id: randomId(),
        ts,
        kind: 'group',
        group: conv.group!,
        name: conv.title,
        members: next,
      });
      const added = next.filter((m) => !conv.members.includes(m));
      const removed = conv.members.filter((m) => !next.includes(m));
      conv.members = next;
      for (const m of added) this.notice(conv, `You added @${m}.`);
      for (const m of removed) this.notice(conv, `You removed @${m}.`);
      await this.persist();
    });
  }

  /** Remove a conversation and its messages from this device only. */
  async deleteConversation(convId: string): Promise<void> {
    await this.lock(async () => {
      this.convs.delete(convId);
      this.msgs.delete(convId);
      this.dirty.add(convId);
      await this.persist();
    });
  }

  // ── Sending ────────────────────────────────────────────────────────────────

  private mustConv(convId: string): Conversation {
    const c = this.convs.get(convId);
    if (!c) throw new ChatInputError('Unknown conversation.');
    return c;
  }

  async sendText(convId: string, text: string): Promise<StoredMessage> {
    const body = text.trim();
    if (!body) throw new ChatInputError('Message is empty.');
    if (body.length > TEXT_MAX_CHARS) {
      throw new ChatInputError(`Messages are limited to ${TEXT_MAX_CHARS} characters.`);
    }
    return this.lock(async () => {
      const conv = this.mustConv(convId);
      const p: Payload = {
        v: 1,
        id: randomId(),
        ts: this.now(),
        kind: 'text',
        text: body,
        timer: conv.timer,
        ...(conv.group ? { group: conv.group } : {}),
      };
      await this.sendPayload(conv, p);
      const m = this.appendOwn(conv, { id: p.id, kind: 'text', text: body });
      await this.persist();
      return m;
    });
  }

  /** Share an already-uploaded Drop (encrypted file) in a conversation. */
  async sendFile(convId: string, file: FileRef, caption?: string): Promise<StoredMessage> {
    return this.lock(async () => {
      const conv = this.mustConv(convId);
      const text = caption?.trim();
      const p: Payload = {
        v: 1,
        id: randomId(),
        ts: this.now(),
        kind: 'file',
        file,
        ...(text ? { text } : {}),
        timer: conv.timer,
        ...(conv.group ? { group: conv.group } : {}),
      };
      await this.sendPayload(conv, p);
      const m = this.appendOwn(conv, { id: p.id, kind: 'file', file, ...(text ? { text } : {}) });
      await this.persist();
      return m;
    });
  }

  async setTimer(convId: string, seconds: number): Promise<void> {
    if (!(DISAPPEARING_TIMER_OPTIONS_SECONDS as readonly number[]).includes(seconds)) {
      throw new ChatInputError('Unsupported timer.');
    }
    await this.lock(async () => {
      const conv = this.mustConv(convId);
      if (conv.timer === seconds) return;
      await this.sendPayload(conv, {
        v: 1,
        id: randomId(),
        ts: this.now(),
        kind: 'timer',
        timer: seconds,
        ...(conv.group ? { group: conv.group } : {}),
      });
      conv.timer = seconds;
      this.notice(
        conv,
        seconds
          ? `You set disappearing messages to ${timerLabel(seconds)}.`
          : 'You turned off disappearing messages.',
      );
      await this.persist();
    });
  }

  private recipients(conv: Conversation): string[] {
    if (conv.left) throw new ChatInputError('You left this group.');
    return conv.kind === 'direct' ? [conv.peer!] : conv.members.filter((m) => m !== this.username);
  }

  private async cipherFor(username: string): Promise<SessionCipher> {
    const address = new SignalProtocolAddress(username, DEVICE_ID);
    const cipher = new SessionCipher(this.store, address);
    if (await cipher.hasOpenSession()) return cipher;

    const b = await this.authed((t) => this.server.bundle(t, username));
    const identityKey = b64ToAB(b.identity_pub);
    const rec = await this.store.getIdentity(username);
    if (rec?.verified && rec.key !== b.identity_pub) {
      await this.kv.setJSON(`pending-identity:${username}`, b.identity_pub);
      throw new IdentityChangedError(username);
    }
    const device = {
      identityKey,
      registrationId: b.registration_id,
      signedPreKey: {
        keyId: b.signed_prekey.key_id,
        publicKey: b64ToAB(b.signed_prekey.pub),
        signature: b64ToAB(b.signed_prekey.sig),
      },
      ...(b.one_time_prekey
        ? { preKey: { keyId: b.one_time_prekey.key_id, publicKey: b64ToAB(b.one_time_prekey.pub) } }
        : {}),
    };
    try {
      // Verifies the signed prekey's signature against the identity key.
      await new SessionBuilder(this.store, address).processPreKey(device);
    } catch (e) {
      if (e instanceof Error && e.message === 'Identity key changed') {
        throw new IdentityChangedError(username);
      }
      throw e;
    }
    return cipher;
  }

  private async sendPayload(conv: Conversation, p: Payload): Promise<void> {
    let plaintext: ArrayBuffer;
    try {
      plaintext = toAB(encodePayload(p));
    } catch (e) {
      if (e instanceof PayloadTooLargeError) {
        throw new ChatInputError('This message is too long to send. Please shorten it.');
      }
      throw e;
    }
    const out: OutgoingMessage[] = [];
    for (const to of this.recipients(conv)) {
      const cipher = await this.cipherFor(to);
      let ct;
      try {
        ct = await cipher.encrypt(plaintext);
      } catch (e) {
        if (e instanceof Error && e.message === 'Identity key changed') {
          throw new IdentityChangedError(to);
        }
        throw e;
      }
      if (ct.type !== 1 && ct.type !== 3) throw new Error('unexpected Signal message type');
      out.push({ to, type: ct.type, body: toBase64Url(binToBytes(ct.body ?? '')) });
    }
    if (out.length) await this.authed((t) => this.server.send(t, out));
  }

  private appendOwn(
    conv: Conversation,
    m: Pick<StoredMessage, 'id' | 'kind' | 'text' | 'file'>,
  ): StoredMessage {
    const now = this.now();
    const msg: StoredMessage = {
      ...m,
      convId: conv.id,
      from: this.username,
      sentAt: now,
      receivedAt: now,
      timer: conv.timer,
      readAt: now,
      ...(conv.timer ? { expiresAt: now + conv.timer * 1000 } : {}),
    };
    this.push(conv, msg);
    conv.updatedAt = now;
    return msg;
  }

  private push(conv: Conversation, msg: StoredMessage) {
    const list = this.msgs.get(conv.id) ?? [];
    list.push(msg);
    if (list.length > MAX_MESSAGES_PER_CONVERSATION)
      list.splice(0, list.length - MAX_MESSAGES_PER_CONVERSATION);
    this.msgs.set(conv.id, list);
    this.dirty.add(conv.id);
  }

  private notice(conv: Conversation, text: string) {
    const now = this.now();
    this.push(conv, {
      id: randomId(),
      convId: conv.id,
      from: '',
      kind: 'system',
      text,
      sentAt: now,
      receivedAt: now,
      timer: 0,
    });
    conv.updatedAt = now;
  }

  // ── Receiving ──────────────────────────────────────────────────────────────

  /** Fetch and process everything waiting on the server. Returns how many were new. */
  async sync(): Promise<number> {
    // The server returns at most one page (500) per call; keep going until the
    // mailbox is empty (bounded, in case something keeps refilling it).
    let total = 0;
    for (let page = 0; page < 50; page++) {
      const pending = await this.authed((t) => this.server.pending(t));
      if (!pending.length) break;
      total += await this.receive(pending);
    }
    return total;
  }

  /** Process messages (from sync or WebSocket push), then ACK them so the server deletes them. */
  async receive(messages: IncomingMessage[]): Promise<number> {
    if (!messages.length) return 0;
    const fresh = await this.lock(async () => {
      let n = 0;
      for (const m of messages) {
        if (this.seen.includes(m.id)) continue;
        await this.processOne(m);
        this.seen.push(m.id);
        n++;
      }
      if (this.seen.length > SEEN_IDS_KEPT) this.seen = this.seen.slice(-SEEN_IDS_KEPT);
      await this.persist();
      return n;
    });
    await this.authed((t) =>
      this.server.ack(
        t,
        messages.map((m) => m.id),
      ),
    );
    return fresh;
  }

  private async processOne(m: IncomingMessage): Promise<void> {
    if (!m.from) return; // sender deleted their account
    if (!USERNAME_PATTERN.test(m.from)) return; // never trust the relay's labels blindly
    const cipher = new SessionCipher(this.store, new SignalProtocolAddress(m.from, DEVICE_ID));
    let plain: ArrayBuffer;
    try {
      const bin = bytesToBin(fromBase64Url(m.body));
      plain =
        m.type === 3
          ? await cipher.decryptPreKeyWhisperMessage(bin, 'binary')
          : await cipher.decryptWhisperMessage(bin, 'binary');
    } catch {
      this.notice(this.ensureDirect(m.from), `A message from @${m.from} could not be decrypted.`);
      return;
    }
    let p: Payload;
    try {
      p = decodePayload(new Uint8Array(plain));
    } catch {
      this.notice(this.ensureDirect(m.from), `@${m.from} sent a message this version can't show.`);
      return;
    }
    // Replay guard: a payload id is applied at most once per sender, even if
    // the server re-delivers an old first-contact message after a session reset.
    const seen = (this.seenPayloads[m.from] ??= []);
    if (seen.includes(p.id)) return;
    seen.push(p.id);
    if (seen.length > SEEN_PAYLOADS_PER_SENDER)
      seen.splice(0, seen.length - SEEN_PAYLOADS_PER_SENDER);
    this.apply(p, m.from);
  }

  /**
   * True (and records it) unless this control message is older than the last
   * one applied from `from`. Exact replays are already caught by payload id;
   * this stops an old timer/membership change from being re-applied later.
   */
  private freshControl(conv: Conversation, from: string, ts: number): boolean {
    const last = conv.controlTs?.[from];
    if (last !== undefined && ts < last) return false;
    conv.controlTs = { ...conv.controlTs, [from]: ts };
    return true;
  }

  private memberGroup(gid: string, from: string): Conversation | null {
    const c = this.convs.get(groupId(gid));
    return c && !c.left && c.members.includes(from) ? c : null;
  }

  private apply(p: Payload, from: string) {
    const now = this.now();
    switch (p.kind) {
      case 'text':
      case 'file': {
        const conv = p.group ? this.memberGroup(p.group, from) : this.ensureDirect(from);
        if (!conv) return; // not a member, or unknown group: ignore
        this.push(conv, {
          id: p.id,
          convId: conv.id,
          from,
          kind: p.kind,
          ...(p.text ? { text: p.text } : {}),
          ...(p.kind === 'file' ? { file: p.file } : {}),
          sentAt: p.ts,
          receivedAt: now,
          timer: p.timer,
          // Hard ceiling for unread messages: 2 × timer after arrival.
          ...(p.timer ? { expiresAt: now + 2 * p.timer * 1000 } : {}),
        });
        conv.unread++;
        conv.updatedAt = now;
        return;
      }
      case 'timer': {
        const conv = p.group ? this.memberGroup(p.group, from) : this.ensureDirect(from);
        if (!conv || !this.freshControl(conv, from, p.ts)) return;
        conv.timer = p.timer;
        this.notice(
          conv,
          p.timer
            ? `@${from} set disappearing messages to ${timerLabel(p.timer)}.`
            : `@${from} turned off disappearing messages.`,
        );
        return;
      }
      case 'group': {
        const existing = this.convs.get(groupId(p.group));
        if (existing) {
          // Only the creator may change membership or the name, and every
          // change is spelled out. (Groups from before admins existed have no
          // admin: their membership is frozen.)
          if (!existing.admin || from !== existing.admin) return;
          // Once out of a group, only being added back by the creator counts.
          if (existing.left && !p.members.includes(this.username)) return;
          if (!this.freshControl(existing, from, p.ts)) return;
          const added = p.members.filter((m) => !existing.members.includes(m));
          const removed = existing.members.filter((m) => !p.members.includes(m));
          if (p.name !== existing.title) {
            this.notice(existing, `@${from} renamed the group to “${p.name}”.`);
            existing.title = p.name;
          }
          for (const m of added) {
            this.notice(
              existing,
              m === this.username ? `@${from} added you back.` : `@${from} added @${m}.`,
            );
          }
          for (const m of removed) {
            this.notice(
              existing,
              m === this.username ? `@${from} removed you.` : `@${from} removed @${m}.`,
            );
          }
          existing.members = p.members;
          if (p.members.includes(this.username)) delete existing.left;
          else existing.left = true;
          return;
        }
        if (!p.members.includes(this.username) || !p.members.includes(from)) return;
        const conv: Conversation = {
          id: groupId(p.group),
          kind: 'group',
          title: p.name,
          group: p.group,
          members: p.members,
          timer: DISAPPEARING_DEFAULT_SECONDS,
          updatedAt: now,
          unread: 0,
          admin: from,
          controlTs: { [from]: p.ts },
        };
        this.convs.set(conv.id, conv);
        this.msgs.set(conv.id, []);
        this.notice(conv, `@${from} added you to “${p.name}”.`);
        return;
      }
      case 'leave': {
        const conv = this.memberGroup(p.group, from);
        if (!conv || !this.freshControl(conv, from, p.ts)) return;
        conv.members = conv.members.filter((m) => m !== from);
        this.notice(conv, `@${from} left the group.`);
        return;
      }
    }
  }

  private onIdentityChanged(username: string) {
    const text = `Your safety number with @${username} changed. Verify it before sharing anything sensitive.`;
    this.notice(this.ensureDirect(username), text);
    for (const c of this.convs.values()) {
      if (c.kind === 'group' && !c.left && c.members.includes(username)) this.notice(c, text);
    }
  }

  // ── Disappearing messages ──────────────────────────────────────────────────

  /** Mark a conversation read: starts the timers of its unread disappearing messages. */
  async markRead(convId: string): Promise<void> {
    await this.lock(async () => {
      const conv = this.convs.get(convId);
      if (!conv) return;
      const now = this.now();
      let changed = conv.unread !== 0;
      conv.unread = 0;
      for (const m of this.msgs.get(convId) ?? []) {
        const expired = m.expiresAt !== undefined && m.expiresAt <= now;
        if (m.from !== this.username && m.timer && m.readAt === undefined && !expired) {
          // The 2 × timer ceiling only bounds *unread* messages (plan §4.1);
          // once read, the reader gets the full timer from now.
          m.readAt = now;
          m.expiresAt = now + m.timer * 1000;
          changed = true;
        }
      }
      if (changed) {
        this.dirty.add(convId);
        await this.persist();
      }
    });
  }

  /** Delete expired messages (and with them any attachment keys). Returns how many. */
  async purgeExpired(): Promise<number> {
    const now = this.now();
    const due = [...this.msgs.values()].some((l) =>
      l.some((m) => m.expiresAt !== undefined && m.expiresAt <= now),
    );
    if (!due) return 0;
    return this.lock(async () => {
      let removed = 0;
      for (const [id, list] of this.msgs) {
        const kept = list.filter((m) => m.expiresAt === undefined || m.expiresAt > now);
        if (kept.length !== list.length) {
          removed += list.length - kept.length;
          this.msgs.set(id, kept);
          this.dirty.add(id);
        }
      }
      await this.persist();
      return removed;
    });
  }

  /** Earliest pending expiry, so a UI can schedule the next purge. */
  nextExpiry(): number | undefined {
    let next: number | undefined;
    for (const list of this.msgs.values()) {
      for (const m of list) {
        if (m.expiresAt !== undefined && (next === undefined || m.expiresAt < next))
          next = m.expiresAt;
      }
    }
    return next;
  }

  // ── Safety numbers ─────────────────────────────────────────────────────────

  async identity(username: string): Promise<IdentityRecord | undefined> {
    return this.store.getIdentity(username);
  }

  /** 60-digit safety number for this pair of identities, or null before first contact. */
  async safetyNumber(username: string): Promise<string | null> {
    const rec = await this.store.getIdentity(username);
    if (!rec) return null;
    return safetyNumber(
      this.username,
      fromBase64Url(this.account.identityPub),
      username,
      fromBase64Url(rec.key),
      FINGERPRINT_ITERATIONS,
    );
  }

  /**
   * Mark a contact verified (or not). Pass the safety number the user actually
   * compared: if the key changed in the meantime, nothing is marked.
   */
  async setVerified(username: string, verified: boolean, comparedNumber?: string): Promise<void> {
    await this.lock(async () => {
      const rec = await this.store.getIdentity(username);
      if (!rec) throw new ChatInputError('No safety number yet: exchange a message first.');
      if (
        verified &&
        comparedNumber !== undefined &&
        comparedNumber !== (await this.safetyNumber(username))
      ) {
        throw new ChatInputError(
          'The safety number changed while you were checking it. Compare it again.',
        );
      }
      await this.store.putIdentity(username, { ...rec, verified, changed: false });
    });
  }

  /**
   * After an {@link IdentityChangedError}: accept the contact's new key (which
   * resets "verified") and drop the old session so the next send uses it.
   */
  async acceptNewIdentity(username: string): Promise<void> {
    await this.lock(async () => {
      const pending = await this.kv.getJSON<string>(`pending-identity:${username}`);
      const rec = await this.store.getIdentity(username);
      if (pending) {
        await this.store.putIdentity(username, {
          key: pending,
          verified: false,
          changed: false,
          firstSeen: rec?.firstSeen ?? this.now(),
        });
        await this.kv.delete(`pending-identity:${username}`);
      } else if (rec) {
        await this.store.putIdentity(username, { ...rec, changed: false });
      }
      await this.store.removeSession(`${username}.${DEVICE_ID}`);
    });
  }

  /**
   * Forget the Signal session with a contact, so the next message starts a
   * fresh one from their current prekey bundle. Use when they reinstalled and
   * messages "could not be decrypted". If their key changed and they were
   * verified, the next send raises {@link IdentityChangedError}.
   */
  async resetSession(username: string): Promise<void> {
    await this.lock(async () => {
      await this.store.removeSession(`${username}.${DEVICE_ID}`);
      const conv = this.convs.get(directId(username));
      if (conv) {
        this.notice(conv, 'Secure session reset. The next message starts a new one.');
        await this.persist();
      }
    });
  }

  // ── Key maintenance ────────────────────────────────────────────────────────

  /** Top up one-time prekeys and rotate the signed prekey weekly. Call periodically. */
  async maintainKeys(): Promise<void> {
    await this.lock(async () => {
      const count = await this.authed((t) => this.server.preKeyCount(t));
      if (count < PREKEY_REFILL_BELOW) {
        const start = this.account.nextPreKeyId;
        const upload: PreKeyUpload[] = [];
        for (let id = start; id < start + this.preKeyBatch; id++) {
          const k = await KeyHelper.generatePreKey(id);
          await this.store.storePreKey(id, k.keyPair);
          upload.push({ key_id: id, pub: abToB64(k.keyPair.pubKey) });
        }
        await this.authed((t) => this.server.uploadPreKeys(t, upload));
        this.account = { ...this.account, nextPreKeyId: start + this.preKeyBatch };
        await this.kv.setJSON('account', this.account);
      }
      if (this.now() - this.account.signedPreKeyCreatedAt > SIGNED_PREKEY_ROTATE_MS) {
        const id = this.account.signedPreKeyId + 1;
        const identity = await this.store.getIdentityKeyPair();
        const spk = await KeyHelper.generateSignedPreKey(identity, id);
        await this.store.storeSignedPreKey(id, spk.keyPair);
        await this.authed((t) =>
          this.server.putSignedPreKey(t, {
            key_id: id,
            pub: abToB64(spk.keyPair.pubKey),
            sig: abToB64(spk.signature),
          }),
        );
        // Keep the previous one for sessions still being set up; drop older.
        await this.store.removeSignedPreKey(id - 2);
        this.account = { ...this.account, signedPreKeyId: id, signedPreKeyCreatedAt: this.now() };
        await this.kv.setJSON('account', this.account);
      }
    });
  }
}
