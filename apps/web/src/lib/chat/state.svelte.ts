import {
  ChatClient,
  HttpChatServer,
  createVault,
  hasVault,
  unlockVault,
  type Conversation,
  type StoredMessage,
} from '@opsec-aio/chat';
import { fromBase64Url, ready, toBase64Url, utf8Decode, utf8Encode } from '@opsec-aio/crypto';
import type { WsServerMessage } from '@opsec-aio/types';
import { IndexedDbKV } from './idb.js';

export type Phase = 'loading' | 'no-account' | 'locked' | 'ready';

const MAINTAIN_EVERY_MS = 60 * 60 * 1000;
const EXPORT_MAGIC = 'opsec-aio-keystore-v1';

/**
 * Chat session state for the UI: vault lifecycle, the live WebSocket (with
 * reconnect), and timers for disappearing messages and key maintenance.
 * The ChatClient holds the data; `version` bumps whenever it changes so Svelte
 * components re-read it.
 */
class ChatState {
  phase = $state<Phase>('loading');
  version = $state(0);
  online = $state(false);
  client = $state.raw<ChatClient | null>(null);

  private raw: IndexedDbKV | null = null;
  private ws: WebSocket | null = null;
  private retry = 0;
  private timers: ReturnType<typeof setInterval>[] = [];
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private unsubscribe: (() => void) | null = null;
  private readonly server = new HttpChatServer();

  async init(): Promise<void> {
    if (this.phase !== 'loading' && this.raw) return;
    await ready();
    this.raw = await IndexedDbKV.open();
    this.phase = (await hasVault(this.raw)) ? 'locked' : 'no-account';
  }

  async createAccount(username: string, passphrase: string): Promise<void> {
    const raw = this.raw!;
    const kv = await createVault(raw, passphrase);
    try {
      this.attach(await ChatClient.create(this.server, kv, username));
    } catch (e) {
      await raw.clear(); // nothing was registered, or registration failed: start over
      throw e;
    }
  }

  async unlock(passphrase: string): Promise<void> {
    const kv = await unlockVault(this.raw!, passphrase);
    this.attach(await ChatClient.open(this.server, kv));
  }

  private attach(client: ChatClient) {
    this.client = client;
    this.unsubscribe = client.onChange(() => this.version++);
    this.phase = 'ready';
    this.connect();
    void client.maintainKeys().catch(() => {});
    this.timers.push(
      setInterval(() => {
        const next = client.nextExpiry();
        if (next !== undefined && next <= Date.now()) void client.purgeExpired();
      }, 1000),
      setInterval(() => void client.maintainKeys().catch(() => {}), MAINTAIN_EVERY_MS),
    );
    document.addEventListener('visibilitychange', this.onVisible);
  }

  private onVisible = () => {
    if (document.visibilityState === 'visible') void this.client?.sync().catch(() => {});
  };

  private connect() {
    const client = this.client;
    if (!client || this.ws) return;
    const ws = new WebSocket(
      `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/v1/ws`,
    );
    this.ws = ws;
    ws.onopen = async () => {
      try {
        ws.send(JSON.stringify({ type: 'auth', token: await client.sessionToken() }));
      } catch {
        ws.close();
      }
    };
    ws.onmessage = (ev) => {
      let m: WsServerMessage;
      try {
        m = JSON.parse(String(ev.data)) as WsServerMessage;
      } catch {
        return;
      }
      if (m.type === 'ready') {
        this.online = true;
        this.retry = 0;
        void client.sync().catch(() => {});
      } else if (m.type === 'message') {
        void client.receive([m.message]).catch(() => {});
      }
    };
    ws.onclose = () => {
      this.ws = null;
      this.online = false;
      if (this.client !== client) return;
      const delay = Math.min(30_000, 1000 * 2 ** this.retry++);
      this.reconnectTimer = setTimeout(() => this.connect(), delay);
    };
  }

  private teardown() {
    this.unsubscribe?.();
    this.unsubscribe = null;
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    document.removeEventListener('visibilitychange', this.onVisible);
    const ws = this.ws;
    this.ws = null;
    this.client = null;
    ws?.close();
    this.online = false;
  }

  /** Forget keys from memory; the passphrase is needed again. */
  async lock(): Promise<void> {
    const c = this.client;
    this.teardown();
    await c?.logout();
    this.phase = 'locked';
  }

  async deleteAccount(): Promise<void> {
    const c = this.client;
    if (!c) return;
    await c.deleteAccount();
    this.teardown();
    this.phase = 'no-account';
  }

  /** Remove the local account without touching the server (e.g. a lost passphrase). */
  async forgetDevice(): Promise<void> {
    this.teardown();
    await this.raw?.clear();
    this.phase = 'no-account';
  }

  /**
   * Export the encrypted keystore (still protected by the passphrase) to move
   * the account to another device. Using it on two devices at once breaks
   * sessions: this is a move, not multi-device.
   */
  async exportKeystore(): Promise<Blob> {
    const entries = await this.raw!.exportAll();
    const json = JSON.stringify({
      format: EXPORT_MAGIC,
      entries: entries.map(([k, v]) => [k, toBase64Url(v)]),
    });
    return new Blob([utf8Encode(json) as Uint8Array<ArrayBuffer>], {
      type: 'application/octet-stream',
    });
  }

  async importKeystore(file: File): Promise<void> {
    const parsed = JSON.parse(utf8Decode(new Uint8Array(await file.arrayBuffer()))) as {
      format?: string;
      entries?: [string, string][];
    };
    if (parsed.format !== EXPORT_MAGIC || !Array.isArray(parsed.entries)) {
      throw new Error('This is not an OpSec AIO keystore file.');
    }
    await this.raw!.importAll(parsed.entries.map(([k, v]) => [k, fromBase64Url(v)]));
    this.phase = 'locked';
  }

  conversations(): Conversation[] {
    void this.version;
    return this.client?.conversations() ?? [];
  }

  messages(convId: string): StoredMessage[] {
    void this.version;
    return this.client?.messages(convId) ?? [];
  }
}

export const chat = new ChatState();
