import { EventEmitter } from 'node:events';
import type { Redis } from 'ioredis';

/**
 * Delivers "new message for user X" events to whichever API process holds that
 * user's WebSocket. Payloads are already-encrypted messages; nothing here is
 * plaintext. Delivery is best-effort: clients always fetch /messages/pending on
 * (re)connect, so a missed push only adds latency.
 */
export interface Notifier {
  publish(userId: string, payload: string): Promise<void>;
  /** Returns an unsubscribe function. */
  subscribe(userId: string, listener: (payload: string) => void): Promise<() => void>;
  close(): Promise<void>;
}

/** Single-process notifier (tests, or a single API replica). */
export class MemoryNotifier implements Notifier {
  private readonly bus = new EventEmitter().setMaxListeners(0);
  async publish(userId: string, payload: string) {
    this.bus.emit(userId, payload);
  }
  async subscribe(userId: string, listener: (payload: string) => void) {
    this.bus.on(userId, listener);
    return () => void this.bus.off(userId, listener);
  }
  async close() {
    this.bus.removeAllListeners();
  }
}

/** Redis pub/sub notifier, so several API replicas can share WebSocket delivery. */
export class RedisNotifier implements Notifier {
  private readonly sub: Redis;
  private readonly listeners = new Map<string, Set<(payload: string) => void>>();

  constructor(private readonly pub: Redis) {
    this.sub = pub.duplicate();
    this.sub.on('error', () => {});
    this.sub.on('message', (channel: string, payload: string) => {
      for (const l of this.listeners.get(channel.slice(4)) ?? []) l(payload);
    });
  }

  async publish(userId: string, payload: string) {
    await this.pub.publish(`mbx:${userId}`, payload);
  }

  async subscribe(userId: string, listener: (payload: string) => void) {
    let set = this.listeners.get(userId);
    if (!set) {
      set = new Set();
      this.listeners.set(userId, set);
      await this.sub.subscribe(`mbx:${userId}`);
    }
    set.add(listener);
    return () => {
      set.delete(listener);
      if (set.size === 0) {
        this.listeners.delete(userId);
        void this.sub.unsubscribe(`mbx:${userId}`).catch(() => {});
      }
    };
  }

  async close() {
    this.sub.disconnect();
  }
}
