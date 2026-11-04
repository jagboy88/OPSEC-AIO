import { utf8Decode, utf8Encode } from '@opsec-aio/crypto';
import {
  DISAPPEARING_TIMER_OPTIONS_SECONDS,
  GROUP_MAX_MEMBERS,
  USERNAME_PATTERN,
} from '@opsec-aio/types';

/**
 * Plaintext carried inside each Signal message. Everything here — text,
 * timers, group names and membership — is end-to-end encrypted; the server
 * only ever relays opaque ciphertext.
 *
 * Wire: JSON, ISO/IEC 7816-4 padded to a multiple of 160 bytes (as Signal
 * does) so short messages all look alike in size.
 */

export const PAYLOAD_PAD_BLOCK = 160;
export const TEXT_MAX_CHARS = 8000;
const GROUP_NAME_MAX = 64;
const ID_RE = /^[A-Za-z0-9_-]{22}$/;

export interface FileRef {
  /** Drop id. */
  drop: string;
  /** Drop link fragment (key and flags). Wiped together with the message. */
  key: string;
  name: string;
  size: number;
  type: string;
}

interface Base {
  v: 1;
  /** Sender-chosen message id (random, 22 chars). */
  id: string;
  /** Sender clock, ms. Display only. */
  ts: number;
  /** Group id if this is a group message. */
  group?: string;
}

export type Payload =
  | (Base & { kind: 'text'; text: string; timer: number })
  | (Base & { kind: 'file'; file: FileRef; text?: string; timer: number })
  | (Base & { kind: 'timer'; timer: number })
  | (Base & { kind: 'group'; group: string; name: string; members: string[] })
  | (Base & { kind: 'leave'; group: string });

export class PayloadError extends Error {
  constructor() {
    super('invalid message payload');
    this.name = 'PayloadError';
  }
}

export function encodePayload(p: Payload): Uint8Array {
  validate(p); // never send something a peer would reject
  const json = utf8Encode(JSON.stringify(p));
  const len = Math.ceil((json.length + 1) / PAYLOAD_PAD_BLOCK) * PAYLOAD_PAD_BLOCK;
  const out = new Uint8Array(len);
  out.set(json);
  out[json.length] = 0x80;
  return out;
}

export function decodePayload(bytes: Uint8Array): Payload {
  let end = bytes.length - 1;
  while (end >= 0 && bytes[end] === 0) end--;
  if (end < 0 || bytes[end] !== 0x80) throw new PayloadError();
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(bytes.subarray(0, end)));
  } catch {
    throw new PayloadError();
  }
  validate(parsed);
  return parsed;
}

const isUser = (u: unknown): u is string => typeof u === 'string' && USERNAME_PATTERN.test(u);
const isTimer = (t: unknown): t is number =>
  typeof t === 'number' && (DISAPPEARING_TIMER_OPTIONS_SECONDS as readonly number[]).includes(t);
const isText = (t: unknown, max = TEXT_MAX_CHARS): t is string =>
  typeof t === 'string' && t.length > 0 && t.length <= max;

function validate(x: unknown): asserts x is Payload {
  const p = x as Record<string, unknown>;
  if (
    typeof p !== 'object' ||
    p === null ||
    p.v !== 1 ||
    typeof p.id !== 'string' ||
    !ID_RE.test(p.id) ||
    typeof p.ts !== 'number' ||
    !Number.isFinite(p.ts) ||
    (p.group !== undefined && (typeof p.group !== 'string' || !ID_RE.test(p.group)))
  ) {
    throw new PayloadError();
  }
  switch (p.kind) {
    case 'text':
      if (!isText(p.text) || !isTimer(p.timer)) throw new PayloadError();
      return;
    case 'file': {
      const f = p.file as Record<string, unknown> | undefined;
      if (
        !f ||
        typeof f.drop !== 'string' ||
        !ID_RE.test(f.drop) ||
        typeof f.key !== 'string' ||
        !/^[A-Za-z0-9_.-]{43,64}$/.test(f.key) ||
        !isText(f.name, 255) ||
        typeof f.size !== 'number' ||
        !Number.isSafeInteger(f.size) ||
        f.size < 0 ||
        typeof f.type !== 'string' ||
        f.type.length > 255 ||
        (p.text !== undefined && !isText(p.text)) ||
        !isTimer(p.timer)
      ) {
        throw new PayloadError();
      }
      return;
    }
    case 'timer':
      if (!isTimer(p.timer)) throw new PayloadError();
      return;
    case 'group':
      if (
        typeof p.group !== 'string' ||
        !isText(p.name, GROUP_NAME_MAX) ||
        !Array.isArray(p.members) ||
        p.members.length < 2 ||
        p.members.length > GROUP_MAX_MEMBERS ||
        !p.members.every(isUser) ||
        new Set(p.members).size !== p.members.length
      ) {
        throw new PayloadError();
      }
      return;
    case 'leave':
      if (typeof p.group !== 'string') throw new PayloadError();
      return;
    default:
      throw new PayloadError();
  }
}
