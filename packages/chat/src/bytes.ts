import { fromBase64Url, toBase64Url } from '@opsec-aio/crypto';

/** Copy a view into a standalone ArrayBuffer (the Signal library wants ArrayBuffers). */
export function toAB(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

export const fromAB = (b: ArrayBuffer): Uint8Array => new Uint8Array(b);

/** The Signal library represents ciphertext bodies as "binary strings" (one char per byte). */
export function binToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

export function bytesToBin(u: Uint8Array): string {
  let s = '';
  for (let i = 0; i < u.length; i += 0x8000) {
    s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  }
  return s;
}

export const abToB64 = (b: ArrayBuffer): string => toBase64Url(new Uint8Array(b));
export const b64ToAB = (s: string): ArrayBuffer => toAB(fromBase64Url(s));
