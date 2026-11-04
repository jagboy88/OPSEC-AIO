import { fromBase64Url, toBase64Url } from './encoding.js';
import { FormatError } from './errors.js';
import { KEY_LENGTH } from './format.js';

/**
 * Share-link secrets live in the URL fragment (`#...`). Browsers never send
 * the fragment to the server, so the server only ever sees the id.
 */

export function keyToFragment(key: Uint8Array): string {
  if (key.length !== KEY_LENGTH) throw new FormatError('key must be 32 bytes');
  return toBase64Url(key);
}

/** Accepts `location.hash` (with or without the leading '#'). */
export function keyFromFragment(fragment: string): Uint8Array {
  const raw = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  const key = fromBase64Url(raw);
  if (key.length !== KEY_LENGTH) throw new FormatError('invalid link key');
  return key;
}

/** e.g. buildShareLink('https://opsec.example', 'n', id, key) → https://opsec.example/n/<id>#<key> */
export function buildShareLink(
  origin: string,
  kind: 'n' | 'd',
  id: string,
  key: Uint8Array,
): string {
  const base = origin.replace(/\/+$/, '');
  return `${base}/${kind}/${encodeURIComponent(id)}#${keyToFragment(key)}`;
}
