import { fromBase64Url, toBase64Url } from './encoding.js';
import { FormatError } from './errors.js';
import { KEY_LENGTH } from './format.js';

/**
 * Share-link secrets live in the URL fragment (`#...`). Browsers never send
 * the fragment to the server, so the server only ever sees the id.
 *
 * Fragment grammar:  <base64url(key)>( "." <flag> )*
 * Flags are single lowercase words that tell the *recipient's* client how to
 * behave before it contacts the server (e.g. "p" = a password will be needed).
 */

const FLAG_RE = /^[a-z]{1,8}$/;

export interface LinkSecret {
  key: Uint8Array;
  flags: string[];
}

export function keyToFragment(key: Uint8Array, flags: readonly string[] = []): string {
  if (key.length !== KEY_LENGTH) throw new FormatError('key must be 32 bytes');
  for (const f of flags) if (!FLAG_RE.test(f)) throw new FormatError('invalid link flag');
  return [toBase64Url(key), ...flags].join('.');
}

/** Accepts `location.hash` (with or without the leading '#'). */
export function parseFragment(fragment: string): LinkSecret {
  const raw = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  const [encodedKey = '', ...flags] = raw.split('.');
  const key = fromBase64Url(encodedKey);
  if (key.length !== KEY_LENGTH) throw new FormatError('invalid link key');
  for (const f of flags) if (!FLAG_RE.test(f)) throw new FormatError('invalid link flag');
  return { key, flags };
}

/** Key only; rejects fragments that carry flags. */
export function keyFromFragment(fragment: string): Uint8Array {
  const { key, flags } = parseFragment(fragment);
  if (flags.length) throw new FormatError('unexpected link flags');
  return key;
}

/** e.g. buildShareLink('https://opsec.example', 'n', id, key) → https://opsec.example/n/<id>#<key> */
export function buildShareLink(
  origin: string,
  kind: 'n' | 'd',
  id: string,
  key: Uint8Array,
  flags: readonly string[] = [],
): string {
  const base = origin.replace(/\/+$/, '');
  return `${base}/${kind}/${encodeURIComponent(id)}#${keyToFragment(key, flags)}`;
}
