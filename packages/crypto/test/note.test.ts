import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  DecryptionError,
  FormatError,
  NOTE_PADDING_BLOCK,
  NOTE_TEXT_MAX_BYTES,
  buildShareLink,
  decryptNote,
  encryptNote,
  fromHex,
  generateKey,
  keyFromFragment,
  keyToFragment,
  parseFragment,
  ready,
  type OpenedNote,
} from '../src/index.js';

await ready();

const FAST = { opsLimit: 2, memLimitBytes: 8 * 1024 * 1024 };
const vectors = JSON.parse(
  readFileSync(new URL('./fixtures/note-vectors.json', import.meta.url), 'utf8'),
) as {
  plain: { key: string; ciphertext: string; text: string };
  password: { key: string; ciphertext: string; text: string; password: string };
};

function assertUnlocked(n: OpenedNote): asserts n is { locked: false; text: string } {
  expect(n.locked).toBe(false);
}
function assertLocked(
  n: OpenedNote,
): asserts n is { locked: true; unlock: (p: string) => Promise<string> } {
  expect(n.locked).toBe(true);
}

describe('note format v1 (pinned vectors)', () => {
  it('decrypts a plain note created by an earlier client', async () => {
    const n = await decryptNote(fromHex(vectors.plain.key), fromHex(vectors.plain.ciphertext));
    assertUnlocked(n);
    expect(n.text).toBe(vectors.plain.text);
  });

  it('decrypts a password note created by an earlier client', async () => {
    const n = await decryptNote(
      fromHex(vectors.password.key),
      fromHex(vectors.password.ciphertext),
    );
    assertLocked(n);
    expect(await n.unlock(vectors.password.password)).toBe(vectors.password.text);
  });
});

describe('encryptNote / decryptNote', () => {
  it('round-trips Unicode text', async () => {
    const text = 'Meet at 9.\nKey: 🔑 — ünïcødé';
    const { key, ciphertext } = await encryptNote(text);
    const n = await decryptNote(key, ciphertext);
    assertUnlocked(n);
    expect(n.text).toBe(text);
  });

  it('pads so the server only learns a 1 KiB size bucket', async () => {
    const short = await encryptNote('a');
    const longer = await encryptNote('a'.repeat(900));
    expect(short.ciphertext.length).toBe(longer.ciphertext.length);
    const bigger = await encryptNote('a'.repeat(NOTE_PADDING_BLOCK));
    expect(bigger.ciphertext.length - short.ciphertext.length).toBe(NOTE_PADDING_BLOCK);
  });

  it('accepts exactly the maximum size and rejects one byte more or empty notes', async () => {
    await expect(encryptNote('x'.repeat(NOTE_TEXT_MAX_BYTES))).resolves.toBeTruthy();
    await expect(encryptNote('x'.repeat(NOTE_TEXT_MAX_BYTES + 1))).rejects.toBeInstanceOf(
      FormatError,
    );
    await expect(encryptNote('')).rejects.toBeInstanceOf(FormatError);
  });

  it('password notes: the link alone is not enough, wrong passwords can be retried', async () => {
    const { key, ciphertext } = await encryptNote('secret', {
      password: 'pa55word',
      kdfParams: FAST,
    });
    const n = await decryptNote(key, ciphertext);
    assertLocked(n);
    await expect(n.unlock('wrong')).rejects.toBeInstanceOf(DecryptionError);
    expect(await n.unlock('pa55word')).toBe('secret');
  });

  it('rejects an empty password rather than silently creating a weak note', async () => {
    await expect(encryptNote('x', { password: '' })).rejects.toBeInstanceOf(FormatError);
  });

  it('rejects the wrong link key and tampering', async () => {
    const { key, ciphertext } = await encryptNote('hello');
    await expect(decryptNote(generateKey(), ciphertext)).rejects.toBeInstanceOf(DecryptionError);
    const bad = ciphertext.slice();
    bad[bad.length - 20]! ^= 1;
    await expect(decryptNote(key, bad)).rejects.toBeInstanceOf(DecryptionError);
  });

  it('is domain-separated from other envelopes sealed with the same key', async () => {
    const { seal } = await import('../src/index.js');
    const key = generateKey();
    const foreign = await seal(key, new Uint8Array([1, 0, 1, 104, 105]));
    await expect(decryptNote(key, foreign)).rejects.toBeInstanceOf(DecryptionError);
  });
});

describe('link fragments', () => {
  it('round-trips a key with flags', () => {
    const key = generateKey();
    const frag = keyToFragment(key, ['p']);
    expect(frag.endsWith('.p')).toBe(true);
    const parsed = parseFragment('#' + frag);
    expect(parsed.key).toEqual(key);
    expect(parsed.flags).toEqual(['p']);
  });

  it('builds share links whose secret is only in the fragment', () => {
    const key = generateKey();
    const url = new URL(
      buildShareLink('https://x.example', 'n', 'AAAAAAAAAAAAAAAAAAAAAA', key, ['p']),
    );
    expect(url.pathname).toBe('/n/AAAAAAAAAAAAAAAAAAAAAA');
    expect(parseFragment(url.hash)).toEqual({ key, flags: ['p'] });
  });

  it('rejects malformed flags and keyFromFragment rejects flagged fragments', () => {
    const key = generateKey();
    expect(() => keyToFragment(key, ['P!'])).toThrow(FormatError);
    expect(() => parseFragment(keyToFragment(key) + '.UPPER')).toThrow(FormatError);
    expect(() => keyFromFragment(keyToFragment(key, ['p']))).toThrow(FormatError);
  });
});
