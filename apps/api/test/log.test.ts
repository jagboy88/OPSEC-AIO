import { describe, expect, it } from 'vitest';
import { scrub, serializeError } from '../src/log.js';

describe('log scrubbing', () => {
  it('removes paths, ids, tokens, UUIDs and IPs from messages', () => {
    const id = 'AbCdEfGhIjKlMnOpQrStUv';
    const fsErr = Object.assign(
      new Error(`ENOENT: no such file or directory, open '/data/blobs/${id}/3'`),
      { code: 'ENOENT' },
    );
    const e = serializeError(fsErr);
    expect(e).toMatchObject({ type: 'Error', code: 'ENOENT' });
    expect(e.message).toBe("ENOENT: no such file or directory, open '<path>'");
    expect(JSON.stringify(e)).not.toContain(id);
    expect(JSON.stringify(e)).not.toContain('/data/blobs');

    const text = scrub(
      `token ${'x'.repeat(43)} user 0b9c6a1e-2f3d-4c5b-8a7e-1d2c3b4a5f60 from 203.0.113.7 or 2001:db8:0:1::42 at /srv/app/x.js`,
    );
    expect(text).toBe('token <id> user <uuid> from <ip> or <ip> at <path>');
  });

  it('keeps only file names in stack frames, and never logs non-error values', () => {
    const err = new Error('boom');
    err.stack =
      'Error: boom\n    at handler (/app/node_modules/x/lib/index.js:10:5)\n    at file:///app/dist/server.js:3:1';
    const { stack } = serializeError(err);
    expect(stack).toContain('(index.js:10:5)');
    expect(stack).not.toContain('/app/node_modules');
    expect(serializeError('secret string')).toEqual({ type: 'string', message: '', stack: '' });
  });

  it('drops codes that are not plain identifiers', () => {
    const err = Object.assign(new Error('x'), { code: 'user@example 1' });
    expect(serializeError(err).code).toBeUndefined();
  });
});
