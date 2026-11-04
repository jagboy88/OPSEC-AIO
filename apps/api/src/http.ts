import { fromBase64Url } from '@opsec-aio/crypto';

export const httpError = (statusCode: number) =>
  Object.assign(new Error(String(statusCode)), { statusCode });

/** Route config enabling a per-client rate limit. */
export const rl = (r: { max: number; windowSeconds: number }) => ({
  rateLimit: { max: r.max, timeWindow: r.windowSeconds * 1000 },
});

/** Unpadded base64url length for n bytes. */
export const b64Len = (n: number) => Math.ceil((n * 4) / 3);

/** JSON-schema fragment for a base64url string encoding exactly `n` bytes. */
export const b64Exact = (n: number) =>
  ({ type: 'string', pattern: `^[A-Za-z0-9_-]{${b64Len(n)}}$` }) as const;

/** Strict decode; throws a 400 on bad encoding or (if given) wrong length. */
export function decodeB64(s: string, length?: number): Uint8Array {
  let out: Uint8Array;
  try {
    out = fromBase64Url(s);
  } catch {
    throw httpError(400);
  }
  if (length !== undefined && out.length !== length) throw httpError(400);
  return out;
}

export const UUID_PATTERN = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
export const USERNAME_SCHEMA = { type: 'string', pattern: '^[a-z0-9_]{3,32}$' } as const;
