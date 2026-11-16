/**
 * Log scrubbing (plan §7). Error messages can carry data the server must not
 * write down: Node's fs errors include the full path (which contains a drop
 * id), and library errors can quote tokens, usernames or UUIDs. Only the error
 * type, its code and a scrubbed message/stack are ever logged.
 */

const PATTERNS: [RegExp, string][] = [
  // Absolute paths, quoted or bare (fs errors: "open '/data/blobs/<id>/3'").
  [/'\/[^']*'/g, "'<path>'"],
  [/(^|[\s(=:,])\/(?:[\w.@+-]+\/)*[\w.@+-]+/g, '$1<path>'],
  // UUIDs (message / user ids).
  [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<uuid>'],
  // Ids, tokens, keys: any run of 22+ base64url characters.
  [/[A-Za-z0-9_-]{22,}/g, '<id>'],
  // IPv4 / IPv6 addresses.
  [/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '<ip>'],
  [/\b(?:[0-9a-f]{1,4})?(?::{1,2}[0-9a-f]{1,4}){2,7}(?:::)?/gi, '<ip>'],
];

export function scrub(text: string): string {
  let out = text;
  for (const [re, replacement] of PATTERNS) out = out.replace(re, replacement);
  return out;
}

/** Keep stack frames but only as `at fn (<file>:line)`: no directory layout. */
function scrubStack(stack: string): string {
  return stack
    .split('\n')
    .map((line, i) =>
      i === 0 ? scrub(line) : line.replace(/\((?:file:\/\/)?\/[^)]*\/([^/)]+)\)/, '($1)'),
    )
    .slice(0, 12)
    .join('\n');
}

export type LoggedError = {
  [key: string]: unknown;
  type: string;
  code?: string;
  message: string;
  stack: string;
};

export function serializeError(err: unknown): LoggedError {
  if (!(err instanceof Error)) return { type: typeof err, message: '', stack: '' };
  const code = (err as { code?: unknown }).code;
  return {
    type: err.name,
    ...(typeof code === 'string' && /^[A-Z0-9_]{1,40}$/.test(code) ? { code } : {}),
    message: scrub(err.message).slice(0, 300),
    stack: err.stack ? scrubStack(err.stack) : '',
  };
}
