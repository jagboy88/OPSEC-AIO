import type {
  CreateNoteRequest,
  CreateNoteResponse,
  DeleteDropRequest,
  DropMetaResponse,
  ErrorResponse,
  FinalizeDropResponse,
  InitDropRequest,
  InitDropResponse,
  OpenNoteResponse,
  StartDownloadResponse,
} from '@opsec-aio/types';

const BASE = '/api/v1';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorResponse['error'] | 'network',
  ) {
    super(code);
    this.name = 'ApiError';
  }
}

interface RequestOptions {
  json?: unknown;
  bytes?: Uint8Array;
  token?: string;
  signal?: AbortSignal;
  /** Return the response body as bytes instead of JSON. */
  binary?: boolean;
}

async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {};
  let body: BodyInit | undefined;
  if (opts.json !== undefined) {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(opts.json);
  } else if (opts.bytes) {
    headers['content-type'] = 'application/octet-stream';
    body = opts.bytes as Uint8Array<ArrayBuffer>;
  }
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;

  let res: Response;
  try {
    res = await fetch(BASE + path, {
      method,
      headers,
      ...(body === undefined ? {} : { body }),
      ...(opts.signal ? { signal: opts.signal } : {}),
      // Never send cookies, never leak where the user came from, never cache.
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'network');
  }
  if (res.status === 204) return undefined as T;
  if (!res.ok) {
    let code: ErrorResponse['error'] = 'internal';
    try {
      code = ((await res.json()) as ErrorResponse).error ?? code;
    } catch {
      /* non-JSON error (e.g. proxy) */
    }
    throw new ApiError(res.status, code);
  }
  if (opts.binary) return new Uint8Array(await res.arrayBuffer()) as T;
  return (await res.json()) as T;
}

const enc = encodeURIComponent;

export const api = {
  createNote: (req: CreateNoteRequest) =>
    request<CreateNoteResponse>('POST', '/note', { json: req }),
  openNote: (id: string) => request<OpenNoteResponse>('POST', `/note/${enc(id)}/open`),
  deleteNote: (id: string, deletionToken: string) =>
    request<void>('DELETE', `/note/${enc(id)}`, { json: { deletion_token: deletionToken } }),

  initDrop: (req: InitDropRequest) =>
    request<InitDropResponse>('POST', '/drop/init', { json: req }),
  putChunk: (id: string, n: number, bytes: Uint8Array, uploadToken: string, signal?: AbortSignal) =>
    request<void>('PUT', `/drop/${enc(id)}/chunk/${n}`, {
      bytes,
      token: uploadToken,
      ...(signal ? { signal } : {}),
    }),
  finalizeDrop: (id: string, uploadToken: string) =>
    request<FinalizeDropResponse>('POST', `/drop/${enc(id)}/finalize`, { token: uploadToken }),
  dropMeta: (id: string) => request<DropMetaResponse>('GET', `/drop/${enc(id)}/meta`),
  startDownload: (id: string) =>
    request<StartDownloadResponse>('POST', `/drop/${enc(id)}/download`),
  getChunk: (id: string, n: number, downloadToken: string) =>
    request<Uint8Array>('GET', `/drop/${enc(id)}/chunk/${n}`, {
      token: downloadToken,
      binary: true,
    }),
  deleteDrop: (id: string, req: DeleteDropRequest) =>
    request<void>('DELETE', `/drop/${enc(id)}`, { json: req }),
};

/** Retry transient failures (network errors, 5xx) with backoff; never retry 4xx. */
export async function withRetry<T>(fn: () => Promise<T>, attempts = 4): Promise<T> {
  for (let i = 0; ; i++) {
    try {
      return await fn();
    } catch (e) {
      const transient = e instanceof ApiError && (e.status === 0 || e.status >= 500);
      if (!transient || i >= attempts - 1) throw e;
      await new Promise((r) => setTimeout(r, 500 * 2 ** i));
    }
  }
}
