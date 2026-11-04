import type {
  CreateNoteRequest,
  CreateNoteResponse,
  ErrorResponse,
  OpenNoteResponse,
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

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(BASE + path, {
      method,
      // Never send cookies, never leak where the user came from, never cache.
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
      ...(body === undefined
        ? {}
        : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
    });
  } catch {
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
  return (await res.json()) as T;
}

export const api = {
  createNote: (req: CreateNoteRequest) => request<CreateNoteResponse>('POST', '/note', req),
  openNote: (id: string) =>
    request<OpenNoteResponse>('POST', `/note/${encodeURIComponent(id)}/open`),
  deleteNote: (id: string, deletionToken: string) =>
    request<void>('DELETE', `/note/${encodeURIComponent(id)}`, { deletion_token: deletionToken }),
};
