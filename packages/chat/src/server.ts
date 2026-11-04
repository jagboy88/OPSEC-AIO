import type {
  ErrorResponse,
  IncomingMessage,
  KeyBundleResponse,
  LoginRequest,
  LoginResponse,
  OutgoingMessage,
  PreKeyUpload,
  RegisterRequest,
  SignedPreKeyUpload,
} from '@opsec-aio/types';

/** Everything the chat client needs from the server (see apps/api routes). */
export interface ChatServer {
  register(req: RegisterRequest): Promise<void>;
  challenge(username: string): Promise<string>;
  login(req: LoginRequest): Promise<LoginResponse>;
  logout(token: string): Promise<void>;
  deleteAccount(token: string): Promise<void>;
  bundle(token: string, username: string): Promise<KeyBundleResponse>;
  preKeyCount(token: string): Promise<number>;
  uploadPreKeys(token: string, keys: PreKeyUpload[]): Promise<void>;
  putSignedPreKey(token: string, spk: SignedPreKeyUpload): Promise<void>;
  userExists(token: string, username: string): Promise<boolean>;
  send(token: string, messages: OutgoingMessage[]): Promise<void>;
  pending(token: string): Promise<IncomingMessage[]>;
  ack(token: string, ids: string[]): Promise<void>;
}

export class ChatServerError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorResponse['error'] | 'network',
  ) {
    super(code);
    this.name = 'ChatServerError';
  }
}

type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

/** HTTP implementation over `fetch` (browser) or any fetch-compatible function (tests). */
export class HttpChatServer implements ChatServer {
  constructor(
    private readonly fetchFn: FetchFn = (i, o) => fetch(i, o),
    private readonly base = '/api/v1',
  ) {}

  private async req<T>(
    method: string,
    path: string,
    opts: { token?: string; json?: unknown } = {},
  ): Promise<T> {
    const headers: Record<string, string> = {};
    if (opts.token) headers.authorization = `Bearer ${opts.token}`;
    if (opts.json !== undefined) headers['content-type'] = 'application/json';
    let res: Response;
    try {
      res = await this.fetchFn(this.base + path, {
        method,
        headers,
        ...(opts.json !== undefined ? { body: JSON.stringify(opts.json) } : {}),
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        cache: 'no-store',
      });
    } catch {
      throw new ChatServerError(0, 'network');
    }
    if (res.status === 204) return undefined as T;
    if (!res.ok) {
      let code: ErrorResponse['error'] = 'internal';
      try {
        code = ((await res.json()) as ErrorResponse).error ?? code;
      } catch {
        /* non-JSON */
      }
      throw new ChatServerError(res.status, code);
    }
    return (await res.json()) as T;
  }

  async register(req: RegisterRequest) {
    await this.req('POST', '/auth/register', { json: req });
  }
  async challenge(username: string) {
    return (await this.req<{ nonce: string }>('POST', '/auth/challenge', { json: { username } }))
      .nonce;
  }
  login(req: LoginRequest) {
    return this.req<LoginResponse>('POST', '/auth/login', { json: req });
  }
  async logout(token: string) {
    await this.req('POST', '/auth/logout', { token });
  }
  async deleteAccount(token: string) {
    await this.req('DELETE', '/auth/account', { token });
  }
  bundle(token: string, username: string) {
    return this.req<KeyBundleResponse>('GET', `/keys/bundle/${encodeURIComponent(username)}`, {
      token,
    });
  }
  async preKeyCount(token: string) {
    return (await this.req<{ one_time_prekeys: number }>('GET', '/keys/count', { token }))
      .one_time_prekeys;
  }
  async uploadPreKeys(token: string, keys: PreKeyUpload[]) {
    await this.req('POST', '/keys/prekeys', { token, json: { one_time_prekeys: keys } });
  }
  async putSignedPreKey(token: string, spk: SignedPreKeyUpload) {
    await this.req('PUT', '/keys/signed-prekey', { token, json: spk });
  }
  async userExists(token: string, username: string) {
    try {
      await this.req('GET', `/users/${encodeURIComponent(username)}`, { token });
      return true;
    } catch (e) {
      if (e instanceof ChatServerError && e.status === 404) return false;
      throw e;
    }
  }
  async send(token: string, messages: OutgoingMessage[]) {
    await this.req('POST', '/messages', { token, json: { messages } });
  }
  async pending(token: string) {
    return (await this.req<{ messages: IncomingMessage[] }>('GET', '/messages/pending', { token }))
      .messages;
  }
  async ack(token: string, ids: string[]) {
    if (ids.length) await this.req('POST', '/messages/ack', { token, json: { ids } });
  }
}
