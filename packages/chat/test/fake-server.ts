import {
  authChallengeMessage,
  fromBase64Url,
  randomBytes,
  randomId,
  toBase64Url,
  verify,
} from '@opsec-aio/crypto';
import type {
  IncomingMessage,
  KeyBundleResponse,
  LoginRequest,
  OutgoingMessage,
  PreKeyUpload,
  RegisterRequest,
  SignedPreKeyUpload,
} from '@opsec-aio/types';
import { ChatServerError, type ChatServer } from '../src/server.js';

interface User {
  reg: RegisterRequest;
  spk: SignedPreKeyUpload;
  otpks: PreKeyUpload[];
}

/**
 * In-memory stand-in for the API with the same semantics (single-use
 * challenges, one-time prekeys handed out once, recipient-only ACK). The real
 * HTTP server is covered by apps/api/test/chat-e2e.test.ts.
 */
export class FakeChatServer implements ChatServer {
  users = new Map<string, User>();
  mailbox: (IncomingMessage & { to: string })[] = [];
  private challenges = new Map<string, string>(); // nonce → username
  private tokens = new Map<string, string>(); // token → username

  private who(token: string): string {
    const u = this.tokens.get(token);
    if (!u || !this.users.has(u)) throw new ChatServerError(401, 'unauthorized');
    return u;
  }

  async register(req: RegisterRequest) {
    if (this.users.has(req.username)) throw new ChatServerError(409, 'conflict');
    this.users.set(req.username, {
      reg: req,
      spk: req.signed_prekey,
      otpks: [...req.one_time_prekeys],
    });
  }
  async challenge(username: string) {
    const nonce = toBase64Url(randomBytes(32));
    if (this.users.has(username)) this.challenges.set(nonce, username);
    return nonce;
  }
  async login(req: LoginRequest) {
    const owner = this.challenges.get(req.nonce);
    this.challenges.delete(req.nonce);
    const user = this.users.get(req.username);
    if (
      owner !== req.username ||
      !user ||
      !verify(
        fromBase64Url(req.signature),
        authChallengeMessage(req.username, fromBase64Url(req.nonce)),
        fromBase64Url(user.reg.auth_pub),
      )
    ) {
      throw new ChatServerError(401, 'unauthorized');
    }
    const token = toBase64Url(randomBytes(32));
    this.tokens.set(token, req.username);
    return { session_token: token, expires_at: new Date(Date.now() + 86_400_000).toISOString() };
  }
  async logout(token: string) {
    this.tokens.delete(token);
  }
  async deleteAccount(token: string) {
    const u = this.who(token);
    this.users.delete(u);
    this.mailbox = this.mailbox
      .filter((m) => m.to !== u)
      .map((m) => (m.from === u ? { ...m, from: null } : m));
  }
  async bundle(token: string, username: string): Promise<KeyBundleResponse> {
    this.who(token);
    const u = this.users.get(username);
    if (!u) throw new ChatServerError(404, 'not_found');
    return {
      username,
      identity_pub: u.reg.identity_pub,
      registration_id: u.reg.registration_id,
      signed_prekey: u.spk,
      one_time_prekey: u.otpks.shift() ?? null,
    };
  }
  async preKeyCount(token: string) {
    return this.users.get(this.who(token))!.otpks.length;
  }
  async uploadPreKeys(token: string, keys: PreKeyUpload[]) {
    this.users.get(this.who(token))!.otpks.push(...keys);
  }
  async putSignedPreKey(token: string, spk: SignedPreKeyUpload) {
    this.users.get(this.who(token))!.spk = spk;
  }
  async userExists(token: string, username: string) {
    this.who(token);
    return this.users.has(username);
  }
  async send(token: string, messages: OutgoingMessage[]) {
    const from = this.who(token);
    if (messages.some((m) => !this.users.has(m.to))) throw new ChatServerError(404, 'not_found');
    for (const m of messages) {
      this.mailbox.push({
        id: randomId(),
        to: m.to,
        from,
        type: m.type,
        body: m.body,
        sent_at: new Date().toISOString(),
      });
    }
  }
  async pending(token: string) {
    const u = this.who(token);
    return this.mailbox.filter((m) => m.to === u).map(({ to: _to, ...m }) => m);
  }
  async ack(token: string, ids: string[]) {
    const u = this.who(token);
    this.mailbox = this.mailbox.filter((m) => !(m.to === u && ids.includes(m.id)));
  }
}
