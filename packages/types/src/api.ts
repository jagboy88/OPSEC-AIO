/**
 * Request/response contracts for /api/v1 (docs/PLAN.md §5).
 * Binary values travel as base64url strings in JSON bodies; bulk binary
 * (drop chunks) travels as application/octet-stream.
 */

/** base64url (RFC 4648 §5, no padding). */
export type B64 = string;

export interface HealthResponse {
  status: 'ok';
}

export interface ReadyResponse {
  status: 'ok' | 'degraded';
  checks: Record<string, 'ok' | 'fail'>;
}

/** Every error response has this shape. Messages are deliberately generic. */
export interface ErrorResponse {
  error:
    | 'bad_request'
    | 'not_found'
    | 'rate_limited'
    | 'payload_too_large'
    | 'storage_full'
    | 'unauthorized'
    | 'conflict'
    | 'internal';
}

// ── Burn ────────────────────────────────────────────────────────────────────
export interface CreateNoteRequest {
  ciphertext: B64;
  expires_in: number;
  max_views: number;
}
export interface CreateNoteResponse {
  note_id: string;
  deletion_token: string;
  expires_at: string;
}
export interface OpenNoteResponse {
  ciphertext: B64;
  views_remaining: number;
}
export interface DeleteWithTokenRequest {
  deletion_token: string;
}

// ── Drop ────────────────────────────────────────────────────────────────────
// Upload:   init → PUT each chunk (Bearer upload_token) → finalize
// Download: meta → POST download (gets download_token) → GET each chunk (Bearer download_token)
export interface InitDropRequest {
  chunk_count: number;
  expires_in: number;
  /** null or absent = unlimited within the expiry. */
  max_downloads?: number | null;
  /** Opaque, client-encrypted (file name, type, size, stream header). */
  header_blob: B64;
}
export interface InitDropResponse {
  drop_id: string;
  upload_token: string;
  expires_at: string;
}
export interface FinalizeDropResponse {
  deletion_token: string;
  expires_at: string;
}
export interface DropMetaResponse {
  chunk_count: number;
  expires_at: string;
  header_blob: B64;
  downloads_remaining: number | null;
}
export interface StartDownloadResponse {
  download_token: string;
  downloads_remaining: number | null;
}
/** Either token works: deletion_token after finalize, upload_token to abort an upload. */
export interface DeleteDropRequest {
  deletion_token?: string;
  upload_token?: string;
}

// ── Auth (Phase 3) ──────────────────────────────────────────────────────────
// The passphrase never leaves the device: it only unlocks the local keystore.
// The server authenticates by Ed25519 challenge–response on `auth_pub`.
export interface PreKeyUpload {
  key_id: number;
  pub: B64;
}
export interface SignedPreKeyUpload extends PreKeyUpload {
  /** XEdDSA signature by the Signal identity key. */
  sig: B64;
}
export interface RegisterRequest {
  username: string;
  /** Ed25519 key used only for login. */
  auth_pub: B64;
  /** Signal identity key (33 bytes, type-prefixed Curve25519). */
  identity_pub: B64;
  registration_id: number;
  signed_prekey: SignedPreKeyUpload;
  one_time_prekeys: PreKeyUpload[];
}
export interface RegisterResponse {
  username: string;
}
export interface ChallengeRequest {
  username: string;
}
export interface ChallengeResponse {
  nonce: B64;
}
export interface LoginRequest {
  username: string;
  nonce: B64;
  /** Ed25519 signature over authChallengeMessage(username, nonce). */
  signature: B64;
}
export interface LoginResponse {
  session_token: string;
  expires_at: string;
}

// ── Keys (Phase 3) ──────────────────────────────────────────────────────────
export interface KeyBundleResponse {
  username: string;
  identity_pub: B64;
  registration_id: number;
  signed_prekey: SignedPreKeyUpload;
  /** null when the user has run out; X3DH then proceeds without one. */
  one_time_prekey: PreKeyUpload | null;
}
export interface PreKeyCountResponse {
  one_time_prekeys: number;
}
export interface UploadPreKeysRequest {
  one_time_prekeys: PreKeyUpload[];
}

// ── Messages (Phase 3) ──────────────────────────────────────────────────────
/** Signal message types: 3 = PreKeyWhisperMessage (first), 1 = WhisperMessage. */
export type SignalMessageType = 1 | 3;
export interface OutgoingMessage {
  to: string;
  type: SignalMessageType;
  body: B64;
}
/** Groups are pairwise fan-out: one request carries one ciphertext per member. */
export interface SendMessagesRequest {
  messages: OutgoingMessage[];
}
export interface SendMessagesResponse {
  sent: number;
}
export interface IncomingMessage {
  id: string;
  /** null if the sender has since deleted their account. */
  from: string | null;
  type: SignalMessageType;
  body: B64;
  sent_at: string;
}
export interface PendingMessagesResponse {
  messages: IncomingMessage[];
}
export interface AckRequest {
  ids: string[];
}

// WebSocket /api/v1/ws — browsers cannot set headers on WebSockets, so the
// session token is sent as the first message.
export type WsClientMessage = { type: 'auth'; token: string } | { type: 'ping' };
export type WsServerMessage =
  | { type: 'ready' }
  | { type: 'pong' }
  | { type: 'message'; message: IncomingMessage }
  | { type: 'error'; error: 'unauthorized' | 'bad_request' };
