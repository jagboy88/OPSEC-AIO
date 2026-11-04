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

// ── Auth / keys (Phase 3) ───────────────────────────────────────────────────
export interface RegisterRequest {
  username: string;
  /** Ed25519 key used only for challenge–response login. */
  auth_pub: B64;
  /** Signal identity key. */
  identity_pub: B64;
  signed_prekey: { key_id: number; pub: B64; sig: B64 };
  one_time_prekeys: { key_id: number; pub: B64 }[];
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
  signature: B64;
}
export interface LoginResponse {
  session_token: string;
}

// ── Chat (Phase 3) ──────────────────────────────────────────────────────────
export interface SendMessageRequest {
  to: string;
  msg_id: string;
  header: B64;
  ciphertext: B64;
}
export interface AckRequest {
  msg_ids: string[];
}
