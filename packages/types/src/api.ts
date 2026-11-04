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
  error: 'bad_request' | 'not_found' | 'rate_limited' | 'payload_too_large' | 'internal';
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
export interface InitDropRequest {
  size: number;
  chunk_count: number;
  expires_in: number;
  max_downloads?: number;
  /** Stream header + encrypted filename/MIME metadata. */
  header_blob: B64;
}
export interface InitDropResponse {
  drop_id: string;
  upload_token: string;
  expires_at: string;
}
export interface FinalizeDropResponse {
  deletion_token: string;
}
export interface DropMetaResponse {
  size: number;
  chunk_count: number;
  expires_at: string;
  header_blob: B64;
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
