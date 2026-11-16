/**
 * Product limits. These are the decisions recorded in docs/PLAN.md §10 —
 * change them there first, then here. The server enforces every limit; the
 * client uses them for UX only.
 */

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export const API_PREFIX = '/api/v1';

// ── Drop ────────────────────────────────────────────────────────────────────
/** Max plaintext file size: 2 GiB. */
export const DROP_MAX_BYTES = 2 * 1024 * 1024 * 1024;
/** Hard ceiling: no drop survives longer than 24h, no exceptions. */
export const DROP_MAX_TTL_SECONDS = 24 * HOUR;
export const DROP_EXPIRY_OPTIONS_SECONDS = [1 * HOUR, 6 * HOUR, 12 * HOUR, 24 * HOUR] as const;
export const DROP_DEFAULT_TTL_SECONDS = 24 * HOUR;
/** Plaintext bytes per chunk; matches STREAM_CHUNK_SIZE in @opsec-aio/crypto. */
export const DROP_CHUNK_BYTES = 1024 * 1024;
/** secretstream overhead per chunk. */
export const DROP_CHUNK_OVERHEAD = 17;
export const DROP_MAX_CHUNKS = DROP_MAX_BYTES / DROP_CHUNK_BYTES;
export const DROP_HEADER_BLOB_MAX_BYTES = 4096;
/** Download limit choices offered to uploaders; null = unlimited within the TTL. */
export const DROP_MAX_DOWNLOAD_OPTIONS = [1, 2, 3, 5, 10, null] as const;
export const DROP_MAX_DOWNLOADS_LIMIT = 100;
/** A started download may take this long to fetch all chunks (never beyond the drop's expiry). */
export const DROP_DOWNLOAD_WINDOW_SECONDS = 6 * HOUR;
/** Anonymous uploads allowed (decision #4). */
export const DROP_ANONYMOUS_UPLOADS = true;

// ── Burn ────────────────────────────────────────────────────────────────────
/** Max plaintext note size: 64 KiB. */
export const NOTE_MAX_PLAINTEXT_BYTES = 64 * 1024;
/** Text + 1 KiB padding + password wrap + two AEAD envelopes, rounded up to 68 KiB. */
export const NOTE_MAX_CIPHERTEXT_BYTES = 68 * 1024;
/** One bare AEAD envelope (header 2 + nonce 24 + tag 16). */
export const NOTE_MIN_CIPHERTEXT_BYTES = 42;
export const NOTE_EXPIRY_OPTIONS_SECONDS = [1 * HOUR, 1 * DAY, 7 * DAY, 30 * DAY] as const;
export const NOTE_DEFAULT_TTL_SECONDS = 7 * DAY;
export const NOTE_MAX_TTL_SECONDS = 30 * DAY;
export const NOTE_DEFAULT_MAX_VIEWS = 1;
export const NOTE_MAX_VIEWS = 5;

// ── Chat ────────────────────────────────────────────────────────────────────
/** Disappearing-message timer options in seconds; 0 = off. */
export const DISAPPEARING_TIMER_OPTIONS_SECONDS = [
  0,
  30,
  5 * MINUTE,
  1 * HOUR,
  8 * HOUR,
  1 * DAY,
  7 * DAY,
  30 * DAY,
] as const;
/** Default for new conversations: off (decision #9). */
export const DISAPPEARING_DEFAULT_SECONDS = 0;
/** In groups any member may change the timer; the change is announced in-chat (decision #9). */
export const DISAPPEARING_GROUP_ANY_MEMBER_MAY_CHANGE = true;
export const GROUP_MAX_MEMBERS = 20;
export const ONE_TIME_PREKEY_BATCH = 100;
/** Undelivered mailbox ciphertext is swept after 30 days. */
export const MAILBOX_MAX_AGE_SECONDS = 30 * DAY;
/** Generated usernames allowed (decision #6). */
export const CHAT_ANONYMOUS_USERNAMES = true;
export const USERNAME_PATTERN = /^[a-z0-9_]{3,32}$/;
/** Max one-time prekeys stored per user. */
export const ONE_TIME_PREKEY_MAX = 300;
/** Login sessions are short: the client can always re-authenticate with its key. */
export const SESSION_TTL_SECONDS = 24 * HOUR;
export const AUTH_CHALLENGE_TTL_SECONDS = 2 * MINUTE;
/**
 * Max ciphertext per chat message. Files go through Drop, not the mailbox.
 * Fits the longest allowed text (4000 characters, up to 3 UTF-8 bytes each)
 * plus padding and Signal overhead.
 */
export const CHAT_MESSAGE_MAX_BYTES = 16 * 1024;
/** Max ciphertexts per send request (one per group member). */
export const CHAT_BATCH_MAX = GROUP_MAX_MEMBERS;
/** Max undelivered messages queued for one recipient. */
export const CHAT_MAILBOX_MAX = 5000;
/** Messages returned per `GET /messages/pending` page (and max ids per ACK). */
export const CHAT_PENDING_PAGE = 200;

// ── Rate limits (per IP unless stated) ──────────────────────────────────────
export const RATE_LIMITS = {
  register: { max: 5, windowSeconds: HOUR },
  dropUpload: { max: 20, windowSeconds: HOUR },
  noteCreate: { max: 60, windowSeconds: HOUR },
  noteOpen: { max: 60, windowSeconds: MINUTE },
  noteDelete: { max: 30, windowSeconds: MINUTE },
  dropMeta: { max: 60, windowSeconds: MINUTE },
  dropDownload: { max: 30, windowSeconds: MINUTE },
  dropDelete: { max: 30, windowSeconds: MINUTE },
  authChallenge: { max: 30, windowSeconds: MINUTE },
  authLogin: { max: 30, windowSeconds: MINUTE },
  keyBundle: { max: 60, windowSeconds: MINUTE },
  messageSend: { max: 240, windowSeconds: MINUTE },
  messagePending: { max: 120, windowSeconds: MINUTE },
} as const;
