-- OpSec AIO initial schema (docs/PLAN.md §6).
-- The server stores ciphertext and the minimum metadata needed to route and
-- expire it. Limits are enforced here as well as in the API (defence in depth).

-- ── Chat accounts (Phase 3) ────────────────────────────────────────────────
CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username      text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9_]{3,32}$'),
  -- Ed25519 key used only for challenge–response login.
  auth_pub      bytea NOT NULL CHECK (octet_length(auth_pub) = 32),
  -- Signal identity key (libsignal serialises with a 1-byte type prefix).
  identity_pub  bytea NOT NULL CHECK (octet_length(identity_pub) BETWEEN 32 AND 64),
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE signed_prekeys (
  user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  key_id      integer NOT NULL CHECK (key_id >= 0),
  pub         bytea NOT NULL CHECK (octet_length(pub) BETWEEN 32 AND 64),
  sig         bytea NOT NULL CHECK (octet_length(sig) = 64),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, key_id)
);

CREATE TABLE one_time_prekeys (
  user_id  uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  key_id   integer NOT NULL CHECK (key_id >= 0),
  pub      bytea NOT NULL CHECK (octet_length(pub) BETWEEN 32 AND 64),
  PRIMARY KEY (user_id, key_id)
);

CREATE TABLE sessions (
  token_hash  bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  expires_at  timestamptz NOT NULL
);
CREATE INDEX sessions_expires_at ON sessions (expires_at);

-- Relay mailbox: rows are deleted on ACK; anything older than 30 days is swept.
CREATE TABLE mailbox (
  id          uuid PRIMARY KEY,
  to_user     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  -- Nullable so sealed sender (v1.1) can drop it without a table rewrite.
  from_user   uuid REFERENCES users (id) ON DELETE SET NULL,
  header      bytea NOT NULL,
  ciphertext  bytea NOT NULL CHECK (octet_length(ciphertext) <= 262144),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mailbox_to_user ON mailbox (to_user, created_at);
CREATE INDEX mailbox_created_at ON mailbox (created_at);

-- ── Drop (Phase 2) ─────────────────────────────────────────────────────────
CREATE TABLE drops (
  id                   text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{22}$'),
  size                 bigint NOT NULL CHECK (size BETWEEN 0 AND 2147483648),
  chunk_count          integer NOT NULL CHECK (chunk_count BETWEEN 1 AND 2049),
  header_blob          bytea NOT NULL CHECK (octet_length(header_blob) <= 4096),
  created_at           timestamptz NOT NULL DEFAULT now(),
  expires_at           timestamptz NOT NULL,
  max_downloads        integer CHECK (max_downloads IS NULL OR max_downloads >= 1),
  downloads            integer NOT NULL DEFAULT 0 CHECK (downloads >= 0),
  finalized            boolean NOT NULL DEFAULT false,
  upload_token_hash    bytea NOT NULL CHECK (octet_length(upload_token_hash) = 32),
  deletion_token_hash  bytea NOT NULL CHECK (octet_length(deletion_token_hash) = 32),
  -- The 24-hour rule, enforced by the database itself.
  CONSTRAINT drops_max_24h CHECK (expires_at > created_at AND expires_at <= created_at + interval '24 hours')
);
CREATE INDEX drops_expires_at ON drops (expires_at);

-- ── Burn (Phase 1) ─────────────────────────────────────────────────────────
CREATE TABLE notes (
  id                   text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{22}$'),
  ciphertext           bytea NOT NULL CHECK (octet_length(ciphertext) <= 66560),
  created_at           timestamptz NOT NULL DEFAULT now(),
  expires_at           timestamptz NOT NULL,
  max_views            integer NOT NULL DEFAULT 1 CHECK (max_views BETWEEN 1 AND 5),
  views                integer NOT NULL DEFAULT 0 CHECK (views >= 0 AND views < max_views),
  deletion_token_hash  bytea NOT NULL CHECK (octet_length(deletion_token_hash) = 32),
  CONSTRAINT notes_max_30d CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days')
);
CREATE INDEX notes_expires_at ON notes (expires_at);
