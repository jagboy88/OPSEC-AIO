-- Phase 2: Drop.
-- `size` is now the total *ciphertext* size, known only once all chunks are in
-- (set at finalize). 2 GiB of padded plaintext + 17 bytes per chunk × 2048 chunks.
ALTER TABLE drops DROP CONSTRAINT drops_size_check;
ALTER TABLE drops ALTER COLUMN size SET DEFAULT 0;
ALTER TABLE drops ADD CONSTRAINT drops_size_bounds CHECK (size BETWEEN 0 AND 2147518464);
ALTER TABLE drops DROP CONSTRAINT drops_chunk_count_check;
ALTER TABLE drops ADD CONSTRAINT drops_chunk_count_bounds CHECK (chunk_count BETWEEN 1 AND 2048);
ALTER TABLE drops ADD CONSTRAINT drops_max_downloads_bounds
  CHECK (max_downloads IS NULL OR max_downloads BETWEEN 1 AND 100);

-- One row per started download. Chunks are served only to a holder of a live
-- token, so a download limit cannot be bypassed by fetching chunks directly.
CREATE TABLE drop_downloads (
  token_hash  bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  drop_id     text NOT NULL REFERENCES drops (id) ON DELETE CASCADE,
  expires_at  timestamptz NOT NULL
);
CREATE INDEX drop_downloads_drop_id ON drop_downloads (drop_id);
CREATE INDEX drop_downloads_expires_at ON drop_downloads (expires_at);
