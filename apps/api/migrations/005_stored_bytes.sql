-- Phase 4 (security review): count Drop storage by the bytes actually stored,
-- updated on every chunk upload, instead of reserving the worst case at init.
-- Reserving let anyone lock out uploads for 24 h with a few init calls that
-- never sent a byte.
ALTER TABLE drops ADD COLUMN stored_bytes bigint NOT NULL DEFAULT 0
  CHECK (stored_bytes BETWEEN 0 AND 2147518464);
UPDATE drops SET stored_bytes = size WHERE finalized;
-- Unfinished uploads are swept after a deadline (sweeper.ts).
CREATE INDEX drops_unfinalized_created_at ON drops (created_at) WHERE NOT finalized;
