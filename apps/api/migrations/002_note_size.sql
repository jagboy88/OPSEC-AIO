-- Phase 1: room for 1 KiB padding blocks plus the password-wrapped key.
-- Max = 64 KiB text + padding + wrap + two AEAD envelopes, rounded up to 68 KiB.
-- Min = one bare AEAD envelope (header 2 + nonce 24 + tag 16).
ALTER TABLE notes DROP CONSTRAINT notes_ciphertext_check;
ALTER TABLE notes ADD CONSTRAINT notes_ciphertext_size
  CHECK (octet_length(ciphertext) BETWEEN 42 AND 69632);
