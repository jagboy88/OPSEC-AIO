-- Phase 4 (security review): chat messages are capped at 16 KiB of ciphertext
-- (was 256 KiB here, 64 KiB in the API). NOT VALID: applies to new rows only;
-- anything already queued is delivered or swept as usual.
ALTER TABLE mailbox ADD CONSTRAINT mailbox_ciphertext_16k
  CHECK (octet_length(ciphertext) <= 16384) NOT VALID;
