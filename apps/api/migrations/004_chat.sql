-- Phase 3: Chat. No chat data has been stored by any earlier release, so the
-- tables from 001 can be tightened in place.

-- Signal identity keys are 33 bytes (0x05 type prefix + Curve25519 point).
ALTER TABLE users DROP CONSTRAINT users_identity_pub_check;
ALTER TABLE users ADD CONSTRAINT users_identity_pub_len CHECK (octet_length(identity_pub) = 33);
ALTER TABLE users ADD COLUMN registration_id integer NOT NULL
  CHECK (registration_id BETWEEN 1 AND 16383);

ALTER TABLE signed_prekeys DROP CONSTRAINT signed_prekeys_pub_check;
ALTER TABLE signed_prekeys ADD CONSTRAINT signed_prekeys_pub_len CHECK (octet_length(pub) = 33);
ALTER TABLE one_time_prekeys DROP CONSTRAINT one_time_prekeys_pub_check;
ALTER TABLE one_time_prekeys ADD CONSTRAINT one_time_prekeys_pub_len CHECK (octet_length(pub) = 33);

-- Single-use login challenges (deleted on use; swept when expired).
CREATE TABLE auth_challenges (
  nonce       bytea PRIMARY KEY CHECK (octet_length(nonce) = 32),
  user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  expires_at  timestamptz NOT NULL
);
CREATE INDEX auth_challenges_expires_at ON auth_challenges (expires_at);

-- Mailbox rows carry the Signal message type; the old free-form header goes.
-- Ids are server-generated (the client's own message id lives inside the
-- encrypted payload).
ALTER TABLE mailbox DROP COLUMN header;
ALTER TABLE mailbox ADD COLUMN msg_type smallint NOT NULL CHECK (msg_type IN (1, 3));
ALTER TABLE mailbox ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE mailbox DROP CONSTRAINT mailbox_ciphertext_check;
ALTER TABLE mailbox ADD CONSTRAINT mailbox_ciphertext_size
  CHECK (octet_length(ciphertext) BETWEEN 1 AND 65536);
