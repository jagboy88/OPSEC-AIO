-- Phase 4 (security review): limit how fast anyone can drain a user's one-time
-- prekeys. Past the hourly limit, bundles are still served (so nobody can be
-- made unreachable), just without a one-time prekey; X3DH then uses the signed
-- prekey alone. Only a count and the start of the current hour window are kept.
ALTER TABLE users
  ADD COLUMN otpk_window_start timestamptz NOT NULL DEFAULT '-infinity',
  ADD COLUMN otpk_window_count integer NOT NULL DEFAULT 0 CHECK (otpk_window_count >= 0);
