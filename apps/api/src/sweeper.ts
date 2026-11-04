import type { FastifyBaseLogger } from 'fastify';
import type { Pool } from './db.js';

export interface SweepResult {
  notes: number;
  mailbox: number;
  sessions: number;
}

/**
 * Delete everything past its lifetime. Reads already refuse expired rows, so
 * this is about not *keeping* data, not about access control. Only counts are
 * returned or logged, never ids (plan §4.2).
 *
 * Note: Postgres frees deleted tuples lazily (autovacuum) and SSDs do not
 * overwrite in place. The real deletion guarantee is that the server never had
 * the keys; this sweeper limits how long even ciphertext lingers.
 */
export async function sweep(pool: Pool): Promise<SweepResult> {
  const notes = await pool.query('DELETE FROM notes WHERE expires_at <= now()');
  const mailbox = await pool.query(
    "DELETE FROM mailbox WHERE created_at <= now() - interval '30 days'",
  );
  const sessions = await pool.query('DELETE FROM sessions WHERE expires_at <= now()');
  return {
    notes: notes.rowCount ?? 0,
    mailbox: mailbox.rowCount ?? 0,
    sessions: sessions.rowCount ?? 0,
  };
}

/** Run {@link sweep} now and then every `intervalMs` (default 5 min). Returns a stop function. */
export function startSweeper(
  pool: Pool,
  log: FastifyBaseLogger,
  intervalMs = 5 * 60_000,
): () => void {
  let running = false;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      const r = await sweep(pool);
      if (r.notes || r.mailbox || r.sessions) log.info({ swept: r }, 'expired data deleted');
    } catch {
      log.warn('sweeper run failed');
    } finally {
      running = false;
    }
  };
  void tick();
  const timer = setInterval(() => void tick(), intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}
