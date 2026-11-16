import type { FastifyBaseLogger } from 'fastify';
import type { BlobStore } from './blobs.js';
import type { Pool } from './db.js';

/** An upload must be finalized within this long, or it is deleted. */
export const DROP_UPLOAD_DEADLINE_SECONDS = 6 * 3600;

export interface SweepResult {
  notes: number;
  drops: number;
  /** Blob directories with no database row (e.g. after a crash mid-delete). */
  orphanBlobs: number;
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
 * the keys; the sweeper limits how long even ciphertext lingers.
 */
export async function sweep(pool: Pool, blobs?: BlobStore): Promise<SweepResult> {
  const notes = await pool.query('DELETE FROM notes WHERE expires_at <= now()');

  await pool.query('DELETE FROM drop_downloads WHERE expires_at <= now()');
  // Expired drops; uploads never finished within the deadline (they hold
  // storage but can never be downloaded); and drops whose download limit is
  // used up and that have no download still in progress.
  const drops = await pool.query<{ id: string }>(
    `DELETE FROM drops d WHERE d.expires_at <= now()
       OR (NOT d.finalized AND d.created_at <= now() - make_interval(secs => $1))
       OR (d.max_downloads IS NOT NULL AND d.downloads >= d.max_downloads
           AND NOT EXISTS (SELECT 1 FROM drop_downloads t WHERE t.drop_id = d.id))
     RETURNING id`,
    [DROP_UPLOAD_DEADLINE_SECONDS],
  );
  let orphanBlobs = 0;
  if (blobs) {
    for (const { id } of drops.rows) await blobs.remove(id);
    const stored = await blobs.list();
    if (stored.length) {
      const { rows } = await pool.query<{ id: string }>(
        'SELECT id FROM drops WHERE id = ANY($1::text[])',
        [stored],
      );
      const live = new Set(rows.map((r) => r.id));
      for (const id of stored) {
        if (!live.has(id)) {
          await blobs.remove(id);
          orphanBlobs++;
        }
      }
    }
  }

  const mailbox = await pool.query(
    "DELETE FROM mailbox WHERE created_at <= now() - interval '30 days'",
  );
  const sessions = await pool.query('DELETE FROM sessions WHERE expires_at <= now()');
  await pool.query('DELETE FROM auth_challenges WHERE expires_at <= now()');
  return {
    notes: notes.rowCount ?? 0,
    drops: drops.rowCount ?? 0,
    orphanBlobs,
    mailbox: mailbox.rowCount ?? 0,
    sessions: sessions.rowCount ?? 0,
  };
}

/**
 * Run {@link sweep} now and then every `intervalMs` (default 1 minute, so a
 * drop outlives its 24 h deadline on disk by at most about a minute).
 * Returns a stop function.
 */
export function startSweeper(
  pool: Pool,
  log: FastifyBaseLogger,
  blobs?: BlobStore,
  intervalMs = 60_000,
): () => void {
  let running = false;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      const r = await sweep(pool, blobs);
      if (Object.values(r).some((n) => n > 0)) log.info({ swept: r }, 'expired data deleted');
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
