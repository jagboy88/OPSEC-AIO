/**
 * Integration tests against a real Postgres. Skipped unless TEST_DATABASE_URL
 * is set (CI provides one; locally: `docker compose up -d postgres`).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MIGRATIONS_DIR, createPool, migrate, type Pool } from '../src/db.js';

const url = process.env.TEST_DATABASE_URL;
const ID = 'AAAAAAAAAAAAAAAAAAAAAA';
const HASH = Buffer.alloc(32, 1);

describe.skipIf(!url)('migrations (postgres)', () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = createPool(url!);
    await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
  });
  afterAll(() => pool?.end());

  it('applies cleanly and is idempotent', async () => {
    expect(await migrate(pool, MIGRATIONS_DIR)).toEqual([
      '001_init.sql',
      '002_note_size.sql',
      '003_drops.sql',
      '004_chat.sql',
      '005_stored_bytes.sql',
      '006_mailbox_limits.sql',
      '007_prekey_handout.sql',
    ]);
    expect(await migrate(pool, MIGRATIONS_DIR)).toEqual([]);
  });

  it('enforces the 24h drop ceiling in the database', async () => {
    const insert = (ttl: string) =>
      pool.query(
        `INSERT INTO drops (id, size, chunk_count, header_blob, expires_at, upload_token_hash, deletion_token_hash)
         VALUES ($1, 1, 1, '\\x00', now() + $2::interval, $3, $3)`,
        [ID, ttl, HASH],
      );
    await expect(insert('25 hours')).rejects.toThrow(/drops_max_24h/);
    await insert('24 hours');
    await pool.query('DELETE FROM drops');
  });

  it('enforces the 30-day note ceiling and the 5-view cap', async () => {
    const insert = (ttl: string, views: number) =>
      pool.query(
        `INSERT INTO notes (id, ciphertext, expires_at, max_views, deletion_token_hash)
         VALUES ($1, decode(repeat('00', 42), 'hex'), now() + $2::interval, $3, $4)`,
        [ID, ttl, views, HASH],
      );
    await expect(insert('31 days', 1)).rejects.toThrow(/notes_max_30d/);
    await expect(insert('1 day', 6)).rejects.toThrow(/max_views/);
    await insert('30 days', 5);
    await pool.query('DELETE FROM notes');
  });

  it('enforces the note ciphertext size bounds (migration 002)', async () => {
    const insert = (bytes: number) =>
      pool.query(
        `INSERT INTO notes (id, ciphertext, expires_at, deletion_token_hash)
         VALUES ($1, decode(repeat('00', $2), 'hex'), now() + interval '1 hour', $3)`,
        [ID, bytes, HASH],
      );
    await expect(insert(41)).rejects.toThrow(/notes_ciphertext_size/);
    await expect(insert(69633)).rejects.toThrow(/notes_ciphertext_size/);
    await insert(69632);
    await pool.query('DELETE FROM notes');
  });

  it('rejects malformed ids', async () => {
    await expect(
      pool.query(
        `INSERT INTO notes (id, ciphertext, expires_at, deletion_token_hash) VALUES ('../x', decode(repeat('00', 42), 'hex'), now() + interval '1 hour', $1)`,
        [HASH],
      ),
    ).rejects.toThrow(/notes_id_check/);
  });
});
