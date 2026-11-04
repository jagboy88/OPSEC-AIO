import { loadConfig } from './config.js';
import { MIGRATIONS_DIR, createPool, migrate } from './db.js';

const config = loadConfig();
const pool = createPool(config.databaseUrl);
try {
  const applied = await migrate(pool, MIGRATIONS_DIR);
  console.log(applied.length ? `applied: ${applied.join(', ')}` : 'up to date');
} finally {
  await pool.end();
}
