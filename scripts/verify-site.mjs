#!/usr/bin/env node
// Check that a live OpSec AIO site serves exactly the web app built from this
// source tree, byte for byte. All encryption happens in that code, so this is
// how you check the server hasn't swapped it (docs/THREAT_MODEL.md §4).
//
//   pnpm install --frozen-lockfile
//   pnpm --filter "@opsec-aio/web..." build      # reproducible: same source, same hash
//   node scripts/verify-site.mjs https://your.site
//
// Compares against apps/web/build-meta/build-manifest.json (SHA-256 of every
// served file). Use --manifest <file> to compare against another manifest, and
// --insecure only for a local test stack with a self-signed certificate.
// Needs Node 20+; no dependencies.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  if (i === -1) return undefined;
  const [, value] = args.splice(i, 2);
  return value;
};
const insecure = args.includes('--insecure');
if (insecure) args.splice(args.indexOf('--insecure'), 1);
const manifestPath =
  flag('--manifest') ??
  join(dirname(fileURLToPath(import.meta.url)), '../apps/web/build-meta/build-manifest.json');
const site = args[0];
if (!site || !/^https?:\/\//.test(site)) {
  console.error(
    'usage: node scripts/verify-site.mjs https://your.site [--manifest file] [--insecure]',
  );
  process.exit(2);
}
if (insecure) process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

let manifest;
try {
  manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
} catch {
  console.error(
    `No build manifest at ${manifestPath}. Build first: pnpm --filter "@opsec-aio/web..." build`,
  );
  process.exit(2);
}

const base = new URL(site);
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const files = Object.entries(manifest.files);
const mismatched = [];
const missing = [];
let checked = 0;

// A few at a time: be gentle with the server and its rate limits.
const queue = [...files];
async function worker() {
  for (let next = queue.shift(); next; next = queue.shift()) {
    const [path, expected] = next;
    const res = await fetch(new URL(path, base), { redirect: 'follow', cache: 'no-store' });
    if (!res.ok) {
      missing.push(`${path} (HTTP ${res.status})`);
      continue;
    }
    const got = sha256(Buffer.from(await res.arrayBuffer()));
    if (got !== expected) mismatched.push(path);
    checked++;
  }
}
await Promise.all(Array.from({ length: 4 }, worker));

// The root page must be the same index.html (it pins every script by hash).
const root = await fetch(new URL('/', base), { cache: 'no-store' });
const rootOk =
  root.ok && sha256(Buffer.from(await root.arrayBuffer())) === manifest.files['/index.html'];

console.log(`Site:       ${base.origin}`);
console.log(`Build hash: ${manifest.buildHash}`);
console.log(`Checked:    ${checked}/${files.length} files`);
if (!mismatched.length && !missing.length && rootOk) {
  console.log('\n✔ MATCH: the site serves exactly this build.');
  process.exit(0);
}
console.log('\n✘ MISMATCH: the site is NOT serving this build.');
if (!rootOk) console.log('  - / differs from index.html');
for (const p of mismatched) console.log(`  - different: ${p}`);
for (const p of missing) console.log(`  - missing:   ${p}`);
console.log(
  '\nIf you built a different commit than the server runs, check out the same commit and rebuild.' +
    '\nOtherwise, do not trust this server with anything sensitive.',
);
process.exit(1);
