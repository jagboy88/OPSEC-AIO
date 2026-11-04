# OpSec AIO — Build Plan

> **Purpose of this document:** A complete, self-contained spec to hand to Claude (or any engineer) to build the OpSec AIO platform from scratch. All `[DECIDE]` items were resolved on 2026-11-04 — see §10 for the decisions and §12 for where the implementation deliberately deviates from the original text.

---

## 1. Product summary

**Brand:** OpSec AIO ("all-in-one")
**One-liner:** A zero-knowledge privacy suite — encrypted chat, ephemeral encrypted file drops, and burn-after-reading notes — where the server never has the ability to read anything.

**Core principle: zero-knowledge.** All encryption and decryption happens in the user's browser. The server stores only ciphertext and metadata it strictly needs to function. If the server (or the VPS host, or a subpoena) gets a full copy of the database and disk, nothing meaningful is recoverable.

**Three modules (v1):**

| Module                 | What it does                                                          | Lifetime                                                  |
| ---------------------- | --------------------------------------------------------------------- | --------------------------------------------------------- |
| **Chat**               | 1:1 and small-group messaging with Signal-grade end-to-end encryption | Until deleted by users; optional disappearing timer       |
| **Drop** (file upload) | Upload an encrypted file, get a share link                            | Hard-deleted 24h after upload, no exceptions              |
| **Burn** (notes)       | Write a note, get a link; note is destroyed the moment it is read     | Deleted on first view, or after a max TTL if never viewed |

---

## 2. Cryptography decisions

### 2.1 Summary table

| Need                                                  | Choice                                                                                                                         | Why                                                                                                                                                                                                                                                          |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Symmetric encryption (files, notes, message payloads) | **XChaCha20-Poly1305** (primary) via libsodium; **AES-256-GCM** via WebCrypto as fallback / option                             | XChaCha20 has a 192-bit nonce so random nonces are safe at scale, constant-time in software, no hardware dependence. AES-256-GCM is the "AES" option the user asked for and is hardware-accelerated; both are AEAD and both are considered state of the art. |
| Key agreement                                         | **X25519**                                                                                                                     | Signal standard, fast, safe curve                                                                                                                                                                                                                            |
| Signatures / identity                                 | **Ed25519**                                                                                                                    | Pairs with X25519, libsodium native                                                                                                                                                                                                                          |
| Chat protocol                                         | **Signal Protocol: X3DH (PQXDH) + Double Ratchet** via `@signalapp/libsignal-client` (WASM) or `libsignal-protocol-javascript` | Forward secrecy + post-compromise security; don't reinvent this                                                                                                                                                                                              |
| Password → key derivation                             | **Argon2id** (memory 64–128 MiB, iterations 3, parallelism 1)                                                                  | Current best practice; resists GPU/ASIC attacks                                                                                                                                                                                                              |
| Hashing / HMAC                                        | **BLAKE2b** (libsodium) or **SHA-256** (WebCrypto)                                                                             | Fast, secure                                                                                                                                                                                                                                                 |
| Randomness                                            | `crypto.getRandomValues` / `sodium.randombytes_buf`                                                                            | Never `Math.random`                                                                                                                                                                                                                                          |
| Link-based secrets (Drop / Burn)                      | Key lives in the **URL fragment** (`#`) — never sent to the server                                                             | Fragments are not transmitted in HTTP requests                                                                                                                                                                                                               |

### 2.2 Libraries

- **Browser:** `libsodium-wrappers-sumo` (WASM) for XChaCha20/X25519/Ed25519/Argon2id. WebCrypto (`SubtleCrypto`) for AES-GCM and for anything that benefits from non-extractable keys.
- **Chat:** `@signalapp/libsignal-client` (official, WASM build) — preferred. Fallback: `libsignal-protocol-javascript` (older but battle-tested).
- **Server:** Server does **no** content crypto. It only verifies signatures on API requests and manages storage/TTLs. Use `libsodium` server-side only for signature verification and for encrypting at-rest metadata.

### 2.3 Key handling rules (non-negotiable)

1. Private keys and content keys never leave the client unencrypted.
2. Keys that must persist on a device are stored in **IndexedDB**, encrypted with a key derived (Argon2id) from the user's passphrase. Nothing in `localStorage`.
3. Every ciphertext has a version byte so algorithms can be rotated later.
4. Every encrypted blob is authenticated (AEAD) — no encrypt-then-trust.
5. Nonces are random, never reused, never derived from counters that could reset.
6. Zeroize key material in memory after use where the runtime allows (`sodium.memzero`).

---

## 3. Architecture

### 3.1 High-level

```
[ Browser (SPA / PWA) ]  ←HTTPS/WSS→  [ Edge: Caddy / nginx (TLS 1.3, HSTS) ]
          │                                       │
   all crypto happens here                [ API server (Node/TS or Go) ]
                                                  │
                     ┌────────────────────────────┼────────────────────────────┐
             [ PostgreSQL ]                 [ Object storage ]           [ Redis ]
        metadata + ciphertext          encrypted file blobs          sessions, rate limits,
        (small payloads)               (Docker volume on             WebSocket pub/sub,
                                        local disk)                  TTL schedulers
```

### 3.2 Tech stack

| Layer            | Choice                                                                                              | Notes                                                                                                                                                |
| ---------------- | --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Frontend         | **SvelteKit** (TypeScript), built as a static SPA/PWA                                               | ✅ Decided: SvelteKit.                                                                                                                               |
| Styling          | Tailwind CSS                                                                                        | Dark theme default                                                                                                                                   |
| Backend          | **Node.js 22 + Fastify (TypeScript)**                                                               | ✅ Decided: Node/Fastify, sharing TS types and crypto code with the frontend.                                                                        |
| Realtime         | WebSockets (`ws` / Fastify websocket plugin) with Redis pub/sub                                     | For chat delivery and read receipts                                                                                                                  |
| Database         | PostgreSQL 16                                                                                       | Ciphertext stored as `bytea`; encrypt sensitive metadata columns at rest                                                                             |
| Blob storage     | ✅ Plain disk (dedicated Docker volume) on a LUKS-encrypted host                                    | Encrypted blobs only. MinIO dropped: its Docker image is no longer distributed (§12). Garage is the S3-compatible option if we ever outgrow one VPS. |
| Cache / queues   | Redis 7                                                                                             | TTL keys for expiry; BullMQ for the deletion worker                                                                                                  |
| Reverse proxy    | Caddy (auto TLS)                                                                                    | TLS 1.3 only, HSTS preload, OCSP stapling                                                                                                            |
| Containerization | Docker Compose                                                                                      | One-command deploy on a VPS                                                                                                                          |
| Hosting          | ✅ Single privacy-respecting VPS (provider chosen before Phase 4), full-disk encryption on the host | Tor onion service added in Phase 4                                                                                                                   |

### 3.3 Data at rest on the VPS

- Host disk: **LUKS** full-disk encryption.
- Database: ciphertext columns only; any metadata that must be plaintext (timestamps, TTLs) is minimized.
- Blobs: already client-encrypted, stored on a dedicated volume on the LUKS-encrypted disk, so a disk image yields double-encrypted data.
- **Secure deletion:** After TTL expiry, delete the DB row, delete the blob, and then overwrite the storage key/record. Note: on SSDs, byte-overwrite is not a guarantee — rely on **client-side encryption + key destruction** as the real deletion mechanism (once the key is gone, the ciphertext is noise). Document this honestly in the UI.

---

## 4. Module specs

### 4.1 Chat (Signal-style E2EE)

**Identity & accounts**

- Accounts are **username + passphrase**, no email, no phone. ✅ Users may pick a username or take a generated one.
- On registration the client generates: Ed25519 identity keypair, X25519 identity keypair, a signed prekey, and a batch (100) of one-time prekeys. Public halves are uploaded; private halves are encrypted with the Argon2id-derived key and stored in IndexedDB.
- Login = derive key from passphrase, decrypt local keystore. The server authenticates via a **challenge–response signature** (server sends nonce, client signs with Ed25519) — the passphrase is never sent to the server.
- Optional: export/import an encrypted keystore file so the user can move devices. (Multi-device sync is **out of scope for v1**.)

**Session setup**

- Use **X3DH** (or PQXDH if the libsignal build supports it — adds post-quantum resistance via Kyber) to establish a shared secret with a contact using their prekey bundle fetched from the server.
- Then **Double Ratchet** for every message: new message key per message, forward secrecy, self-healing.

**Message flow**

1. Client encrypts plaintext with the Double Ratchet session → ciphertext + header.
2. Client POSTs `{ recipient_id, ciphertext, header, msg_id, ttl_seconds? }` over WSS.
3. Server stores ciphertext in a per-recipient mailbox (Postgres) and pushes over WebSocket if recipient is online.
4. Recipient client decrypts, stores plaintext **only in its encrypted local IndexedDB**, and sends an ACK. Server deletes the ciphertext from the mailbox on ACK (server is a relay, not an archive).
5. If a message has a `ttl_seconds`, both clients delete it locally after the timer.

**Disappearing messages (required feature)**

- Per-conversation setting, changeable by either participant (✅ groups: any member; the change is announced in the chat). Change is sent as an E2EE control message so both sides stay in sync.
- Timer options: off / 30s / 5m / 1h / 8h / 24h / 7d / 30d. ✅ Default for new conversations: **off**.
- Timer starts when the message is **read** (not sent). Unread messages still expire at a hard ceiling of `ttl × 2` so an offline recipient can't keep them forever.
- Deletion is enforced client-side on both devices (DB row + any cached attachment key). The server never holds the message after ACK anyway, so there is nothing server-side to expire.
- Show the active timer in the chat header; a message's remaining time is visible on long-press.
- Media sent with a timer: the Drop attachment key is wiped with the message, so the blob (which dies at 24h regardless) becomes unreadable immediately.

**Groups (v1: small groups ≤ 20)**

- Simplest correct approach: **pairwise fan-out** (sender encrypts the message separately for every member using their Double Ratchet session). Adequate for small groups; upgrade to Sender Keys / MLS later.

**Safety features**

- Safety numbers / key fingerprint verification screen (QR + numeric), warn on key change.
- Typing indicators and read receipts are **off by default**.
- Attachments inside chat reuse the Drop module (encrypt with a random key, upload, send the key inside the E2EE message).
- No message search server-side (impossible by design); local search over decrypted IndexedDB only.

**Metadata minimization**

- Server stores: sender id, recipient id, timestamp, ciphertext size — nothing else. ✅ **Sealed sender** (encrypt the sender id inside the envelope) in v1.1; `mailbox.from_user` is already nullable for it.

### 4.2 Drop (encrypted file upload, 24h hard delete)

**Flow**

1. User picks a file (max ✅ 2 GB, no account needed). Client generates a random 256-bit file key `K` and a random nonce.
2. Client streams the file through XChaCha20-Poly1305 in chunks (e.g. 1 MiB chunks using `crypto_secretstream_xchacha20poly1305`) so large files don't need to fit in memory. Filename and MIME type are encrypted into a small header blob too.
3. Client uploads chunks to `/api/drop/upload` (resumable, tus-style or multipart). Server stores blob + `{ id, created_at, expires_at = created_at + 24h, size, download_limit? }`.
4. Server returns `drop_id`. Client builds share link: `https://opsecaio.example/d/<drop_id>#<base64url(K)>`. The `#` part never reaches the server.
5. Recipient opens the link; client reads `K` from the fragment, fetches ciphertext, decrypts and streams to a download using `StreamSaver`/File System Access API.

**Options the uploader can set**

- Max downloads (1–∞). Default: unlimited within 24h.
- Shorter expiry (1h, 6h, 12h, 24h). 24h is the **hard ceiling**; cannot be extended.
- Optional extra password → `K` is itself wrapped with an Argon2id-derived key so the link alone is insufficient.

**Deletion (the 24h rule)**

- Deletion worker (BullMQ job scheduled at `expires_at`, plus a sweeping cron every 5 min as a safety net) deletes: blob from disk, Postgres row, Redis keys.
- Deletion is logged only as a counter (no ids retained).
- Deleting early: uploader gets a **deletion token** (random, shown once) to delete manually before 24h.
- Nothing ever gets backed up: object storage and the drop table are explicitly **excluded from any backups**.

### 4.3 Burn (disappearing notes)

**Flow**

1. User writes a note (text, Markdown allowed; max 64 KB; optional small attachment via Drop).
2. Client generates key `K`, encrypts note with XChaCha20-Poly1305, POSTs ciphertext.
3. Server stores `{ id, ciphertext, created_at, expires_at, max_views = 1, views = 0 }`.
4. Link: `https://opsecaio.example/n/<note_id>#<K>`.
5. Recipient opens link. Client first shows an interstitial: **"This note will be destroyed when you open it. Continue?"** (prevents link-preview bots and accidental burns). On confirm, client fetches ciphertext; the server **atomically deletes the row in the same transaction as the read** (`DELETE ... RETURNING ciphertext`). Client decrypts and renders.
6. If never opened, the note is deleted at `expires_at` (✅ default 7 days, max 30 days).

**Options**

- Views: 1 (default) — ✅ up to 5.
- Expiry: 1h / 24h / 7d / 30d.
- Optional password (same wrapping scheme as Drop).
- Optional "notify me when read" — only if the sender has a chat account; sends an E2EE system message.

**Anti-leak measures**

- `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, no server-side rendering of note pages, no Open Graph previews on `/n/` and `/d/` routes.
- Client clears decrypted content from DOM/memory on navigation.

---

## 5. API outline

All endpoints under `/api/v1`. JSON, except binary upload/download which use `application/octet-stream`.

```
AUTH
POST   /auth/register           { username, identity_pub, signed_prekey, prekey_sig, one_time_prekeys[] }
POST   /auth/challenge          { username } → { nonce }
POST   /auth/login              { username, nonce, signature } → { session_token }
POST   /auth/logout
DELETE /auth/account            (wipes everything server-side for the user)

KEYS
GET    /keys/bundle/:username   → prekey bundle (consumes one one-time prekey)
POST   /keys/prekeys            { one_time_prekeys[] }   (replenish)
PUT    /keys/signed-prekey      { signed_prekey, sig }   (rotate weekly)

CHAT
WSS    /ws                      auth via session token; events: message, ack, presence(optional)
POST   /messages                { to, msg_id, header, ciphertext, ttl? }
GET    /messages/pending        → undelivered ciphertexts for me
POST   /messages/ack            { msg_ids[] }  (server deletes)

DROP
POST   /drop/init               { size, chunk_count, expires_in, max_downloads?, header_blob } → { drop_id, upload_token }
PUT    /drop/:id/chunk/:n       octet-stream
POST   /drop/:id/finalize       → { deletion_token }
GET    /drop/:id/meta           → { size, chunk_count, expires_at, header_blob }
GET    /drop/:id/chunk/:n       octet-stream
DELETE /drop/:id                { deletion_token }

BURN
POST   /note                    { ciphertext, expires_in, max_views } → { note_id, deletion_token }
POST   /note/:id/open           → { ciphertext }   (atomic read+delete / view-count decrement)
DELETE /note/:id                { deletion_token }
```

**Rate limiting:** per-IP and per-account token buckets in Redis (register 5/h/IP, uploads 20/h, note opens 60/min). Return generic errors — never reveal whether an id exists (404 for both "never existed" and "already burned").

---

## 6. Database schema (Postgres)

```sql
users            (id uuid pk, username text unique, identity_pub bytea, created_at timestamptz)
signed_prekeys   (user_id fk, key_id int, pub bytea, sig bytea, created_at)
one_time_prekeys (user_id fk, key_id int, pub bytea)
sessions         (token_hash bytea pk, user_id fk, expires_at)
mailbox          (id uuid pk, to_user fk, from_user fk, header bytea, ciphertext bytea, created_at)
                 -- rows deleted on ACK; sweeper deletes anything >30 days
drops            (id text pk, size bigint, chunk_count int, header_blob bytea,
                  created_at, expires_at, max_downloads int, downloads int,
                  deletion_token_hash bytea)
notes            (id text pk, ciphertext bytea, created_at, expires_at,
                  max_views int, views int, deletion_token_hash bytea)
```

IDs for drops/notes: 128-bit random, base64url (22 chars). Never sequential.

---

## 7. Security hardening checklist

**Transport & headers**

- TLS 1.3 only, HSTS (preload), `Content-Security-Policy` with no inline scripts and `connect-src 'self'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Permissions-Policy` locked down, `Cross-Origin-Opener-Policy: same-origin`.
- **Subresource Integrity** on all assets; serve all JS from the same origin (no third-party CDNs — a compromised CDN = compromised crypto).
- No analytics, no third-party fonts, no external requests of any kind from the client.

**Server**

- Docker containers run as non-root, read-only filesystems where possible, dropped capabilities.
- Postgres and Redis not exposed outside the Docker network.
- fail2ban / CrowdSec on the host; SSH key-only, non-standard port, no password auth.
- Logs: **no IPs, no user ids, no URLs with ids** — only aggregate counters and error traces with ids scrubbed. Log retention 24h.
- Automatic security updates; unattended-upgrades on the host.

**Application**

- Constant-time comparison for tokens; hash deletion tokens (Argon2id or BLAKE2b with pepper) before storing.
- All ids and tokens from CSPRNG.
- Input size limits enforced before reading bodies.
- Dependency audit in CI (`npm audit`, Snyk/OSV).
- Reproducible frontend builds + publish build hash so users can verify the served JS (defense against a malicious server swapping the client).

**Threat model (write this into the README honestly)**

- ✅ Protects against: server compromise, hosting provider snooping, database leaks, network eavesdropping, legal demands for content.
- ⚠️ Does _not_ fully protect against: a compromised client device, a malicious JavaScript build served by a compromised server (mitigated, not eliminated, by SRI + published hashes + optional browser extension in future), traffic analysis / metadata correlation at the network level (use Tor).

---

## 8. UX notes

- Dark, minimal, no marketing fluff. Three big entry tiles: **Chat / Drop / Burn**.
- Drop and Burn require **no account**. Chat requires one.
- Every share link screen shows: expiry countdown, what the server can and can't see, a copy button, and a QR code.
- Show a plain-English "Who can read this?" panel on every screen.
- PWA installable; works offline for reading already-decrypted local chat history.
- Accessibility: keyboard navigable, screen-reader labels.

---

## 9. Build phases

**Phase 0 — Foundations (week 1)** ✅ done

- Monorepo: `apps/web`, `apps/api`, `packages/crypto` (shared TS crypto helpers wrapping libsodium with a stable API and version bytes), `packages/types`.
- Docker Compose with Caddy, API, Postgres, Redis, and a blob volume (✅ done; MinIO replaced, see §12).
- CI: lint, typecheck, unit tests, dependency audit.
- Write `packages/crypto` first with **test vectors** and a known-answer test suite.

**Phase 1 — Burn (week 2)** ✅ done (see §12 items 9–14)

- Simplest module; proves the whole zero-knowledge pipeline end-to-end (fragment keys, atomic delete, headers, rate limits).

**Phase 2 — Drop (weeks 3–4)** ✅ done (see §12 items 16–23)

- Chunked secretstream encryption, resumable upload, streaming download, 24h deletion worker + sweeper, deletion tokens, download limits, optional password.

**Phase 3 — Chat (weeks 5–8)**

- Accounts + challenge-response auth, prekey bundles, libsignal integration, WebSocket relay, local encrypted store, disappearing messages, safety numbers, attachments via Drop, small groups via pairwise fan-out.

**Phase 4 — Hardening & launch (weeks 9–10)**

- Threat-model doc, security headers audit (securityheaders.com + Mozilla Observatory A+), reproducible build + published hashes, Tor onion service, load test, external review/pen-test, public source code repo.

**Later (v1.1+)**

- Sealed sender, Sender Keys/MLS for larger groups, multi-device, browser extension for client verification, mobile wrappers (Capacitor), post-quantum (PQXDH / ML-KEM) if not already in libsignal build.

---

## 10. Decisions (resolved 2026-11-04)

| #   | Question                          | Decision                                                                                                           |
| --- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| 1   | Frontend framework                | **SvelteKit** (static SPA, `ssr = false`)                                                                          |
| 2   | Backend                           | **Node 22 + Fastify**                                                                                              |
| 3   | Primary cipher in UI              | **XChaCha20-Poly1305**. AES-256-GCM is implemented and tested in `packages/crypto` but not offered as a UI choice. |
| 4   | Max Drop size / anonymous uploads | **2 GB**, anonymous uploads **allowed** (abuse controlled by rate limits)                                          |
| 5   | Burn views / TTL                  | Default **1** view, max **5**; default expiry **7 days**, max **30 days**                                          |
| 6   | Anonymous chat accounts           | **Yes**: users can pick a username or get a generated one                                                          |
| 7   | Hosting / Tor                     | **Single VPS**, provider chosen before Phase 4; Tor onion service in Phase 4                                       |
| 8   | License                           | **None yet** (all rights reserved). Decide before the repo is made public; AGPL-3.0 remains the recommendation.    |
| 9   | Disappearing messages             | Default **off**; in groups **any member** may change it                                                            |

These values live in code in `packages/types/src/limits.ts` and are enforced by both the API and database constraints.

## 11. How to use this file with Claude

Paste this file and say, e.g.:

- "Build Phase 0 from the OpSec AIO plan — set up the monorepo and `packages/crypto` with tests."
- "Implement the Burn module per section 4.3 and the API in section 5."
- "Review the threat model in section 7 and suggest additions."

Work through phases in order; each phase should end with passing tests and a running Docker Compose stack.

---

## 12. Implementation notes & deviations

Changes made while building, with the reason. Update this list whenever the code departs from the text above.

1. **MinIO → plain disk volume.** The `minio/minio` Docker Hub repository no longer exists (MinIO stopped distributing community builds in 2025). The plan already allowed "plain disk with LUKS"; it also has fewer moving parts and makes deletion simpler. Storage will sit behind an interface so an S3 store (e.g. Garage) can be swapped in.
2. **Separate login key.** `users.auth_pub` (Ed25519) is used only for challenge–response login, separate from the Signal identity key (`identity_pub`). libsignal identity keys sign with XEdDSA, which the server cannot verify with libsodium.
3. **No `ttl` on `POST /messages`.** Disappearing timers travel only inside the E2EE payload; sending them to the server would leak metadata and the server deletes on ACK anyway.
4. **Redis has persistence disabled** (`--save "" --appendonly no`): nothing from Redis ever touches disk. The database sweeper is the source of truth for expiry, so a restart loses nothing important.
5. **CSP & SRI arrive in Phase 0, not Phase 4.** The web build post-processes `index.html` to add an import map with SRI hashes for every JS module, integrity on static links, and a CSP that allows only hashed inline scripts (no `'unsafe-inline'`). `'wasm-unsafe-eval'` is required for libsodium's WebAssembly. One `'unsafe-hashes'` style hash covers SvelteKit's screen-reader route announcer.
6. **Reproducible web build** from Phase 0: SvelteKit's version name is pinned (`BUILD_VERSION`, default `dev`), so the same sources produce the same `buildHash`, which CI publishes.
7. **Kyber/PQXDH prekeys** are not in the initial schema; they will be added by a Phase 3 migration once the libsignal version is pinned.
8. **Timestamps in `created_at`** are kept at full precision for now; consider coarsening them to the hour in Phase 4 for metadata minimisation.
9. **Burn note format.** `stored = seal(K, inner)`, where `inner` is a version byte, a flags byte, and either the payload or `wrap(C, password) ‖ seal(C, payload)`. The payload is padded to 1 KiB blocks (ISO/IEC 7816-4), so the server learns only a size bucket. With a password, the wrapped key sits _inside_ the link-key envelope, so a database leak alone doesn't allow offline password guessing. Pinned vectors live in `packages/crypto/test/fixtures/note-vectors.json`.
10. **Link fragments.** `#<key>` or `#<key>.p` (the `.p` flag tells the recipient's page a password will be needed, before it burns the note). Deletion links are `/n/<id>#del.<token>`, so the token is also never sent in a URL the server sees. After use, the page removes the fragment from the address bar.
11. **Note size cap raised to 68 KiB of ciphertext** (migration `002_note_size.sql`) to fit the padding and the password wrap around 64 KiB of text.
12. **Rate-limit keys never contain IPs.** The key is a BLAKE2b MAC of `(UTC day, IP)` under the server pepper, with IPv6 grouped by /64. If Redis is down, limits fail open so notes stay readable.
13. **Notes render as plain text.** Markdown rendering is deferred: it needs a sanitiser, and plain text has no XSS surface. "Notify me when read" is deferred to Phase 3 (it needs a chat account).
14. **Argon2id runs on the main thread** (about 1 s pause when a password is used). Move it to a Web Worker in Phase 4.
15. **CI build fix.** Phase 0's root `pnpm build` used unquoted globs that the shell expanded, so it silently built nothing; it is now `pnpm -r run build`.
16. **Drop file format.** `header_blob = seal(L, inner)`. `inner` holds a version, flags, a 98-byte password slot (random bytes when there is no password, so the blob size doesn't reveal password use), the secretstream header, and the name/type/exact size encrypted under the content key and padded to 256 bytes. The file is padded with PADMÉ (minimum 4 KiB) before chunking, so the server learns only the chunk count, a coarse size bucket. With a password, even the file name needs the password. Pinned vectors are in `packages/crypto/test/fixtures/drop-vectors.json`.
17. **Drop API differs from §5.** `init` takes no `size` (the server learns the ciphertext size from the chunks at finalize). Downloads go `POST /drop/:id/download`, which returns a download token, then `GET /drop/:id/chunk/:n` with `Authorization: Bearer <token>`; chunks are only served to a live token, so download limits can't be bypassed. `DELETE` also accepts the `upload_token`, to abort an unfinished upload. `meta` returns `downloads_remaining`.
18. **No BullMQ.** A sweeper runs every minute instead. Reads refuse expired drops at the exact deadline, and files are deleted within about a minute. Redis has persistence disabled, so queued jobs would be lost on restart anyway; the database is the source of truth.
19. **Download limits delete immediately.** When the last allowed download finishes (its final chunk is served), the drop's row and files are deleted at once, not at expiry.
20. **Storage cap.** `DROP_STORAGE_MAX_BYTES` (default 20 GiB) reserves worst-case space per live drop. New uploads beyond it get `507 storage_full`, so the disk can't be filled.
21. **Saving large downloads.** Above 256 MiB, desktop Chromium streams straight to disk (File System Access API). Other browsers hold the file in memory, and the page warns above 512 MiB. A same-origin service-worker stream (for Android and Firefox) is a Phase 4 item; iOS Safari stays memory-bound.
22. **No byte-overwrite on delete.** Overwriting is unreliable on SSDs and costly at 2 GB; deletion relies on the server never having held the key (§3.3).
23. **`randomBytes` uses `crypto.getRandomValues` directly.** libsodium's WASM wrapper took about 2.6 s per MiB; the platform CSPRNG is the same source libsodium uses in the browser.
