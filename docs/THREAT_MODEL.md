# OpSec AIO — Threat model

What OpSec AIO protects, from whom, what it cannot protect, and what the server can
still see. Read this before trusting it with anything that matters. The design
details are in [`PLAN.md`](PLAN.md); operating the server is in [`DEPLOY.md`](DEPLOY.md).

## 1. What is protected

| Asset                               | Protection                                                                                                                                   |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Chat message and attachment content | Signal Protocol (X3DH + Double Ratchet), end to end, in the browser. The server relays ciphertext only.                                      |
| Group names and membership          | Inside the encrypted messages. The server sees N separate 1:1 messages and nothing about groups.                                             |
| Disappearing-message timers         | Inside the encrypted messages. The server never learns them.                                                                                 |
| File contents, names, types         | Encrypted in the browser (secretstream, 1 MiB chunks). Name and type are in the encrypted header; the key is in the link's `#fragment` only. |
| Note text                           | Encrypted in the browser; the key is in the link's `#fragment` only, padded to 1 KiB blocks.                                                 |
| Optional passwords (notes, files)   | Argon2id (64 MiB, t = 3) wrapping, _inside_ the link-key envelope: the database alone isn't enough to start guessing.                        |
| Your chat keys on your device       | Encrypted IndexedDB vault, unlocked by your passphrase (Argon2id). Record names are keyed hashes, so contacts aren't visible on disk.        |
| Login                               | Ed25519 challenge–response. Your passphrase never leaves the device.                                                                         |

## 2. Adversaries

| Adversary                                                | Outcome                                                                                                                                                       |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Network eavesdropper** (Wi-Fi, ISP, backbone)          | Sees TLS 1.3 traffic to the server: that you use it, when, and how much. No content. Over Tor, not even that you use it.                                      |
| **Hosting provider / someone with the disk or a backup** | Ciphertext and the metadata in §3. No keys. Deleted data is unrecoverable once its key is gone (it never was on the server).                                  |
| **Server compromised later** (attacker gets root)        | Past content stays safe: it was never decryptable there. From then on they see the metadata in §3 live, and can try the attack in §4.                         |
| **Malicious operator, or a server compromised _now_**    | Can serve modified JavaScript that leaks keys. This is the main residual risk; see §4.                                                                        |
| **Legal demand to the operator**                         | Can only hand over what's in §3. There are no keys to give.                                                                                                   |
| **Another user / stranger on the internet**              | Rate limits, storage caps, per-client socket caps and strict validation. Can't read anyone's data; can't drain anyone's prekeys or lock out uploads (tested). |
| **Your chat partner**                                    | Can screenshot or copy anything you send. Disappearing messages are a convenience, not a guarantee against the recipient.                                     |
| **Malware or a hostile extension on your device**        | Out of scope: it can read whatever you can read.                                                                                                              |

## 3. What the server can see (metadata)

| Module | Visible to the server                                                                                                                                                         | Not visible                                    |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| Chat   | Usernames (you pick them; generated ones are fine), who sends to whom and when, message sizes (padded to 160-byte blocks), when you're online (WebSocket), number of prekeys. | Content, group membership, timers, attachments |
| Drop   | That a drop exists, its padded size, chunk count, expiry, download count and limit.                                                                                           | File name, type, exact size, content, password |
| Burn   | That a note exists, its padded size (1 KiB blocks), expiry, when it's opened.                                                                                                 | Content, whether it has a password             |
| All    | Your IP address while connected (unless you use Tor). It is **never logged or stored**: rate-limit keys are a daily keyed hash of the IP.                                     |                                                |

Retention: undelivered chat messages are deleted on delivery (ACK) or after 30 days. Drops
are deleted at expiry (≤ 24 h) or after the last allowed download; unfinished uploads after
6 h. Notes are deleted when read or at expiry. Login sessions last 24 h. Logs contain no IPs,
URLs, ids or tokens (scrubbed and tested).

**Not yet hidden:** sealed sender (hiding the sender from the relay) is planned for v1.1. Until
then the relay sees the sender of each chat message.

## 4. The main residual risk: the code the server sends you

All encryption runs in JavaScript that the server sends to your browser. A malicious or
compromised server could send a modified version that leaks your keys. Mitigations:

1. **Subresource Integrity** on every module and a **strict CSP** (no inline or remote
   scripts): the page can only run the exact files `index.html` pins by hash.
2. **Reproducible build.** The same source always produces the same files and the same
   build hash. CI publishes the hash for every commit.
3. **Anyone can check the live site:** build the same commit yourself and run
   `node scripts/verify-site.mjs https://the.site`. It fetches every file and compares
   SHA-256 hashes (see DEPLOY.md §8).

What this doesn't cover: a server that serves the right code to the verifier and modified code
to one target. A browser extension that checks every page load against published hashes would
close that gap; it is planned but not built. If you can't trust the operator, run your own
server.

## 5. Other known limitations

- **Trust on first use.** A new contact's key is accepted the first time. Compare safety
  numbers (in person, over a call, or by QR code) to rule out interception. Once you mark a
  contact verified, a key change pauses sending until you accept the new key.
- **No post-quantum key agreement yet.** The Signal library used (`@privacyresearch/libsignal-protocol-typescript`
  0.0.16) predates PQXDH. Recorded traffic could in theory be decrypted by a future quantum
  computer. Messages are still protected against everything practical today.
- **That library is a community port**, not Signal's own code (Signal ships no browser build).
  An independent review found one bug in it (old ratchet chains were never pruned, so sessions
  grew without limit); it is fixed by a reviewed patch in `patches/` with a test that fails
  without it.
- **Single device per account.** Using one account on two devices at once breaks sessions.
- **Deletion on SSDs.** Overwriting isn't reliable on flash storage. Deletion relies on the
  server never having held the keys.
- **Browser storage.** Your vault is only as safe as your passphrase and your device. Lock the
  app (or close the tab) on shared computers.
- **WebAssembly required.** The cryptography runs in WebAssembly. Browsers or modes that turn
  it off (iOS Lockdown Mode, Tor Browser "Safer", some hardened Firefox/Android settings) can't
  use Chat, Drop or Burn; the site says so instead of silently failing.

## 6. Running it safely (operators)

- **Use your own domain.** A free `*.sslip.io` address works, but whoever controls sslip.io's
  DNS could point the name elsewhere and get a certificate for it. With your own domain, only
  you (and your registrar/DNS provider) can.
- **Offer the onion service** (`scripts/enable-tor.sh`) for people who need to hide that they
  use it.
- **Keep `RATE_LIMIT_MULTIPLIER=1`**, disk encryption on, SSH key-only, and don't back up
  the database (DEPLOY.md §3).
- **Update** with `sudo bash scripts/update.sh`; check the build hash it prints against CI.

## 7. Security review (Phase 4, 2026-11)

Before launch the code had an independent review (separate reviewers for the chat client,
crypto formats and server), plus a live scan of the deployed site (Mozilla Observatory: A+,
12/12 tests passed). Every confirmed finding was fixed and has a test:

| Area   | Finding                                                                       | Fix                                                                                     |
| ------ | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Chat   | A verified contact's key could be replaced by an incoming message             | Verified keys are never replaced silently; sending pauses until the user accepts        |
| Chat   | Old messages could be replayed after a session reset                          | Per-sender message-id replay guard; control messages can't go back in time              |
| Chat   | Any member could change a group's membership                                  | Only the creator can; every change is announced                                         |
| Chat   | Expired messages could reappear after reopening the app                       | Expiry is enforced on load                                                              |
| Chat   | "Mark verified" could apply to a number that changed meanwhile                | Verifies only the number on screen                                                      |
| Chat   | Signal library never pruned old chains (unbounded session growth)             | Patched (`patches/`), with a test                                                       |
| Burn   | Ciphertext size revealed whether a note had a password                        | Note format v2: same size either way                                                    |
| Server | A malformed WebSocket frame (`null`) crashed the API                          | Strict frame validation, errors contained per socket, crash-proof handlers              |
| Server | Caddy logged client IP + full URL (incl. note/drop ids) when the API was down | Those logs are off; verified on a 502                                                   |
| Server | Empty Drop inits reserved worst-case storage, locking out uploads for 24 h    | Storage counted as bytes arrive; free-space floor; unfinished uploads deleted after 6 h |
| Server | Large chat messages × many mailboxes could fill the database                  | 16 KiB per message, 2 GiB global cap                                                    |
| Server | Anyone could drain a user's one-time prekeys                                  | ≤ 30 per user per hour; bundles still served after that                                 |
| Server | Error logs could contain file paths with drop ids                             | All logged errors are scrubbed (paths, ids, tokens, UUIDs, IPs)                         |
| Server | Unlimited WebSockets per client; `/ready` exposed which backend was down      | 20 sockets per client; `/ready` internal only                                           |
| Deploy | Redis password visible in `ps`; no container memory limits                    | Password via a private tmpfs file; memory and process limits on every container         |

## 8. Capacity (load test)

Measured on the full Docker stack (about 2 CPU cores per container, rate limits lifted for
the test):

| Operation                     | Throughput    | Latency (p50) |
| ----------------------------- | ------------- | ------------- |
| Static app files              | ~10,400 req/s | —             |
| Create a note                 | ~2,000 req/s  | 24 ms         |
| Open (and burn) a note        | ~990 req/s    | 42 ms         |
| Send a chat message           | ~330 req/s    | —             |
| WebSockets: 10,000 connected  | +140 MiB RAM  | —             |
| One message to 10,000 sockets | 385 ms        | —             |

With the default 768 MiB memory limit, the API holds roughly 40,000 concurrent chat
connections. A 4 GB VPS is comfortable for a small community.
