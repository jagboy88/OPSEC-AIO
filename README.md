# OpSec AIO

A zero-knowledge privacy suite: **encrypted chat**, **24-hour encrypted file drops** and
**burn-after-reading notes**. All encryption happens in the browser. The server stores only
ciphertext and the minimum metadata it needs to deliver and expire it.

The full specification and the decisions behind it are in [`docs/PLAN.md`](docs/PLAN.md).

## Status

| Phase | Scope                                                                              | State   |
| ----- | ---------------------------------------------------------------------------------- | ------- |
| 0     | Monorepo, crypto library + known-answer tests, API/web skeletons, Docker stack, CI | ✅ Done |
| 1     | Burn (notes): API, crypto format, UI, end-to-end tests                             | ✅ Done |
| 2     | Drop (files)                                                                       | Next    |
| 3     | Chat                                                                               | —       |
| 4     | Hardening & launch                                                                 | —       |

## Repository layout

```
apps/api          Fastify API (TypeScript): health/readiness, migrations, privacy-preserving logging
apps/web          SvelteKit static SPA: Burn (/burn, /n/<id>), crypto self-test (/selftest)
packages/crypto   All client-side crypto: versioned AEAD envelopes, file streams, Argon2id, Ed25519, X25519
packages/types    Shared API contracts and product limits (the §10 decisions, in code)
infra/caddy       Edge: TLS 1.3 only, security headers, generated CSP
e2e/              Playwright tests against the running Docker stack
docs/             PLAN.md (spec + decisions), DEPLOY.md (VPS runbook)
```

## Development

Requires Node 22.12+ and pnpm 10 (`corepack enable`).

```sh
pnpm install
pnpm test          # all unit tests (crypto known-answer tests included)
pnpm lint          # eslint + prettier
pnpm typecheck
pnpm build         # packages, API and web (web build also emits SRI, CSP and build hash)
```

Database integration tests run when `TEST_DATABASE_URL` points to a disposable Postgres 16:

```sh
docker run -d --rm -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16.15-alpine
TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/postgres pnpm --filter @opsec-aio/api test
```

Full stack locally (served at https://localhost with Caddy's internal CA):

```sh
./scripts/init-secrets.sh
cp .env.example .env
docker compose up -d --build
pnpm e2e           # browser tests against the running stack (first: pnpm --filter @opsec-aio/e2e exec playwright install chromium)
```

## Cryptography at a glance

| Use                     | Primitive                                                                               |
| ----------------------- | --------------------------------------------------------------------------------------- |
| Notes, message payloads | XChaCha20-Poly1305 (libsodium), AES-256-GCM available via WebCrypto                     |
| Files                   | libsodium secretstream (XChaCha20-Poly1305), 1 MiB chunks, truncation/reorder detection |
| Passwords               | Argon2id, 64 MiB, t = 3                                                                 |
| Identity / login        | Ed25519 challenge–response (passphrase never sent)                                      |
| Key agreement           | X25519; Signal Protocol (X3DH + Double Ratchet) for chat                                |
| Link secrets            | 256-bit key in the URL `#fragment`, never sent to the server                            |

Every ciphertext begins with a version byte and an algorithm byte, and both are authenticated
as associated data. `packages/crypto/test/kat.test.ts` checks the primitives against published
vectors (RFC 8032, RFC 7748, RFC 7693, draft-irtf-cfrg-xchacha, the GCM spec, and an Argon2id
vector cross-checked against RFC 9106). The same checks run in your browser at `/selftest`.

## Threat model

**Protects against:** server compromise, hosting-provider snooping, database or disk leaks,
network eavesdropping, and legal demands for content. The server has no keys, so it has
nothing readable to hand over.

**Does not fully protect against:**

- **A compromised device.** Malware on your device can read whatever you can read.
- **A malicious server serving modified JavaScript.** This is mitigated by SRI on every
  module, a strict CSP, and a reproducible build whose hash CI publishes. It is not
  eliminated: a browser extension that verifies the build is planned for later.
- **Traffic analysis.** The server sees when and how much, and the network sees who connects.
  Use Tor if that metadata matters to you.
- **Secure deletion on SSDs.** Overwriting bytes is not reliable on flash storage, so deletion
  really means destroying the key. Once the key is gone, any leftover ciphertext is noise.

## License

No license has been chosen yet, so all rights are reserved. A license (AGPL-3.0 is the
recommendation) will be picked before the repository is made public.
