# Deploying OpSec AIO to a VPS

Target: one Linux VPS running Docker Compose. Everything (TLS, web app, API, Postgres, Redis,
file blobs) runs on that one machine.

## Quick install (Ubuntu 24.04 / 26.04 LTS)

On a fresh server, as root:

```sh
curl -fsSL https://raw.githubusercontent.com/jagboy88/OPSEC-AIO/main/scripts/install-vps.sh -o install.sh
bash install.sh                    # free address: <your-ip>.sslip.io
bash install.sh chat.example.com   # or your own domain (point its A record here first)
```

A `*.sslip.io` address is fine for trying it out, but for real use put the site on **your own
domain**: whoever runs sslip.io's DNS could point the name at another server and get a
certificate for it (docs/THREAT_MODEL.md §6).

It runs system updates, turns on automatic security updates, sets up a firewall
(SSH/80/443 only), fail2ban and swap, installs Docker, generates secrets, sizes Drop
storage to the disk, builds and starts the stack, and checks HTTPS. It is safe to
re-run. The manual steps below are what it automates, plus what it can't do for you
(SSH keys, disk encryption).

### After installing: SSH key login

1. Create an SSH key on your device (e.g. Termius: Keychain → Generate key → Ed25519)
   and add its public key to `/root/.ssh/authorized_keys` on the server.
2. Log in again **using the key** and confirm it works.
3. Only then turn off password logins:
   ```sh
   # 01-…: sshd keeps the FIRST value it reads, and Ubuntu cloud images ship
   # 50-cloud-init.conf with PasswordAuthentication yes.
   printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' > /etc/ssh/sshd_config.d/01-opsec.conf
   sshd -t && systemctl reload ssh
   sshd -T | grep -E '^(passwordauthentication|permitrootlogin)'   # expect: no / without-password
   ```

## 1. Host preparation

1. **Full-disk encryption (LUKS).** Pick a provider that supports custom ISOs or encrypted
   volumes. At minimum, put `/var/lib/docker` on a LUKS volume, because it holds the
   database and blob volumes.
2. **SSH:** key-only, password auth off, non-standard port.
3. **Firewall:** allow only the SSH port plus 80/tcp, 443/tcp and 443/udp (HTTP/3).
4. **Intrusion prevention:** CrowdSec or fail2ban.
5. **Automatic security updates:** `unattended-upgrades` (Debian/Ubuntu).
6. Install Docker Engine and the Compose plugin.
7. Redis: set `vm.overcommit_memory = 1` in `/etc/sysctl.conf` to silence its warning.

## 2. First deploy

```sh
git clone <repo> opsec-aio && cd opsec-aio
./scripts/init-secrets.sh            # creates secrets/ (0700); keep it off backups and out of git
cp .env.example .env
# edit .env: SITE_ADDRESS=your.domain.example
docker compose up -d --build
docker compose ps                    # all services should become healthy
curl -fsS https://your.domain.example/api/v1/health
```

The detailed readiness check (database, Redis, storage) is only reachable from inside the
stack; from outside, `/api/v1/ready` is a 404:

```sh
docker compose exec api node -e "fetch('http://127.0.0.1:3000/api/v1/ready').then(r=>r.text()).then(console.log)"
```

Caddy obtains and renews the TLS certificate automatically. Point the domain's A/AAAA records
at the VPS before the first start.

## 3. Backups: what must NOT be backed up

| Data                                           | Back up?     | Why                                                                  |
| ---------------------------------------------- | ------------ | -------------------------------------------------------------------- |
| `blobs` volume                                 | **Never**    | Drop files must be gone after 24 h.                                  |
| `drops`, `notes`, `mailbox`, `sessions` tables | **Never**    | Ephemeral by design.                                                 |
| `users`, prekey tables                         | Optional     | Losing them only means users re-register.                            |
| `secrets/`                                     | Yes, offline | `token_pepper` is needed to validate outstanding deletion tokens.    |
| Redis                                          | n/a          | Persistence is disabled; nothing from Redis is ever written to disk. |

Simplest safe policy: **don't back up the database at all.** The service is designed to hold
nothing worth keeping.

## 4. Rate limits and resource caps

Per-client limits (plan §5) apply as written when `RATE_LIMIT_MULTIPLIER` is 1, the default.
Never raise it in production: it exists so test stacks can create many accounts from
one IP.

Settings in `.env` (defaults in brackets):

| Setting                  | Meaning                                                                                  |
| ------------------------ | ---------------------------------------------------------------------------------------- |
| `DROP_STORAGE_MAX_BYTES` | Cap on stored Drop ciphertext, counted as chunks arrive [20 GiB; the installer sizes it] |
| `DROP_MIN_FREE_BYTES`    | Drop refuses new chunks when the disk has less free space than this [2 GiB]              |
| `MAILBOX_MAX_BYTES`      | Cap on undelivered chat ciphertext across all users [2 GiB]                              |

Fixed limits: 16 KiB per chat message, 5,000 undelivered messages per user, 20 WebSockets per
client (500 for the shared onion bucket), at most 30 one-time prekeys handed out per user per
hour (bundles are still served without one after that), unfinished uploads deleted after 6 h.

Every container has a memory and process limit in `docker-compose.yml`, sized for a 4 GB VPS
(API 768 MiB: about 40,000 concurrent chat connections; see THREAT_MODEL.md §8). Raise them on
a bigger server.

## 5. Open source obligation (AGPL-3.0)

The code is AGPL-3.0. Before anyone else uses your deployment, make the repository
public (or point the footer's "Source code" link at a public copy of exactly what you
run).

## 6. Logging

- Caddy writes **no access logs and no request-error logs** (those would include the client
  IP and the full URL, with note and drop ids), only its own errors (certificates, config).
- The API logs no request lines, IPs, URLs or user agents. It logs only lifecycle events and
  server errors, and every logged error message is scrubbed of paths, ids, tokens, UUIDs and
  IP addresses (`apps/api/src/log.ts`, tested).
- Docker's `local` log driver keeps at most 2 × 5 MB per container. Since nothing in the logs
  identifies anyone, they are size-capped rather than time-capped.
- `/api/v1/ready` (which backend is down) answers only inside the stack; from outside it is a 404. Use `/api/v1/health` for external monitoring.

## 7. Updating

```sh
sudo bash /opt/opsec-aio/scripts/update.sh
```

It pulls the latest code, rebuilds, restarts (keeping secrets, `.env` and Tor if enabled),
waits until every service is healthy, checks the site and prints the build hash now being
served. Migrations run automatically on API start, guarded by a Postgres advisory lock. By
hand: `git pull && docker compose up -d --build`.

## 8. Verifying the served web app

Each build writes `build-meta/build-manifest.json` (baked into the Caddy image at
`/etc/caddy/build-manifest.json`), which contains a `buildHash` over every served file. CI
publishes the same hash for each commit. Because the build is reproducible, anyone can rebuild
from the tagged source and compare.

```sh
docker compose exec caddy cat /etc/caddy/build-manifest.json | head -3
```

**Check a live site from anywhere** (you don't need access to the server):

```sh
git clone https://github.com/jagboy88/OPSEC-AIO.git && cd OPSEC-AIO
git checkout <commit the server runs>
pnpm install --frozen-lockfile && pnpm --filter "@opsec-aio/web..." build
node scripts/verify-site.mjs https://the.site
```

It downloads every file the app consists of and compares SHA-256 hashes with your own build.
`✔ MATCH` means the site serves exactly that source code. A mismatch on the right commit
means the server is serving something else: don't trust it.

## 9. Tor onion service

On the server:

```sh
bash /opt/opsec-aio/scripts/enable-tor.sh
```

It enables the `tor` Compose profile, waits for Tor to generate the service's key,
prints the `.onion` address, and makes the clearnet site send an `Onion-Location`
header so Tor Browser offers the onion version. Back up the key as the script
explains: the key _is_ the address.

How it fits together:

- The `tor` container shares Caddy's network namespace and forwards the onion's
  port 80 to a second Caddy site on `127.0.0.1:8081`, which is not published
  anywhere else.
- The onion site is plain HTTP (Tor already encrypts and authenticates it end to end;
  Tor Browser treats `.onion` as a secure context) with the same CSP and headers,
  minus HSTS.
- Every onion visitor reaches Caddy from `127.0.0.1`, so the API rate-limits onion
  traffic as one shared bucket with 20× the per-IP limits. Caddy marks onion
  requests with `X-Opsec-Via: onion` and strips that header from clearnet requests.
- Tor Browser must be on security level **Standard**: "Safer" disables WebAssembly,
  which the encryption needs (the site explains this if it happens).
