# Deploying OpSec AIO to a VPS

Target: one Linux VPS running Docker Compose. Everything (TLS, web app, API, Postgres, Redis,
file blobs) runs on that one machine.

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
curl -fsS https://your.domain.example/api/v1/ready
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

## 4. Logging

- Caddy writes **no access logs**, only its own errors.
- The API logs no request lines, IPs, URLs or user agents. It logs only lifecycle events and
  server errors.
- Docker's `local` log driver is capped at 2 × 5 MB per container. For a 24-hour retention
  ceiling, also run `docker compose logs` rotation or a nightly `docker compose restart`.

## 5. Updating

```sh
git pull
docker compose up -d --build
```

Migrations run automatically on API start, guarded by a Postgres advisory lock.

## 6. Verifying the served web app

Each build writes `build-meta/build-manifest.json` (baked into the Caddy image at
`/etc/caddy/build-manifest.json`), which contains a `buildHash` over every served file. CI
publishes the same hash for each commit. Because the build is reproducible, anyone can rebuild
from the tagged source and compare.

```sh
docker compose exec caddy cat /etc/caddy/build-manifest.json | head -3
```

## 7. Tor onion service (Phase 4)

Planned: a `tor` container that publishes the Caddy service as a v3 onion address, with an
`Onion-Location` header on clearnet responses.
