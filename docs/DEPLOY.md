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
   printf 'PasswordAuthentication no\nPermitRootLogin prohibit-password\n' > /etc/ssh/sshd_config.d/99-opsec.conf
   systemctl reload ssh
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

## 4. Rate limits

Per-client limits (plan §5) apply as written when `RATE_LIMIT_MULTIPLIER` is 1, the default.
Never raise it in production: it exists so test stacks can create many accounts from
one IP.

## 5. Open source obligation (AGPL-3.0)

The code is AGPL-3.0. Before anyone else uses your deployment, make the repository
public (or point the footer's "Source code" link at a public copy of exactly what you
run).

## 6. Logging

- Caddy writes **no access logs**, only its own errors.
- The API logs no request lines, IPs, URLs or user agents. It logs only lifecycle events and
  server errors.
- Docker's `local` log driver is capped at 2 × 5 MB per container. For a 24-hour retention
  ceiling, also run `docker compose logs` rotation or a nightly `docker compose restart`.

## 7. Updating

```sh
git pull
docker compose up -d --build
```

Migrations run automatically on API start, guarded by a Postgres advisory lock.

## 8. Verifying the served web app

Each build writes `build-meta/build-manifest.json` (baked into the Caddy image at
`/etc/caddy/build-manifest.json`), which contains a `buildHash` over every served file. CI
publishes the same hash for each commit. Because the build is reproducible, anyone can rebuild
from the tagged source and compare.

```sh
docker compose exec caddy cat /etc/caddy/build-manifest.json | head -3
```

## 9. Tor onion service (Phase 4)

Planned: a `tor` container that publishes the Caddy service as a v3 onion address, with an
`Onion-Location` header on clearnet responses.
