#!/usr/bin/env bash
# OpSec AIO — update a running server to the latest version.
#
#   sudo bash /opt/opsec-aio/scripts/update.sh
#
# Pulls the code, rebuilds, restarts with zero config changes (secrets and
# .env are kept), waits until every service is healthy, then checks the site.
# Database migrations run automatically when the API starts.
set -euo pipefail

APP_DIR="${APP_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$APP_DIR"

say() { printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!!  %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mxx  %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (or with sudo)."
[ -f .env ] || die "No $APP_DIR/.env. Install first: bash scripts/install-vps.sh"

say "Downloading the latest version"
before="$(git rev-parse --short HEAD)"
git pull --ff-only || die "git pull failed (local edits in $APP_DIR?). Check: git -C $APP_DIR status"
after="$(git rev-parse --short HEAD)"
if [ "$before" = "$after" ]; then
  echo "Already up to date ($after). Rebuilding anyway."
else
  echo "$before → $after"
  git --no-pager log --oneline "$before..$after" | head -20
fi

say "Rebuilding and restarting (a few minutes)"
# COMPOSE_PROFILES in .env (set by enable-tor.sh) keeps Tor running if enabled.
docker compose up -d --build --wait --wait-timeout 300 --remove-orphans

say "Checking the site"
DOMAIN="$(sed -n 's/^SITE_ADDRESS=//p' .env)"
ok=""
for _ in $(seq 1 12); do
  if curl -fsS --max-time 10 "https://$DOMAIN/api/v1/health" 2>/dev/null | grep -q '"status":"ok"'; then
    ok=1
    break
  fi
  sleep 5
done
if [ -n "$ok" ]; then
  printf '\033[1;32m✔ Updated and live: https://%s\033[0m\n' "$DOMAIN"
else
  warn "Services are running but https://$DOMAIN isn't answering yet."
  warn "Look at: docker compose -f $APP_DIR/docker-compose.yml logs --tail 50 caddy api"
fi

cat <<EOF

Build hash now being served (compare with the one CI publishes for $after):
  $(docker compose exec -T caddy cat /etc/caddy/build-manifest.json 2>/dev/null | sed -n 's/.*"buildHash": "\(.*\)".*/\1/p')
EOF
ONION="$(sed -n 's/^ONION_ADDRESS=//p' .env)"
[ -z "$ONION" ] || echo "Onion address: http://$ONION"

# Old images from previous builds just take up disk.
docker image prune -f >/dev/null 2>&1 || true

if [ -f /var/run/reboot-required ]; then
  warn "System updates need a reboot. Run: reboot   (the site starts again automatically)"
fi
