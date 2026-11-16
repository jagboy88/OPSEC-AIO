#!/usr/bin/env bash
# Enable the Tor onion service for an OpSec AIO install (run on the server, as root):
#   bash /opt/opsec-aio/scripts/enable-tor.sh
# Safe to re-run. Prints the .onion address when done.
set -euo pipefail
cd "$(dirname "$0")/.."

say() { printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mxx  %s\033[0m\n' "$*" >&2; exit 1; }

[ -f .env ] || die "No .env found: run scripts/install-vps.sh first."

set_env() { # set_env KEY VALUE: replace or append a line in .env
  if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi
}

say "Turning on the tor profile"
set_env COMPOSE_PROFILES tor

say "Building and starting Tor"
docker compose up -d --build tor

say "Waiting for the onion address"
ONION=""
for _ in $(seq 1 30); do
  ONION="$(docker compose exec -T tor cat /var/lib/tor/opsec/hostname 2>/dev/null | tr -d '[:space:]' || true)"
  [ -n "$ONION" ] && break
  sleep 2
done
[[ "$ONION" =~ ^[a-z2-7]{56}\.onion$ ]] || die "Tor did not create an onion address. Logs: docker compose logs tor"

say "Advertising it to Tor Browser users (Onion-Location header)"
set_env ONION_ADDRESS "$ONION"
docker compose up -d --force-recreate caddy tor

cat <<MSG

$(printf '\033[1;32m✔ Onion service enabled:\033[0m') http://$ONION

It can take a few minutes before the address is reachable on the Tor network.
Open it in Tor Browser (security level "Standard": "Safer" turns off WebAssembly,
which the encryption needs).

Back up the onion key (it IS the address; lose it and you get a new one):
  docker compose cp tor:/var/lib/tor/opsec/hs_ed25519_secret_key ./secrets/onion_hs_ed25519_secret_key
  chmod 600 ./secrets/onion_hs_ed25519_secret_key
then copy secrets/ off the server as before.

To turn it off: remove COMPOSE_PROFILES and ONION_ADDRESS from .env, then
  docker compose up -d --remove-orphans
MSG
