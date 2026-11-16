#!/usr/bin/env bash
# OpSec AIO — one-shot installer for a fresh Ubuntu 24.04 / 26.04 LTS VPS.
#
#   curl -fsSL https://raw.githubusercontent.com/jagboy88/OPSEC-AIO/main/scripts/install-vps.sh -o install.sh
#   sudo bash install.sh                 # free address: <your-ip>.sslip.io
#   sudo bash install.sh chat.example.com   # or your own domain (A record → this server first)
#
# Safe to re-run: it updates the code and keeps existing secrets and settings.
# What it does: system updates + automatic security updates, firewall (SSH, 80,
# 443), fail2ban, swap, Docker, then builds and starts the stack and checks it.
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/jagboy88/OPSEC-AIO.git}"
APP_DIR="${APP_DIR:-/opt/opsec-aio}"
DOMAIN="${1:-}"

say() { printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!!  %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mxx  %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (or with sudo)."
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || die "This installer supports Ubuntu only (found: ${ID:-unknown})."
case "${VERSION_ID:-}" in
  24.04 | 26.04) ;;
  *) warn "Tested on Ubuntu 24.04/26.04 LTS; you have ${VERSION_ID:-unknown}. Continuing." ;;
esac

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
APT_OPTS=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

say "Updating the system (this can take a few minutes)"
apt-get update -q
apt-get "${APT_OPTS[@]}" full-upgrade
apt-get "${APT_OPTS[@]}" install ca-certificates curl git ufw fail2ban unattended-upgrades

say "Turning on automatic security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true

say "Firewall: allow SSH, HTTP and HTTPS only"
SSH_PORTS="$(sshd -T 2>/dev/null | awk '/^port /{print $2}' | sort -u | tr '\n' ' ')"
[ -n "$SSH_PORTS" ] || SSH_PORTS="22"
for p in $SSH_PORTS; do ufw allow "$p/tcp" comment 'SSH' >/dev/null; done
ufw allow 80/tcp comment 'HTTP (certificates, redirect)' >/dev/null
ufw allow 443/tcp comment 'HTTPS' >/dev/null
ufw allow 443/udp comment 'HTTP/3' >/dev/null
ufw --force enable >/dev/null
echo "SSH port(s) kept open: $SSH_PORTS"

say "fail2ban: block repeated SSH login failures"
systemctl enable --now fail2ban >/dev/null 2>&1 || true

if ! swapon --show | grep -q .; then
  say "Adding 2 GB swap (keeps builds from running out of memory)"
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
# Recommended by Redis; harmless otherwise.
echo 'vm.overcommit_memory = 1' > /etc/sysctl.d/90-opsec-aio.conf
sysctl -q -p /etc/sysctl.d/90-opsec-aio.conf

if ! command -v docker >/dev/null 2>&1; then
  say "Installing Docker (official repository)"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get "${APT_OPTS[@]}" install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
fi
docker compose version >/dev/null || die "Docker Compose plugin missing."

say "Downloading OpSec AIO"
if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" pull --ff-only
else
  git clone --depth 1 "$REPO_URL" "$APP_DIR" ||
    die "Could not download $REPO_URL. Is the GitHub repository public?"
fi
cd "$APP_DIR"

say "Generating secrets (kept if they already exist)"
./scripts/init-secrets.sh

if [ ! -f .env ]; then
  if [ -z "$DOMAIN" ]; then
    # The address on this server's own default route (no packet is sent). Only
    # if that is private (the server is behind NAT) ask a public IP service.
    IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="src") print $(i+1)}')"
    case "$IP" in
      "" | 10.* | 127.* | 192.168.* | 169.254.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[01].* | \
        100.6[4-9].* | 100.[7-9][0-9].* | 100.1[01][0-9].* | 100.12[0-7].*)
        IP="$(curl -4fsS --max-time 10 https://api.ipify.org || true)" ;;
    esac
    [ -n "$IP" ] || die "Could not detect this server's public IPv4. Re-run with your domain: bash install.sh your.domain"
    DOMAIN="${IP//./-}.sslip.io"
  fi
  # Cap Drop storage at the free disk minus 15 GiB headroom (OS, Docker images, database).
  AVAIL="$(df --output=avail -B1 / | tail -1)"
  CAP=$(( AVAIL - 15 * 1024 ** 3 ))
  MIN=$(( 2 * 1024 ** 3 )); MAX=$(( 100 * 1024 ** 3 ))
  [ "$CAP" -lt "$MIN" ] && CAP=$MIN
  [ "$CAP" -gt "$MAX" ] && CAP=$MAX
  cat > .env <<EOF
SITE_ADDRESS=$DOMAIN
HTTP_PORT=80
HTTPS_PORT=443
LOG_LEVEL=warn
DROP_STORAGE_MAX_BYTES=$CAP
RATE_LIMIT_MULTIPLIER=1
EOF
  chmod 600 .env
  echo "Address: $DOMAIN · Drop storage cap: $(( CAP / 1024 ** 3 )) GiB"
else
  DOMAIN="$(sed -n 's/^SITE_ADDRESS=//p' .env)"
  echo "Keeping existing settings in $APP_DIR/.env (address: $DOMAIN)"
fi

say "Building and starting (first build takes 3–8 minutes)"
docker compose up -d --build --wait --wait-timeout 300

say "Checking the site over HTTPS (certificate can take up to a minute)"
ok=""
for _ in $(seq 1 24); do
  if curl -fsS --max-time 10 "https://$DOMAIN/api/v1/health" 2>/dev/null | grep -q '"status":"ok"'; then
    ok=1
    break
  fi
  sleep 5
done

echo
if [ -n "$ok" ]; then
  printf '\033[1;32m✔ OpSec AIO is live: https://%s\033[0m\n' "$DOMAIN"
else
  warn "The stack is running but https://$DOMAIN isn't answering yet."
  warn "Wait a minute and open it in a browser. If it still fails: docker compose -f $APP_DIR/docker-compose.yml logs caddy"
fi
cat <<EOF

Build hash of the web app now being served (compare with CI's published hash):
  $(docker compose exec -T caddy cat /etc/caddy/build-manifest.json 2>/dev/null | sed -n 's/.*"buildHash": "\(.*\)".*/\1/p')

Secrets:   $APP_DIR/secrets/   (back these up offline; never commit them)
Settings:  $APP_DIR/.env
Update:    sudo bash $APP_DIR/scripts/update.sh
Logs:      cd $APP_DIR && docker compose logs --tail 50

Next: set up an SSH key and turn off password logins (see docs/DEPLOY.md).
Tip: a *.sslip.io address works, but whoever runs sslip.io's DNS could point it
elsewhere. For real use, put the site on your own domain (docs/DEPLOY.md §1).
EOF
if [ -f /var/run/reboot-required ]; then
  warn "System updates need a reboot. Run: reboot   (the site starts again automatically)"
fi
