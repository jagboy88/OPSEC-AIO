#!/bin/sh
# Generate the stack's secrets once. Never commit the secrets/ directory.
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p secrets
chmod 700 secrets

gen() {
  # 32 random bytes, base64url without padding.
  head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'
}

for name in postgres_password redis_password token_pepper; do
  if [ -s "secrets/$name" ]; then
    echo "secrets/$name exists, keeping it"
  else
    gen > "secrets/$name"
    echo "generated secrets/$name"
  fi
  # Readable by the unprivileged container users; the 0700 directory keeps
  # other host users out.
  chmod 644 "secrets/$name"
done
