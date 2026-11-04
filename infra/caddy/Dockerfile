# syntax=docker/dockerfile:1
# Build context: repository root. Builds the static web app and bakes it,
# plus its generated CSP, into the Caddy image.

FROM node:22.23.4-alpine AS web
WORKDIR /repo
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc tsconfig.base.json ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/types/package.json packages/types/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY e2e/package.json e2e/
RUN pnpm install --frozen-lockfile --filter "@opsec-aio/web..."
COPY packages/crypto packages/crypto
COPY packages/types packages/types
COPY apps/web apps/web
RUN pnpm --filter @opsec-aio/web run build

FROM caddy:2.11.7-alpine
COPY infra/caddy/Caddyfile /etc/caddy/Caddyfile
COPY --from=web /repo/apps/web/build /srv
COPY --from=web /repo/apps/web/build-meta/csp.caddy /etc/caddy/csp.caddy
COPY --from=web /repo/apps/web/build-meta/build-manifest.json /etc/caddy/build-manifest.json
# Run unprivileged; the official binary already has cap_net_bind_service.
RUN mkdir -p /data/caddy /config/caddy && chown -R 1000:1000 /data /config
USER 1000:1000
