# syntax=docker/dockerfile:1
# Build context: repository root.

FROM node:22.23.4-alpine AS build
WORKDIR /repo
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc tsconfig.base.json ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/types/package.json packages/types/
COPY packages/chat/package.json packages/chat/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY e2e/package.json e2e/
RUN pnpm install --frozen-lockfile --filter "@opsec-aio/api..."
COPY packages/crypto packages/crypto
COPY packages/types packages/types
COPY packages/chat packages/chat
COPY apps/api apps/api
RUN pnpm --filter "@opsec-aio/api..." run build \
 && pnpm --filter @opsec-aio/api deploy --prod --legacy /out

FROM node:22.23.4-alpine
ENV NODE_ENV=production
WORKDIR /app
# Code is root-owned and read-only to the runtime user.
COPY --from=build /out /app
# Blob volume mount point, owned by the unprivileged user so a fresh named
# volume inherits the right ownership.
RUN mkdir -p /data/blobs && chown node:node /data/blobs && chmod 700 /data/blobs
USER node
EXPOSE 3000
CMD ["node", "dist/server.js"]
