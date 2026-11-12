# syntax=docker/dockerfile:1
# Build context: repository root (needs the pnpm workspace).
FROM node:26.12.0-alpine AS build
WORKDIR /src
# Node 25+ 镜像不再内置 corepack，直接安装 pnpm
RUN npm install -g pnpm@12.18.0

COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY apps/web/package.json apps/web/
COPY packages/shared-types/package.json packages/shared-types/
RUN pnpm install --no-frozen-lockfile

COPY packages/shared-types packages/shared-types
COPY apps/web apps/web
RUN pnpm --filter @aps/shared-types generate && pnpm --filter @aps/web build

FROM nginx:1.31.8-alpine
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/apps/web/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1/healthz || exit 1
