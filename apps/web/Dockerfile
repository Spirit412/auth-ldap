# syntax=docker/dockerfile:1
# Runtime-only image: the SPA is built OUTSIDE docker (pnpm --filter @aps/web
# build) and shipped via the build context, because this host cannot reach
# registry.npmjs.org (ENETUNREACH) nor the Alpine package CDN.
# CI builds the app with pnpm directly; the full node build variant can be
# restored when registry access is available.
# Build context: repository root.
FROM nginx:1.31.8-alpine
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY apps/web/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1/healthz || exit 1
