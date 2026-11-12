# syntax=docker/dockerfile:1
# --- build ---------------------------------------------------------------
# NOTE: runtime stage is scratch because the Alpine package CDN is not
# reachable from this build host (apk add fails); everything needed ships
# from the builder stage.
FROM golang:1.27.3-alpine AS build
ARG VERSION=dev
WORKDIR /src

# Dependencies ship via vendor/ — this build host cannot reach
# proxy.golang.org (network unreachable), so no `go mod download` here.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/api ./cmd/api && \
    CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath \
    -ldflags "-s -w" -o /out/migrate ./cmd/migrate && \
    CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath \
    -ldflags "-s -w" -o /out/healthcheck ./cmd/healthcheck && \
    cp /etc/ssl/certs/ca-certificates.crt /out/

# --- runtime -------------------------------------------------------------
FROM scratch
COPY --from=build /out/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/api /usr/local/bin/api
COPY --from=build /out/migrate /usr/local/bin/migrate
COPY --from=build /out/healthcheck /usr/local/bin/healthcheck
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/healthcheck"]
ENTRYPOINT ["/usr/local/bin/api"]
