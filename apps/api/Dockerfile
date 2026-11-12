# syntax=docker/dockerfile:1
# --- build ---------------------------------------------------------------
FROM golang:1.27.3-alpine AS build
ARG VERSION=dev
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/api ./cmd/api && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w" -o /out/migrate ./cmd/migrate

# --- runtime -------------------------------------------------------------
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata wget && \
    adduser -D -u 10001 aps
COPY --from=build /out/api /usr/local/bin/api
COPY --from=build /out/migrate /usr/local/bin/migrate
USER aps
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["api"]
