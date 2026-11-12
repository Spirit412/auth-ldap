# APS monorepo — unified commands.
SHELL := /bin/bash

.PHONY: help keys certs dev up down logs build test lint openapi generate-types migrate smoke e2e

help:
	@echo "make keys            — generate JWT signing key + kid into deploy/keys"
	@echo "make certs           — generate self-signed cert for mock LDAP (glauth)"
	@echo "make dev             — build & start the full stack (incl. mock AD) on :8006"
	@echo "make up / down       — start/stop without the dev profile"
	@echo "make logs            — tail api+web logs"
	@echo "make test            — go unit tests + web vitest"
	@echo "make lint            — go vet/fmt check + web tsc"
	@echo "make build           — go build + vite build"
	@echo "make openapi         — dump openapi.yaml into packages/shared-types"
	@echo "make generate-types  — regenerate TS client from the spec"
	@echo "make migrate         — apply DB migrations (cmd/migrate)"
	@echo "make smoke           — end-to-end smoke check against :8006"
	@echo "make e2e             — playwright suite against :8006"

keys:
	@mkdir -p deploy/keys
	@test -f deploy/keys/jwt-active.pem || openssl genrsa -out deploy/keys/jwt-active.pem 2048
	@bash -c 'test -f deploy/keys/kid || openssl rand -hex 4 > deploy/keys/kid'
	@echo "JWT key ready; kid = $$(cat deploy/keys/kid)"

certs:
	@mkdir -p deploy/glauth
	@test -f deploy/glauth/glauth.crt || MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 \
		-keyout deploy/glauth/glauth.key -out deploy/glauth/glauth.crt -days 3650 -nodes -subj "/CN=glauth"
	@echo "glauth TLS cert ready"

dev: keys certs
	docker compose --profile dev up --build -d
	@echo "APS: http://localhost:8006 (alice/alice_password — admin, bob/bob_password — user)"

up:
	docker compose up --build -d

down:
	docker compose --profile dev down

logs:
	docker compose logs -f api web

build:
	cd apps/api && go build ./...
	cd apps/web && pnpm build

test:
	cd apps/api && go test ./...
	cd apps/web && pnpm test

lint:
	cd apps/api && go vet ./... && test -z "$$(gofmt -l . | grep -v _gen)" || (gofmt -l .; exit 1)
	cd apps/web && pnpm lint

openapi:
	cd apps/api && go run ./cmd/openapi -out ../../packages/shared-types/openapi.yaml

generate-types: openapi
	cd packages/shared-types && pnpm generate

migrate:
	cd apps/api && go run ./cmd/migrate up

smoke:
	@bash scripts/smoke.sh

e2e:
	cd apps/web && npx playwright install --with-deps && npx playwright test
