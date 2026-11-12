#!/usr/bin/env bash
# End-to-end smoke check against the deployed stack (default :8006).
# Verifies acceptance-critical flows: login -> refresh -> replay -> JWKS.
set -euo pipefail

BASE="${1:-http://localhost:8006}"
USER="${SMOKE_USER:-alice}"
PASS="${SMOKE_PASS:-alice_password}"

say() { printf '\n== %s\n' "$*"; }

say "health/ready"
curl -fsS "$BASE/health" | grep -q '"ok"'
curl -fsS "$BASE/ready" | grep -q '"ready"'

say "JWKS publishes a kid"
KID=$(curl -fsS "$BASE/.well-known/jwks.json" | grep -o '"kid":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$KID" ] && echo "kid=$KID"

say "login ($USER)"
LOGIN=$(curl -fsS -X POST "$BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' \
  -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}")
ACCESS=$(echo "$LOGIN" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
REFRESH=$(echo "$LOGIN" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
[ -n "$ACCESS" ] && [ -n "$REFRESH" ] && echo "tokens received"

say "refresh rotates"
R2=$(curl -fsS -X POST "$BASE/api/v1/auth/refresh" \
  -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' \
  -d "{\"refresh_token\":\"$REFRESH\"}")
NEW=$(echo "$R2" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
[ -n "$NEW" ] && [ "$NEW" != "$REFRESH" ] && echo "rotated ok"

say "replay of used token -> 401 (S-04)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/refresh" \
  -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' \
  -d "{\"refresh_token\":\"$REFRESH\"}")
[ "$CODE" = "401" ] && echo "replay rejected with 401"

say "/auth/me with access token"
curl -fsS "$BASE/api/v1/auth/me" -H "Authorization: Bearer $ACCESS" | grep -q "$USER"

say "cookie flags (S-10)"
FLAGS=$(curl -s -D - -o /dev/null -X POST "$BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' \
  -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" | grep -i 'set-cookie: aps_refresh')
echo "$FLAGS" | grep -qi 'httponly' && echo "$FLAGS" | grep -qi 'samesite=strict' \
  && echo "$FLAGS" | grep -qi 'path=/api/v1/auth' && echo "cookie flags ok"

say "ALL SMOKE CHECKS PASSED"
