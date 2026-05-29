#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8081}"

require() { command -v "$1" >/dev/null || { echo "missing dependency: $1" >&2; exit 1; }; }
require curl
require jq

pass="securepass123"
email="e2e+$(date +%s%N)@example.com"
payload=$(jq -nc --arg email "$email" --arg password "$pass" '{email:$email,password:$password}')
idem="e2e-reg-$(date +%s%N)"

echo "→ health"
curl -fsS "$BASE_URL/health" >/dev/null

echo "→ register (idempotent)"
status=$(curl -s -o /tmp/e2e_reg.json -w "%{http_code}" -X POST "$BASE_URL/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: $idem" \
  -d "$payload")
test "$status" = "201"

status2=$(curl -s -o /tmp/e2e_reg2.json -w "%{http_code}" -X POST "$BASE_URL/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: $idem" \
  -d "$payload")
test "$status2" = "201"
cmp -s /tmp/e2e_reg.json /tmp/e2e_reg2.json

echo "→ login (cookie jar)"
cookies="$(mktemp)"
login=$(curl -fsS -c "$cookies" -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "$payload")
access=$(echo "$login" | jq -r '.access_token')
test -n "$access" && test "$access" != "null"

echo "→ me"
curl -fsS "$BASE_URL/api/v1/me" -H "Authorization: Bearer $access" | jq -e '.Email' >/dev/null

echo "→ refresh (cookie)"
refresh=$(curl -fsS -b "$cookies" -c "$cookies" -X POST "$BASE_URL/api/v1/auth/refresh")
access2=$(echo "$refresh" | jq -r '.access_token')
test -n "$access2" && test "$access2" != "null"

echo "→ logout"
curl -fsS -b "$cookies" -c "$cookies" -X POST "$BASE_URL/api/v1/auth/logout" \
  -H "Authorization: Bearer $access2" >/dev/null

rm -f "$cookies" /tmp/e2e_reg.json /tmp/e2e_reg2.json
echo "OK"
