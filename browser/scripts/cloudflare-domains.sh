#!/usr/bin/env bash
# Attach the identity service's custom domains via the Workers Domains
# API. The ONLY way domains are managed: `routes` in wrangler.toml are
# forbidden (the generated deploy config applies a top-level route to
# every env deploy and ignores env-scoped routes — an env deploy once
# stole the production domain, 2026-08-15).
#
# Usage: source ~/.cloudflare-credentials-oimlsmart && browser/scripts/cloudflare-domains.sh
set -euo pipefail
# Accept the operator's file OR the CI workflow's env names.
: "${ACCOUNT_ID:="${CLOUDFLARE_ACCOUNT_ID:-}"}"
: "${API_TOKEN:="${CLOUDFLARE_API_TOKEN:-}"}"
: "${ACCOUNT_ID:?source the credentials file or set CLOUDFLARE_ACCOUNT_ID}"
: "${API_TOKEN:?source the credentials file or set CLOUDFLARE_API_TOKEN}"

api() {
  local method="$1" path="$2" data="${3:-}"
  curl -sS -X "$method" "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/$path" \
    -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
    ${data:+--data "$data"}
}

attach() {
  local hostname="$1" service="$2"
  local exists
  exists=$(api GET "workers/services/$service" | jq -r '.result.id // empty' 2>/dev/null)
  if [ -z "$exists" ]; then
    echo "$hostname: skipped (the service $service is not deployed yet)"
    return 0
  fi
  local existing
  existing=$(api GET "workers/domains" | jq -r ".result[]? | select(.hostname==\"$hostname\") | .id")
  if [ -n "$existing" ]; then
    local current
    current=$(api GET "workers/domains" | jq -r ".result[]? | select(.hostname==\"$hostname\") | .service")
    if [ "$current" = "$service" ]; then
      echo "$hostname -> $service (already correct)"
      return 0
    fi
    echo "$hostname: re-pointing from $current to $service"
    api DELETE "workers/domains/$existing" > /dev/null
  fi
  api PUT "workers/domains" "{\"environment\":\"production\",\"hostname\":\"$hostname\",\"service\":\"$service\"}" \
    | jq -r '.result | "\(.hostname) -> \(.service)"'
}

# The identity service's two domains ONLY (the platform's attach lines
# stay with the monorepo's script).
attach "id.oimlsmart.org"                "oiml-smart-platform-identity"
attach "id-preview.oimlsmart.org"        "oiml-smart-platform-identity-preview"
