#!/usr/bin/env bash
# One-time setup of the vps_sso token registry in mesh-postgres.
# - creates role `vps_sso` + database `vps_sso` (owned by it)
# - applies db/schema.sql (schema vps_sso + tables)
# - stores the connection URL in secrets-gateway as VPS_SSO_DB_URL
# Idempotent: safe to re-run (rotates the role password each run).
# The DB password is generated on-host and never printed.
set -euo pipefail
cd /root/vps-sso

SECGW="${SECGW_URL:-http://100.66.108.118:8783}"
PGC="mesh-postgres"                 # docker container name
PGHOST_APP="127.0.0.1"             # how the app/CLI reach PG from the host
PGPORT_APP="5433"

# --- bootstrap MESH_TOKEN from BWS (same pattern as mint-machine-token.sh) ----
set -a; . ./.env 2>/dev/null || true; set +a
BWS_ENV="${BWS_ENV_FILE:-/root/.hermes/bitwarden-sm.env}"
BWS_PROJECT="${BWS_PROJECT:-8de999c8-5765-4de5-92a5-b45e001d0955}"
if [ -z "${MESH_TOKEN:-}" ] && [ -f "$BWS_ENV" ]; then
  MESH_TOKEN="$(bash -c "set -a; . '$BWS_ENV'; set +a; /root/.hermes/bin/bws secret list '$BWS_PROJECT' -o json" 2>/dev/null \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print({s["key"]:s["value"] for s in d}.get("MESH_TOKEN",""))' 2>/dev/null || true)"
fi
MT="${MESH_TOKEN:?MESH_TOKEN unavailable (BWS/.env)}"

# --- 1) generate a strong, URL-safe role password (never printed) ------------
DBPASS="$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 48)"
[ "${#DBPASS}" -ge 40 ] || { echo "setup: weak password generated" >&2; exit 1; }

# --- 2) role + database as superuser (mesh_admin, local socket) ---------------
docker exec -i "$PGC" psql -U mesh_admin -d postgres -v ON_ERROR_STOP=1 <<SQL
DO \$do\$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vps_sso') THEN
    ALTER ROLE vps_sso LOGIN PASSWORD '${DBPASS}';
  ELSE
    CREATE ROLE vps_sso LOGIN PASSWORD '${DBPASS}';
  END IF;
END \$do\$;
SQL

if ! docker exec "$PGC" psql -U mesh_admin -d postgres -tAc \
      "SELECT 1 FROM pg_database WHERE datname='vps_sso'" | grep -q 1; then
  docker exec "$PGC" psql -U mesh_admin -d postgres -c "CREATE DATABASE vps_sso OWNER vps_sso"
fi

# --- 3) apply schema as the owning role (TCP => password auth) ----------------
docker exec -i -e PGPASSWORD="$DBPASS" "$PGC" \
  psql -h 127.0.0.1 -U vps_sso -d vps_sso -v ON_ERROR_STOP=1 < db/schema.sql

# --- 4) store connection URL in secrets-gateway (value never printed) ---------
DBURL="postgresql://vps_sso:${DBPASS}@${PGHOST_APP}:${PGPORT_APP}/vps_sso"
CODE="$(curl -fsS -m 8 -o /dev/null -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer $MT" -H "Content-Type: application/json" \
  --data "$(python3 -c 'import json,sys;print(json.dumps({"value":sys.argv[1],"note":sys.argv[2]}))' \
            "$DBURL" "vps-sso opaque service_tokens registry (Plan B)")" \
  "$SECGW/secrets/VPS_SSO_DB_URL")"

echo "setup: role+db vps_sso ready; schema applied"
echo "setup: PUT VPS_SSO_DB_URL -> HTTP $CODE"
echo "setup: verify -> docker exec -e PGPASSWORD=... $PGC psql -h 127.0.0.1 -U vps_sso -d vps_sso -c '\\dt vps_sso.*'"
