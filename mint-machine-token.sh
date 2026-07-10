#!/usr/bin/env bash
# Mint a per-service machine token for SSO-protected services and store it in
# secrets-gateway. The token is a JWT (HS256, same secret as human cookies) with
# a `svc` claim scoping it to ONE service host. A machine delivers it as the
# sso_token cookie: `Cookie: sso_token=<jwt>` (nginx forwards Cookie, not Authorization).
#
# Usage:  mint-machine-token.sh <machine> <service-host> [exp]
#   e.g.  mint-machine-token.sh sergpc obhid.ibotz.fun
#         mint-machine-token.sh sergpc obhid.ibotz.fun 90d
#
# Stores under key  SSO_MACHINE_TOKEN_<MACHINE>_<SERVICE_SLUG>  in secrets-gateway.
# Prints the key name and a usage curl (never re-prints the secret value in logs).
set -euo pipefail
cd /root/vps-sso

MACHINE="${1:?usage: mint-machine-token.sh <machine> <service-host> [exp]}"
SERVICE="${2:?usage: mint-machine-token.sh <machine> <service-host> [exp]}"
EXP="${3:-3650d}"
SERVICE="$(echo "$SERVICE" | tr '[:upper:]' '[:lower:]')"

SECGW="${SECGW_URL:-http://100.66.108.118:8783}"
NODE=/root/.nvm/versions/node/v22.22.3/bin/node

# --- bootstrap MESH_TOKEN from BWS (same pattern as run.sh) -------------------
set -a; . ./.env 2>/dev/null || true; set +a
BWS_ENV="${BWS_ENV_FILE:-/root/.hermes/bitwarden-sm.env}"
BWS_PROJECT="${BWS_PROJECT:-8de999c8-5765-4de5-92a5-b45e001d0955}"
if [ -z "${MESH_TOKEN:-}" ] && [ -f "$BWS_ENV" ]; then
  MESH_TOKEN="$(bash -c "set -a; . '$BWS_ENV'; set +a; /root/.hermes/bin/bws secret list '$BWS_PROJECT' -o json" 2>/dev/null \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print({s["key"]:s["value"] for s in d}.get("MESH_TOKEN",""))' 2>/dev/null || true)"
fi
MT="${MESH_TOKEN:?MESH_TOKEN unavailable (BWS/.env)}"

_val() { python3 -c "import sys,json;print(json.load(sys.stdin).get('value') or '')"; }

# --- fetch signing secret from secrets-gateway -------------------------------
JWT_SECRET="$(curl -fsS -m 8 -H "Authorization: Bearer $MT" "$SECGW/secrets/VPS_SSO_JWT_SECRET" | _val)"
[ -n "$JWT_SECRET" ] || { echo "mint: VPS_SSO_JWT_SECRET empty from gateway" >&2; exit 1; }

# --- sign -------------------------------------------------------------------
TOKEN="$(JWT_SECRET="$JWT_SECRET" \
  SUB="machine:${MACHINE}" NAME="${MACHINE} (machine)" EMAIL="${MACHINE}@machines.mesh" \
  SVC="$SERVICE" EXP="$EXP" \
  "$NODE" /root/vps-sso/sign-machine-token.js)"
[ -n "$TOKEN" ] || { echo "mint: signing produced empty token" >&2; exit 1; }

# --- store in secrets-gateway ------------------------------------------------
SVC_SLUG="$(echo "$SERVICE" | tr '.-' '__' | tr '[:lower:]' '[:upper:]')"
MACH_SLUG="$(echo "$MACHINE" | tr '.-' '__' | tr '[:lower:]' '[:upper:]')"
KEY="SSO_MACHINE_TOKEN_${MACH_SLUG}_${SVC_SLUG}"
NOTE="machine=${MACHINE} svc=${SERVICE} exp=${EXP} — deliver as Cookie sso_token=<value>"

CODE="$(curl -fsS -m 8 -o /dev/null -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer $MT" -H "Content-Type: application/json" \
  --data "$(python3 -c 'import json,sys;print(json.dumps({"value":sys.argv[1],"note":sys.argv[2]}))' "$TOKEN" "$NOTE")" \
  "$SECGW/secrets/$KEY")"

echo "mint: PUT $KEY -> HTTP $CODE"
echo "mint: key    = $KEY"
echo "mint: svc    = $SERVICE   (token valid ONLY for this host)"
echo "mint: exp    = $EXP"
echo "mint: usage  = curl -H 'Cookie: sso_token=<value>' https://$SERVICE/..."
echo "mint: fetch  = curl -H 'Authorization: Bearer \$MESH_TOKEN' $SECGW/secrets/$KEY"
