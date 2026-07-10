#!/usr/bin/env bash
# Prove sso_access is read LIVE from config-store (no SSO restart needed).
# Adds a throwaway email->[reader.ibotz.fun] to config-store, signs a human token
# for it, and checks auth/check reflects it within the TTL. The email is NOT in
# the boot-time env snapshot, so a 200 can only come from a live config-store read.
# Reverts config-store at the end.
set -euo pipefail
cd /root/vps-sso
export PATH=/root/.nvm/versions/node/v22.22.3/bin:$PATH
SECGW=http://100.66.108.118:8783
CFGW=http://100.66.108.118:8782
TTL=16
EMAIL="dyntest@example.invalid"

set -a; . ./.env 2>/dev/null || true; set +a
BWS_ENV=/root/.hermes/bitwarden-sm.env
BWS_PROJECT=8de999c8-5765-4de5-92a5-b45e001d0955
if [ -z "${MESH_TOKEN:-}" ]; then
  MESH_TOKEN="$(bash -c "set -a; . '$BWS_ENV'; set +a; /root/.hermes/bin/bws secret list '$BWS_PROJECT' -o json" 2>/dev/null \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print({s["key"]:s["value"] for s in d}.get("MESH_TOKEN",""))')"
fi
MT="$MESH_TOKEN"
_val() { python3 -c "import sys,json;print(json.load(sys.stdin).get('value') or '')"; }

JWT_SECRET="$(curl -fsS -H "Authorization: Bearer $MT" "$SECGW/secrets/VPS_SSO_JWT_SECRET" | _val)"
INTERNAL="$(curl -fsS -H "Authorization: Bearer $MT" "$SECGW/secrets/VPS_SSO_INTERNAL_SECRET" | _val)"
CST="$(curl -fsS -H "Authorization: Bearer $MT" "$SECGW/secrets/CONFIG_STORE_TOKEN" | _val)"

# --- snapshot current sso_access (to restore) ---
ORIG_JSON="$(curl -fsS -H "Authorization: Bearer $CST" "$CFGW/config/defaults/sso_access")"
ORIG_VAL="$(echo "$ORIG_JSON" | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin).get("value")))')"
echo "snapshot sso_access captured (len=${#ORIG_VAL})"

# --- build modified map with throwaway email, PUT back (value type preserved) ---
NEW_VAL="$(echo "$ORIG_VAL" | python3 -c '
import sys, json
raw = json.load(sys.stdin)                 # original value (str-JSON or object)
obj = json.loads(raw) if isinstance(raw, str) else raw
obj["dyntest@example.invalid"] = ["reader.ibotz.fun"]
# preserve original storage shape: string-JSON stays string, object stays object
print(json.dumps(json.dumps(obj) if isinstance(raw, str) else obj))
')"
put() { curl -fsS -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $CST" \
  -H "Content-Type: application/json" --data "$(python3 -c 'import json,sys;print(json.dumps({"value":json.loads(sys.argv[1])}))' "$1")" \
  "$CFGW/config/defaults/sso_access"; }

restore() { echo; echo "restore: $(put "$ORIG_VAL")"; }
trap restore EXIT

echo "PUT modified sso_access: $(put "$NEW_VAL")"

# --- sign human token for the throwaway email (email path, no svc claim) ---
sign_human() { JWT_SECRET="$JWT_SECRET" node -e '
const {SignJWT}=require("jose");
const s=new TextEncoder().encode(process.env.JWT_SECRET);
(async()=>{const t=await new SignJWT({sub:"u",email:process.argv[1],name:"dyn"})
  .setProtectedHeader({alg:"HS256"}).setIssuedAt().setExpirationTime("1h").sign(s);
  process.stdout.write(t)})()' "$1"; }
TOKEN="$(sign_human "$EMAIL")"

check() { local host="$1" want="$2" code
  code="$(curl -fsS -o /dev/null -w '%{http_code}' -H "X-Internal-Secret: $INTERNAL" \
    -H "X-Forwarded-Host: $host" -H "Cookie: sso_token=$TOKEN" \
    "http://[::1]:3010/api/auth/check" || true)"
  local m=OK; [ "$code" = "$want" ] || m=FAIL
  printf '  [%s] %-18s -> %s (want %s)\n' "$m" "$host" "$code" "$want"; }

echo "waiting ${TTL}s for TTL cache to expire, then re-check (NO restart)..."
sleep "$TTL"
echo "dynamic access matrix (email=$EMAIL, added live to config-store):"
check reader.ibotz.fun 200   # granted live -> must be 200 (proves live read)
check obhid.ibotz.fun  403   # not granted   -> 403
