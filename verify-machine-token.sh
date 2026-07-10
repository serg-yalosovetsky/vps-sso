#!/usr/bin/env bash
# Verify the machine-token auth path by replaying nginx's auth subrequest against
# the running vps-sso. Reads (never writes) JWT_SECRET + INTERNAL_SECRET from the
# gateway, signs a token scoped to obhid.ibotz.fun, and checks the 200/403/401 matrix.
set -euo pipefail
cd /root/vps-sso
export PATH=/root/.nvm/versions/node/v22.22.3/bin:$PATH
SECGW="${SECGW_URL:-http://100.66.108.118:8783}"

set -a; . ./.env 2>/dev/null || true; set +a
BWS_ENV=/root/.hermes/bitwarden-sm.env
BWS_PROJECT=8de999c8-5765-4de5-92a5-b45e001d0955
if [ -z "${MESH_TOKEN:-}" ] && [ -f "$BWS_ENV" ]; then
  MESH_TOKEN="$(bash -c "set -a; . '$BWS_ENV'; set +a; /root/.hermes/bin/bws secret list '$BWS_PROJECT' -o json" 2>/dev/null \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print({s["key"]:s["value"] for s in d}.get("MESH_TOKEN",""))')"
fi
MT="${MESH_TOKEN:?no MESH_TOKEN}"
_val() { python3 -c "import sys,json;print(json.load(sys.stdin).get('value') or '')"; }

JWT_SECRET="$(curl -fsS -H "Authorization: Bearer $MT" "$SECGW/secrets/VPS_SSO_JWT_SECRET" | _val)"
INTERNAL="$(curl -fsS -H "Authorization: Bearer $MT" "$SECGW/secrets/VPS_SSO_INTERNAL_SECRET" | _val)"
[ -n "$JWT_SECRET" ] && [ -n "$INTERNAL" ] || { echo "verify: secret fetch failed"; exit 1; }

TOKEN="$(JWT_SECRET="$JWT_SECRET" SUB="machine:sergpc" SVC="obhid.ibotz.fun" EXP="1d" node sign-machine-token.js)"

check() {  # $1=host $2=cookie $3=expect  → curls auth/check like nginx does
  local host="$1" cookie="$2" want="$3"
  local code
  code="$(curl -fsS -o /dev/null -w '%{http_code}' \
    -H "X-Internal-Secret: $INTERNAL" -H "X-Forwarded-Host: $host" \
    ${cookie:+-H "Cookie: sso_token=$cookie"} \
    "http://[::1]:3010/api/auth/check" || true)"
  local mark="OK"; [ "$code" = "$want" ] || mark="FAIL"
  printf '  [%s] host=%-20s cookie=%-8s -> %s (want %s)\n' "$mark" "$host" "${cookie:+yes}" "$code" "$want"
}

echo "machine-token auth matrix:"
check obhid.ibotz.fun  "$TOKEN" 200   # its service      -> allow
check reader.ibotz.fun "$TOKEN" 403   # other service    -> deny (scoped)
check obhid.ibotz.fun  ""       401   # no token         -> unauthorized
