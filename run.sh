#!/usr/bin/env bash
# vps-sso launcher: секреты из secrets-gateway, конфиг из config-store, .env — фолбэк.
# Паттерн как alice-relay/run.sh. Bootstrap-bearer = MESH_TOKEN (единственный секрет
# в .env). Источник каждого ключа логируется по ИМЕНИ (никогда не значение).
set -euo pipefail
cd "$(dirname "$0")"

# База/фолбэк: .env (в т.ч. MESH_TOKEN, NEXT_PUBLIC_* build-time, и текущие значения)
set -a; . ./.env 2>/dev/null || true; set +a

SECGW="${SECGW_URL:-http://100.66.108.118:8783}"
CFGW="${CFGW_URL:-http://100.66.108.118:8782}"

# Bootstrap bearer: MESH_TOKEN из BWS (как secrets-gateway/alice-relay). Ни BWS-токен,
# ни MESH_TOKEN не печатаются. Если BWS недоступен — падаем на MESH_TOKEN из .env (если есть).
BWS_ENV="${BWS_ENV_FILE:-/root/.hermes/bitwarden-sm.env}"
BWS_PROJECT="${BWS_PROJECT:-8de999c8-5765-4de5-92a5-b45e001d0955}"
if [ -z "${MESH_TOKEN:-}" ] && [ -f "$BWS_ENV" ]; then
  MESH_TOKEN="$(bash -c "set -a; . '$BWS_ENV'; set +a; /root/.hermes/bin/bws secret list '$BWS_PROJECT' -o json" 2>/dev/null \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print({s["key"]:s["value"] for s in d}.get("MESH_TOKEN",""))' 2>/dev/null || true)"
fi
MT="${MESH_TOKEN:-}"
[ -n "$MT" ] && echo "sso-cfg: MESH_TOKEN bootstrapped (BWS/.env)" >&2 || echo "sso-cfg: MESH_TOKEN отсутствует — только .env-фолбэк" >&2

_val() { python3 -c "import sys,json;print(json.load(sys.stdin).get('value') or '')"; }

fetch_secret() {  # $1=key → эхо значение или пусто
  [ -n "$MT" ] || return 0
  curl -fsS -m 8 -H "Authorization: Bearer $MT" "$SECGW/secrets/$1" 2>/dev/null | _val 2>/dev/null || true
}
fetch_config() {  # $1=key (defaults/<key>) → эхо значение или пусто
  [ -n "${CONFIG_STORE_TOKEN:-}" ] || return 0
  curl -fsS -m 8 -H "Authorization: Bearer ${CONFIG_STORE_TOKEN}" \
    "$CFGW/config/defaults/$1" 2>/dev/null | _val 2>/dev/null || true
}

set_from() {  # $1=VAR $2=value $3=source — не перезаписываем пустым (фолбэк на .env)
  if [ -n "$2" ]; then export "$1=$2"; echo "sso-cfg: $1 <- $3" >&2
  elif [ -n "${!1:-}" ]; then echo "sso-cfg: $1 <- .env fallback" >&2
  else echo "sso-cfg: $1 MISSING" >&2; fi
}

# 1) токен config-store — из secrets-gateway (бутстрап по MESH_TOKEN)
CST=$(fetch_secret CONFIG_STORE_TOKEN); [ -n "$CST" ] && export CONFIG_STORE_TOKEN="$CST"
export CONFIG_STORE_URL="$CFGW"

# 2) секреты приложения — из secrets-gateway (в security store — токены приложений)
set_from JWT_SECRET       "$(fetch_secret VPS_SSO_JWT_SECRET)"       secrets-gateway
set_from CLERK_SECRET_KEY "$(fetch_secret VPS_SSO_CLERK_SECRET_KEY)" secrets-gateway
set_from INTERNAL_SECRET  "$(fetch_secret VPS_SSO_INTERNAL_SECRET)"  secrets-gateway
# Plan B: реестр opaque service-token'ов в mesh-postgres (схема vps_sso).
set_from VPS_SSO_DB_URL   "$(fetch_secret VPS_SSO_DB_URL)"           secrets-gateway

# 3) несекретный конфиг + карта доступов — из config-store
set_from SSO_ACCESS             "$(fetch_config sso_access)"             config-store
set_from ALLOWED_REDIRECT_HOSTS "$(fetch_config sso_allowed_redirects)" config-store
set_from COOKIE_DOMAIN          "$(fetch_config sso_cookie_domain)"     config-store
set_from SSO_HOST               "$(fetch_config sso_host)"              config-store

# 3.5) Plan B фаза 3: per-consumer ключи подписи assertion'ов.
# config-store defaults/sso_assertion_consumers = { "<host>": "<secretName>" };
# значения ключей лежат в secrets-gateway под этими именами. Собираем
# SSO_ASSERT_KEYS = { "<host>": "<keyValue>" }. Хост без ключа → assertion не
# чеканится (сервисы, не потребляющие assertion, не затрагиваются).
CONSUMERS="$(fetch_config sso_assertion_consumers)"
if [ -n "$CONSUMERS" ] && [ -n "$MT" ]; then
  ASSERT_KEYS="$(SECGW="$SECGW" MT="$MT" python3 - "$CONSUMERS" <<'PY' 2>/dev/null || true
import sys, json, os, urllib.request
try:
    consumers = json.loads(sys.argv[1])
except Exception:
    consumers = {}
secgw = os.environ["SECGW"]; mt = os.environ["MT"]
out = {}
for host, secname in (consumers.items() if isinstance(consumers, dict) else []):
    try:
        req = urllib.request.Request(
            f"{secgw}/secrets/{secname}",
            headers={"Authorization": f"Bearer {mt}"},
        )
        val = json.load(urllib.request.urlopen(req, timeout=8)).get("value")
        if val:
            out[str(host).strip().lower()] = val
    except Exception:
        pass
print(json.dumps(out))
PY
)"
  # Экспортируем только если реально собрали хотя бы один ключ ({} = пусто-эквивалент).
  if [ -n "$ASSERT_KEYS" ] && [ "$ASSERT_KEYS" != "{}" ]; then
    export SSO_ASSERT_KEYS="$ASSERT_KEYS"
    echo "sso-cfg: SSO_ASSERT_KEYS <- secrets-gateway×config-store" >&2
  else
    echo "sso-cfg: SSO_ASSERT_KEYS пуст (нет потребителей/ключей)" >&2
  fi
fi

# 4) Next standalone НЕ кладёт .next/static (и public) в свою папку, а сервер
# отдаёт /_next/static/* из своего CWD (.next/standalone). Без линка все чанки =
# 404 → клиентские компоненты не гидратируются (кнопки мертвы). Self-heal: линк
# всегда указывает на статику ТЕКУЩЕЙ сборки, переживает любой ребилд.
ROOT="$PWD"
mkdir -p .next/standalone/.next
ln -sfn "$ROOT/.next/static" ".next/standalone/.next/static"
[ -d "$ROOT/public" ] && ln -sfn "$ROOT/public" ".next/standalone/public"

# 5) запуск standalone-сервера Next (CWD = .next/standalone)
cd .next/standalone
exec /root/.nvm/versions/node/v22.22.3/bin/node server.js
