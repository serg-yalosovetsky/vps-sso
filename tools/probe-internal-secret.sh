#!/usr/bin/env bash
# Пробы пер-сервисного X-Internal-Secret прямо в vps-sso (loopback, минуя nginx).
# 401 = гейт ПРОЙДЕН (секрет принят), дальше просто нет сессии.
# 403 = гейт НЕ пройден (секрет отвергнут) — именно это мы и доказываем для чужих.
# Значения секретов не печатаются.
set -uo pipefail

SECGW="${SECGW_URL:-http://100.66.108.118:8783}"
URL=http://[::1]:3010/api/auth/check
set -a; . /root/vps-sso/.env 2>/dev/null || true; set +a
MT="${MESH_TOKEN:-}"

sec() {  # $1=имя ключа -> значение
  curl -fsS -m 8 -H "Authorization: Bearer $MT" "$SECGW/secrets/$1" 2>/dev/null \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value") or "")' 2>/dev/null || true
}

probe() {  # $1=описание $2=ожидаемый код $3=host $4=секрет(может быть пусто)
  local desc="$1" want="$2" host="$3" val="${4:-}" code
  if [ -n "$val" ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: sso.ibotz.fun" \
      -H "X-Forwarded-Host: $host" -H "X-Internal-Secret: $val" "$URL")
  else
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: sso.ibotz.fun" \
      -H "X-Forwarded-Host: $host" "$URL")
  fi
  if [ "$code" = "$want" ]; then printf 'PASS  %-58s -> %s\n' "$desc" "$code"
  else printf 'FAIL  %-58s -> %s (ждали %s)\n' "$desc" "$code" "$want"; RC=1; fi
}

RC=0
OLD=$(sec VPS_SSO_INTERNAL_SECRET)
TILES=$(sec VPS_SSO_INTERNAL_SECRET_TILES)
READER=$(sec VPS_SSO_INTERNAL_SECRET_READER)
LLM=$(sec VPS_SSO_INTERNAL_SECRET_LLM)

echo "== (a) свой секрет пускает =="
probe "секрет tiles  как tiles.ibotz.fun"            401 tiles.ibotz.fun  "$TILES"
probe "секрет reader как reader.ibotz.fun"           401 reader.ibotz.fun "$READER"
probe "секрет llm    как llm.ibotz.fun (алиас)"      401 llm.ibotz.fun    "$LLM"

echo
echo "== (в) КЛЮЧЕВОЕ: секрет одного сайта от имени другого =="
probe "секрет tiles  как reader.ibotz.fun"           403 reader.ibotz.fun "$TILES"
probe "секрет reader как tiles.ibotz.fun"            403 tiles.ibotz.fun  "$READER"
probe "секрет llm    как langfuse.ibotz.fun"         403 langfuse.ibotz.fun "$LLM"
probe "секрет tiles  как неизвестный хост"           403 evil.example.com "$TILES"

echo
echo "== прочее =="
probe "без секрета вовсе"                            403 tiles.ibotz.fun  ""
probe "мусор вместо секрета (проверка длины!)"       403 tiles.ibotz.fun  "short"
probe "мусор той же длины 64"                        403 tiles.ibotz.fun  "$(printf 'a%.0s' $(seq 1 64))"

echo
echo "== переходный режим: старый общий секрет =="
if [ "${EXPECT_LEGACY:-on}" = "off" ]; then
  probe "СТАРЫЙ утёкший секрет (ждём отказ)"         403 tiles.ibotz.fun  "$OLD"
  probe "СТАРЫЙ утёкший как reader"                  403 reader.ibotz.fun "$OLD"
else
  probe "СТАРЫЙ общий секрет (переходный, ждём приём)" 401 tiles.ibotz.fun "$OLD"
fi

echo
[ $RC -eq 0 ] && echo "ИТОГ: все пробы прошли" || echo "ИТОГ: ЕСТЬ ПРОВАЛЫ"
exit $RC
