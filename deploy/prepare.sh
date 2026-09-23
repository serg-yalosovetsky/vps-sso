#!/usr/bin/env bash
# serg/tasks#1108: привилегированный шаг перед стартом (ExecStartPre=+): симлинки standalone.
# Next standalone не копирует static/public — их кладёт сюда каждый старт, потому что
# каждый npm run build пересоздаёт .next.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p .next/standalone/.next
ln -sfn "$ROOT/.next/static" .next/standalone/.next/static
[ -d "$ROOT/public" ] && ln -sfn "$ROOT/public" .next/standalone/public || true
