#!/usr/bin/env bash
# Bring up the stack, initialize the database, then run the integration suite.
#
#   ./tests/run.sh            # build + up + seed + pytest
#   SKIP_BUILD=1 ./tests/run.sh   # reuse the already-running containers
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
SRC="$ROOT/src"

cd "$SRC"

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "==> docker compose build"
  docker compose build
  echo "==> docker compose up -d"
  docker compose up -d
fi

echo "==> waiting for the databases"
for _ in $(seq 1 60); do
  if docker compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1 \
     && docker compose exec -T mysql mysqladmin ping -uroot -pmysql_password >/dev/null 2>&1; then
    echo "    databases ready"
    break
  fi
  sleep 2
done

echo "==> initializing the database (migrations + seed)"
docker compose exec -T cflix dotnet CFlix.dll database update all

echo "==> waiting for the CFlix site"
for _ in $(seq 1 30); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" https://localhost/Login || true)
  [ "$code" = "200" ] && { echo "    site ready"; break; }
  sleep 2
done

echo "==> pytest"
cd "$HERE"
if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi
exec .venv/bin/pytest -v "$@"
