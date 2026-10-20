#!/usr/bin/env bash
# Monte la stack, initialise la base, puis lance la suite de tests d'intégration.
#
#   ./tests/run.sh            # build + up + seed + pytest
#   SKIP_BUILD=1 ./tests/run.sh   # réutilise les conteneurs déjà lancés
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

echo "==> attente des bases de données"
for _ in $(seq 1 60); do
  if docker compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1 \
     && docker compose exec -T mysql mysqladmin ping -uroot -pmysql_password >/dev/null 2>&1; then
    echo "    bases prêtes"
    break
  fi
  sleep 2
done

echo "==> initialisation de la base (migrations + seed)"
docker compose exec -T cflix dotnet CFlix.dll database update all

echo "==> attente du site CFlix"
for _ in $(seq 1 30); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" https://localhost/Login || true)
  [ "$code" = "200" ] && { echo "    site prêt"; break; }
  sleep 2
done

echo "==> pytest"
cd "$HERE"
if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi
exec .venv/bin/pytest -v "$@"
