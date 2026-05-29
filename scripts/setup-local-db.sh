#!/usr/bin/env bash
# Cria usuário e banco para desenvolvimento local (sem Docker).
set -euo pipefail

echo "→ Criando role e database auth..."
sudo -u postgres psql -v ON_ERROR_STOP=0 <<'SQL'
DO $$ BEGIN
  CREATE ROLE auth WITH LOGIN PASSWORD 'auth';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
SELECT 'CREATE DATABASE auth OWNER auth'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'auth')\gexec
SQL

echo "→ Verificando Redis..."
if redis-cli ping 2>/dev/null | grep -q PONG; then
  echo "Redis OK"
else
  echo "Redis não responde. Rode: sudo systemctl start redis-server"
fi

echo ""
echo "Próximo: make migrate-up && make run"
