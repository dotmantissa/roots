#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node -e "if(Number(process.versions.node.split('.')[0])<22)throw Error('Roots needs Node 22 or newer')"
npm ci
if python3 -c 'import ensurepip' >/dev/null 2>&1; then
  python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements.lock.txt
else
  python3 -m venv --without-pip .venv
  python3 -m pip --python .venv/bin/python install -r requirements.lock.txt
fi
python3 scripts/build_contracts.py
if [ ! -f .env ]; then cp .env.example .env; fi
chmod 600 .env
printf 'Add credentials to .env, then run npm run db:migrate and npm run dev.\n'
