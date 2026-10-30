#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node -e "if(Number(process.versions.node.split('.')[0])<22)throw Error('Roots needs Node 22 or newer')"
npm ci
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock.txt
python3 scripts/build_contracts.py
if [ ! -f .env ]; then cp .env.example .env; chmod 600 .env; fi
printf 'Add credentials to .env, then run npm run db:migrate and npm run dev.\n'
