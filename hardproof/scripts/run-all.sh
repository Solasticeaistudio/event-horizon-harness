#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
npm install --ignore-scripts
npm run build
npm test
cd ..
python -m unittest discover -s tests -v
PYTHONPATH=src python -m event_horizon.demo
