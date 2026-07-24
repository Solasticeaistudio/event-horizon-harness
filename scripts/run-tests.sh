#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/hardproof"
npm test
cd "$ROOT"
PYTHONPATH=src python -m unittest discover -s tests -v
