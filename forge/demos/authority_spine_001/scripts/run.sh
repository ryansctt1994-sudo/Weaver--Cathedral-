#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$ROOT_DIR"

mkdir -p forge/demos/authority_spine_001/logs forge/demos/authority_spine_001/receipts

python -m core.authority verify core/authority/fixtures/valid_envelope.json \
  | tee forge/demos/authority_spine_001/logs/verify_valid.log

python -m core.authority receipt core/authority/fixtures/valid_envelope.json --accepted --reason demo_run \
  | tee forge/demos/authority_spine_001/receipts/receipt.json
