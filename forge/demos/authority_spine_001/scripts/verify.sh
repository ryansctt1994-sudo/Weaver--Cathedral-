#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$ROOT_DIR"

mkdir -p forge/demos/authority_spine_001/logs

pytest -q core/authority/tests | tee forge/demos/authority_spine_001/logs/pytest.log
python -m core.authority promote demo.authority_spine.001 E1 --evidence declared_claim,file_scaffold,risk_boundary \
  | tee forge/demos/authority_spine_001/logs/promotion_e1.log
