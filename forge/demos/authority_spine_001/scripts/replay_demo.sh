#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$ROOT_DIR"

BUNDLE_DIR="forge/receipts/demo_bundle"

python -m core.authority demo-receipt --output "$BUNDLE_DIR"
python -m core.authority verify-receipt --bundle "$BUNDLE_DIR"

echo "E3-candidate receipt bundle generated and verified at $BUNDLE_DIR"
find "$BUNDLE_DIR" -maxdepth 2 -type f | sort
