# Core Authority Spine

**Status:** Phase 1 authority kernel merged; E2 candidate; E3 hardening in progress.  
**Evidence level:** E2 candidate after green CI. E3 requires verified receipt bundle replay.

This module enforces the first executable form of the master invariants:

```text
NO RECEIPT = NO PROMOTION
NO TEST = NO EXECUTION CLAIM
NO REPLAY = NO TRUSTED STATE
NO BOUNDARY = NO AUTHORITY
```

## What this module does

- Validates synthetic authority envelopes with Pydantic.
- Produces deterministic SHA-256 receipts.
- Rejects duplicate nonces through in-memory and SQLite-backed replay caches.
- Evaluates basic promotion requests.
- Exports and verifies E3-candidate receipt bundles.
- Exposes a small CLI for verification.

## What this module does not do yet

- It does not provide cryptographic signatures.
- It does not provide production-grade distributed replay storage.
- It does not grant legal, clinical, defense, safety, AGI, ASI, or production authority.
- It does not prove real-world legitimacy.
- It does not claim independent reproduction.

## Basic examples

```bash
weaver-authority verify core/authority/fixtures/valid_envelope.json
weaver-authority receipt core/authority/fixtures/valid_envelope.json
python -m core.authority promote demo.authority_spine.001 E1 --evidence declared_claim,file_scaffold,risk_boundary
```

## E3-candidate receipt bundle

Generate and verify a synthetic receipt bundle:

```bash
python -m core.authority demo-receipt --output forge/receipts/demo_bundle
python -m core.authority verify-receipt --bundle forge/receipts/demo_bundle
```

Or run the demo wrapper:

```bash
bash forge/demos/authority_spine_001/scripts/replay_demo.sh
```

The bundle includes:

```text
envelope.json
receipt.json
verification_result.json
failure_case_report.json
replay.log
replay.db
REPLAY.md
artifact_manifest.json
```

## Promotion path

To keep E2:

```bash
python -m pip install -e ".[dev]"
pytest -q
```

To support E3 candidate status:

```bash
pytest -q
bash forge/demos/authority_spine_001/scripts/replay_demo.sh
```

E3 remains bounded to the local authority spine only. E4 requires independent reproduction by an external witness or runner.
