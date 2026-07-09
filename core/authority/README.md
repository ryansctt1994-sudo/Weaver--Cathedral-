# Core Authority Spine

**Status:** Phase 1 minimal verification kernel.  
**Evidence level:** E1 scaffold, promotable to E2 after tests run locally/CI.

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
- Rejects duplicate nonces through an in-memory replay cache.
- Evaluates basic promotion requests.
- Exposes a small CLI for verification.

## What this module does not do yet

- It does not provide cryptographic signatures.
- It does not provide persistent atomic replay storage.
- It does not grant legal, clinical, defense, safety, AGI, ASI, or production authority.
- It does not prove real-world legitimacy.

## Example

```bash
weaver-authority verify core/authority/fixtures/valid_envelope.json
weaver-authority receipt core/authority/fixtures/valid_envelope.json
python -m core.authority promote demo.authority_spine.001 E1 --evidence declared_claim,file_scaffold,risk_boundary
```

## Next promotions

To promote this layer from E1 to E2:

```bash
python -m pip install -e ".[dev]"
pytest -q
```

To promote beyond E2, add replay receipts, logs, failure paths, and independent reproduction.
