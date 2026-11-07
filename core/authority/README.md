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
- Rejects duplicate nonces through a replay store: `InMemoryReplayCache` for tests, or `SqliteReplayStore` (persistent, atomic across processes and restarts on one host). The verifier fails closed if the store errors.
- Receipts v2 record the hash profile they were made under and bind it into the hash (RFC 8785 JCS by default). v1 receipts still verify exactly.
- Evaluates basic promotion requests.
- Exposes a small CLI for verification.
- Hashes under named canonical-JSON profiles (`canonical.py`). RFC 8785 JCS is the profile for every new format. The legacy `weaver.c14n.v1` (receipts v1) and `zorel.ascii.v1` (zorel-kernel's sealed receipt) stay verifiable under their own ids. JCS number output is cross-checked against ECMAScript in the test suite.
- Keeps a tamper-evident, hash-chained Chronicle (`chronicle.py`, JSON Lines). Editing, deleting, reordering or inserting entries is detected at the exact index; tail truncation is detected against an anchored head hash.
- Gates actions on uncertainty (`gate.py`): VETO at or above the threshold, VETO on any malformed input or internal error, and no disabled mode. Operator overrides are HMAC-signed, bound to one request hash, time-limited and single-use. Every decision can be chronicled, and an ALLOW whose chronicle write fails becomes a VETO.

## What this module does not do yet

- It does not provide public-key signatures. Gate overrides use a shared HMAC key.
- The persistent replay store is single-host. Retention: `prune_expired(now)` removes only nonces stored with an `expires_at` that has passed. Gate override nonces expire at `issued_at + override_max_age`, after which the override is refused as expired anyway; envelope nonces have no expiry and are never pruned. `now` must come from the same clock the gate uses. Nothing prunes on a schedule. A gate that accepts overrides must be given a replay store explicitly (`SqliteReplayStore` for anything long-lived, `InMemoryReplayCache` only in tests and one-shot demos); there is no silent in-memory default (GAP-002).
- The Chronicle is single-writer and local. It has no multi-process locking and no signed head.
- It does not grant legal, clinical, defense, safety, AGI, ASI, or production authority.
- It does not prove real-world legitimacy.

## Example

```bash
weaver-authority verify core/authority/fixtures/valid_envelope.json
weaver-authority verify core/authority/fixtures/valid_envelope.json --replay-db .replay.sqlite   # rejects the same envelope on a second run
weaver-authority receipt core/authority/fixtures/valid_envelope.json
python -m core.authority promote demo.authority_spine.001 E1 --evidence declared_claim,file_scaffold,risk_boundary
python -m core.authority chronicle-verify path/to/chronicle.jsonl --expected-head <hex>
```

## Next promotions

To promote this layer from E1 to E2:

```bash
python -m pip install -e ".[dev]"
pytest -q
```

To promote beyond E2, add replay receipts, logs, failure paths, and independent reproduction.
