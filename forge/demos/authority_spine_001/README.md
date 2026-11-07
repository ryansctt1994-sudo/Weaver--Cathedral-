# Authority Spine Demo 001

**Status:** E1 demo scaffold.  
**Fixture policy:** Synthetic only.  
**Network:** Not required.  
**Secrets:** Forbidden.

## Claim

This demo verifies that the Phase 1 authority spine can accept a valid synthetic envelope, generate a bounded receipt, and exercise failure paths through tests.

## Run

```bash
bash forge/demos/authority_spine_001/scripts/run.sh
```

## Verify

```bash
bash forge/demos/authority_spine_001/scripts/verify.sh
```

## Evidence bundle

```bash
python forge/demos/authority_spine_001/scripts/bundle.py out/bundle
python forge/demos/authority_spine_001/scripts/verify_bundle.py out/bundle
```

`bundle.py` writes receipts, a transcript for each exercised failure path (bad payload hash, nonce replay, invalid schema, promotion with missing evidence, gate veto, override replay, override on the wrong request, chronicle tamper), a hash-chained chronicle of every step, the pytest log, environment details, `MANIFEST.json` with the hashes of every bundle and source file, and `REPLAY.md`. `verify_bundle.py` re-checks all of it and rebuilds the bundle, requiring the deterministic files to be byte-identical. CI does this on every Python version and uploads each bundle as an artifact.

## Promotion boundary

This demo may become E2 after local or CI tests pass. It cannot become E3 until receipts, logs, replay instructions, artifact hashes, and failure-case transcripts are captured as a reproducible bundle.
