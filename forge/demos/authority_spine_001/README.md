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

## Promotion boundary

This demo may become E2 after local or CI tests pass. It cannot become E3 until receipts, logs, replay instructions, artifact hashes, and failure-case transcripts are captured as a reproducible bundle.
