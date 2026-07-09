# Authority Spine Demo 001

**Status:** E3-candidate demo scaffold.  
**Fixture policy:** Synthetic only.  
**Network:** Not required.  
**Secrets:** Forbidden.

## Claim

This demo verifies that the authority spine can accept a valid synthetic envelope, generate a bounded receipt, persist replay evidence in SQLite, export a receipt bundle, and verify that bundle from repository materials.

## Run basic E2 path

```bash
bash forge/demos/authority_spine_001/scripts/run.sh
```

## Verify tests and E1 promotion decision

```bash
bash forge/demos/authority_spine_001/scripts/verify.sh
```

## Generate and verify E3-candidate receipt bundle

```bash
bash forge/demos/authority_spine_001/scripts/replay_demo.sh
```

The script writes:

```text
forge/receipts/demo_bundle/
  envelope.json
  receipt.json
  verification_result.json
  failure_case_report.json
  replay.log
  replay.db
  REPLAY.md
  artifact_manifest.json
```

Manual replay command:

```bash
python -m core.authority verify-receipt --bundle forge/receipts/demo_bundle
```

Expected result: `valid: true` with matching receipt, manifest, payload, replay log, and exercised failure cases.

## Promotion boundary

This demo can support an E3-candidate claim for the local authority spine only after CI or local replay verifies the generated bundle. It does **not** claim independent reproduction, production authority, autonomous authority, cryptographic signature verification, or domain validation.
