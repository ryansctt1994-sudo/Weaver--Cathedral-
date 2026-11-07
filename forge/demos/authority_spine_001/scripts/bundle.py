"""Build the evidence bundle for demo authority_spine_001 (GAP-005).

Produces, under the output directory:

  receipts/        receipts for the accepted run and for each failure path
  failures/        one transcript per exercised failure path
  chronicle.jsonl  every step above, hash-chained
  logs/pytest.txt  the test-suite run
  environment.json interpreter, platform, package versions, git commit
  MANIFEST.json    sha256 of every bundle file and every tracked source file,
                   plus the chronicle head hash
  REPLAY.md        how to reproduce and check this bundle

Everything except logs/ and environment.json is deterministic: receipts use a
fixed timestamp, and the override key is derived from a fixed test seed, so
two runs on any machine must produce byte-identical files. verify_bundle.py
re-runs the generator and checks that.

This bundle is evidence for review. It does not promote anything by itself.

Usage: python forge/demos/authority_spine_001/scripts/bundle.py <out-dir> [--skip-pytest]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from core.authority import (  # noqa: E402
    Chronicle,
    InMemoryReplayCache,
    UncertaintyGate,
    evaluate_promotion,
    normalized_entropy,
    request_hash,
    sign_override,
    verify_entries,
    verify_envelope,
)
from core.authority.canonical import JCS_RFC8785, canonicalize  # noqa: E402
from core.authority.models import AuthorityEnvelope  # noqa: E402
from core.authority.receipts import generate_receipt, verify_receipt  # noqa: E402

DEMO_ID = "demo.authority_spine.001"
FIXTURES = ROOT / "core" / "authority" / "fixtures"
FIXED_AT = datetime(2026, 7, 8, tzinfo=timezone.utc)
# Synthetic, published on purpose: the demo must be reproducible by anyone.
DEMO_OVERRIDE_KEY = hashlib.sha256(b"weaver-cathedral demo authority_spine_001 override key").digest()
DETERMINISTIC_EXCLUDE = ("logs/", "environment.json", "MANIFEST.json")


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _tracked_sources() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        return sorted(line for line in out.splitlines() if line and not line.startswith("forge/demos/authority_spine_001/bundle"))
    except (OSError, subprocess.CalledProcessError):
        return []


def _git_commit() -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def build(out: Path, *, run_pytest: bool = True) -> dict:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    chron = Chronicle(out / "chronicle.jsonl")
    step = 0

    def record(kind: str, data: dict) -> None:
        nonlocal step
        chron.append(kind, data, recorded_at=FIXED_AT + timedelta(seconds=step))
        step += 1

    def receipt_for(raw: dict, *, accepted: bool, reason: str) -> dict:
        envelope = AuthorityEnvelope.model_validate(raw)
        receipt = generate_receipt(envelope, accepted=accepted, reason=reason, created_at=FIXED_AT)
        assert verify_receipt(receipt)
        return json.loads(receipt.model_dump_json())

    # 1. The claim: a valid synthetic envelope is accepted.
    valid = _load("valid_envelope.json")
    cache = InMemoryReplayCache()
    accepted = verify_envelope(valid, cache)
    assert accepted.accepted, accepted
    accept_receipt = receipt_for(valid, accepted=True, reason=accepted.reason)
    _write_json(out / "receipts" / "accept_valid_envelope.json", accept_receipt)
    record("demo.verify", {"fixture": "valid_envelope.json", "accepted": True, "reason": accepted.reason, "receipt_hash": accept_receipt["receipt_hash"]})

    failures: list[dict] = []

    def failure(name: str, expected: str, observed: str, detail: dict) -> None:
        ok = expected == observed
        transcript = {"failure_path": name, "expected": expected, "observed": observed, "behaved_as_expected": ok, **detail}
        _write_json(out / "failures" / f"{name}.json", transcript)
        record("demo.failure_path", {"name": name, "expected": expected, "observed": observed, "ok": ok})
        failures.append(transcript)

    # 2. Failure paths, each expected to be rejected.
    bad = _load("bad_hash_envelope.json")
    r = verify_envelope(bad, InMemoryReplayCache())
    rr = receipt_for(bad, accepted=False, reason=r.reason)
    _write_json(out / "receipts" / "reject_bad_hash.json", rr)
    failure("payload_hash_mismatch", "payload_hash_mismatch", r.reason, {"fixture": "bad_hash_envelope.json", "receipt_hash": rr["receipt_hash"]})

    r = verify_envelope(valid, cache)  # same nonce, same cache
    rr = receipt_for(valid, accepted=False, reason=r.reason)
    _write_json(out / "receipts" / "reject_replay.json", rr)
    failure("nonce_replay", "replay_detected", r.reason, {"fixture": "valid_envelope.json", "receipt_hash": rr["receipt_hash"]})

    r = verify_envelope({**valid, "nonce": "short"}, InMemoryReplayCache())
    failure("schema_invalid", "schema_invalid", r.reason.split(":")[0], {"mutation": "nonce shorter than 8 characters"})

    p = evaluate_promotion(DEMO_ID, "E3", ["receipt_bundle", "logs"])
    failure("promotion_missing_evidence", "promotion_blocked_missing_evidence", p.reason, {"required_missing": p.required_missing})

    gate = UncertaintyGate(threshold=0.7, override_key=DEMO_OVERRIDE_KEY)
    req = {"action": "promote", "artifact": DEMO_ID}
    uncertainty = normalized_entropy([0.25, 0.25, 0.25, 0.25])
    g = gate.evaluate(req, uncertainty, now=FIXED_AT)
    failure("gate_high_uncertainty", "VETO", g.decision.value, {"uncertainty": uncertainty, "threshold": 0.7, "reason": g.reason})

    ov = sign_override(DEMO_OVERRIDE_KEY, operator_id="demo.operator", reason="demo", request_hash=request_hash(req), nonce="demo-override-0001", issued_at=FIXED_AT)
    first = gate.evaluate(req, uncertainty, now=FIXED_AT, override=ov)
    again = gate.evaluate(req, uncertainty, now=FIXED_AT, override=ov)
    failure("gate_override_replay", "override_rejected:replayed", again.reason, {"first_use": first.decision.value})

    other = gate.evaluate({"action": "delete", "artifact": DEMO_ID}, uncertainty, now=FIXED_AT, override=ov)
    failure("gate_override_wrong_request", "override_rejected:wrong_request", other.reason, {})

    entries = chron.entries
    entries[0]["data"]["accepted"] = False
    tampered = verify_entries(entries)
    failure("chronicle_tamper", "entry_hash_mismatch", tampered.reason, {"tampered_index": 0, "detected_at": tampered.first_bad_index})

    # 3. Tests.
    pytest_ok = None
    if run_pytest:
        result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=ROOT, capture_output=True, text=True)
        (out / "logs").mkdir(exist_ok=True)
        (out / "logs" / "pytest.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
        # Recorded in the manifest, not the chronicle: the chronicle holds only
        # deterministic steps, so a replay without pytest must match it exactly.
        pytest_ok = result.returncode == 0

    final = chron.verify()
    assert final.ok

    _write_json(out / "environment.json", {
        "python": sys.version,
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "packages": {name: _version(name) for name in ("pydantic", "pytest", "hypothesis", "jsonschema")},
        "git_commit": _git_commit(),
    })
    (out / "REPLAY.md").write_text(REPLAY_TEXT, encoding="utf-8")

    bundle_files = sorted(
        p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file() and p.name != "MANIFEST.json"
    )
    manifest = {
        "bundle_version": "weaver.forge.evidence_bundle.v1",
        "demo": DEMO_ID,
        "hash_profile_for_manifest_hash": JCS_RFC8785,
        "chronicle_head": final.head_hash,
        "chronicle_entries": final.entries,
        "all_failure_paths_behaved_as_expected": all(f["behaved_as_expected"] for f in failures),
        "pytest_passed": pytest_ok,
        "deterministic_files": [f for f in bundle_files if not f.startswith(DETERMINISTIC_EXCLUDE)],
        "bundle_files": {f: _sha256(out / f) for f in bundle_files},
        "source_files": {f: _sha256(ROOT / f) for f in _tracked_sources() if (ROOT / f).is_file()},
    }
    manifest["manifest_hash"] = hashlib.sha256(canonicalize(manifest, JCS_RFC8785).encode("utf-8")).hexdigest()
    _write_json(out / "MANIFEST.json", manifest)
    return manifest


def _version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


REPLAY_TEXT = """# Replaying this evidence bundle

This bundle was produced by `forge/demos/authority_spine_001/scripts/bundle.py`
at the commit recorded in `environment.json`.

## Check it

```bash
git checkout <git_commit from environment.json>
python -m pip install -e ".[dev]"
python forge/demos/authority_spine_001/scripts/verify_bundle.py <this-bundle-dir>
```

`verify_bundle.py` checks:

1. every file's sha256 matches `MANIFEST.json`, and the manifest hash matches its contents;
2. every tracked source file matches the hash recorded at build time;
3. the chronicle verifies and its head equals `chronicle_head`;
4. every receipt verifies under its own version and hash profile;
5. every failure path behaved as expected;
6. **replay**: it rebuilds the bundle in a temporary directory and requires every
   file in `deterministic_files` to be byte-identical.

## What this is not

This is a local, synthetic demonstration package. It contains no real data,
grants no authority, and is not independent reproduction. Promotion to any
evidence level is a separate decision recorded in `governance/`.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("out", type=Path)
    parser.add_argument("--skip-pytest", action="store_true", help="omit the test-suite run (used by the replay check)")
    args = parser.parse_args(argv)
    manifest = build(args.out.resolve(), run_pytest=not args.skip_pytest)
    print(json.dumps({k: manifest[k] for k in ("manifest_hash", "chronicle_head", "all_failure_paths_behaved_as_expected", "pytest_passed")}, indent=2))
    ok = manifest["all_failure_paths_behaved_as_expected"] and manifest["pytest_passed"] is not False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
