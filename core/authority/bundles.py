"""Receipt bundle generation and verification.

These helpers create an E3-candidate artifact package for the authority spine.
They do not claim independent reproduction or production authority.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
from typing import Any

from .models import AuthorityEnvelope, Receipt
from .receipts import payload_hash, verify_receipt
from .replay import InMemoryReplayCache, PersistentReplayCache
from .verifier import verify_envelope, verify_envelope_with_receipt


REQUIRED_BUNDLE_FILES = [
    "envelope.json",
    "receipt.json",
    "verification_result.json",
    "failure_case_report.json",
    "replay.log",
    "replay.db",
    "REPLAY.md",
    "artifact_manifest.json",
]


def load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, value: Any) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_failure_case_report(
    raw: dict[str, Any],
    replay_cache: PersistentReplayCache,
    failure_fixture_path: str | Path | None = None,
) -> dict[str, Any]:
    """Exercise required failure paths for the demo bundle."""

    replay_result, _replay_receipt = verify_envelope_with_receipt(raw, replay_cache)
    cases = [
        {
            "id": "replay_detected",
            "accepted": replay_result.accepted,
            "reason": replay_result.reason,
            "passed": (not replay_result.accepted and replay_result.reason == "replay_detected"),
        }
    ]

    if failure_fixture_path is not None:
        bad_raw = load_json(failure_fixture_path)
        bad_result = verify_envelope(bad_raw, InMemoryReplayCache())
        cases.append(
            {
                "id": "payload_hash_mismatch",
                "accepted": bad_result.accepted,
                "reason": bad_result.reason,
                "passed": (not bad_result.accepted and bad_result.reason == "payload_hash_mismatch"),
            }
        )

    return {
        "failure_report_version": "weaver.authority.failure_report.v1",
        "all_passed": all(case["passed"] for case in cases),
        "cases": cases,
    }


def write_replay_instructions(output_dir: Path) -> Path:
    return (output_dir / "REPLAY.md").write_text(
        "# Authority Spine Receipt Bundle Replay\n\n"
        "This bundle is an E3-candidate reproduction package for the local authority spine.\n"
        "It does not claim independent reproduction, production authority, or domain validation.\n\n"
        "## Verify\n\n"
        "```bash\n"
        f"python -m core.authority verify-receipt --bundle {output_dir.as_posix()}\n"
        "```\n\n"
        "Expected result: `valid: true` with matching receipt, manifest, payload, replay log, and failure-case checks.\n",
        encoding="utf-8",
    )


def build_artifact_manifest(output_dir: Path) -> dict[str, Any]:
    files = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file() or path.name == "artifact_manifest.json":
            continue
        files.append(
            {
                "path": path.relative_to(output_dir).as_posix(),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return {
        "manifest_version": "weaver.authority.artifact_manifest.v1",
        "bundle_type": "authority_spine_receipt_bundle",
        "files": files,
    }


def build_receipt_bundle(
    envelope_path: str | Path,
    output_dir: str | Path,
    *,
    failure_fixture_path: str | Path | None = None,
    fresh: bool = True,
) -> Path:
    """Build a self-contained E3-candidate receipt bundle."""

    output = Path(output_dir)
    if fresh and output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    raw = load_json(envelope_path)
    envelope = AuthorityEnvelope.model_validate(raw)

    replay_cache = PersistentReplayCache(output / "replay.db")
    try:
        result, receipt = verify_envelope_with_receipt(raw, replay_cache)
        if receipt is None:
            raise ValueError("cannot build bundle for schema-invalid envelope")

        failure_report = build_failure_case_report(raw, replay_cache, failure_fixture_path)
        replay_cache.export_jsonl(output / "replay.log")
    finally:
        replay_cache.close()

    write_json(output / "envelope.json", envelope)
    write_json(output / "receipt.json", receipt)
    write_json(output / "verification_result.json", result)
    write_json(output / "failure_case_report.json", failure_report)
    write_replay_instructions(output)
    write_json(output / "artifact_manifest.json", build_artifact_manifest(output))

    return output


def verify_artifact_manifest(bundle_dir: Path, manifest: dict[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    seen = set()
    for item in manifest.get("files", []):
        rel = item.get("path")
        seen.add(rel)
        path = bundle_dir / rel
        if not path.exists():
            failures.append(f"missing_manifest_file:{rel}")
            continue
        actual = sha256_file(path)
        if actual != item.get("sha256"):
            failures.append(f"sha256_mismatch:{rel}")

    for required in REQUIRED_BUNDLE_FILES:
        if required == "artifact_manifest.json":
            continue
        if required not in seen:
            failures.append(f"required_file_not_listed:{required}")

    return not failures, failures


def verify_receipt_bundle(bundle_dir: str | Path) -> dict[str, Any]:
    """Verify a receipt bundle from disk."""

    bundle = Path(bundle_dir)
    checks: dict[str, Any] = {"bundle": bundle.as_posix()}

    missing = [name for name in REQUIRED_BUNDLE_FILES if not (bundle / name).exists()]
    checks["required_files_present"] = not missing
    checks["missing_files"] = missing

    if missing:
        return {"valid": False, "checks": checks}

    envelope = AuthorityEnvelope.model_validate(load_json(bundle / "envelope.json"))
    receipt = Receipt.model_validate(load_json(bundle / "receipt.json"))
    result = load_json(bundle / "verification_result.json")
    failure_report = load_json(bundle / "failure_case_report.json")
    manifest = load_json(bundle / "artifact_manifest.json")
    replay_log_lines = [line for line in (bundle / "replay.log").read_text(encoding="utf-8").splitlines() if line]

    checks["receipt_hash_valid"] = verify_receipt(receipt)
    checks["payload_hash_valid"] = payload_hash(envelope.payload) == envelope.payload_hash
    checks["receipt_matches_result"] = result.get("receipt_hash") == receipt.receipt_hash
    checks["receipt_matches_envelope"] = receipt.envelope_id == envelope.envelope_id and receipt.payload_hash == envelope.payload_hash
    checks["failure_cases_passed"] = bool(failure_report.get("all_passed"))
    checks["replay_log_present"] = len(replay_log_lines) > 0

    manifest_valid, manifest_failures = verify_artifact_manifest(bundle, manifest)
    checks["artifact_manifest_valid"] = manifest_valid
    checks["artifact_manifest_failures"] = manifest_failures

    valid = all(
        checks[key]
        for key in [
            "required_files_present",
            "receipt_hash_valid",
            "payload_hash_valid",
            "receipt_matches_result",
            "receipt_matches_envelope",
            "failure_cases_passed",
            "replay_log_present",
            "artifact_manifest_valid",
        ]
    )

    return {"valid": valid, "checks": checks}
