"""Check an evidence bundle produced by bundle.py. Exit 0 only if every check passes.

Usage: python forge/demos/authority_spine_001/scripts/verify_bundle.py <bundle-dir> [--no-replay] [--no-sources]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from core.authority.canonical import canonicalize  # noqa: E402
from core.authority.chronicle import verify_file  # noqa: E402
from core.authority.models import Receipt  # noqa: E402
from core.authority.receipts import verify_receipt  # noqa: E402

HERE = Path(__file__).resolve().parent


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(bundle: Path, *, replay: bool = True, sources: bool = True) -> list[str]:
    problems: list[str] = []
    try:
        manifest = json.loads((bundle / "MANIFEST.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"MANIFEST.json unreadable: {exc}"]

    claimed = manifest.get("manifest_hash")
    body = {k: v for k, v in manifest.items() if k != "manifest_hash"}
    if hashlib.sha256(canonicalize(body, manifest.get("hash_profile_for_manifest_hash", "")).encode("utf-8")).hexdigest() != claimed:
        problems.append("manifest_hash does not match manifest contents")

    on_disk = {p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if p.is_file() and p.name != "MANIFEST.json"}
    listed = set(manifest.get("bundle_files", {}))
    for extra in sorted(on_disk - listed):
        problems.append(f"{extra}: in bundle but not in manifest")
    for name, digest in sorted(manifest.get("bundle_files", {}).items()):
        path = bundle / name
        if not path.is_file():
            problems.append(f"{name}: listed in manifest but missing")
        elif _sha256(path) != digest:
            problems.append(f"{name}: sha256 mismatch")

    if sources:
        for name, digest in sorted(manifest.get("source_files", {}).items()):
            path = ROOT / name
            if not path.is_file():
                problems.append(f"source {name}: missing from this checkout")
            elif _sha256(path) != digest:
                problems.append(f"source {name}: differs from the build-time hash (wrong commit, or modified)")

    result = verify_file(bundle / "chronicle.jsonl", expected_head=manifest.get("chronicle_head"))
    if not result.ok:
        problems.append(f"chronicle.jsonl: {result.reason} at index {result.first_bad_index}")

    for path in sorted((bundle / "receipts").glob("*.json")):
        try:
            receipt = Receipt.model_validate_json(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            problems.append(f"receipts/{path.name}: invalid ({exc.__class__.__name__})")
            continue
        if not verify_receipt(receipt):
            problems.append(f"receipts/{path.name}: receipt hash does not verify")

    for path in sorted((bundle / "failures").glob("*.json")):
        transcript = json.loads(path.read_text(encoding="utf-8"))
        if not transcript.get("behaved_as_expected"):
            problems.append(f"failures/{path.name}: expected {transcript.get('expected')!r}, observed {transcript.get('observed')!r}")
    if not manifest.get("all_failure_paths_behaved_as_expected"):
        problems.append("manifest: not all failure paths behaved as expected")
    if manifest.get("pytest_passed") is False:
        problems.append("manifest: the test suite failed when the bundle was built")

    if replay:
        sys.path.insert(0, str(HERE))
        import bundle as builder  # noqa: E402

        with tempfile.TemporaryDirectory() as tmp:
            rebuilt = Path(tmp) / "replay"
            builder.build(rebuilt, run_pytest=False)
            for name in manifest.get("deterministic_files", []):
                original, again = bundle / name, rebuilt / name
                if not again.is_file():
                    problems.append(f"replay: {name} was not reproduced")
                elif original.is_file() and original.read_bytes() != again.read_bytes():
                    problems.append(f"replay: {name} differs when rebuilt")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--no-replay", action="store_true")
    parser.add_argument("--no-sources", action="store_true", help="skip source-hash checks (e.g. reviewing on another commit)")
    args = parser.parse_args(argv)
    problems = check(args.bundle.resolve(), replay=not args.no_replay, sources=not args.no_sources)
    if problems:
        print("BUNDLE CHECK FAILED")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("BUNDLE CHECK PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
