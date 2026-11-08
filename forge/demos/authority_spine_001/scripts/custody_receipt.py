"""Custody receipt for the evidence bundle: who produced it, who verified it, what each file was.

In CI the bundle is built as root (its test run needs the gate's root-owned
anchor) and verified as the unprivileged runner user. This records that split
instead of hiding it.

  produce <bundle> --out producer.json
      run by the producer: its identity, and each file's owner, group, mode,
      size and SHA-256.
  verify <bundle> --producer producer.json --out verifier.json
      run by the verifier: its own identity, each file re-hashed, and a
      comparison with the producer's record. Exits 1 on any difference
      (hash, size, a missing or an extra file). Owner and mode differences
      are recorded, not failed: the checkout is handed back to the runner
      after the build, so ownership changes by design.

The receipts sit outside the bundle so the bundle's deterministic files are
unchanged. Standard library only.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def identity() -> dict:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - a user name is informative only
        user = None
    return {"uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(), "user": user}


def inventory(bundle: Path) -> dict:
    files = {}
    for p in sorted(bundle.rglob("*")):
        if p.is_file() and not p.is_symlink():
            st = p.stat()
            files[p.relative_to(bundle).as_posix()] = {
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "size": st.st_size,
                "uid": st.st_uid, "gid": st.st_gid, "mode": oct(st.st_mode & 0o7777)}
    return files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("produce"); p.add_argument("bundle", type=Path); p.add_argument("--out", type=Path, required=True)
    v = sub.add_parser("verify"); v.add_argument("bundle", type=Path); v.add_argument("--producer", type=Path, required=True)
    v.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    now = datetime.now(timezone.utc).isoformat()
    files = inventory(args.bundle)
    if args.cmd == "produce":
        doc = {"schema": "weaver.bundle.custody.producer.v1", "role": "producer", "identity": identity(),
               "recorded_utc": now, "files": files}
        args.out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        print(f"producer {doc['identity']}: {len(files)} files")
        return 0
    producer = json.loads(args.producer.read_text())
    theirs = producer["files"]
    problems, notes = [], []
    for rel in sorted(set(theirs) | set(files)):
        a, b = theirs.get(rel), files.get(rel)
        if a is None:
            problems.append(f"extra file: {rel}")
        elif b is None:
            problems.append(f"missing file: {rel}")
        else:
            if (a["sha256"], a["size"]) != (b["sha256"], b["size"]):
                problems.append(f"content differs: {rel}")
            if (a["uid"], a["gid"], a["mode"]) != (b["uid"], b["gid"], b["mode"]):
                notes.append(f"ownership or mode differs: {rel}")
    doc = {"schema": "weaver.bundle.custody.verifier.v1", "role": "verifier", "identity": identity(),
           "producer_identity": producer["identity"],
           "producer_receipt_sha256": hashlib.sha256(args.producer.read_bytes()).hexdigest(),
           "recorded_utc": now, "files": files, "problems": problems, "notes": notes,
           "result": "PASS" if not problems else "FAIL"}
    args.out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(f"verifier {doc['identity']} vs producer {producer['identity']}: {len(files)} files, "
          f"{len(problems)} problems, {len(notes)} ownership notes -> {doc['result']}")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
