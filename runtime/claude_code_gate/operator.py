"""Operator tool for G3 overrides (schema v2). Run by a person, under the operator's identity.

  keygen --private PATH --key-id ID --operator ID [--days N]
         create an Ed25519 key. The private key is written 0600 to PATH. Prints
         a key-registry entry (weaver.gate.key_registry.v1) for the
         administrator to add to the registry and re-pin in the anchor.
  sign   --private PATH --key-id ID --operator ID --pending FILE --reason TEXT
         [--minutes N] --out FILE
         sign an override for one pending request. The hook writes the pending
         file to .weaver/gate/pending/<request_sha256>.json when it denies a
         call with role_not_permitted. Review its tool, input and target before
         signing: the signature authorizes exactly that call, once.

Keep the private key where the agent's identity cannot read it: another
machine, or a file owned by the operator's user with mode 0600. Nothing in the
hook reads it. This tool is not part of the enforcement manifest.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from runtime.claude_code_gate.override import MAX_LIFETIME, _crypto, sign
from runtime.claude_code_gate.registry import fingerprint


def keygen(private_path: Path, key_id: str, operator_id: str, days: float) -> dict:
    private_cls, _, _ = _crypto()
    if private_path.exists():
        raise SystemExit(f"{private_path} exists; refusing to overwrite a key")
    key = private_cls.generate()
    raw = key.private_bytes_raw()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(raw.hex() + "\n")
    public_hex = key.public_key().public_bytes_raw().hex()
    now = datetime.now(timezone.utc)
    return {
        "private_key_file": str(private_path),
        "registry_entry": {
            "key_id": key_id, "algorithm": "ed25519", "public_key_hex": public_hex,
            "fingerprint": fingerprint(public_hex), "operator_id": operator_id,
            "not_before": now.isoformat(), "not_after": (now + timedelta(days=days)).isoformat(),
            "status": "active", "revoked_at": None,
        },
    }


def sign_pending(private_path: Path, key_id: str, operator: str, pending_path: Path, reason: str, minutes: float) -> dict:
    lifetime = timedelta(minutes=minutes)
    if lifetime <= timedelta(0) or lifetime > MAX_LIFETIME:
        raise SystemExit(f"--minutes must be between 0 and {MAX_LIFETIME.total_seconds() / 60:g}")
    pending = json.loads(pending_path.read_text(encoding="utf-8"))
    context = pending["signing_context"]
    raw = bytes.fromhex(private_path.read_text().strip())
    return sign(raw, key_id=key_id, operator_id=operator, reason=reason, nonce=secrets.token_hex(16),
                issued_at=datetime.now(timezone.utc), lifetime=lifetime, context=context)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Weaver gate operator overrides (G3, schema v2)")
    sub = parser.add_subparsers(dest="command", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--private", type=Path, required=True)
    k.add_argument("--key-id", required=True)
    k.add_argument("--operator", required=True)
    k.add_argument("--days", type=float, default=90)
    s = sub.add_parser("sign")
    s.add_argument("--private", type=Path, required=True)
    s.add_argument("--key-id", required=True)
    s.add_argument("--operator", required=True)
    s.add_argument("--pending", type=Path, required=True)
    s.add_argument("--reason", required=True)
    s.add_argument("--minutes", type=float, default=10)
    s.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.command == "keygen":
        print(json.dumps(keygen(args.private, args.key_id, args.operator, args.days), indent=2))
        return 0
    doc = sign_pending(args.private, args.key_id, args.operator, args.pending, args.reason, args.minutes)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n")
    print(json.dumps({"written": str(args.out), "expires_at": doc["expires_at"], "nonce": doc["nonce"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
