"""Operator tool for G3 overrides. Run by a person, under the operator's identity.

  keygen --private PATH       create an Ed25519 key. The private key is written
                              0600 to PATH. The public key (hex) goes into
                              WEAVER_GATE_OPERATOR_PUBKEY in .claude/settings.json.
  sign   --private PATH --request SHA256 --operator ID --reason TEXT
         [--minutes N] --out FILE
                              sign an override for one denied request. The hook
                              prints the request hash with every denial.

Keep the private key where the agent's identity cannot read it: another
machine, or a file owned by the operator's user with mode 0600. Nothing in the
hook reads it.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from runtime.claude_code_gate.override import MAX_LIFETIME, _crypto, fingerprint, sign


def keygen(private_path: Path) -> dict:
    crypto = _crypto()
    if crypto is None:
        raise SystemExit("cryptography is not installed")
    private_cls, _, _ = crypto
    if private_path.exists():
        raise SystemExit(f"{private_path} exists; refusing to overwrite a key")
    key = private_cls.generate()
    raw = key.private_bytes_raw()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(raw.hex() + "\n")
    public_hex = key.public_key().public_bytes_raw().hex()
    return {"public_key": public_hex, "fingerprint": fingerprint(public_hex), "private_key_file": str(private_path)}


def sign_request(private_path: Path, request: str, operator: str, reason: str, minutes: float) -> dict:
    lifetime = timedelta(minutes=minutes)
    if lifetime <= timedelta(0) or lifetime > MAX_LIFETIME:
        raise SystemExit(f"--minutes must be between 0 and {MAX_LIFETIME.total_seconds() / 60:g}")
    raw = bytes.fromhex(private_path.read_text().strip())
    return sign(raw, request_sha256=request, operator_id=operator, reason=reason,
                nonce=secrets.token_hex(16), issued_at=datetime.now(timezone.utc), lifetime=lifetime)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Weaver gate operator overrides (G3)")
    sub = parser.add_subparsers(dest="command", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--private", type=Path, required=True)
    s = sub.add_parser("sign")
    s.add_argument("--private", type=Path, required=True)
    s.add_argument("--request", required=True)
    s.add_argument("--operator", required=True)
    s.add_argument("--reason", required=True)
    s.add_argument("--minutes", type=float, default=10)
    s.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.command == "keygen":
        print(json.dumps(keygen(args.private), indent=2))
        return 0
    doc = sign_request(args.private, args.request, args.operator, args.reason, args.minutes)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n")
    print(json.dumps({"written": str(args.out), "expires_at": doc["expires_at"], "nonce": doc["nonce"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
