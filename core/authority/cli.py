"""CLI for the authority spine."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .bundles import build_receipt_bundle, verify_receipt_bundle
from .models import AuthorityEnvelope
from .receipts import generate_receipt
from .replay import InMemoryReplayCache
from .verifier import evaluate_promotion, verify_envelope


DEFAULT_ENVELOPE = "core/authority/fixtures/valid_envelope.json"
DEFAULT_FAILURE_FIXTURE = "core/authority/fixtures/bad_hash_envelope.json"


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cmd_verify(args: argparse.Namespace) -> int:
    cache = InMemoryReplayCache()
    result = verify_envelope(load_json(args.envelope), cache)
    print(result.model_dump_json(indent=2))
    return 0 if result.accepted else 1


def cmd_receipt(args: argparse.Namespace) -> int:
    envelope = AuthorityEnvelope.model_validate(load_json(args.envelope))
    receipt = generate_receipt(envelope, accepted=args.accepted, reason=args.reason)
    print(receipt.model_dump_json(indent=2))
    return 0


def cmd_demo_receipt(args: argparse.Namespace) -> int:
    bundle = build_receipt_bundle(
        args.envelope,
        args.output,
        failure_fixture_path=args.failure_fixture,
        fresh=not args.keep_existing,
    )
    print(json.dumps({"bundle": bundle.as_posix(), "created": True}, indent=2, sort_keys=True))
    return 0


def cmd_verify_receipt(args: argparse.Namespace) -> int:
    result = verify_receipt_bundle(args.bundle)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


def cmd_promote(args: argparse.Namespace) -> int:
    evidence = [item.strip() for item in args.evidence.split(",") if item.strip()]
    decision = evaluate_promotion(args.artifact_id, args.level, evidence)
    print(decision.model_dump_json(indent=2))
    return 0 if decision.granted else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="weaver-authority")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="Verify an authority envelope")
    verify.add_argument("envelope")
    verify.set_defaults(func=cmd_verify)

    receipt = sub.add_parser("receipt", help="Generate a receipt for an envelope")
    receipt.add_argument("envelope")
    receipt.add_argument("--accepted", action="store_true")
    receipt.add_argument("--reason", default="manual_receipt")
    receipt.set_defaults(func=cmd_receipt)

    demo_receipt = sub.add_parser("demo-receipt", help="Generate an E3-candidate receipt bundle")
    demo_receipt.add_argument("--envelope", default=DEFAULT_ENVELOPE)
    demo_receipt.add_argument("--failure-fixture", default=DEFAULT_FAILURE_FIXTURE)
    demo_receipt.add_argument("--output", default="forge/receipts/demo_bundle")
    demo_receipt.add_argument("--keep-existing", action="store_true", help="Do not remove an existing bundle directory first")
    demo_receipt.set_defaults(func=cmd_demo_receipt)

    verify_receipt = sub.add_parser("verify-receipt", help="Verify an E3-candidate receipt bundle")
    verify_receipt.add_argument("--bundle", required=True)
    verify_receipt.set_defaults(func=cmd_verify_receipt)

    promote = sub.add_parser("promote", help="Evaluate promotion evidence")
    promote.add_argument("artifact_id")
    promote.add_argument("level")
    promote.add_argument("--evidence", default="")
    promote.set_defaults(func=cmd_promote)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
