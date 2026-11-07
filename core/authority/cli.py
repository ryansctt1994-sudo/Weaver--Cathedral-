"""CLI for the Phase 1 authority spine."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dataclasses import asdict

from .chronicle import verify_file
from .models import AuthorityEnvelope
from .receipts import generate_receipt
from .replay import InMemoryReplayCache, SqliteReplayStore
from .verifier import evaluate_promotion, verify_envelope


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cmd_verify(args: argparse.Namespace) -> int:
    # Without --replay-db each invocation starts with an empty cache, so the
    # same envelope is accepted again on the next run.
    cache = SqliteReplayStore(args.replay_db) if args.replay_db else InMemoryReplayCache()
    result = verify_envelope(load_json(args.envelope), cache)
    print(result.model_dump_json(indent=2))
    return 0 if result.accepted else 1


def cmd_receipt(args: argparse.Namespace) -> int:
    envelope = AuthorityEnvelope.model_validate(load_json(args.envelope))
    receipt = generate_receipt(envelope, accepted=args.accepted, reason=args.reason)
    print(receipt.model_dump_json(indent=2))
    return 0


def cmd_promote(args: argparse.Namespace) -> int:
    evidence = [item.strip() for item in args.evidence.split(",") if item.strip()]
    decision = evaluate_promotion(args.artifact_id, args.level, evidence)
    print(decision.model_dump_json(indent=2))
    return 0 if decision.granted else 1


def cmd_chronicle_verify(args: argparse.Namespace) -> int:
    result = verify_file(args.chronicle, expected_head=args.expected_head)
    print(json.dumps(asdict(result), indent=2))
    return 0 if result.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="weaver-authority")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="Verify an authority envelope")
    verify.add_argument("envelope")
    verify.add_argument("--replay-db", default=None, help="SQLite nonce store; rejects replays across runs")
    verify.set_defaults(func=cmd_verify)

    receipt = sub.add_parser("receipt", help="Generate a receipt for an envelope")
    receipt.add_argument("envelope")
    receipt.add_argument("--accepted", action="store_true")
    receipt.add_argument("--reason", default="manual_receipt")
    receipt.set_defaults(func=cmd_receipt)

    promote = sub.add_parser("promote", help="Evaluate promotion evidence")
    promote.add_argument("artifact_id")
    promote.add_argument("level")
    promote.add_argument("--evidence", default="")
    promote.set_defaults(func=cmd_promote)

    chronicle = sub.add_parser("chronicle-verify", help="Verify a hash-chained chronicle file")
    chronicle.add_argument("chronicle")
    chronicle.add_argument("--expected-head", default=None, help="Head hash recorded elsewhere; detects tail truncation")
    chronicle.set_defaults(func=cmd_chronicle_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
