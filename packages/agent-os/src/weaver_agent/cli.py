from __future__ import annotations

import argparse
import json

from .adapters import ADAPTERS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="weaver-agent")
    parser.add_argument("command", choices=["adapters"])
    args = parser.parse_args(argv)
    if args.command == "adapters":
        print(json.dumps([adapter.__dict__ for adapter in ADAPTERS], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

