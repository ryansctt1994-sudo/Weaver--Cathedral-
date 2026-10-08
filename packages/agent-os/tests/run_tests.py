from __future__ import annotations

import inspect
import tempfile
from pathlib import Path

import test_agent_os


def main() -> int:
    failures = []
    tests = [(name, value) for name, value in vars(test_agent_os).items() if name.startswith("test_") and callable(value)]
    for name, function in sorted(tests):
        try:
            if "tmp_path" in inspect.signature(function).parameters:
                with tempfile.TemporaryDirectory() as directory:
                    function(Path(directory))
            else:
                function()
            print(f"PASS {name}")
        except Exception as exc:
            failures.append(name)
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    print(f"RESULT passed={len(tests) - len(failures)} failed={len(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

