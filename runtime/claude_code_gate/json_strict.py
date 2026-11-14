"""Strict JSON ingestion for the Claude Code gate's authority inputs.

JSON objects with duplicate names are ambiguous across parsers. Python's
default json.loads silently keeps the last duplicate, and accepts nonstandard
NaN/Infinity constants. Neither behavior is admissible at a policy or tool
authorization boundary. This parser makes the entire input fail closed.
"""
from __future__ import annotations

import json
from typing import Any


def strict_loads(raw: str | bytes) -> Any:
    """Parse JSON and reject duplicate object keys and nonfinite constants."""
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError(f"duplicate JSON object key: {key}")
            obj[key] = value
        return obj

    def no_nonfinite(token: str) -> None:
        raise ValueError(f"nonfinite JSON token: {token}")

    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=no_nonfinite)
