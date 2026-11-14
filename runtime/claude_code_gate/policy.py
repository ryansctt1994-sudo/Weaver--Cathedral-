"""Gate configuration: which tool calls go through without a human, and which need one.

A config is one JSON file. Its ordered ``rules`` give each tool call an
uncertainty in [0, 1], read as "how far this policy is from letting the call
through unreviewed". The first rule that matches wins. The gate then compares
that number with ``threshold``: below it the call proceeds to Claude Code's
normal permission flow, at or above it the call is vetoed unless an operator
has signed an override for that exact call.

Two things hold whatever the rules say:

* A call that no rule matches gets ``default_uncertainty``, and a config whose
  default is below the threshold is refused. Unknown tools are vetoed.
* Protected paths are vetoed for every tool: the gate's own config file, its
  state directory (chronicle, replay store, overrides), its override key, any
  extra ``protected_paths``, and Claude Code settings files, where the hook is
  registered. Otherwise an agent could edit its way out of the gate.

Matching is on tool names and on the text of tool inputs. Text patterns over
shell commands can be evaded (aliases, ``bash -c``, variables, encodings), so
treat Bash rules as a tripwire for mistakes, not as containment.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterator, Mapping

SCHEMA = "weaver.claude_code_gate.config.v1"
PATH_FIELDS = ("file_path", "path", "notebook_path")
SETTINGS_NAMES = ("settings.json", "settings.local.json")
# Vetoes that are final. A protected path guards the gate itself (its config,
# state, key) and Claude Code's settings, where the hook is installed. Letting
# an override lift those would let one signed call disable or rewrite the gate.
PROTECTED_RULE_ID = "builtin:protected-path"
TERMINAL_RULES = frozenset({PROTECTED_RULE_ID})
MAX_OVERRIDE_AGE_S = 3600

_REQUIRED = {"schema", "threshold", "default_uncertainty", "state_dir", "rules"}
_OPTIONAL = {"override_key_file", "override_max_age_seconds", "protected_paths", "description"}
_RULE_REQUIRED = {"id", "tool", "uncertainty", "reason"}
_RULE_OPTIONAL = {"path_glob", "input_regex"}


class GateConfigError(ValueError):
    """The config is unusable. The hook vetoes every call until it is fixed."""


@dataclass(frozen=True)
class Match:
    rule_id: str
    uncertainty: float
    reason: str

    @property
    def overridable(self) -> bool:
        """False for a protected-path veto. An operator override never lifts it."""
        return self.rule_id not in TERMINAL_RULES


@dataclass(frozen=True)
class Rule:
    id: str
    tool: re.Pattern[str]
    uncertainty: float
    reason: str
    path_globs: tuple[str, ...] = ()
    input_regex: tuple[tuple[str, re.Pattern[str]], ...] = ()

    def matches(self, tool_name: str, tool_input: Mapping[str, Any]) -> bool:
        if not self.tool.fullmatch(tool_name):
            return False
        if self.path_globs:
            paths = [v for k in PATH_FIELDS if isinstance(v := tool_input.get(k), str)]
            if not any(fnmatch.fnmatchcase(p, g) for p in paths for g in self.path_globs):
                return False
        for name, pattern in self.input_regex:
            value = tool_input.get(name)
            if not isinstance(value, str) or not pattern.search(value):
                return False
        return True


@dataclass(frozen=True)
class GateConfig:
    path: Path
    sha256: str
    threshold: float
    default_uncertainty: float
    rules: tuple[Rule, ...]
    state_dir: Path
    override_key_file: Path | None
    override_max_age: timedelta
    protected: tuple[Path, ...] = field(default=())

    @property
    def chronicle_path(self) -> Path:
        return self.state_dir / "chronicle.jsonl"

    @property
    def lock_path(self) -> Path:
        return self.state_dir / "chronicle.lock"

    @property
    def replay_path(self) -> Path:
        return self.state_dir / "replay.sqlite"

    @property
    def overrides_dir(self) -> Path:
        return self.state_dir / "overrides"

    def classify(self, tool_name: str, tool_input: Mapping[str, Any]) -> Match:
        hit = self.protected_hit(tool_input)
        if hit is not None:
            return Match(PROTECTED_RULE_ID, 1.0, f"touches a protected path ({hit})")
        for rule in self.rules:
            if rule.matches(tool_name, tool_input):
                return Match(rule.id, rule.uncertainty, rule.reason)
        return Match("builtin:default", self.default_uncertainty, "no rule matches this tool call")

    def protected_hit(self, tool_input: Mapping[str, Any]) -> str | None:
        """The protected path a tool call reaches, if any."""
        for key in PATH_FIELDS:
            value = tool_input.get(key)
            if isinstance(value, str) and value:
                hit = self._protected_path(value)
                if hit:
                    return hit
        needles = [str(p) for p in self.protected] + [f".claude{os.sep}{name}" for name in SETTINGS_NAMES]
        for text in _strings(tool_input):
            for needle in needles:
                if needle in text:
                    return needle
        return None

    def _protected_path(self, value: str) -> str | None:
        candidate = Path(os.path.realpath(os.path.expanduser(value)))
        if candidate.name in SETTINGS_NAMES and candidate.parent.name == ".claude":
            return str(candidate)
        for root in self.protected:
            if candidate == root or root in candidate.parents:
                return str(root)
        return None


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _number(value: Any, name: str, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise GateConfigError(f"{name} must be a number")
    if not low <= value <= high:
        raise GateConfigError(f"{name} must be between {low} and {high}")
    return float(value)


def _resolve(base: Path, value: Any, name: str) -> Path:
    if not isinstance(value, str) or not value:
        raise GateConfigError(f"{name} must be a non-empty path")
    path = Path(os.path.expanduser(value))
    if not path.is_absolute():
        path = base / path
    return Path(os.path.realpath(path))


def _rule(data: Any, index: int) -> Rule:
    where = f"rules[{index}]"
    if not isinstance(data, Mapping) or not _RULE_REQUIRED <= set(data) <= _RULE_REQUIRED | _RULE_OPTIONAL:
        raise GateConfigError(f"{where} needs {sorted(_RULE_REQUIRED)}, optionally {sorted(_RULE_OPTIONAL)}")
    for key in ("id", "tool", "reason"):
        if not isinstance(data[key], str) or not data[key].strip():
            raise GateConfigError(f"{where}.{key} must be a non-empty string")
    try:
        tool = re.compile(data["tool"])
        regexes = tuple(
            (name, re.compile(pattern)) for name, pattern in dict(data.get("input_regex", {})).items()
        )
    except (re.error, TypeError, ValueError) as exc:
        raise GateConfigError(f"{where}: invalid pattern ({exc})") from exc
    for name, _ in regexes:
        if not isinstance(name, str) or not name:
            raise GateConfigError(f"{where}.input_regex keys must be field names")
    globs = data.get("path_glob", [])
    if not isinstance(globs, list) or not all(isinstance(g, str) and g for g in globs):
        raise GateConfigError(f"{where}.path_glob must be a list of glob strings")
    return Rule(
        id=data["id"],
        tool=tool,
        uncertainty=_number(data["uncertainty"], f"{where}.uncertainty", 0.0, 1.0),
        reason=data["reason"],
        path_globs=tuple(globs),
        input_regex=regexes,
    )


def load_config(path: str | Path) -> GateConfig:
    """Load and check a gate config. Any problem raises GateConfigError."""
    config_path = Path(os.path.realpath(os.path.expanduser(str(path))))
    try:
        raw = config_path.read_bytes()
        data = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise GateConfigError(f"cannot read config {config_path}: {exc}") from exc
    if not isinstance(data, dict) or not _REQUIRED <= set(data) <= _REQUIRED | _OPTIONAL:
        raise GateConfigError(f"config needs {sorted(_REQUIRED)}, optionally {sorted(_OPTIONAL)}")
    if data["schema"] != SCHEMA:
        raise GateConfigError(f"schema must be {SCHEMA!r}")

    threshold = _number(data["threshold"], "threshold", 0.0, 1.0)
    if not 0.0 < threshold < 1.0:
        raise GateConfigError("threshold must be strictly between 0 and 1")
    default = _number(data["default_uncertainty"], "default_uncertainty", 0.0, 1.0)
    if default < threshold:
        raise GateConfigError("default_uncertainty must be at least the threshold: unmatched calls are vetoed")

    rules_data = data["rules"]
    if not isinstance(rules_data, list):
        raise GateConfigError("rules must be a list")
    rules = tuple(_rule(rule, i) for i, rule in enumerate(rules_data))
    ids = [rule.id for rule in rules]
    if len(ids) != len(set(ids)):
        raise GateConfigError("rule ids must be unique")
    if any(rule_id.startswith("builtin:") for rule_id in ids):
        raise GateConfigError("rule ids may not start with 'builtin:'")

    base = config_path.parent
    state_dir = _resolve(base, data["state_dir"], "state_dir")
    key_file = None
    if data.get("override_key_file") is not None:
        key_file = _resolve(base, data["override_key_file"], "override_key_file")
    max_age = data.get("override_max_age_seconds", 300)
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 1 <= max_age <= MAX_OVERRIDE_AGE_S:
        raise GateConfigError(f"override_max_age_seconds must be an integer from 1 to {MAX_OVERRIDE_AGE_S}")
    extra = data.get("protected_paths", [])
    if not isinstance(extra, list):
        raise GateConfigError("protected_paths must be a list of paths")
    protected = [config_path, state_dir] + ([key_file] if key_file else [])
    protected += [_resolve(base, p, "protected_paths[]") for p in extra]

    return GateConfig(
        path=config_path,
        sha256=hashlib.sha256(raw).hexdigest(),
        threshold=threshold,
        default_uncertainty=default,
        rules=rules,
        state_dir=state_dir,
        override_key_file=key_file,
        override_max_age=timedelta(seconds=max_age),
        protected=tuple(dict.fromkeys(protected)),
    )
