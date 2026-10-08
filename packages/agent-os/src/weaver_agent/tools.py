"""Allow-listed tool registry."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from .models import ToolOutcome


class Tool(Protocol):
    name: str

    def execute(self, arguments: dict[str, Any]) -> ToolOutcome: ...


@dataclass
class FunctionTool:
    name: str
    handler: Callable[[dict[str, Any]], dict[str, Any]]

    def execute(self, arguments: dict[str, Any]) -> ToolOutcome:
        started = time.monotonic_ns()
        try:
            data = self.handler(dict(arguments))
            if not isinstance(data, dict):
                raise TypeError("tool handlers must return a dict")
            return ToolOutcome(True, data, None, time.monotonic_ns() - started)
        except Exception as exc:
            return ToolOutcome(False, {}, f"{type(exc).__name__}: {exc}", time.monotonic_ns() - started)


@dataclass
class SubprocessTool:
    """A fixed executable with a bounded list-valued `args` input.

    This is process isolation, not a complete security sandbox. Network,
    syscall, and filesystem isolation require an external runtime adapter.
    """

    name: str
    executable: str
    fixed_args: tuple[str, ...] = ()
    allowed_argument_prefixes: tuple[str, ...] = ()
    timeout_seconds: int = 30
    max_output_bytes: int = 65536

    def execute(self, arguments: dict[str, Any]) -> ToolOutcome:
        started = time.monotonic_ns()
        raw_args = arguments.get("args", [])
        if not isinstance(raw_args, list) or not all(isinstance(item, str) for item in raw_args):
            return ToolOutcome(False, {}, "INVALID_ARGUMENTS", time.monotonic_ns() - started)
        if self.allowed_argument_prefixes and any(
            not any(item.startswith(prefix) for prefix in self.allowed_argument_prefixes)
            for item in raw_args
        ):
            return ToolOutcome(False, {}, "ARGUMENT_NOT_ALLOWED", time.monotonic_ns() - started)

        environment = {key: value for key, value in os.environ.items() if key in {"PATH", "LANG", "LC_ALL"}}
        try:
            with tempfile.TemporaryDirectory(prefix="weaver-tool-") as directory:
                completed = subprocess.run(
                    [self.executable, *self.fixed_args, *raw_args],
                    cwd=Path(directory),
                    env=environment,
                    capture_output=True,
                    text=False,
                    timeout=self.timeout_seconds,
                    shell=False,
                    check=False,
                )
            stdout = completed.stdout[: self.max_output_bytes].decode("utf-8", errors="replace")
            stderr = completed.stderr[: self.max_output_bytes].decode("utf-8", errors="replace")
            return ToolOutcome(
                completed.returncode == 0,
                {"exit_code": completed.returncode, "stdout": stdout, "stderr": stderr},
                None if completed.returncode == 0 else "NONZERO_EXIT",
                time.monotonic_ns() - started,
            )
        except subprocess.TimeoutExpired:
            return ToolOutcome(False, {}, "TIMEOUT", time.monotonic_ns() - started)
        except OSError as exc:
            return ToolOutcome(False, {}, f"OS_ERROR: {exc}", time.monotonic_ns() - started)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if not tool.name or tool.name in self._tools:
            raise ValueError(f"duplicate or empty tool name: {tool.name!r}")
        self._tools[tool.name] = tool

    def execute(self, name: str, arguments: dict[str, Any]) -> ToolOutcome:
        tool = self._tools.get(name)
        if tool is None:
            return ToolOutcome(False, {}, "UNKNOWN_TOOL", 0)
        return tool.execute(arguments)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

