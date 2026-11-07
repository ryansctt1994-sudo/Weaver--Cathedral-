#!/usr/bin/env bash
# Claude Code PreToolUse hook entry point.
#
# Claude Code treats only exit 2 as a block. Any other non-zero exit lets the
# tool run anyway, so a crash in Python, a missing interpreter, or a segfault
# would fail open. This wrapper maps every outcome other than the gate's own
# 0 (allow) and 2 (veto) to 2.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}"
python3 -m runtime.claude_code_gate.hook
rc=$?
case "$rc" in
  0|2) exit "$rc" ;;
  *) echo "Weaver gate crashed (exit $rc); blocking." >&2; exit 2 ;;
esac
