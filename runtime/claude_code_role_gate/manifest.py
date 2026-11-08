"""GAP-003 D-4: the policy digest covers every decision-changing component.

``policy_digest = sha256(JCS(manifest))`` where the manifest lists each
component's SHA-256 and the runtime versions. Every override signs the digest.
A change to any listed file, or to the interpreter or ``cryptography``
version, changes the digest, so outstanding overrides fail with
``policy_digest_mismatch``.

Inventory (v0.3 §6, with additions marked; the reviewer confirms completeness
before freeze):

* runtime/claude_code_role_gate: policy.py, hook.py, override.py, gate.sh,
  plus trusted_root.py, registry.py, manifest.py and __init__.py [additions:
  modules the candidate's hook imports]
* core/authority: canonical.py, gate.py, replay.py, plus chronicle.py,
  __init__.py, models.py, receipts.py and verifier.py [additions: decision
  recording, and modules loaded by the package's __init__ when the hook
  imports it; any imported module can change behaviour at import time]
* core/__init__.py and runtime/__init__.py [additions: package init]

Excluded: operator.py (operator-side tool, not in the hook's path), the key
registry (pinned separately, changes by design), managed settings and the
anchor (the trust root cannot sit inside its own digest).

tests/test_claude_code_role_gate_override.py checks that every repository module
the hook imports appears in MANIFEST_FILES (mutation M-D2).
"""

from __future__ import annotations

import platform
from hashlib import sha256
from pathlib import Path

from core.authority.canonical import JCS_RFC8785, canonicalize
from runtime.claude_code_role_gate.policy import POLICY_VERSION

MANIFEST_SCHEMA = "weaver.gate.enforcement_manifest.v1"
CODE_ROOT = Path(__file__).resolve().parents[2]

MANIFEST_FILES = (
    "core/__init__.py",
    "core/authority/__init__.py",
    "core/authority/canonical.py",
    "core/authority/chronicle.py",
    "core/authority/gate.py",
    "core/authority/models.py",
    "core/authority/receipts.py",
    "core/authority/replay.py",
    "core/authority/verifier.py",
    "runtime/__init__.py",
    "runtime/claude_code_role_gate/__init__.py",
    "runtime/claude_code_role_gate/gate.sh",
    "runtime/claude_code_role_gate/hook.py",
    "runtime/claude_code_role_gate/manifest.py",
    "runtime/claude_code_role_gate/override.py",
    "runtime/claude_code_role_gate/policy.py",
    "runtime/claude_code_role_gate/registry.py",
    "runtime/claude_code_role_gate/trusted_root.py",
)


def _cryptography_version() -> str:
    try:
        import cryptography
    except ImportError:  # the digest still computes; verification fails closed elsewhere
        return "absent"
    return cryptography.__version__


def build_manifest(code_root: Path = CODE_ROOT, files: tuple[str, ...] = MANIFEST_FILES) -> dict:
    return {
        "schema": MANIFEST_SCHEMA,
        "policy_version": POLICY_VERSION,
        "files": [{"path": rel, "sha256": sha256((code_root / rel).read_bytes()).hexdigest()} for rel in files],
        "runtime": {"python": platform.python_version(), "cryptography": _cryptography_version()},
    }


def policy_digest(manifest: dict | None = None) -> str:
    doc = manifest if manifest is not None else build_manifest()
    return sha256(canonicalize(doc, JCS_RFC8785).encode("utf-8")).hexdigest()
