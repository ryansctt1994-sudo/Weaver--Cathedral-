"""GAP-003 remediation candidate: operator override, trusted root, key registry, manifest.

Organised by the v0.3 §9 test IDs. Every test asserts the reason, not only the
exit code. These are implementer-authored tests; they are not the R8
independent reproduction.

R7: cryptography is imported directly. If it is missing this module fails to
collect instead of skipping, so a green run cannot hide an untested G3.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import cryptography  # noqa: F401  (R7: hard dependency, never importorskip)
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.authority.chronicle import Chronicle, verify_file
from core.authority.gate import request_hash
from core.authority.replay import SqliteReplayStore
from runtime.claude_code_gate import hook
from runtime.claude_code_gate.manifest import MANIFEST_FILES, build_manifest, policy_digest
from runtime.claude_code_gate.override import OVERRIDE_SCHEMA, LiveContext, sign
from runtime.claude_code_gate.policy import ELIGIBLE_RULES, decide
from runtime.claude_code_gate.registry import fingerprint
from runtime.claude_code_gate.trusted_root import write_anchor

REPO = Path(__file__).resolve().parents[1]
STATE = Path(".weaver") / "gate"
REQ = re.compile(r"request ([0-9a-f]{64})")


def utc_now():
    return datetime.now(timezone.utc)


class Gate:
    """A project, an anchor, a pinned key registry and one operator key."""

    def __init__(self, tmp_path: Path):
        self.root = tmp_path / "project"
        self.root.mkdir()
        (self.root / "src").mkdir()
        (self.root / "src" / "app.py").write_text("x = 1\n")
        (self.root / ".claude").mkdir()
        (self.root / ".claude" / "settings.json").write_text("{}\n")
        os.symlink(".claude", self.root / "linkdir")
        self.outside = tmp_path / "outside"
        self.outside.mkdir()
        self.anchor_dir = tmp_path / "anchor"
        self.anchor_dir.mkdir()
        self.anchor = self.anchor_dir / "anchor.json"
        self.registry = self.anchor_dir / "key_registry.json"
        self.key = Ed25519PrivateKey.generate()
        now = utc_now()
        self.entries = [self.entry(self.key, "op-1", "op.alice", not_before=now - timedelta(days=1), not_after=now + timedelta(days=30))]
        self.publish()

    @staticmethod
    def entry(key, key_id, operator_id, *, not_before, not_after, status="active", revoked_at=None):
        pub = key.public_key().public_bytes_raw().hex()
        return {"key_id": key_id, "algorithm": "ed25519", "public_key_hex": pub, "fingerprint": fingerprint(pub),
                "operator_id": operator_id, "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
                "status": status, "revoked_at": revoked_at.isoformat() if revoked_at else None}

    def publish(self):
        raw = json.dumps({"schema": "weaver.gate.key_registry.v1", "keys": self.entries}, indent=2).encode()
        self.registry.write_bytes(raw)
        write_anchor(self.anchor, self.root, registry_path=self.registry, registry_sha256=sha256(raw).hexdigest())

    def revoke(self, at):
        self.entries[0] = {**self.entries[0], "status": "revoked", "revoked_at": at.isoformat()}
        self.publish()

    def env(self, role="Planner", **extra):
        env = {"CLAUDE_PROJECT_DIR": str(self.root), "WEAVER_GATE_ANCHOR": str(self.anchor), "WEAVER_GATE_ROLE": role}
        env.update(extra)
        return env

    def event(self, tool, tool_input, **extra):
        return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input, "cwd": str(self.root), **extra}

    def run(self, tool, tool_input, role="Planner", *, env=None, store_factory=None, now=None, **extra):
        err = io.StringIO()
        rc = hook.run_hook(io.StringIO(json.dumps(self.event(tool, tool_input, **extra))), err,
                           env if env is not None else self.env(role), now=now, store_factory=store_factory)
        text = err.getvalue()
        match = REQ.search(text)
        return rc, text, (match.group(1) if match else None)

    def context(self, tool, tool_input, role="Planner", ceiling=None):
        """The eligible-form signing context an operator would sign for this call."""
        ceiling = ceiling or role
        d = decide(tool, tool_input, self.root, role, ceiling)
        req = request_hash({"tool": tool, "input": tool_input, "role": role, "ceiling": ceiling,
                            "agent_id": None, "resolved_target": d.target})
        return req, LiveContext(req, "role_not_permitted", d.target, d.target_identity, policy_digest()).signing_context()

    def signed(self, context, *, key=None, key_id="op-1", operator="op.alice", nonce="n-0001",
               issued=None, minutes=10, **changes):
        ctx = {**context, **changes}
        return sign((key or self.key).private_bytes_raw(), key_id=key_id, operator_id=operator, reason="reviewed",
                    nonce=nonce, issued_at=issued or utc_now(), lifetime=timedelta(minutes=minutes), context=ctx)

    def place(self, req, doc):
        path = self.root / STATE / "overrides" / f"{req}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(doc if isinstance(doc, str) else json.dumps(doc))

    def entries_logged(self):
        path = self.root / STATE / "chronicle.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def nonce_spent(self, nonce):
        db = self.root / STATE / "override_nonces.sqlite"
        return db.exists() and SqliteReplayStore(db).contains(f"operator-override:{nonce}")


@pytest.fixture
def g(tmp_path):
    return Gate(tmp_path)


WRITE_NEW = ("Write", {"file_path": "src/new.py", "content": "y = 2\n"})


def approve(g, tool, tool_input, role="Planner", **kw):
    """Deny once, then sign and place a valid override for exactly that call."""
    req, ctx = g.context(tool, tool_input, role)
    doc = g.signed(ctx, **kw)
    g.place(req, doc)
    return req, doc


# --- OQ-1: eligibility is a closed allowlist -------------------------------------


def test_only_role_not_permitted_is_eligible():
    assert ELIGIBLE_RULES == frozenset({"role_not_permitted"})


def test_every_other_denial_including_future_ones_is_non_overridable():
    from runtime.claude_code_gate.policy import Decision
    source = (REPO / "runtime" / "claude_code_gate" / "policy.py").read_text()
    emitted = set(re.findall(r'_veto\("([a-z_]+)"', source))
    assert "role_not_permitted" in emitted and len(emitted) > 10
    for rule in emitted | {"outside_project", "some_future_reason", "unsolicited_override", "trusted_root_mismatch"}:
        assert Decision(False, rule, "r").overridable is (rule == "role_not_permitted"), rule
    assert Decision(True, "role_not_permitted", "allowed").overridable is False


# --- Authorization regressions (R1, R5): each ALLOWed on the baseline or must stay denied --


@pytest.mark.parametrize(
    ("case", "tool", "tool_input", "role", "rule"),
    [
        ("X1", "Write", {"file_path": ".claude/settings.json", "content": "x"}, "Planner", "protected_path"),
        ("X2", "Write", {"file_path": "OUTSIDE", "content": "x"}, "Planner", "outside_project"),
        ("X3", "Write", {"file_path": "linkdir/settings.json", "content": "x"}, "Planner", "protected_path"),
        ("B1", "Write", {"file_path": ".claude/settings.json", "content": "x"}, "Builder", "protected_path"),
        ("B2", "Write", {"file_path": "OUTSIDE", "content": "x"}, "Builder", "outside_project"),
        ("B3", "Bash", {"command": "rm -rf src"}, "Planner", "bash_not_allowlisted"),
        ("B4", "Agent", {"subagent_type": "Builder", "prompt": "x"}, "Planner", "delegation_escalation"),
        ("B4b", "Agent", {"subagent_type": "Builder", "prompt": "x"}, "Researcher", "delegation_escalation"),
    ],
)
def test_mandatory_denials_survive_a_validly_signed_override(g, case, tool, tool_input, role, rule):
    if tool_input.get("file_path") == "OUTSIDE":
        tool_input = {**tool_input, "file_path": str(g.outside / "target.txt")}
    rc, err, _ = g.run(tool, tool_input, role)
    assert rc == 2 and f"rule {rule}" in err, (case, err)
    req, _ = approve(g, tool, tool_input, role)
    rc, err, _ = g.run(tool, tool_input, role)
    assert rc == 2 and f"rule {rule}" in err and "operator override rejected: not_overridable" in err, (case, err)
    assert g.entries_logged()[-1]["data"]["context"]["override_rejected"] == "not_overridable"
    assert not (g.root / STATE / "pending" / f"{req}.json").exists()  # nothing is offered for signing


def test_a1_eligible_role_denial_is_lifted_exactly_once(g):
    rc, err, req = g.run(*WRITE_NEW)
    assert rc == 2 and "rule role_not_permitted" in err and req
    pending = json.loads((g.root / STATE / "pending" / f"{req}.json").read_text())
    doc = g.signed(pending["signing_context"])
    g.place(req, doc)
    assert g.run(*WRITE_NEW)[0] == 0
    # A2: the same override again.
    rc, err, _ = g.run(*WRITE_NEW)
    assert rc == 2 and "operator override rejected: replayed" in err


def test_a3_role_permitted_call_without_material_is_allowed(g):
    assert g.run("Read", {"file_path": "src/app.py"})[0] == 0


def test_a4_unsolicited_override_is_denied_and_does_not_spend_the_nonce(g):
    req, ctx = g.context("Read", {"file_path": "src/app.py"})
    g.place(req, g.signed(ctx, nonce="n-unsolicited"))
    rc, err, _ = g.run("Read", {"file_path": "src/app.py"})
    assert rc == 2 and "rule unsolicited_override" in err
    assert not g.nonce_spent("n-unsolicited")


def test_u1_malformed_material_is_denied_whether_or_not_the_role_permits(g):
    req, _ = g.context("Read", {"file_path": "src/app.py"})
    g.place(req, "{not json")
    rc, err, _ = g.run("Read", {"file_path": "src/app.py"})
    assert rc == 2 and "rule unsolicited_override" in err
    req, _ = g.context(*WRITE_NEW)
    g.place(req, "{not json")
    rc, err, _ = g.run(*WRITE_NEW)
    assert rc == 2 and "operator override rejected: malformed" in err


def test_a5_a_failed_check_leaves_the_nonce_unspent(g):
    req, ctx = g.context(*WRITE_NEW)
    g.place(req, g.signed(ctx, nonce="n-shared", resolved_target="src/other.py"))
    rc, err, _ = g.run(*WRITE_NEW)
    assert rc == 2 and "context_mismatch" in err
    assert not g.nonce_spent("n-shared")
    g.place(req, g.signed(ctx, nonce="n-shared"))
    assert g.run(*WRITE_NEW)[0] == 0


# --- Override validation (D-1, D-3, R2) ------------------------------------------


@pytest.mark.parametrize(
    ("case", "change", "problem"),
    [
        ("M1", {"overridden_rule": "outside_project"}, "context_mismatch"),
        ("M2", {"resolved_target": "src/elsewhere.py"}, "context_mismatch"),
        ("M3", {"policy_digest": "0" * 64}, "policy_digest_mismatch"),
        ("M4", {"target_identity": "1:2/new.py"}, "context_mismatch"),
        ("M5", {"request_sha256": "f" * 64}, "context_mismatch"),
    ],
)
def test_signed_context_must_equal_the_recomputed_context(g, case, change, problem):
    req, ctx = g.context(*WRITE_NEW)
    g.place(req, g.signed(ctx, **change))
    rc, err, _ = g.run(*WRITE_NEW)
    assert rc == 2 and f"operator override rejected: {problem}" in err, (case, err)


def test_target_identity_binds_the_file_not_just_its_name(g):
    # The signature names src/app.py's current inode. Replacing the file
    # (same name, new inode) invalidates it. The replacement is created while
    # the original still exists, so the two inodes differ. Residual: after an
    # unlink, a filesystem may reuse the inode number, and (dev, ino) identity
    # cannot tell the files apart. OS protection of the target (G1) covers that.
    tool_input = {"file_path": "src/app.py", "content": "x = 3\n"}
    req, ctx = g.context("Write", tool_input)
    g.place(req, g.signed(ctx))
    (g.root / "src" / "replacement").write_text("replaced\n")
    os.replace(g.root / "src" / "replacement", g.root / "src" / "app.py")
    rc, err, _ = g.run("Write", tool_input)
    assert rc == 2 and "context_mismatch" in err


@pytest.mark.parametrize("field", ["reason", "nonce", "expires_at", "operator_id", "key_id"])
def test_editing_any_signed_field_breaks_the_signature(g, field):
    req, ctx = g.context(*WRITE_NEW)
    doc = g.signed(ctx)
    doc[field] = doc[field] + "x" if field != "expires_at" else (utc_now() + timedelta(minutes=14)).isoformat()
    g.place(req, doc)
    rc, err, _ = g.run(*WRITE_NEW)
    assert rc == 2 and re.search(r"override rejected: (bad_signature|unknown_key)", err), err


def test_a_key_the_registry_does_not_list_is_rejected(g):
    agent_key = Ed25519PrivateKey.generate()
    req, ctx = g.context(*WRITE_NEW)
    g.place(req, g.signed(ctx, key=agent_key))          # claims key_id op-1, signs with its own key
    assert "bad_signature" in g.run(*WRITE_NEW)[1]
    g.place(req, g.signed(ctx, key=agent_key, key_id="agent-key"))
    assert "unknown_key" in g.run(*WRITE_NEW)[1]


def test_a_public_key_planted_in_the_project_is_ignored(g):
    agent_key = Ed25519PrivateKey.generate()
    (g.root / "key_registry.json").write_text(json.dumps({"schema": "weaver.gate.key_registry.v1", "keys": [
        Gate.entry(agent_key, "agent", "op.alice", not_before=utc_now() - timedelta(days=1), not_after=utc_now() + timedelta(days=1))]}))
    req, ctx = g.context(*WRITE_NEW)
    g.place(req, g.signed(ctx, key=agent_key, key_id="agent"))
    assert "unknown_key" in g.run(*WRITE_NEW)[1]


def test_key_is_bound_to_its_operator(g):
    req, ctx = g.context(*WRITE_NEW)
    g.place(req, g.signed(ctx, operator="op.mallory"))
    assert "context_mismatch" in g.run(*WRITE_NEW)[1]


def test_k1_revoked_key(g):
    g.revoke(utc_now() - timedelta(hours=1))
    approve(g, *WRITE_NEW)
    assert "override rejected: key_revoked" in g.run(*WRITE_NEW)[1]


def test_k2_signature_made_before_revocation_is_unusable_after_it(g):
    approve(g, *WRITE_NEW, issued=utc_now() - timedelta(minutes=5))
    g.entries[0] = {**g.entries[0], "revoked_at": (utc_now() - timedelta(minutes=1)).isoformat()}
    g.publish()
    assert "override rejected: key_revoked" in g.run(*WRITE_NEW)[1]


@pytest.mark.parametrize(
    ("window", "problem"),
    [((timedelta(hours=1), timedelta(days=1)), "key_not_yet_valid"), ((-timedelta(days=2), -timedelta(days=1)), "key_expired")],
)
def test_k3_key_validity_window(g, window, problem):
    now = utc_now()
    g.entries[0] = Gate.entry(g.key, "op-1", "op.alice", not_before=now + window[0], not_after=now + window[1])
    g.publish()
    approve(g, *WRITE_NEW)
    assert f"override rejected: {problem}" in g.run(*WRITE_NEW)[1]


def test_k4_revocation_between_validation_and_claim_is_honoured_and_the_nonce_stays_spent(g):
    class RevokingStore:
        def __init__(self, real):
            self.real = real

        def check_and_store(self, nonce, **kw):
            fresh = self.real.check_and_store(nonce, **kw)
            g.revoke(utc_now() - timedelta(seconds=1))
            return fresh

    approve(g, *WRITE_NEW, nonce="n-k4")
    rc, err, _ = g.run(*WRITE_NEW, store_factory=lambda state, env: RevokingStore(hook._default_store(state, env)))
    assert rc == 2 and "override rejected: key_revoked" in err
    assert g.nonce_spent("n-k4")


def test_g1_registry_that_does_not_match_its_pin_is_untrusted(g):
    approve(g, *WRITE_NEW)
    g.registry.write_text(g.registry.read_text().replace("op.alice", "op.alice "))
    assert "override rejected: registry_untrusted" in g.run(*WRITE_NEW)[1]


def test_no_registry_in_the_anchor_means_no_overrides(g):
    write_anchor(g.anchor, g.root)
    approve(g, *WRITE_NEW)
    assert "override rejected: overrides_not_configured" in g.run(*WRITE_NEW)[1]


def test_l1_baseline_format_document_is_refused(g):
    req, ctx = g.context(*WRITE_NEW)
    legacy = {"schema": "weaver.claude_code_gate.override.v1", "request_sha256": req, "operator_id": "op.alice",
              "reason": "r", "nonce": "n", "issued_at": utc_now().isoformat(),
              "expires_at": (utc_now() + timedelta(minutes=5)).isoformat(), "key_fingerprint": "0" * 64, "signature": "00"}
    g.place(req, legacy)
    assert "override rejected: unknown_schema" in g.run(*WRITE_NEW)[1]


@pytest.mark.parametrize(
    ("kw", "problem"),
    [
        ({"issued": utc_now() - timedelta(minutes=20), "minutes": 10}, "expired"),
        ({"issued": utc_now() + timedelta(minutes=5), "minutes": 5}, "not_yet_valid"),
        ({"minutes": 20}, "lifetime_too_long"),
    ],
)
def test_validity_window(g, kw, problem):
    approve(g, *WRITE_NEW, **kw)
    assert f"override rejected: {problem}" in g.run(*WRITE_NEW)[1]


# --- Concurrency and failure (TX-2, NM) -----------------------------------------


def test_c1_racing_processes_get_exactly_one_allow(g):
    approve(g, *WRITE_NEW, nonce="n-race")
    env = {**os.environ, **g.env("Planner")}
    body = json.dumps(g.event(*WRITE_NEW))
    procs = [subprocess.Popen([sys.executable, "-m", "runtime.claude_code_gate.hook"], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=REPO, env=env) for _ in range(10)]
    results = [p.communicate(body) for p in procs]
    codes = [p.returncode for p in procs]
    assert codes.count(0) == 1, codes
    assert all("replayed" in err for (_, err), code in zip(results, codes) if code != 0)
    assert verify_file(g.root / STATE / "chronicle.jsonl").ok


def test_c2_chronicle_failure_after_claim_denies_and_the_nonce_stays_spent(g, monkeypatch):
    approve(g, *WRITE_NEW, nonce="n-c2")
    g.run("Read", {"file_path": "src/app.py"})  # create the chronicle first

    def broken(self, *a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(Chronicle, "append", broken)
    rc, err, _ = g.run(*WRITE_NEW)
    assert rc == 2 and "rule chronicle_write_failed" in err
    assert g.nonce_spent("n-c2")
    monkeypatch.undo()
    rc, err, _ = g.run(*WRITE_NEW)
    assert rc == 2 and "replayed" in err


def test_c3_locked_nonce_store_denies_within_a_bounded_wait(g):
    approve(g, *WRITE_NEW, nonce="n-c3")
    db = g.root / STATE / "override_nonces.sqlite"
    SqliteReplayStore(db)
    holder = sqlite3.connect(db, isolation_level=None)
    holder.execute("BEGIN EXCLUSIVE")
    try:
        rc, err, _ = g.run(*WRITE_NEW, env=g.env("Planner", WEAVER_GATE_NONCE_TIMEOUT="0.3"))
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert rc == 2 and "nonce_store_unavailable" in err
    assert g.run(*WRITE_NEW)[0] == 0  # the nonce was not spent by the failed attempt


# --- Trusted root (R3) -----------------------------------------------------------


def test_t1_no_anchor_denies_even_with_a_cwd(g):
    env = g.env(WEAVER_GATE_ANCHOR=str(g.anchor_dir / "absent.json"))
    env.pop("CLAUDE_PROJECT_DIR")
    rc, err, _ = g.run("Read", {"file_path": "src/app.py"}, env=env)
    assert rc == 2 and "rule trusted_root_missing" in err
    assert g.entries_logged() == []


def test_t2_project_dir_that_conflicts_with_the_anchor_is_denied(g, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    rc, err, _ = g.run("Read", {"file_path": "src/app.py"}, env=g.env(CLAUDE_PROJECT_DIR=str(other)))
    assert rc == 2 and "rule trusted_root_mismatch" in err


def test_t2_root_replaced_at_the_same_path_is_a_mismatch(g, tmp_path):
    g.root.rename(tmp_path / "moved")
    g.root.mkdir()
    rc, err, _ = g.run("Read", {"file_path": "x"})
    assert rc == 2 and "rule trusted_root_mismatch" in err


@pytest.mark.parametrize("damage", ["malformed", "group_writable", "not_root_owned", "symlink"])
def test_t3_untrusted_or_unreadable_anchor_is_denied(g, damage):
    if damage == "malformed":
        g.anchor.write_text("{")
    elif damage == "group_writable":
        os.chmod(g.anchor, 0o666)
    elif damage == "not_root_owned":
        if os.geteuid() != 0:
            pytest.skip("needs root to change ownership")
        os.chown(g.anchor, 65534, 65534)
    else:
        real = g.anchor_dir / "real.json"
        g.anchor.rename(real)
        os.symlink(real, g.anchor)
    rc, err, _ = g.run("Read", {"file_path": "src/app.py"})
    assert rc == 2 and "rule trusted_root_missing" in err


def test_event_cwd_does_not_move_the_root(g, tmp_path):
    # The baseline fell back to the event's cwd. Here the anchored root decides.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    env = g.env("Builder")
    env.pop("CLAUDE_PROJECT_DIR")
    err = io.StringIO()
    body = {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": ".claude/settings.json"}, "cwd": str(elsewhere)}
    assert hook.run_hook(io.StringIO(json.dumps(body)), err, env) == 2
    assert "rule protected_path" in err.getvalue()


# --- Audit (R9) --------------------------------------------------------------------


def test_override_use_and_rejection_are_chronicled_with_targets(g):
    approve(g, *WRITE_NEW)
    assert g.run(*WRITE_NEW)[0] == 0
    g.run(*WRITE_NEW)
    used, rejected = g.entries_logged()[-2:]
    ctx = used["data"]["context"]
    assert ctx["override"]["operator_id"] == "op.alice" and ctx["override"]["overridden_rule"] == "role_not_permitted"
    assert (ctx["target"], ctx["target_status"]) == ("src/new.py", "resolved") and ctx["target_identity"]
    assert rejected["data"]["context"]["override_rejected"] == "replayed"
    assert rejected["data"]["context"]["denial"]["target"] == "src/new.py"
    assert verify_file(g.root / STATE / "chronicle.jsonl").ok


# --- Enforcement manifest (D-4, M-D2) ----------------------------------------------


def test_every_repository_module_the_hook_imports_is_in_the_manifest():
    code = ("import sys, json; import runtime.claude_code_gate.hook; from pathlib import Path; r = Path('.').resolve(); "
            "print(json.dumps(sorted(str(Path(m.__file__).resolve().relative_to(r)) for m in list(sys.modules.values()) "
            "if getattr(m, '__file__', None) and Path(m.__file__).resolve().is_relative_to(r))))")
    loaded = json.loads(subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True, text=True, check=True).stdout)
    missing = sorted(set(loaded) - set(MANIFEST_FILES))
    assert not missing, f"decision-path modules missing from the enforcement manifest: {missing}"
    assert "runtime/claude_code_gate/gate.sh" in MANIFEST_FILES


def test_changing_any_manifest_component_changes_the_digest(tmp_path):
    base = policy_digest()
    for rel in MANIFEST_FILES:
        copy = tmp_path / "code"
        if copy.exists():
            shutil.rmtree(copy)
        for f in MANIFEST_FILES:
            (copy / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(REPO / f, copy / f)
        assert policy_digest(build_manifest(copy)) == base
        (copy / rel).write_bytes((copy / rel).read_bytes() + b"\n")
        assert policy_digest(build_manifest(copy)) != base, rel


def test_runtime_versions_are_part_of_the_digest():
    m = build_manifest()
    assert set(m["runtime"]) == {"python", "cryptography"}
    changed = {**m, "runtime": {**m["runtime"], "cryptography": "0.0"}}
    assert policy_digest(changed) != policy_digest(m)


# --- Operator tool: the key is not the agent's to read ----------------------------


def test_operator_tool_round_trip_signs_the_pending_request(g, tmp_path):
    key = tmp_path / "op.key"
    info = json.loads(subprocess.run([sys.executable, "-m", "runtime.claude_code_gate.operator", "keygen", "--private", str(key),
                                      "--key-id", "op-2", "--operator", "op.bob"], cwd=REPO, capture_output=True, text=True, check=True).stdout)
    assert oct(key.stat().st_mode & 0o777) == "0o600"
    g.entries.append(info["registry_entry"])
    g.publish()
    rc, _, req = g.run(*WRITE_NEW)
    assert rc == 2
    out = g.root / STATE / "overrides" / f"{req}.json"
    subprocess.run([sys.executable, "-m", "runtime.claude_code_gate.operator", "sign", "--private", str(key), "--key-id", "op-2",
                    "--operator", "op.bob", "--pending", str(g.root / STATE / "pending" / f"{req}.json"),
                    "--reason", "approved", "--minutes", "5", "--out", str(out)], cwd=REPO, capture_output=True, text=True, check=True)
    assert json.loads(out.read_text())["schema"] == OVERRIDE_SCHEMA
    assert g.run(*WRITE_NEW)[0] == 0


def test_hook_and_verification_never_touch_a_private_key():
    hook_source = (REPO / "runtime" / "claude_code_gate" / "hook.py").read_text()
    override_source = (REPO / "runtime" / "claude_code_gate" / "override.py").read_text()
    assert "private" not in hook_source.lower()
    assert "from_private_bytes" not in override_source.split("def validate(")[1]


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which("runuser") is None, reason="needs root and runuser")
def test_agent_identity_cannot_read_an_operator_key_it_does_not_own(tmp_path):
    key = tmp_path / "op.key"
    subprocess.run([sys.executable, "-m", "runtime.claude_code_gate.operator", "keygen", "--private", str(key),
                    "--key-id", "k", "--operator", "o"], cwd=REPO, capture_output=True, text=True, check=True)
    os.chmod(tmp_path, 0o755)
    os.chown(key, 0, 0)
    result = subprocess.run(["runuser", "-u", "nobody", "--", "cat", str(key)], capture_output=True, text=True)
    assert result.returncode != 0 and "Permission denied" in result.stderr
