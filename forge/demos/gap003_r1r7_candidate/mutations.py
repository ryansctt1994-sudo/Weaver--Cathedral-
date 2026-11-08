"""GAP-003 R6: mutation checks for the R1-R7 remediation candidate.

Each mutant is applied to a disposable copy of the working tree. It counts as
caught only if every test named as its required detection fails. A mutant
that leaves a required test green is reported as survived.

Implementer-run evidence. It is not the R8 independent reproduction.

Usage: python forge/demos/gap003_r1r7_candidate/mutations.py [--out report.json]
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TEST_FILES = ["tests/test_claude_code_gate_override.py", "tests/test_claude_code_gate.py"]

HOOK_ROOT_BLOCK = """        anchor = trusted_root.load_anchor(anchor_path)
        root = trusted_root.establish_root(anchor, env)
    except trusted_root.TrustError as exc:
        print(f"Blocked by Weaver gate (rule {exc.rule}): {exc.detail}. Not chronicled: no trusted root.", file=stderr)
        return 2
"""
HOOK_ROOT_BASELINE = """        anchor = trusted_root.load_anchor(anchor_path)
    except trusted_root.TrustError:
        anchor = trusted_root.Anchor(anchor_path, Path("/"), 0, 0, None, None)
    root = Path(env.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd())
"""

POLICY = "runtime/claude_code_gate/policy.py"
HOOK = "runtime/claude_code_gate/hook.py"
OVERRIDE = "runtime/claude_code_gate/override.py"
REGISTRY = "runtime/claude_code_gate/registry.py"
MANIFEST = "runtime/claude_code_gate/manifest.py"

MUTANTS = [
    {
        "id": "M-P", "what": "restore role-first ordering (the baseline defect)",
        "patches": [(POLICY, "    # Mandatory, role-independent checks.\n",
                     "    _c = 'write' if tool_name in WRITE_TOOLS else 'read' if tool_name in READ_TOOLS else 'delegate' if tool_name in DELEGATE_TOOLS else None\n"
                     "    if _c is not None and _c not in perms:\n"
                     "        return _veto('role_not_permitted', 'mutant: role first')\n"
                     "    # Mandatory, role-independent checks.\n")],
        "required": ["[X1-", "[X2-", "[X3-"],
    },
    {
        "id": "M-E", "what": "restore a denylist instead of the OQ-1 allowlist (policy property and override defence)",
        "patches": [
            (POLICY, "        return (not self.allowed) and self.rule in ELIGIBLE_RULES",
             "        return (not self.allowed) and self.rule not in {'protected_path', 'bash_protected_path', 'malformed_call', "
             "'unknown_role', 'unknown_ceiling', 'missing_path', 'missing_command', 'unparseable'}"),
            (OVERRIDE, '    if live.overridden_rule != "role_not_permitted":  # defence in depth; the hook already applies OQ-1\n        return "not_overridable"\n', ""),
        ],
        "required": ["[B2-", "[B3-", "[B4-", "test_every_other_denial_including_future_ones_is_non_overridable"],
    },
    {
        "id": "M-S", "what": "remove the signature check",
        "patches": [(OVERRIDE, "        public_cls.from_public_bytes(bytes.fromhex(entry.public_key_hex)).verify(bytes.fromhex(doc[\"signature\"]), message(doc))",
                     "        pass")],
        "required": ["test_editing_any_signed_field_breaks_the_signature", "test_a_key_the_registry_does_not_list_is_rejected"],
    },
    {
        "id": "M-N", "what": "do not consume the nonce",
        "patches": [(OVERRIDE, '        fresh = store.check_and_store(f"operator-override:{doc[\'nonce\']}")', "        fresh = True")],
        "required": ["test_a1_eligible_role_denial_is_lifted_exactly_once", "test_c1_racing_processes_get_exactly_one_allow"],
    },
    {
        "id": "M-A", "what": "claim the nonce before step 8 validation",
        "patches": [
            (HOOK, "                    override_problem = operator_override.validate(doc, live=live, keys=keys, now=when)  # step 8",
             "                    override_problem = operator_override.claim(doc, _default_store(state, env)) or operator_override.validate(doc, live=live, keys=keys, now=when)"),
            (HOOK, "                        override_problem = operator_override.claim(doc, store)", "                        override_problem = None"),
        ],
        "required": ["test_a5_a_failed_check_leaves_the_nonce_unspent"],
    },
    {
        "id": "M-K", "what": "skip key status checks",
        "patches": [(REGISTRY, '    """None if entry may authorize a decision at time ``at``, else the denial reason."""\n',
                     '    """None if entry may authorize a decision at time ``at``, else the denial reason."""\n    return None\n')],
        "required": ["test_k1_revoked_key", "test_k2_", "test_k3_", "test_k4_"],
    },
    {
        "id": "M-C", "what": "treat a Chronicle write failure as ALLOW",
        "patches": [(HOOK, "    if record.allowed:\n        return 0\n",
                     "    if record.allowed or record.reason.startswith('chronicle_write_failed'):\n        return 0\n")],
        "required": ["test_c2_chronicle_failure_after_claim_denies_and_the_nonce_stays_spent"],
    },
    {
        "id": "M-R9", "what": "read the root from CLAUDE_PROJECT_DIR or the event cwd (baseline)",
        "patches": [(HOOK, HOOK_ROOT_BLOCK, HOOK_ROOT_BASELINE)],
        "required": ["test_t1_no_anchor_denies_even_with_a_cwd", "test_t2_project_dir_that_conflicts_with_the_anchor_is_denied"],
    },
    {
        "id": "M-U", "what": "ignore unsolicited override material",
        "patches": [(HOOK, "        if decision.allowed and material:", "        if decision.allowed and material and False:")],
        "required": ["test_a4_unsolicited_override_is_denied_and_does_not_spend_the_nonce", "test_u1_malformed_material_is_denied"],
    },
    {
        "id": "M-D2", "what": "exclude one manifest component from the digest",
        "patches": [(MANIFEST, '    "core/authority/replay.py",\n', "")],
        "required": ["test_every_repository_module_the_hook_imports_is_in_the_manifest"],
    },
    {
        "id": "M-I", "what": "drop target_identity from the signed and compared fields",
        "patches": [
            (OVERRIDE, '"policy_digest", "overridden_rule", "resolved_target", "target_identity", "request_sha256",\n)',
             '"policy_digest", "overridden_rule", "resolved_target", "request_sha256",\n)'),
            (OVERRIDE, 'CONTEXT_FIELDS = ("request_sha256", "overridden_rule", "resolved_target", "target_identity")',
             'CONTEXT_FIELDS = ("request_sha256", "overridden_rule", "resolved_target")'),
        ],
        "required": ["[M4-", "test_target_identity_binds_the_file_not_just_its_name"],
    },
    {
        "id": "M-R", "what": "drop overridden_rule from the signed and compared fields",
        "patches": [
            (OVERRIDE, '"policy_digest", "overridden_rule", "resolved_target", "target_identity", "request_sha256",\n)',
             '"policy_digest", "resolved_target", "target_identity", "request_sha256",\n)'),
            (OVERRIDE, 'CONTEXT_FIELDS = ("request_sha256", "overridden_rule", "resolved_target", "target_identity")',
             'CONTEXT_FIELDS = ("request_sha256", "resolved_target", "target_identity")'),
            (OVERRIDE, '        **{k: context[k] for k in ("policy_digest", *CONTEXT_FIELDS)},\n',
             '        **{k: context[k] for k in ("policy_digest", *CONTEXT_FIELDS)},\n        "overridden_rule": context["overridden_rule"],\n'),
            (OVERRIDE, "    return canonicalize({k: doc[k] for k in SIGNED_FIELDS}, JCS_RFC8785)",
             "    return canonicalize({k: doc[k] for k in SIGNED_FIELDS if k in doc}, JCS_RFC8785)"),
            (OVERRIDE, '    if set(doc) != set(SIGNED_FIELDS) | {"signature"}:', '    if set(doc) != set(SIGNED_FIELDS) | {"signature", "overridden_rule"}:'),
            (OVERRIDE, '    if any(not isinstance(doc[k], str) for k in (*SIGNED_FIELDS, "signature")):',
             '    if any(not isinstance(doc[k], str) for k in (*SIGNED_FIELDS, "signature")) and False:'),
        ],
        "required": ["[M1-"],
    },
]


def copy_tree(dst: Path) -> None:
    ignore = shutil.ignore_patterns(".git", ".weaver", "__pycache__", ".pytest_cache", ".hypothesis", "*.egg-info", "logs")
    shutil.copytree(REPO, dst, ignore=ignore)


def apply(dst: Path, patches) -> None:
    for rel, old, new in patches:
        path = dst / rel
        text = path.read_text()
        count = text.count(old)
        if count != 1:
            raise SystemExit(f"patch target for {rel} found {count} times; the mutant would be meaningless")
        path.write_text(text.replace(old, new))


def run_tests(dst: Path, files=TEST_FILES) -> tuple[int, str]:
    res = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rf", *files],
                         cwd=dst, capture_output=True, text=True, timeout=900)
    return res.returncode, res.stdout + res.stderr


def failed_ids(output: str) -> list[str]:
    return sorted(set(re.findall(r"^FAILED (\S+)", output, flags=re.M)))


def missing_cryptography(dst: Path) -> dict:
    """M-D: with cryptography unimportable, the G3 module must fail to collect, never skip."""
    shim = dst / "_no_crypto"
    (shim / "cryptography").mkdir(parents=True)
    (shim / "cryptography" / "__init__.py").write_text("raise ImportError('cryptography removed by mutant M-D')\n")
    env_cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_claude_code_gate_override.py"]
    res = subprocess.run(env_cmd, cwd=dst, capture_output=True, text=True, timeout=600,
                         env={"PATH": "/usr/bin:/bin:/usr/local/bin", "PYTHONPATH": str(shim)})
    out = res.stdout + res.stderr
    caught = res.returncode != 0 and "error" in out.lower() and " skipped" not in out.split("\n")[-2]
    return {"id": "M-D", "what": "cryptography unavailable", "exit_code": res.returncode,
            "summary": out.strip().splitlines()[-1] if out.strip() else "", "caught": caught}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path(__file__).with_name("mutations_report.json"))
    args = parser.parse_args()
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        clean = Path(tmp) / "clean"
        copy_tree(clean)
        rc, out = run_tests(clean)
        baseline_fail = failed_ids(out)
        if rc != 0:
            raise SystemExit(f"unmutated copy does not pass; refusing to score mutants: {baseline_fail}")
        for m in MUTANTS:
            dst = Path(tmp) / m["id"]
            copy_tree(dst)
            apply(dst, m["patches"])
            rc, out = run_tests(dst)
            fails = failed_ids(out)
            detected = {req: any(req in f for f in fails) for req in m["required"]}
            results.append({"id": m["id"], "what": m["what"], "exit_code": rc, "required_detections": detected,
                            "caught": all(detected.values()), "failed_tests": fails})
            print(f"{m['id']:5s} caught={all(detected.values())} required={detected} failed={len(fails)}", flush=True)
        dst = Path(tmp) / "M-D"
        copy_tree(dst)
        md = missing_cryptography(dst)
        results.append(md)
        print(f"M-D   caught={md['caught']} exit={md['exit_code']} {md['summary']}", flush=True)

    files = {rel: sha256((REPO / rel).read_bytes()).hexdigest()
             for rel in sorted({p for m in MUTANTS for p, _, _ in m["patches"]} | set(TEST_FILES))}
    report = {
        "schema": "weaver.gap003.mutation_report.v1",
        "classification": "IMPLEMENTER_RUN (not R8)",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "unmutated_copy_passed": True,
        "source_sha256": files,
        "mutants": results,
        "all_caught": all(r["caught"] for r in results),
    }
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("all_caught:", report["all_caught"])
    return 0 if report["all_caught"] else 1


if __name__ == "__main__":
    sys.exit(main())
