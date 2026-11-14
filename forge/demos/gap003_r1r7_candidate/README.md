# GAP-003 R1–R7 remediation candidate: implementer evidence

**Classification:** IMPLEMENTER-TESTED. Not R8 (independent reproduction), not deployment-verified, not merged. G3 stays `FAIL` and GAP-003 stays `OPEN · HOLD` until R8 and the deployment checks (L-1, L-2) pass.

**Baseline:** `300bd326898e0c1045f6121a700649145ef4f23e` (PR #13 head, frozen). **Specification:** GAP-003 R1–R8 v0.3 DRAFT, not frozen. The implementer is also the specification author, so this work cannot serve as R8 evidence.

## Package location

The candidate lives in `runtime/claude_code_role_gate/`. `main` gained a separate, independent gate in `runtime/claude_code_gate/` (PR #14), so the candidate was moved to its own package to keep the two apart for comparison. Neither is activated automatically: each needs its own hook entry in Claude Code settings. The role gate protects both gate code directories. The G1, G2 and G3 evidence directories record the baseline under its original path and are left unchanged.

## What changed

| Requirement | Change |
|---|---|
| R1, R5 (precedence, OQ-1) | `policy.decide` runs every mandatory check (paths, protected prefixes, symlinks, Bash rules, delegation escalation) before the role. Only `role_not_permitted` is overridable (`ELIGIBLE_RULES`). |
| R2 (signed context) | Override schema v2 signs the request digest, overridden rule, resolved target, target identity `(st_dev, st_ino)` and policy digest. The hook recomputes and compares each. |
| R3 (trusted root) | `trusted_root.py`: root from a root-owned anchor; `CLAUDE_PROJECT_DIR` must agree; the event `cwd` is ignored. |
| D-1 | Override material on a role-permitted call is denied `unsolicited_override`; its nonce is not spent. |
| NM, TX-1..TX-4 | Validation consumes nothing; the nonce is claimed once by unique-key insert; the key is re-checked after the claim; a failed record denies and leaves the nonce spent. |
| D-3 | `registry.py`: key registry pinned by SHA-256 in the anchor, with validity windows and revocation. |
| D-4 | `manifest.py`: policy digest over every repository module the hook imports, plus interpreter and `cryptography` versions. |
| R6 | `mutations.py` with 13 mutants. |
| R7 | `cryptography` imported directly in the G3 tests (no `importorskip`); CI installs it and fails if any G3 test skips. |
| R9 | Every decision records the supplied target, normalized target, identity and resolution status, including role denials. |

## Results (Python 3.13.18, cryptography 50.0.1)

| Check | Result |
|---|---|
| Full suite, candidate | 508 passed, 1 skipped (opt-in live G2) on 3.11, 3.12 and 3.13 |
| Full suite, baseline `300bd32` (clone) | 477 passed, 1 skipped |
| `regression_check.py`: P1–P3, B1 bypasses through `gate.sh` | DENY with `protected_path` / `outside_project`, override `not_overridable` (baseline: ALLOW) |
| `regression_check.py`: B2 control, positive control | B2 DENY; eligible in-project write ALLOW once, replay DENY |
| `mutations.py` | 13 of 13 caught by their named tests |
| Demo, evidence bundle, claim audit | pass |
| `live_mediation.py`: real Claude Code 2.1.319 sessions, project-level hook | 6/6 as expected: Planner write, Planner write to `.claude/settings.json`, Builder write outside, Builder Bash redirect all blocked by the gate (verdict from the chronicle and file hashes); Builder in-project write permitted; no-hook control permitted |

Report hashes at the time of writing: `regression_report.json` `c91497d7…`, `mutations_report.json` `c916667a…`. The commit that contains them is the authoritative identity.

## Departures from, and corrections to, v0.3

These need review before freeze:

1. **Mutation table.** v0.3 says M-P is detected by X1, X2, X3 and B2. B2 (Builder outside the project) passes the role check, so role-first ordering does not affect it; B2 is caught by M-E (denylist). v0.3 says M-S is detected by M1–M4; those are context checks that do not depend on the signature, so M-S is caught by the signature-edit and foreign-key tests instead.
2. **T1.** "`CLAUDE_PROJECT_DIR` unset, `cwd` set → DENY" is implemented as: with no anchor, a `cwd` cannot establish a root. With a valid anchor and no `CLAUDE_PROJECT_DIR`, the anchored root is used.
3. **Manifest inventory.** Five modules the hook loads through package initialisation were added: `core/__init__.py`, `runtime/__init__.py`, `core/authority/{models,receipts,verifier}.py`, plus the candidate's own `trusted_root.py`, `registry.py`, `manifest.py` and `core/authority/chronicle.py`. A test enforces that every imported repository module is listed.
4. **Anchor location.** `/etc/weaver-gate/anchor.json`, or `WEAVER_GATE_ANCHOR` pointing at a file that, with its directory, is root-owned and not group- or world-writable. A lower-trust setting can still select another root-owned anchor; L-1 decides whether managed settings prevent that.
5. **Additional denial reasons:** `unknown_key`, `bad_timestamp`, `lifetime_too_long`, `not_yet_valid`, `malformed`, `overrides_not_configured`, `policy_digest_unavailable`. These belong in the canonical reason list (v0.3 §11 item 6).
6. **Delegation.** Delegation escalation is checked before the role, so a role without `delegate` cannot have an override lift a spawn of a stronger subagent (test B4b).

## Limits found while validating

- **Inode reuse.** `(st_dev, st_ino)` identity cannot tell a deleted file from a new file that reuses its inode number. The test exercises replacement while the original exists; G1 OS protection is the control for the rest.
- **Root required.** The anchor must be root-owned, so the hook tests run as root. As a non-root user every hook test fails closed with `trusted_root_missing`. CI runs the suite under `sudo`. The CI changes have not been executed.
- **G2 evidence is historical.** The G2 report was produced by the baseline policy; `test_report_was_produced_by_the_baseline_policy` pins that, and a separate test asserts the current policy differs. G2 must be re-run on the candidate. `delegation_check.py` needs an anchor before it can run against the candidate.
- **G1 harness.** `isolation_check.py` runs a Python attempt as `nobody` using `sys.executable`. If that interpreter lives where `nobody` cannot execute it, the negative control fails as if a write went undetected. Seen with a venv in a mode-0700 directory; with an executable interpreter all G1 tests pass.
- **Mediation tested at project level only.** `live_mediation.py` shows real Claude Code sessions route these calls through the role gate when it is installed with `--settings`. Managed settings, `disableAllHooks` and other lower-trust overrides (L-1, L-2) are not tested, so it does not show the hook cannot be bypassed.

## Reproduce

```bash
sudo python -m pytest -q
sudo python forge/demos/gap003_r1r7_candidate/regression_check.py
sudo python forge/demos/gap003_r1r7_candidate/mutations.py
```
