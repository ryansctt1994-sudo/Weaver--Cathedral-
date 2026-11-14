# Operator override (GAP-003-G3), remediation candidate

**Status:** implementer-tested candidate for R1–R7 of the GAP-003 v0.3 draft specification. Not R8 independently reproduced, not deployment-verified, not merged. G3 remains `FAIL` until R8 and the deployment checks pass.

## Retraction (baseline `300bd32`)

The baseline version of this file said the gate's protected paths "cannot be overridden". That was false on `300bd32`. The role check ran before the path check, so a role denial reached the override first, and override eligibility was a denylist. A valid signature let a Planner write `.claude/settings.json`, an absolute path outside the project, or a path through a symlink into `.claude/`, and let a Builder write outside the project. The baseline file stays in git history; this version replaces it.

## Requirement

An authenticated, separately controlled, auditable authorization path that lets a person approve one call the policy denied for its role alone, and that the agent cannot invoke.

## Design

| Property | How it is met |
|---|---|
| Eligible denials only (OQ-1) | Only `role_not_permitted` can be lifted. Every other denial, including any reason added later, is non-overridable. The role check runs last, after every mandatory check (paths, protected prefixes, symlinks, Bash rules, delegation escalation), so a role denial implies the call already passed them. |
| Trusted root (R3) | The project root comes from a root-owned anchor file (`/etc/weaver-gate/anchor.json`, or `WEAVER_GATE_ANCHOR`), with the root's `(st_dev, st_ino)`. `CLAUDE_PROJECT_DIR` must agree with it; the event's `cwd` is ignored. |
| Authenticated (D-3) | Ed25519 signature over the override document (RFC 8785 JCS), by a key listed in the key registry. The anchor pins the registry's SHA-256. Keys carry validity windows and can be revoked. |
| Bound (R2, D-4) | The signature covers the request digest (tool, input, role, ceiling, agent id, resolved target), the overridden rule, the resolved target, the target's filesystem identity, and the policy digest of the running enforcement manifest. The hook recomputes each and compares. |
| Single-use (TX-1, TX-2) | The nonce is claimed by a unique-key insert only after every other check has passed. A rejected document leaves its nonce unspent. The key's status is checked again after the claim (TX-3). |
| Unsolicited material (D-1) | Override material for a call the role already permits is denied (`unsolicited_override`), and its nonce is not spent. Malformed material is denied, never ignored. |
| Recorded | A decision that cannot be chronicled is denied (`chronicle_write_failed`). Every decision records the supplied target, the normalized target, its identity and its resolution status (R9). |

## Flow

1. The call is denied with `role_not_permitted`. The hook writes `.weaver/gate/pending/<request_sha256>.json` with the call and the exact signing context.
2. The operator reviews the pending file (tool, input, target) and signs it:

   ```bash
   python -m runtime.claude_code_role_gate.operator sign --private ~/.weaver/operator.key --key-id <key_id> \
       --operator <operator_id> --pending <project>/.weaver/gate/pending/<sha256>.json \
       --reason "<why>" --minutes 10 --out <project>/.weaver/gate/overrides/<sha256>.json
   ```

3. The agent makes the same call again, and it goes through once.

Key setup: `python -m runtime.claude_code_role_gate.operator keygen --private <path> --key-id <id> --operator <id>`. It writes the private key at mode 0600 and prints a registry entry. An administrator adds the entry to the registry and re-pins the registry's SHA-256 in the anchor.

## Deployment requirements

The local tests cannot check these:

- **Anchor and registry custody.** The anchor, its directory and the registry must be root-owned and not writable by the agent's identity. The hook refuses an anchor that is not root-owned or is group- or world-writable.
- **Managed-settings precedence (L-1).** A lower-trust setting can point `WEAVER_GATE_ANCHOR` at a different root-owned anchor. Whether managed settings win is untested.
- **Private key custody.** The private key lives on another machine, or in a file owned by the operator's user (mode 0600) that the agent's user cannot read.
- **Target races (TOCTOU).** The hook binds the target's `(st_dev, st_ino)` and narrows, but does not close, the window between check and use. A filesystem can reuse an inode number after a file is deleted. OS protection of targets (G1) is the required control.
- **Clock.** Expiry and key windows use the host clock.
- **`cryptography` installed.** Without it, override verification raises and the hook blocks. The G3 tests fail to collect rather than skip (R7).

## Evidence

- `tests/test_claude_code_role_gate_override.py`: candidate tests by v0.3 §9 ID (X1–X3, B1–B4, A1–A5, M1–M5, K1–K4, G1, L1, U1, C1–C3, T1–T3, manifest coverage).
- `forge/demos/gap003_r1r7_candidate/`: the baseline bypass scenarios through `gate.sh` against this candidate, and the R6 mutation report.
- `forge/demos/gap003_g3_override/`: the baseline round trip on `300bd32` (historical; baseline format).
