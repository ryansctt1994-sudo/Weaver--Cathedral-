# Operator override (GAP-003-G3)

## Requirement

An authenticated, separately controlled, auditable authorization path that lets a person approve one call the policy denied, and that the agent cannot invoke.

## Design

| Property | How it is met |
|---|---|
| Authenticated | The override is an Ed25519 signature by the operator's private key over the override document (RFC 8785 JCS). |
| Separately controlled | The hook holds only the public key, pinned in `WEAVER_GATE_OPERATOR_PUBKEY` in `.claude/settings.json`. The private key never sits where the agent's identity can read it. |
| Bound | The document names one `request_sha256`: the hash of tool, tool input, role, ceiling and agent id. Any other call, including the same edit from a subagent, is a different request. |
| Single-use | The nonce is consumed in a persistent store (`.weaver/gate/override_nonces.sqlite`), and only after the signature checks out. |
| Short-lived | At most 15 minutes, with 30 seconds of clock skew allowed. |
| Limited | The gate's own protected paths, protected-path mentions in Bash, malformed calls, and unknown roles or ceilings cannot be overridden. |
| Auditable | Each use is chronicled as `ALLOW` with operator id, reason, nonce, key fingerprint, validity window and the overridden rule. Each rejected attempt is chronicled as `VETO` with its reason (`unknown_key`, `bad_signature`, `replayed`, `wrong_request`, `expired`, …). |

**Why the agent cannot invoke it.** Claude Code runs the hook as the same user as the agent, so any secret the hook can read, the agent can read. A shared-key scheme (such as the HMAC override in `core/authority/gate.py`) would let the agent sign its own overrides. An asymmetric signature removes that: the agent can read the public key, the hook code and the override files, and can write files, but cannot produce a signature the public key accepts. Writing an override file is not enough to make it valid.

## Flow

1. The agent's call is denied. The denial message ends with `request <sha256>`.
2. The operator reviews the call and signs it:

   ```bash
   python -m runtime.claude_code_gate.operator sign --private ~/.weaver/operator.key \
       --request <sha256> --operator <id> --reason "<why>" --minutes 10 \
       --out <project>/.weaver/gate/overrides/<sha256>.json
   ```

3. The agent makes the same call again, and it goes through once.

Key setup: `python -m runtime.claude_code_gate.operator keygen --private <path>`. It writes the private key at mode 0600 and prints the public key to pin.

## Deployment requirements

The local tests cannot check these:

- **Private key custody.** The private key lives on another machine, or in a file owned by the operator's user (mode 0600) that the agent's user cannot read. If the agent can read it, the override is no longer separately controlled.
- **Pinned key integrity.** The agent's identity must not be able to change `.claude/settings.json` (G1). If it can, it can pin its own key.
- **Clock.** Expiry uses the host clock. An agent able to set the clock could stretch the window.
- **One operator.** One key approves alone. There is no two-person rule or revocation list. Rotating the key means changing the pinned value.
- **`cryptography` installed.** Without it, every override is rejected (`crypto_unavailable`). The gate fails closed.

## Evidence

- `tests/test_claude_code_gate_override.py`: 28 tests, with mutation checks on the signature, nonce and non-overridable rules.
- `forge/demos/gap003_g3_override/`: a live round trip through Claude Code 2.1.319: denied, signed, allowed once, replay denied.
