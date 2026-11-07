# Claim Audit

## Purpose

Find the claims a repository makes that its evidence does not back. The audit searches every tracked text file, and every file path, for the terms in the repository's Blocking Rule (`governance/open_gap_ledger.md`), plus a warning-only watch list, and classifies each occurrence.

| Category | Meaning | Severity |
|---|---|---|
| `claim` / `path_claim` | Unbacked use of a blocked term | error |
| `claim` (watch term) | Unbacked use of a watch term | warning |
| `denied` | Its sentence negates it, or (for a list item, table row or code-block line) its heading or lead-in does | info |
| `backed` | A claims-config entry names evidence files, and they exist | info |
| `waived` | A claims-config waiver accepts it with a reason; counted as waiver debt | info |
| `evidence_missing` | A backing entry matched, but its evidence files are absent | error |
| `stale_entry` | A backing entry or waiver matches nothing any more | error |

## When To Use

- In CI, on every change to a repository that keeps a Blocking Rule.
- Before publishing a README, paper or release notes.
- When importing material from another repository, to see what claims come with it.

## When Not To Use

- As proof that a repository makes no overclaims. The negation test reads sentences, not meaning. A passing audit means only that no unhandled blocked term was found.
- On generated or vendored files: exclude them in the config, with a reason.

## Inputs

See `inputs.schema.json`. From the command line:

```bash
python skills/governance/claim_audit/claim_audit.py <root> [--config PATH] [--json REPORT.json] [--show-info]
```

The claims config (`governance/claims.json` by default) holds `exclude` globs, `backed_claims` and `waivers`. Every exclude and waiver needs a reason. Backed claims and waivers match on term, file glob and a `contains` substring of the line, so they go stale when the text changes.

## Outputs

A report (`outputs.schema.json`) with every finding, counts, the waiver debt, and `report_hash`: the SHA-256 of the report under RFC 8785 JCS. The report has no timestamps, so the same inputs always produce the same hash. Exit status: 0 when there are no errors, 1 when there are errors, 2 when the skill refuses.

## Procedure

1. Refuse if the root is not a directory or the claims config is malformed.
2. Read blocked terms from the target's Blocking Rule if it has one; otherwise use the default list that mirrors it.
3. List files with `git ls-files` (or walk the tree), skipping excludes, binary files and files over 2 MB.
4. Split text into units: paragraphs, list items, table rows, code-block lines, indented code lines. For Python, scan only comments and string literals.
5. For each term occurrence, decide denied / backed / waived / claim as in the table above. A negation counts only within the same sentence and within 12 words of the term.
6. Flag backing entries whose evidence is missing, and entries that match nothing.
7. Emit the report and its hash.

## Failure Modes

- **False denial.** A negation near a term that it doesn't govern ("not only fast but certified") hides a claim. The 12-word window narrows this; it does not remove it.
- **False claim.** A definition or a quoted rule reads as a claim. Waive it with a reason.
- **Term drift.** Terms come from the target's own Blocking Rule, so a repository that weakens its rule weakens its audit. The report records `terms_source` and the term lists.

## Evidence Requirements

- `tests/test_skill_contract.py` exercises every category, the refusal paths, determinism of `report_hash`, and the input and output schemas.
- The skill audits this repository in CI using `governance/claims.json`.

## Safety / Security Notes

Read-only on the target, apart from the optional JSON report. It makes no network calls and runs no target code; it calls only `git ls-files` and `git rev-parse`. See `risk.md`.

## Example Invocation

See `examples/example_001.md`.
