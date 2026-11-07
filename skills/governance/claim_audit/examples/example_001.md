# Example 001: auditing a small repository

A repository with this `README.md`:

```markdown
# Example Kit

The kit is production-ready.
It is not certified for clinical use.
The schema is validated in CI.

## Status

- autonomous agents
```

and this `governance/claims.json`, which backs the CI claim with a test file:

```json
{
  "version": 1,
  "backed_claims": [
    {"term": "validated", "file": "README.md", "contains": "schema is validated", "evidence": ["tests/test_schema.py"]}
  ]
}
```

Run:

```bash
python skills/governance/claim_audit/claim_audit.py example-repo --show-info
```

Output (exit status 1):

```text
claim audit of example-repo (2 files, terms from default)
  errors: 2  warnings: 0  waiver debt: 0  backed: 1  claim: 2  denied: 2
  [error] README.md:3  'production-ready' (claim): The kit is production-ready.
  [info] README.md:4  'certified' (denied): It is not certified for clinical use.
  [info] README.md:4  'clinical' (denied): It is not certified for clinical use.
  [info] README.md:5  'validated' (backed): The schema is validated in CI.
  [error] README.md:9  'autonomous' (claim): - autonomous agents
FAILED
```

- Line 3 is an unbacked claim.
- Line 4 negates both terms.
- Line 5 is backed: the evidence file exists.
- Line 9 is a list item under a heading ("Status") that doesn't negate it, so it counts as a claim.

To pass, either back each claim with evidence, reword it, or waive it with a reason. Waivers count toward `waiver_debt`.
