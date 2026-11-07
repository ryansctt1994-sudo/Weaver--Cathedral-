# STATUS — governance/

**Folder:** `governance/`
**Purpose:** Evidence ladder, source boundary, open gap ledger: the rules that decide promotion.
**Authority Level:** `GOVERNANCE_CONTROL`
**Evidence:** Documentation. These files define gates; they don't pass them.

**Allowed contents:** Promotion rules, evidence definitions, gap ledger, source-boundary policy.

**Forbidden contents:** Executable code that grants promotion (that belongs in `core/`). Claims of independent validation or production readiness without a ledger entry.

**Promotion rule:** Changes to a gate require a pull request that states which gaps it opens or closes.

**Audit owner:** Repository owner (`ryansctt1994-sudo`)
**Last reviewed:** 2026-11-07
**Enforced by:** `tests/test_no_liturgical_artifacts.py`
