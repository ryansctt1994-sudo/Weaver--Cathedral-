# Evidence Ladder

**Document:** Weaver Cathedral Master Build Evidence Ladder  
**Status:** v0.1 architecture rule  
**Authority:** Governs promotion language inside this repository only until independently adopted elsewhere.

---

## Core Rule

```text
Evidence promotes artifacts.
Narrative does not.
Architecture does not.
Model output does not.
Symbolic coherence does not.
```

Every claim must declare its evidence level.

---

## Levels

| Level | Name | Meaning | Allowed public claim |
|---|---|---|---|
| E0 | Idea | Concept, note, symbolic design, or unimplemented proposal | "Concept only" |
| E1 | Scaffold | Files/specs exist but are not proven executable end-to-end | "Architecture/scaffold" |
| E2 | Local execution | Runs locally with documented command and tests | "Locally executable prototype" |
| E3 | Reproducible package | Includes receipts, logs, fixtures, failure path, and replay instructions | "Reproducible demo package" |
| E4 | Independent reproduction | External person or system reproduced results from repo materials | "Independently reproduced" |
| E5 | Domain validation | Validated by appropriate domain process | "Domain validated within stated scope" |
| E6 | Production certification | Deployment authority, monitoring, incident controls, legal/compliance review | "Production certified within stated scope" |

---

## Promotion Criteria

### E0 -> E1

Requires:

- named artifact
- declared claim
- file scaffold
- owner or maintainer field
- risk boundary

### E1 -> E2

Requires:

- executable command
- local tests
- expected output
- dependency notes
- failure behavior

### E2 -> E3

Requires:

- receipt bundle
- logs
- synthetic fixture isolation
- replay command
- artifact hashes
- at least one exercised failure path
- promotion report

### E3 -> E4

Requires:

- independent witness or external runner
- reproduction transcript
- environment details
- matching or explainably bounded results

### E4 -> E5

Requires:

- domain-specific validation plan
- qualified reviewer or institution where applicable
- benchmark or evaluation protocol
- limitations section

### E5 -> E6

Requires:

- deployment controls
- monitoring
- rollback
- incident response
- user-facing disclosures
- legal/compliance review where applicable

---

## Fail-Closed Rule

If evidence is missing, contradictory, stale, or unverifiable, the artifact remains at its current level or is downgraded.

```text
Uncertainty cannot silently become authority.
```

---

## Current Repository Level

```text
Weaver Cathedral Master Build: E1 architecture/scaffold
Executable authority kernel: pending
Agent runtime: pending
Skill runtime: pending
Independent reproduction: absent
Production authority: none
```
