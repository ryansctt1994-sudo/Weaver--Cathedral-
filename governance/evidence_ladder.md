# Evidence Ladder

**Document:** Weaver Cathedral Master Build Evidence Ladder  
**Status:** v0.1.1 Phase 1 post-merge update  
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
| E2 | Local execution | Runs locally or in CI with documented command and tests | "Locally executable prototype" |
| E3 | Reproducible package | Includes receipts, logs, fixtures, failure path, artifact hashes, and replay instructions | "Reproducible demo package" |
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
- local or CI test run
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
Executable authority kernel: E2 candidate after PR #1 green CI and merge
Agent runtime: pending
Skill runtime: scaffold/spec only
Independent reproduction: absent
Production authority: none
```

---

## Phase 1 Evidence Record

```text
Artifact: core/authority minimal verification spine
Merge SHA: 1cf86bc1ba7dd7d9c9bdd9270554041b7cc03579
PR: #1 feat(core): implement Phase 1 authority verification spine
Evidence: package install, pytest suite, synthetic fixtures, CLI/module entrypoint, demo scaffold, CI green
Allowed claim: locally executable authority-kernel prototype / E2 candidate
Blocked claim: E3 reproducible package, independent reproduction, production authority, autonomous authority
```

E3 remains blocked until the repository contains a complete reproducible receipt package with logs, artifact hashes, replay instructions, and exercised failure transcripts.
