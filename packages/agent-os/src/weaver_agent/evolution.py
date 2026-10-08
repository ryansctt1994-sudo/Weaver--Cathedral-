"""Bounded, evidence-only candidate promotion."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CandidateMetrics:
    candidate_id: str
    baseline_score_micros: int
    candidate_score_micros: int
    worst_regression_micros: int
    replay_valid: bool
    evaluator_distinct: bool


@dataclass(frozen=True)
class CandidateDecision:
    promote: bool
    reason: str


def evaluate_candidate(
    metrics: CandidateMetrics,
    *,
    minimum_gain_micros: int = 100_000,
    maximum_regression_micros: int = 30_000,
) -> CandidateDecision:
    if not metrics.replay_valid:
        return CandidateDecision(False, "REPLAY_INVALID")
    if not metrics.evaluator_distinct:
        return CandidateDecision(False, "SELF_EVALUATION_FORBIDDEN")
    if metrics.candidate_score_micros - metrics.baseline_score_micros < minimum_gain_micros:
        return CandidateDecision(False, "GAIN_BELOW_THRESHOLD")
    if metrics.worst_regression_micros > maximum_regression_micros:
        return CandidateDecision(False, "REGRESSION_ABOVE_THRESHOLD")
    return CandidateDecision(True, "EVIDENCE_SUPPORTS_CANDIDATE")

