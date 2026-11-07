"""Fail-closed and replay tests for the uncertainty gate."""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

import pytest

from core.authority.chronicle import Chronicle, ChronicleError
from core.authority.gate import (
    GateDecision,
    UncertaintyGate,
    normalized_entropy,
    request_hash,
    sign_override,
)

KEY = b"k" * 32
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
REQUEST = {"action": "deploy_patch", "target": "demo.authority_spine.001"}


def gate(**kwargs) -> UncertaintyGate:
    return UncertaintyGate(threshold=0.7, override_key=KEY, **kwargs)


def override(nonce: str = "nonce-0001", *, req=REQUEST, issued_at=NOW, key=KEY, **fields):
    signed = sign_override(
        key, operator_id="operator.ryan", reason="reviewed manually", request_hash=request_hash(req),
        nonce=nonce, issued_at=issued_at,
    )
    signed.update(fields)
    return signed


# --- Sentinel behaviour ---------------------------------------------------------


def test_low_uncertainty_is_allowed():
    record = gate().evaluate(REQUEST, 0.2, now=NOW)
    assert record.decision is GateDecision.ALLOW and record.allowed


@pytest.mark.parametrize("u", [0.7, 0.71, 1.0])
def test_uncertainty_at_or_above_threshold_is_vetoed(u):
    record = gate().evaluate(REQUEST, u, now=NOW)
    assert record.decision is GateDecision.VETO and record.reason == "above_threshold"


@pytest.mark.parametrize(
    ("u", "reason"),
    [
        (None, "uncertainty_missing"),
        (math.nan, "uncertainty_out_of_range"),
        (math.inf, "uncertainty_out_of_range"),
        (-0.01, "uncertainty_out_of_range"),
        (1.01, "uncertainty_out_of_range"),
        (True, "uncertainty_not_a_number"),
        ("0.1", "uncertainty_not_a_number"),
        ([0.1], "uncertainty_not_a_number"),
    ],
)
def test_malformed_uncertainty_is_vetoed(u, reason):
    record = gate().evaluate(REQUEST, u, now=NOW)
    assert record.decision is GateDecision.VETO and record.reason == reason


def test_unhashable_request_is_vetoed():
    record = gate().evaluate({"x": float("nan")}, 0.1, now=NOW)
    assert record.decision is GateDecision.VETO and record.reason == "request_not_canonicalizable"


def test_internal_error_is_vetoed():
    # A naive `now` makes the freshness comparison raise; that must not escape or allow.
    record = gate().evaluate(REQUEST, 0.9, now=datetime(2026, 11, 7, 12, 0), override=override())
    assert record.decision is GateDecision.VETO and record.reason.startswith("gate_error:")


@pytest.mark.parametrize("threshold", [0, 1, -0.1, 1.5, True, "0.7", math.nan])
def test_invalid_threshold_is_refused(threshold):
    with pytest.raises(ValueError):
        UncertaintyGate(threshold=threshold)


@pytest.mark.parametrize("key", [b"", b"short", "k" * 32])
def test_weak_or_wrong_type_key_is_refused(key):
    with pytest.raises(ValueError):
        UncertaintyGate(threshold=0.7, override_key=key)


def test_there_is_no_disabled_mode():
    # Delta's SovereignGateV2(enabled=False) returned ALLOW for everything.
    with pytest.raises(TypeError):
        UncertaintyGate(threshold=0.7, enabled=False)  # type: ignore[call-arg]


# --- Overrides ------------------------------------------------------------------


def test_valid_override_allows_and_names_operator():
    record = gate().evaluate(REQUEST, 0.9, now=NOW, override=override())
    assert record.decision is GateDecision.ALLOW_WITH_OVERRIDE
    assert record.override_operator == "operator.ryan"


def test_override_cannot_be_replayed():
    g = gate()
    ov = override()
    assert g.evaluate(REQUEST, 0.9, now=NOW, override=ov).allowed
    second = g.evaluate(REQUEST, 0.9, now=NOW, override=ov)
    assert second.decision is GateDecision.VETO and second.reason == "override_rejected:replayed"


def test_override_is_bound_to_one_request():
    other = {"action": "delete_everything"}
    record = gate().evaluate(other, 0.9, now=NOW, override=override())
    assert record.decision is GateDecision.VETO and record.reason == "override_rejected:wrong_request"


@pytest.mark.parametrize(
    ("ov_kwargs", "now", "reason"),
    [
        ({"issued_at": NOW - timedelta(minutes=6)}, NOW, "expired"),
        ({"issued_at": NOW + timedelta(minutes=1)}, NOW, "issued_in_future"),
        ({"key": b"x" * 32}, NOW, "bad_signature"),
        ({"reason": "tampered after signing"}, NOW, "bad_signature"),
        ({"operator_id": "someone.else"}, NOW, "bad_signature"),
        ({"signature": "0" * 64}, NOW, "bad_signature"),
        ({"override_version": "weaver.gate.override.v0"}, NOW, "unknown_version"),
        ({"nonce": ""}, NOW, "malformed"),
        ({"extra": "field"}, NOW, "malformed"),
    ],
)
def test_bad_overrides_are_rejected(ov_kwargs, now, reason):
    key = ov_kwargs.pop("key", KEY)
    issued_at = ov_kwargs.pop("issued_at", NOW)
    ov = override(key=key, issued_at=issued_at, **ov_kwargs)
    record = gate().evaluate(REQUEST, 0.9, now=now, override=ov)
    assert record.decision is GateDecision.VETO and record.reason == f"override_rejected:{reason}"


def test_override_within_clock_skew_is_accepted():
    ov = override(issued_at=NOW + timedelta(seconds=20))
    assert gate().evaluate(REQUEST, 0.9, now=NOW, override=ov).allowed


def test_forged_override_does_not_burn_the_nonce():
    g = gate()
    forged = override(key=b"x" * 32)
    assert not g.evaluate(REQUEST, 0.9, now=NOW, override=forged).allowed
    assert g.evaluate(REQUEST, 0.9, now=NOW, override=override()).allowed


def test_overrides_refused_when_no_key_configured():
    record = UncertaintyGate(threshold=0.7).evaluate(REQUEST, 0.9, now=NOW, override=override())
    assert record.decision is GateDecision.VETO and record.reason == "override_rejected:overrides_not_configured"


def test_override_ignored_below_threshold():
    g = gate()
    ov = override()
    assert g.evaluate(REQUEST, 0.1, now=NOW, override=ov).decision is GateDecision.ALLOW
    assert g.evaluate(REQUEST, 0.9, now=NOW, override=ov).allowed  # nonce wasn't spent


# --- Chronicle integration ------------------------------------------------------


def test_every_decision_is_chronicled():
    chron = Chronicle()
    g = gate(chronicle=chron)
    g.evaluate(REQUEST, 0.1, now=NOW)
    g.evaluate(REQUEST, 0.9, now=NOW)
    g.evaluate(REQUEST, 0.9, now=NOW, override=override())
    g.evaluate(REQUEST, None, now=NOW)
    decisions = [e["data"]["decision"] for e in chron.entries]
    assert decisions == ["ALLOW", "VETO", "ALLOW_WITH_OVERRIDE", "VETO"]
    assert chron.verify().ok


def test_chronicle_failure_turns_allow_into_veto():
    class BrokenChronicle(Chronicle):
        def append(self, *args, **kwargs):
            raise ChronicleError("disk full")

    record = gate(chronicle=BrokenChronicle()).evaluate(REQUEST, 0.1, now=NOW)
    assert record.decision is GateDecision.VETO and record.reason == "chronicle_write_failed:ChronicleError"


# --- Entropy --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("probs", "expected"),
    [([1.0], 0.0), ([1.0, 0.0], 0.0), ([0.5, 0.5], 1.0), ([0.25] * 4, 1.0), ([0.9, 0.1], 0.4689955935892812)],
)
def test_normalized_entropy(probs, expected):
    assert normalized_entropy(probs) == pytest.approx(expected)


@pytest.mark.parametrize("probs", [[], [0.5, 0.4], [1.1, -0.1], [math.nan, 1.0], [True, False]])
def test_normalized_entropy_rejects_non_distributions(probs):
    with pytest.raises(ValueError):
        normalized_entropy(probs)


def test_uniform_distribution_vetoes_and_confident_one_passes():
    g = gate()
    assert g.evaluate(REQUEST, normalized_entropy([0.25] * 4), now=NOW).decision is GateDecision.VETO
    assert g.evaluate(REQUEST, normalized_entropy([0.97, 0.01, 0.01, 0.01]), now=NOW).decision is GateDecision.ALLOW
