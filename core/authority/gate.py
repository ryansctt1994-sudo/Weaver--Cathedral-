"""Fail-closed uncertainty gate with signed, single-use operator overrides.

Consolidates Delta-717's ``Sentinel`` (an entropy circuit breaker) and
``SovereignGateV2`` (HMAC operator overrides), fixing their defects:

* ``SovereignGateV2(enabled=False)`` returned ALLOW. This gate has no
  disabled mode. Every path that is not an explicit pass is a VETO.
* Delta's override signature covered ``operator_id:reason:timestamp`` with no
  nonce, no freshness window and no binding to the request, so one captured
  override could be reused forever, on any input. Here an override is bound
  to a single request hash, expires, and is consumed through the authority
  spine's replay cache.
* Delta read its HMAC secret from an environment variable that the module
  itself set to a hardcoded value. Here the caller supplies the key, and a
  key shorter than 32 bytes is refused.
* Malformed uncertainty (missing, NaN, infinite, out of range, bool) was
  either an exception or slipped through. Here it is a VETO.

Optionally every decision is appended to a ``Chronicle``. If that append fails,
the decision becomes a VETO: an unrecorded ALLOW is not allowed.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Mapping, Sequence

from .canonical import JCS_RFC8785, canonicalize, profiled_sha256
from .chronicle import Chronicle
from .replay import InMemoryReplayCache

MIN_KEY_BYTES = 32
OVERRIDE_VERSION = "weaver.gate.override.v1"
_OVERRIDE_FIELDS = ("override_version", "operator_id", "reason", "request_hash", "nonce", "issued_at")


class GateDecision(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_OVERRIDE = "ALLOW_WITH_OVERRIDE"
    VETO = "VETO"


@dataclass(frozen=True)
class GateRecord:
    decision: GateDecision
    reason: str
    request_hash: str
    uncertainty: float | None
    threshold: float
    override_operator: str | None = None
    chronicle_index: int | None = None

    @property
    def allowed(self) -> bool:
        return self.decision in (GateDecision.ALLOW, GateDecision.ALLOW_WITH_OVERRIDE)


def normalized_entropy(probabilities: Sequence[float]) -> float:
    """Shannon entropy divided by log2(N), in [0, 1].

    Delta's ``SignalIntegrityMonitor`` without numpy/scipy. Raises
    ``ValueError`` on anything that is not a probability distribution.
    """
    probs = list(probabilities)
    if not probs:
        raise ValueError("empty distribution")
    for p in probs:
        if isinstance(p, bool) or not isinstance(p, (int, float)) or not math.isfinite(p) or p < 0:
            raise ValueError(f"invalid probability {p!r}")
    if not math.isclose(sum(probs), 1.0, rel_tol=0, abs_tol=1e-9):
        raise ValueError("probabilities must sum to 1")
    if len(probs) == 1:
        return 0.0
    h = -sum(p * math.log2(p) for p in probs if p > 0)
    return min(1.0, max(0.0, h / math.log2(len(probs))))


def request_hash(request: Mapping[str, Any]) -> str:
    """The hash an override must name to apply to this request."""
    return profiled_sha256(dict(request), JCS_RFC8785)


def _override_message(override: Mapping[str, Any]) -> bytes:
    return canonicalize({k: override[k] for k in _OVERRIDE_FIELDS}, JCS_RFC8785).encode("utf-8")


def sign_override(
    key: bytes,
    *,
    operator_id: str,
    reason: str,
    request_hash: str,
    nonce: str,
    issued_at: datetime,
) -> dict[str, Any]:
    """Build a signed override. Operator tooling uses this; the gate never does."""
    _check_key(key)
    override = {
        "override_version": OVERRIDE_VERSION,
        "operator_id": operator_id,
        "reason": reason,
        "request_hash": request_hash,
        "nonce": nonce,
        "issued_at": issued_at.astimezone(timezone.utc).isoformat(),
    }
    override["signature"] = hmac.new(key, _override_message(override), hashlib.sha256).hexdigest()
    return override


def _check_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_BYTES:
        raise ValueError(f"override key must be at least {MIN_KEY_BYTES} bytes")


@dataclass
class UncertaintyGate:
    """VETO when uncertainty >= threshold, unless a valid override is presented."""

    threshold: float
    override_key: bytes | None = None
    replay_cache: InMemoryReplayCache = field(default_factory=InMemoryReplayCache)
    chronicle: Chronicle | None = None
    override_max_age: timedelta = timedelta(minutes=5)
    clock_skew: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        if isinstance(self.threshold, bool) or not isinstance(self.threshold, (int, float)) or not 0 < self.threshold < 1:
            raise ValueError("threshold must be a number strictly between 0 and 1")
        if self.override_key is not None:
            _check_key(self.override_key)

    def evaluate(
        self,
        request: Mapping[str, Any],
        uncertainty: Any,
        *,
        now: datetime,
        override: Mapping[str, Any] | None = None,
    ) -> GateRecord:
        try:
            req_hash = request_hash(request)
        except Exception:  # noqa: BLE001 - anything unhashable is a veto
            return self._record(GateRecord(GateDecision.VETO, "request_not_canonicalizable", "", None, self.threshold), now)

        try:
            record = self._decide(req_hash, uncertainty, now, override)
        except Exception as exc:  # noqa: BLE001 - fail closed on any internal error
            record = GateRecord(GateDecision.VETO, f"gate_error:{type(exc).__name__}", req_hash, None, self.threshold)
        return self._record(record, now)

    def _decide(self, req_hash: str, uncertainty: Any, now: datetime, override: Mapping[str, Any] | None) -> GateRecord:
        def veto(reason: str, u: float | None = None) -> GateRecord:
            return GateRecord(GateDecision.VETO, reason, req_hash, u, self.threshold)

        if uncertainty is None:
            return veto("uncertainty_missing")
        if isinstance(uncertainty, bool) or not isinstance(uncertainty, (int, float)):
            return veto("uncertainty_not_a_number")
        u = float(uncertainty)
        if not math.isfinite(u) or not 0.0 <= u <= 1.0:
            return veto("uncertainty_out_of_range")

        if u < self.threshold:
            return GateRecord(GateDecision.ALLOW, "below_threshold", req_hash, u, self.threshold)

        if override is None:
            return veto("above_threshold", u)
        problem = self._override_problem(override, req_hash, now)
        if problem:
            return veto(f"override_rejected:{problem}", u)
        return GateRecord(
            GateDecision.ALLOW_WITH_OVERRIDE, "operator_override", req_hash, u, self.threshold,
            override_operator=str(override["operator_id"]),
        )

    def _override_problem(self, override: Mapping[str, Any], req_hash: str, now: datetime) -> str | None:
        if self.override_key is None:
            return "overrides_not_configured"
        if not isinstance(override, Mapping) or set(override) != set(_OVERRIDE_FIELDS) | {"signature"}:
            return "malformed"
        if any(not isinstance(override[k], str) or not override[k] for k in (*_OVERRIDE_FIELDS, "signature")):
            return "malformed"
        if override["override_version"] != OVERRIDE_VERSION:
            return "unknown_version"
        # Signature first: an unauthenticated override must not burn a nonce.
        expected = hmac.new(self.override_key, _override_message(override), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, override["signature"]):
            return "bad_signature"
        if override["request_hash"] != req_hash:
            return "wrong_request"
        try:
            issued = datetime.fromisoformat(override["issued_at"])
        except ValueError:
            return "bad_timestamp"
        if issued.tzinfo is None:
            return "bad_timestamp"
        if issued - now > self.clock_skew:
            return "issued_in_future"
        if now - issued > self.override_max_age:
            return "expired"
        if not self.replay_cache.check_and_store(f"gate-override:{override['nonce']}"):
            return "replayed"
        return None

    def _record(self, record: GateRecord, now: datetime) -> GateRecord:
        if self.chronicle is None:
            return record
        data = {
            "decision": record.decision.value,
            "reason": record.reason,
            "request_hash": record.request_hash,
            "uncertainty": record.uncertainty,
            "threshold": self.threshold,
            "override_operator": record.override_operator,
        }
        try:
            entry = self.chronicle.append("gate.decision", data, recorded_at=now)
        except Exception as exc:  # noqa: BLE001 - an unrecorded allow is not allowed
            return GateRecord(GateDecision.VETO, f"chronicle_write_failed:{type(exc).__name__}", record.request_hash, record.uncertainty, self.threshold)
        return GateRecord(
            record.decision, record.reason, record.request_hash, record.uncertainty, self.threshold,
            record.override_operator, entry["index"],
        )
