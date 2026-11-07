"""Receipt v2: the hash profile is recorded in the receipt and bound into its hash."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.authority.canonical import JCS_RFC8785, WEAVER_C14N_V1, ZOREL_ASCII_V1
from core.authority.models import AuthorityEnvelope, Receipt
from core.authority.receipts import RECEIPT_V1, RECEIPT_V2, generate_receipt, verify_receipt

FIXED_AT = datetime(2026, 7, 8, tzinfo=timezone.utc)
# Cross-checked outside Python: Node re-canonicalized the hash base and
# sha256sum produced the same digest.
GOLDEN_V2_ACCEPT = "beee972e6fe3b4badf53561a3af7931cee3482a55ce8861863811939b3d13344"
GOLDEN_V2_REJECT = "8b1a667261a88242bbb53206dbb713f56a2509a3f0ac25fe873c48b809d91e1a"


def _envelope() -> AuthorityEnvelope:
    return AuthorityEnvelope.model_validate(json.loads(Path("core/authority/fixtures/valid_envelope.json").read_text()))


def _receipt(**kwargs) -> Receipt:
    kwargs.setdefault("accepted", True)
    kwargs.setdefault("reason", "golden_accept")
    return generate_receipt(_envelope(), created_at=FIXED_AT, **kwargs)


def test_new_receipts_default_to_v2_under_jcs():
    r = _receipt()
    assert r.receipt_version == RECEIPT_V2 and r.hash_profile == JCS_RFC8785
    assert r.receipt_hash == GOLDEN_V2_ACCEPT
    assert _receipt(accepted=False, reason="golden_reject").receipt_hash == GOLDEN_V2_REJECT


@pytest.mark.parametrize("profile", [JCS_RFC8785, WEAVER_C14N_V1, ZOREL_ASCII_V1])
def test_v2_verifies_under_each_profile(profile):
    assert verify_receipt(_receipt(hash_profile=profile))


def test_v1_still_generates_and_verifies():
    r = _receipt(receipt_version=RECEIPT_V1)
    assert r.hash_profile is None and verify_receipt(r)


def test_swapping_the_profile_breaks_verification():
    r = _receipt()
    assert not verify_receipt(r.model_copy(update={"hash_profile": WEAVER_C14N_V1}))


def test_downgrading_v2_to_v1_breaks_verification():
    r = _receipt()
    assert not verify_receipt(r.model_copy(update={"receipt_version": RECEIPT_V1}))
    assert not verify_receipt(r.model_copy(update={"receipt_version": RECEIPT_V1, "hash_profile": None}))


def test_v1_with_a_profile_attached_is_rejected():
    r = _receipt(receipt_version=RECEIPT_V1)
    assert not verify_receipt(r.model_copy(update={"hash_profile": JCS_RFC8785}))


@pytest.mark.parametrize("field,value", [("reason", "edited"), ("accepted", False), ("subject", "other"), ("payload_hash", "f" * 64)])
def test_any_field_edit_breaks_v2_verification(field, value):
    assert not verify_receipt(_receipt().model_copy(update={field: value}))


def test_unknown_profile_or_version_is_refused():
    with pytest.raises(ValueError):
        _receipt(hash_profile="made.up.v9")
    with pytest.raises(ValueError):
        _receipt(receipt_version="weaver.authority.receipt.v9")
    assert not verify_receipt(_receipt().model_copy(update={"hash_profile": "made.up.v9"}))


def test_v2_round_trips_through_json():
    r = _receipt()
    again = Receipt.model_validate_json(r.model_dump_json())
    assert verify_receipt(again) and again.receipt_hash == r.receipt_hash
