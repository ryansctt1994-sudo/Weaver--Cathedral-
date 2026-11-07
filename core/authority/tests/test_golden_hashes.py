"""Golden-hash tests for the authority spine's canonical serialization.

If any of these values change, every receipt produced so far stops
verifying. Changing them must be a deliberate, ledgered decision, not a
side effect of a refactor.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.authority.canonical import ZOREL_ASCII_V1, verify_profiled_sha256
from core.authority.models import AuthorityEnvelope
from core.authority.receipts import canonical_json, generate_receipt, payload_hash, sha256_json

FIXTURES = Path("core/authority/fixtures")
FIXED_AT = datetime(2026, 7, 8, tzinfo=timezone.utc)

GOLDEN_VALID_PAYLOAD_HASH = "3e9b2706e1be52aa8875e65756de96f2ccf6b2b45c90fed6f96afeb18069c293"
GOLDEN_ACCEPT_RECEIPT_HASH = "236a13bccbe1dc63ccf239e1acbaa5cfb0536df1afebc20dd91f5fe1dc0a1593"
GOLDEN_REJECT_RECEIPT_HASH = "6bfc180d3a1ff769086997023a7a2ce3d5112abe6c4a6606b28cd1502cc823f0"

ZOREL_BODY = FIXTURES / "external" / "zorel_authorship_receipt_body.json"
ZOREL_SEALED_HASH = "33f78bde8ba348bd24d291e8b871684e85f83a2687dae393a3a86079acdfe9f5"


def _valid_envelope() -> AuthorityEnvelope:
    raw = json.loads((FIXTURES / "valid_envelope.json").read_text(encoding="utf-8"))
    return AuthorityEnvelope.model_validate(raw)


def test_valid_fixture_payload_hash_is_golden():
    raw = json.loads((FIXTURES / "valid_envelope.json").read_text(encoding="utf-8"))
    assert payload_hash(raw["payload"]) == GOLDEN_VALID_PAYLOAD_HASH == raw["payload_hash"]


@pytest.mark.parametrize(
    ("accepted", "reason", "expected"),
    [
        (True, "golden_accept", GOLDEN_ACCEPT_RECEIPT_HASH),
        (False, "golden_reject", GOLDEN_REJECT_RECEIPT_HASH),
    ],
)
def test_receipt_hash_is_golden(accepted, reason, expected):
    receipt = generate_receipt(_valid_envelope(), accepted=accepted, reason=reason, created_at=FIXED_AT)
    assert receipt.receipt_hash == expected


def test_receipt_hash_depends_on_instant_not_timezone_spelling():
    plus_five = timezone(timedelta(hours=5))
    same_instant = FIXED_AT.astimezone(plus_five)
    a = generate_receipt(_valid_envelope(), accepted=True, reason="golden_accept", created_at=FIXED_AT)
    b = generate_receipt(_valid_envelope(), accepted=True, reason="golden_accept", created_at=same_instant)
    assert a.receipt_hash == b.receipt_hash == GOLDEN_ACCEPT_RECEIPT_HASH


@pytest.mark.parametrize("field", ["accepted", "reason", "created_at"])
def test_each_receipt_field_is_bound_into_hash(field):
    kwargs = {"accepted": True, "reason": "golden_accept", "created_at": FIXED_AT}
    kwargs[field] = {
        "accepted": False,
        "reason": "golden_accept ",
        "created_at": FIXED_AT + timedelta(microseconds=1),
    }[field]
    receipt = generate_receipt(_valid_envelope(), **kwargs)
    assert receipt.receipt_hash != GOLDEN_ACCEPT_RECEIPT_HASH


@pytest.mark.parametrize("seed", ["0", "1", "4242"])
def test_hashes_are_independent_of_hash_seed(seed):
    code = (
        "import json,sys;from datetime import datetime,timezone;"
        "from core.authority.models import AuthorityEnvelope;"
        "from core.authority.receipts import generate_receipt;"
        "e=AuthorityEnvelope.model_validate(json.load(open('core/authority/fixtures/valid_envelope.json')));"
        "r=generate_receipt(e,accepted=True,reason='golden_accept',created_at=datetime(2026,7,8,tzinfo=timezone.utc));"
        "sys.stdout.write(r.receipt_hash)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        env={"PYTHONHASHSEED": seed, "PYTHONPATH": "."},
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout == GOLDEN_ACCEPT_RECEIPT_HASH


def test_canonical_json_keeps_non_ascii_as_utf8():
    # Pins current behaviour: Cathedral hashes UTF-8, not \\u escapes.
    assert canonical_json({"invariant": "CAPABILITY ≠ AUTHORITY"}) == '{"invariant":"CAPABILITY ≠ AUTHORITY"}'


# --- Cross-repo: zorel-kernel's sealed authorship receipt -------------------
#
# Zorel hashes json.dumps(sort_keys=True, separators=(",", ":")) with the
# default ensure_ascii=True. Cathedral's canonical_json uses ensure_ascii=False.
# The receipt contains non-ASCII text (e.g. "≠"), so the two serializers
# disagree. GAP-013 resolves this with named hash profiles
# (core/authority/canonical.py): a hash is verified under the profile it was
# made with, and new formats use RFC 8785 JCS.


def _zorel_body() -> dict:
    return json.loads(ZOREL_BODY.read_text(encoding="utf-8"))


def test_zorel_sealed_hash_reproduces_under_its_declared_profile():
    canonical = json.dumps(_zorel_body(), sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == ZOREL_SEALED_HASH


def test_cathedral_verifies_zorel_receipt_under_its_declared_profile():
    assert verify_profiled_sha256(_zorel_body(), ZOREL_SEALED_HASH, ZOREL_ASCII_V1)


def test_legacy_receipt_serializer_still_differs_from_zorel():
    # Receipts v1 keep weaver.c14n.v1 so existing receipt hashes stay valid.
    assert sha256_json(_zorel_body()) != ZOREL_SEALED_HASH
