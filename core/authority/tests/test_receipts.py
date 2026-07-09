from datetime import datetime, timezone
import json
from pathlib import Path

from core.authority.models import AuthorityEnvelope
from core.authority.receipts import generate_receipt, payload_hash, verify_receipt


def test_payload_hash_is_deterministic():
    a = {"b": 2, "a": 1}
    b = {"a": 1, "b": 2}
    assert payload_hash(a) == payload_hash(b)


def test_receipt_verifies_against_own_hash():
    raw = json.loads(Path("core/authority/fixtures/valid_envelope.json").read_text())
    envelope = AuthorityEnvelope.model_validate(raw)
    receipt = generate_receipt(
        envelope,
        accepted=True,
        reason="test",
        created_at=datetime(2026, 7, 8, tzinfo=timezone.utc),
    )
    assert verify_receipt(receipt)
