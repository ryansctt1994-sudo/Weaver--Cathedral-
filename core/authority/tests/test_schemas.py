"""The JSON schemas in core/authority/schemas/ must agree with the models.

Nothing used the schemas before, so they could drift from what the code
emits without anyone noticing. Each check runs both ways: real output must
validate, and known-bad documents must not.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from core.authority.models import AuthorityEnvelope
from core.authority.receipts import RECEIPT_V1, generate_receipt
from core.authority.verifier import evaluate_promotion

SCHEMAS = Path("core/authority/schemas")
FIXTURES = Path("core/authority/fixtures")


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMAS / name).read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _errors(validator: Draft202012Validator, doc: dict) -> list[str]:
    return [e.message for e in validator.iter_errors(doc)]


@pytest.mark.parametrize("name", ["envelope.json", "receipt.json", "promotion.json"])
def test_schema_is_valid_draft_2020_12(name):
    _validator(name)


@pytest.mark.parametrize("fixture", ["valid_envelope.json", "bad_hash_envelope.json"])
def test_fixtures_match_envelope_schema_and_model(fixture):
    raw = json.loads((FIXTURES / fixture).read_text())
    assert _errors(_validator("envelope.json"), raw) == []
    AuthorityEnvelope.model_validate(raw)


@pytest.mark.parametrize("version", [RECEIPT_V1, "weaver.authority.receipt.v2"])
@pytest.mark.parametrize("accepted", [True, False])
def test_generated_receipts_match_schema(version, accepted):
    env = AuthorityEnvelope.model_validate(json.loads((FIXTURES / "valid_envelope.json").read_text()))
    r = generate_receipt(env, accepted=accepted, reason="schema", created_at=datetime(2026, 7, 8, tzinfo=timezone.utc), receipt_version=version)
    assert _errors(_validator("receipt.json"), json.loads(r.model_dump_json())) == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("hash_profile"),
        lambda d: d.update(hash_profile=None),
        lambda d: d.update(hash_profile="made.up.v9"),
        lambda d: d.update(receipt_version="weaver.authority.receipt.v9"),
        lambda d: d.update(receipt_hash="XYZ"),
        lambda d: d.update(extra="field"),
    ],
    ids=["v2-missing-profile", "v2-null-profile", "v2-unknown-profile", "unknown-version", "bad-hash", "extra-field"],
)
def test_receipt_schema_rejects_bad_documents(mutate):
    env = AuthorityEnvelope.model_validate(json.loads((FIXTURES / "valid_envelope.json").read_text()))
    doc = json.loads(generate_receipt(env, accepted=True, reason="schema", created_at=datetime(2026, 7, 8, tzinfo=timezone.utc)).model_dump_json())
    mutate(doc)
    assert _errors(_validator("receipt.json"), doc)


def test_v1_receipt_with_profile_is_rejected_by_schema():
    env = AuthorityEnvelope.model_validate(json.loads((FIXTURES / "valid_envelope.json").read_text()))
    doc = json.loads(generate_receipt(env, accepted=True, reason="s", created_at=datetime(2026, 7, 8, tzinfo=timezone.utc), receipt_version=RECEIPT_V1).model_dump_json())
    doc["hash_profile"] = "jcs.rfc8785"
    assert _errors(_validator("receipt.json"), doc)


@pytest.mark.parametrize(
    ("level", "evidence"),
    [("E1", ["declared_claim", "file_scaffold", "risk_boundary"]), ("E2", ["local_tests"]), ("E9", [])],
)
def test_promotion_decisions_match_schema(level, evidence):
    decision = evaluate_promotion("artifact-1", level, evidence)
    assert _errors(_validator("promotion.json"), json.loads(decision.model_dump_json())) == []


def test_envelope_schema_and_model_agree_on_rejections():
    raw = json.loads((FIXTURES / "valid_envelope.json").read_text())
    for bad in ({**raw, "nonce": "short"}, {**raw, "evidence_level": "E7"}, {**raw, "extra": 1}, {k: v for k, v in raw.items() if k != "claim"}):
        assert _errors(_validator("envelope.json"), bad), bad
        with pytest.raises(Exception):
            AuthorityEnvelope.model_validate(bad)
