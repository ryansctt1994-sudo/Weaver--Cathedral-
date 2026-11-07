"""Tests for the hash-profile registry and the RFC 8785 (JCS) serializer.

Non-ASCII test strings are built with chr() so the source file stays ASCII
and the expected bytes are unambiguous.
"""

from __future__ import annotations

import json
import math
import random
import shutil
import struct
import subprocess

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from core.authority.canonical import (
    DEFAULT_PROFILE,
    JCS_RFC8785,
    PROFILES,
    WEAVER_C14N_V1,
    ZOREL_ASCII_V1,
    CanonicalizationError,
    canonicalize,
    profiled_sha256,
    verify_profiled_sha256,
)
from core.authority.receipts import canonical_json

BS, Q = chr(92), chr(34)


def test_default_profile_for_new_formats_is_jcs():
    assert DEFAULT_PROFILE == JCS_RFC8785
    assert set(PROFILES) == {WEAVER_C14N_V1, ZOREL_ASCII_V1, JCS_RFC8785}


def test_weaver_profile_is_exactly_the_legacy_receipt_serializer():
    value = {"b": [1, "x", None], "a": "CAPABILITY " + chr(0x2260) + " AUTHORITY"}
    assert canonicalize(value, WEAVER_C14N_V1) == canonical_json(value)


def test_zorel_profile_escapes_non_ascii():
    assert canonicalize({"k": chr(0x2260)}, ZOREL_ASCII_V1) == '{"k":"' + BS + 'u2260"}'


def test_unknown_profile_is_refused_and_verification_fails_closed():
    with pytest.raises(CanonicalizationError):
        canonicalize({}, "made.up.v9")
    assert verify_profiled_sha256({}, profiled_sha256({}), "made.up.v9") is False


# --- RFC 8785 test vectors --------------------------------------------------


def test_rfc8785_section_3_2_2_example():
    string = chr(0x20AC) + "$" + chr(0x0F) + chr(0x0A) + "A'B" + Q + BS + BS + Q + "/"
    value = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
        "string": string,
        "literals": [None, True, False],
    }
    expected = (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"'
        + chr(0x20AC) + "$" + BS + "u000f" + BS + "nA'B" + BS + Q + BS + BS + BS + BS + BS + Q + '/"}'
    )
    assert canonicalize(value, JCS_RFC8785) == expected


def test_rfc8785_section_3_2_3_key_sorting_uses_utf16_code_units():
    value = {
        chr(0x20AC): "Euro Sign",
        chr(0x0D): "Carriage Return",
        chr(0xFB33): "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        chr(0x1F600): "Emoji: Grinning Face",
        chr(0x80): "Control",
        chr(0xF6): "Latin Small Letter O With Diaeresis",
    }
    order = list(json.loads(canonicalize(value, JCS_RFC8785)).values())
    assert order == [
        "Carriage Return", "One", "Control", "Latin Small Letter O With Diaeresis",
        "Euro Sign", "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh",
    ]
    # Python's code-point sort puts the emoji last; this is where the legacy
    # weaver profile and JCS really disagree.
    assert list(json.loads(canonicalize(value, WEAVER_C14N_V1)).values())[-1] == "Emoji: Grinning Face"


@pytest.mark.parametrize(
    ("number", "expected"),
    [
        (0.0, "0"), (-0.0, "0"), (1.0, "1"), (-1.5, "-1.5"), (100.0, "100"),
        (1e21, "1e+21"), (1e20, "100000000000000000000"), (1e-6, "0.000001"), (1e-7, "1e-7"),
        (123e-20, "1.23e-18"), (5e-324, "5e-324"), (1.7976931348623157e308, "1.7976931348623157e+308"),
        (9007199254740991, "9007199254740991"), (-9007199254740991, "-9007199254740991"),
        (295147905179352830000.0, "295147905179352830000"),
        (2**53, "9007199254740992"), (64211661142045540, "64211661142045540"), (2.0**64, "18446744073709552000"),
    ],
)
def test_jcs_number_formatting(number, expected):
    assert canonicalize(number, JCS_RFC8785) == expected


@pytest.mark.parametrize(
    "bad",
    [math.nan, math.inf, -math.inf, 2**53 + 1, -(2**53 + 1), 2**64, 10**400, {1: "x"}, {"k": object()}, b"bytes", chr(0xD800)],
)
def test_jcs_refuses_values_it_cannot_represent_faithfully(bad):
    with pytest.raises(CanonicalizationError):
        canonicalize(bad, JCS_RFC8785)


def test_jcs_escapes_only_what_rfc8785_requires():
    controls = "".join(chr(c) for c in range(0x20))
    out = canonicalize(controls + chr(0x7F) + chr(0x2028) + "/", JCS_RFC8785)
    assert out.startswith(Q + BS + "u0000" + BS + "u0001")
    assert BS + "b" in out and BS + "t" in out and BS + "n" in out and BS + "f" in out and BS + "r" in out
    assert out.endswith(chr(0x7F) + chr(0x2028) + "/" + Q)  # DEL, U+2028 and '/' stay literal


def test_jcs_bool_is_not_treated_as_int():
    assert canonicalize([True, 1, False, 0], JCS_RFC8785) == "[true,1,false,0]"


# --- Properties ---------------------------------------------------------------

json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=6), children, max_size=4),
    max_leaves=20,
)


@settings(max_examples=300, deadline=None)
@given(json_values)
def test_jcs_output_is_valid_json_that_round_trips(value):
    out = canonicalize(value, JCS_RFC8785)
    reparsed = json.loads(out)
    assert canonicalize(reparsed, JCS_RFC8785) == out  # idempotent


@settings(max_examples=300, deadline=None)
@given(st.dictionaries(st.text(max_size=6), json_values, max_size=6), st.randoms())
def test_jcs_hash_ignores_key_insertion_order(value, rnd):
    items = list(value.items())
    rnd.shuffle(items)
    assert profiled_sha256(dict(items), JCS_RFC8785) == profiled_sha256(value, JCS_RFC8785)


# --- Independent implementation: ECMAScript (JCS number rules are defined by it)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_jcs_numbers_match_ecmascript_on_random_doubles():
    rng = random.Random(8785)
    values = []
    while len(values) < 5000:
        x = struct.unpack("<d", rng.getrandbits(64).to_bytes(8, "little"))[0]
        if math.isfinite(x):
            values.append(x)
    script = "const v=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(v.map(r=>JSON.stringify(Number(r)))))"
    out = subprocess.run(
        ["node", "-e", script], input=json.dumps([repr(x) for x in values]), capture_output=True, text=True, check=True
    )
    ecmascript = json.loads(out.stdout)
    mismatches = [(repr(x), js) for x, js in zip(values, ecmascript) if canonicalize(x, JCS_RFC8785) != js]
    assert not mismatches, mismatches[:5]
