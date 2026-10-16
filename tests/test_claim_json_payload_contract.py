"""Security evidence must reject ambiguous and non-JSON claim bodies."""

from __future__ import annotations

import math

import pytest

from nomosguard.ledger import Claim, EvidenceLedger, UnevidencedClaimError


@pytest.mark.parametrize("kind", ["", " ", "\t\n"])
def test_claim_kind_must_not_be_blank(kind: str) -> None:
    with pytest.raises(UnevidencedClaimError, match="claim.kind"):
        EvidenceLedger().append(Claim(kind, {"ok": True}, "source line"))


@pytest.mark.parametrize("payload", [{"value": math.nan}, {"value": math.inf}, {"obj": object()}])
def test_payload_must_be_serializable_finite_json(payload: dict) -> None:
    with pytest.raises(UnevidencedClaimError, match="finite JSON"):
        EvidenceLedger().append(Claim("event", payload, "source line"))


def test_nested_finite_json_is_accepted() -> None:
    ledger = EvidenceLedger()
    ledger.append(Claim("event", {"nested": {"scores": [0.0, 1.0]}}, "source line"))
    assert ledger.verify()[0] is True


@pytest.mark.parametrize(
    "payload",
    [
        {1: "numeric"},
        {1: "numeric", "1": "colliding"},
        {"nested": [{"value": {"inner": {False: "boolean"}}}]},
        {"tuple_values": ({None: "null"},)},
    ],
)
def test_non_string_object_keys_fail_closed(payload: dict) -> None:
    with pytest.raises(UnevidencedClaimError, match="finite JSON"):
        EvidenceLedger().append(Claim("event", payload, "source line"))


def test_nested_string_keys_remain_deterministic() -> None:
    ledger = EvidenceLedger()
    ledger.append(Claim("event", {"nested": [{"1": 1, "false": False}]}, "source line"))
    assert ledger.verify()[0] is True


@pytest.mark.parametrize(
    ("kind", "payload", "evidence", "field"),
    [
        ("\ud800", {"ok": True}, "source", "claim.kind"),
        ("event", {"\ud800": "bad key"}, "source", "finite JSON"),
        ("event", {"nested": ["\udfff"]}, "source", "finite JSON"),
        ("event", {"ok": True}, "source \ud800", "claim.evidence"),
    ],
)
def test_unpaired_surrogates_fail_with_typed_evidence_error(
    kind: str, payload: dict, evidence: str, field: str
) -> None:
    with pytest.raises(UnevidencedClaimError, match=field):
        EvidenceLedger().append(Claim(kind, payload, evidence))


def test_valid_multilingual_utf8_evidence_remains_supported() -> None:
    ledger = EvidenceLedger()
    ledger.append(Claim("olay", {"açıklama": ["Türkçe", "日本語", "😀"]}, "kanıt satırı"))
    assert ledger.verify()[0] is True
