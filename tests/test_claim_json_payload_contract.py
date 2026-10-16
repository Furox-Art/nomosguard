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
