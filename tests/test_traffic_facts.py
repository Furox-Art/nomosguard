"""Traffic claim extractors: facts, refusals, and derived silence."""

from __future__ import annotations

import pytest

from nomosguard.constants import (
    CLAIM_KIND_TRAFFIC_REQUEST,
    CLAIM_KIND_TRAFFIC_SESSION,
)
from nomosguard.facts_traffic import (
    _extract_traffic_request,
    _extract_traffic_session,
)
from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.rules import ClaimValueError, RuleEngine


def valid_payload(**overrides):
    payload = {
        "method": "POST",
        "host": "api.anthropic.com",
        "path": "/v1/messages",
        "class": "prompt",
        "payload_sha256": "a" * 64,
        "detected_paths": ["/home/me/x"],
        "detected_urls": ["https://api.anthropic.com/v1/messages"],
        "env_vars": ["API_KEY"],
        "secret_hits": [],
    }
    payload.update(overrides)
    return payload


class TestRequestExtraction:
    def test_request_facts(self):
        facts = _extract_traffic_request(valid_payload(), "e")
        assert [(f.subject, f.relation, f.object) for f in facts] == [
            ("api.anthropic.com", "requestClass", "prompt")
        ]
        assert facts[0].sources == (CLAIM_KIND_TRAFFIC_REQUEST,)

    def test_secret_hits_become_exposure_facts_once_per_name(self):
        payload = valid_payload(
            secret_hits=[
                {"name": "github-token", "masked": "ghp_…1234"},
                {"name": "github-token", "masked": "ghp_…5678"},
                {"name": "openai-key", "masked": "sk-a…uvwx"},
            ]
        )
        facts = _extract_traffic_request(payload, "e")
        relations = [(f.relation, f.object) for f in facts]
        assert ("secretExposure", "github-token") in relations
        assert ("secretExposure", "openai-key") in relations
        assert sum(1 for relation, _ in relations if relation == "secretExposure") == 2

    def test_missing_host_yields_no_facts(self):
        payload = valid_payload()
        payload.pop("host")
        assert _extract_traffic_request(payload, "e") == []

    def test_null_secret_hits_are_accepted_as_empty(self):
        facts = _extract_traffic_request(valid_payload(secret_hits=None), "e")
        assert facts[0].relation == "requestClass"

    def test_missing_class_is_refused(self):
        payload = valid_payload()
        payload.pop("class")
        with pytest.raises(ClaimValueError, match="'class' is required"):
            _extract_traffic_request(payload, "e")

    def test_unknown_class_is_refused(self):
        with pytest.raises(ClaimValueError, match="unknown traffic class"):
            _extract_traffic_request(valid_payload(**{"class": "sneaky"}), "e")

    @pytest.mark.parametrize("field", ["host", "method", "path"])
    def test_non_string_text_fields_are_refused(self, field):
        with pytest.raises(ClaimValueError, match=f"field {field!r} must be a string"):
            _extract_traffic_request(valid_payload(**{field: 42}), "e")

    def test_bad_sha256_is_refused(self):
        with pytest.raises(ClaimValueError, match="lowercase SHA-256"):
            _extract_traffic_request(valid_payload(payload_sha256="ABC"), "e")
        with pytest.raises(ClaimValueError, match="lowercase SHA-256"):
            _extract_traffic_request(valid_payload(payload_sha256="G" * 64), "e")

    @pytest.mark.parametrize("field", ["detected_paths", "detected_urls", "env_vars"])
    def test_detection_lists_must_be_string_lists(self, field):
        with pytest.raises(ClaimValueError, match=f"field {field!r} must be a list of strings"):
            _extract_traffic_request(valid_payload(**{field: [1]}), "e")

    def test_null_detection_list_is_empty(self):
        facts = _extract_traffic_request(valid_payload(detected_paths=None), "e")
        assert len(facts) == 1

    def test_secret_hits_must_be_a_list(self):
        with pytest.raises(ClaimValueError, match="'secret_hits' must be a list"):
            _extract_traffic_request(valid_payload(secret_hits={}), "e")

    def test_each_secret_hit_must_be_an_object(self):
        with pytest.raises(ClaimValueError, match="each secret hit must be an object"):
            _extract_traffic_request(valid_payload(secret_hits=["nope"]), "e")

    @pytest.mark.parametrize(
        "hit",
        [
            {"name": "", "masked": "x"},
            {"name": "k", "masked": ""},
            {"name": 1, "masked": "x"},
            {"name": "k"},
        ],
    )
    def test_secret_hit_requires_name_and_masked(self, hit):
        with pytest.raises(ClaimValueError, match="non-empty 'name' and 'masked'"):
            _extract_traffic_request(valid_payload(secret_hits=[hit]), "e")


class TestSessionExtraction:
    def test_session_facts(self):
        facts = _extract_traffic_session({"session_id": "s-1", "requests": 3}, "e")
        assert [(f.subject, f.relation, f.object) for f in facts] == [
            ("s-1", "requestCount", "3")
        ]

    def test_zero_requests_derives_silence(self):
        facts = _extract_traffic_session({"session_id": "s-1", "requests": 0}, "e")
        assert [(f.relation, f.object) for f in facts] == [
            ("requestCount", "0"),
            ("trafficSilent", "true"),
        ]

    def test_missing_session_id_yields_no_facts(self):
        assert _extract_traffic_session({"requests": 1}, "e") == []

    def test_missing_requests_yields_no_facts(self):
        assert _extract_traffic_session({"session_id": "s"}, "e") == []

    @pytest.mark.parametrize("value", [True, -1, "2", 1.5])
    def test_invalid_requests_count_is_refused(self, value):
        with pytest.raises(ClaimValueError, match="non-negative integer"):
            _extract_traffic_session({"session_id": "s", "requests": value}, "e")

    def test_non_string_session_id_is_refused(self):
        with pytest.raises(ClaimValueError, match="must be a string"):
            _extract_traffic_session({"session_id": 7, "requests": 1}, "e")


class TestLedgerIntegration:
    def test_ledger_claims_become_engine_facts(self):
        ledger = EvidenceLedger()
        ledger.append(
            Claim(
                CLAIM_KIND_TRAFFIC_REQUEST,
                valid_payload(secret_hits=[{"name": "github-token", "masked": "ghp_…1234"}]),
                "observed",
            )
        )
        ledger.append(
            Claim(CLAIM_KIND_TRAFFIC_SESSION, {"session_id": "s-1", "requests": 0}, "closed")
        )
        engine = RuleEngine(rules=[])
        engine.add_facts_from_ledger(ledger)
        assert ("api.anthropic.com", "requestClass", "prompt") in {
            f.key for f in engine.facts
        }
        assert ("api.anthropic.com", "secretExposure", "github-token") in {
            f.key for f in engine.facts
        }
        assert ("s-1", "trafficSilent", "true") in {f.key for f in engine.facts}
        assert engine.unknown_claim_kinds == {}

    def test_transcript_derivation_fires(self):
        from nomosguard.constants import traffic_rules

        ledger = EvidenceLedger()
        ledger.append(
            Claim(
                CLAIM_KIND_TRAFFIC_REQUEST,
                valid_payload(**{"class": "transcript-upload"}),
                "observed transcript upload",
            )
        )
        engine = RuleEngine(rules=traffic_rules())
        engine.add_facts_from_ledger(ledger)
        summary = engine.derive()
        assert ("api.anthropic.com", "transcriptLeak", "true") in {
            f.key for f in engine.facts
        }
        assert summary["rules_fired"] == {"transcript_upload_leaks_transcript": 1}
