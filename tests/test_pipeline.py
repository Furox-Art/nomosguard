"""Pipeline tests: sample -> vote -> audit(flag) -> ground(remove).

All tests use a mock model — no network, fully deterministic. The
invariants tested here are the ones the measured ablation found:
  - voting removes one-off claims (likely hallucinations)
  - deterministic grounding removes claims with non-verbatim evidence
  - the audit stage FLAGS but never REMOVES (recall safety)
"""

from __future__ import annotations

import json

from nomosguard.benchmark.model_compare.pipeline import (
    run_pipeline, parse_claims, _claim_key,
)

RAW = """[08:14:02] SIEM: 203.0.113.77 -> web01:22, 14 failed SSH then one SUCCESS
[08:15:44] VULNSCAN: web01 has CVE-2026-31142
[08:31:55] IAM: root executed on web01 under user deploy"""


def _claim(kind: str, host: str, evidence: str, **extra) -> dict:
    payload = {"host": host, **extra}
    if kind == "network":
        payload.update({"protocol": "ssh", "port": 22, "allowed_from": "203.0.113.77"})
    elif kind == "vuln_host":
        payload = {"host": host, "cve": "CVE-2026-31142"}
    elif kind == "exec_code":
        payload = {"host": host, "user": "deploy"}
    return {"kind": kind, "payload": payload, "evidence": evidence}


GOOD_EVIDENCE = [
    "[08:14:02] SIEM: 203.0.113.77 -> web01:22, 14 failed SSH then one SUCCESS",
    "[08:15:44] VULNSCAN: web01 has CVE-2026-31142",
    "[08:31:55] IAM: root executed on web01 under user deploy",
]


class TestClaimIdentity:
    def test_same_claim_different_format_same_key(self):
        a = _claim("network", "web01", GOOD_EVIDENCE[0])
        b = _claim("network", " web01 (1.2.3.4) ", GOOD_EVIDENCE[0])
        # normalization strips parentheticals and case
        assert _claim_key(a["kind"], a["payload"]) == _claim_key(b["kind"], b["payload"])

    def test_different_claims_different_keys(self):
        a = _claim("network", "web01", GOOD_EVIDENCE[0])
        b = _claim("network", "db02", GOOD_EVIDENCE[0])
        assert _claim_key(a["kind"], a["payload"]) != _claim_key(b["kind"], b["payload"])


class TestParseClaims:
    def test_parses_plain_json_array(self):
        out = json.dumps([_claim("network", "web01", GOOD_EVIDENCE[0])])
        parsed = parse_claims(out)
        assert parsed is not None and len(parsed) == 1

    def test_parses_from_markdown_fence(self):
        out = "```json\n" + json.dumps([_claim("network", "web01", GOOD_EVIDENCE[0])]) + "\n```"
        parsed = parse_claims(out)
        assert parsed is not None and len(parsed) == 1

    def test_rejects_non_json(self):
        assert parse_claims("I cannot help with that.") is None

    def test_skips_malformed_claims(self):
        out = json.dumps([
            _claim("network", "web01", GOOD_EVIDENCE[0]),
            {"kind": "network"},  # no payload
            "not a dict",
        ])
        parsed = parse_claims(out)
        assert parsed is not None and len(parsed) == 1


class TestPipelineVoting:
    def test_one_off_claim_removed_by_vote(self):
        """A claim appearing in only 1 of 3 draws is dropped."""
        stable = _claim("network", "web01", GOOD_EVIDENCE[0])
        hallucination = _claim("vuln_host", "web03", GOOD_EVIDENCE[1])
        # note: web03 hallucination cites a real line (grounding would not catch it)

        def model(prompt):
            if "verify" in prompt or "suspicious" in prompt:
                return "[]"  # audit: nothing suspicious
            return json.dumps([stable, hallucination])

        calls = {"n": 0}

        def counting_model(prompt):
            calls["n"] += 1
            if calls["n"] == 1:
                return json.dumps([stable, hallucination])
            return json.dumps([stable])

        r = run_pipeline(counting_model, RAW, draws=3, min_votes=2, audit=False)
        assert len(r.claims) == 1
        assert r.claims[0]["payload"]["host"] == "web01"
        assert r.report.get("vote_removed") == 1

    def test_unanimous_claim_survives(self):
        stable = _claim("network", "web01", GOOD_EVIDENCE[0])

        def model(prompt):
            return json.dumps([stable])

        r = run_pipeline(model, RAW, draws=3, min_votes=2, audit=False, ground=False)
        assert len(r.claims) == 1
        assert r.report.get("vote_removed", 0) == 0


class TestPipelineGrounding:
    def test_non_verbatim_evidence_removed(self):
        """A claim whose evidence is NOT in the raw logs is removed —
        this is the deterministic floor."""
        claim = _claim("network", "web01", "this evidence text is fabricated entirely")

        def model(prompt):
            return json.dumps([claim])

        r = run_pipeline(model, RAW, draws=1, min_votes=1, audit=False, ground=True)
        assert r.claims == []
        assert r.report["final_stage"] == "ground"

    def test_verbatim_evidence_survives(self):
        claim = _claim("network", "web01", GOOD_EVIDENCE[0])

        def model(prompt):
            return json.dumps([claim])

        r = run_pipeline(model, RAW, draws=1, min_votes=1, audit=False, ground=True)
        assert len(r.claims) == 1


class TestPipelineAuditFlags:
    def test_audit_flags_but_never_removes(self):
        """The audit stage may mark a claim suspicious, but the claim
        itself must survive — only grounding removes."""
        claim = _claim("network", "web01", GOOD_EVIDENCE[0])

        def model(prompt):
            if "suspicious" in prompt:
                return json.dumps([{"index": 0, "suspicious": True, "reason": "wrong port"}])
            return json.dumps([claim])

        r = run_pipeline(model, RAW, draws=1, min_votes=1, audit=True, ground=True)
        # claim survives audit...
        assert len(r.claims) == 1
        # ...and is flagged
        assert len(r.flagged) == 1
        assert r.report.get("audit_flagged") == 1

    def test_audit_failure_keeps_claims(self):
        """If the audit call fails, claims are kept — recall safe."""
        claim = _claim("network", "web01", GOOD_EVIDENCE[0])

        def model(prompt):
            if "suspicious" in prompt:
                raise RuntimeError("audit call failed")
            return json.dumps([claim])

        r = run_pipeline(model, RAW, draws=1, min_votes=1, audit=True, ground=True)
        assert len(r.claims) == 1
        assert "audit_skipped" in r.report


class TestPipelineDegradation:
    def test_all_draws_fail_returns_empty(self):
        def model(prompt):
            raise RuntimeError("model down")

        r = run_pipeline(model, RAW, draws=3, min_votes=2)
        assert r.claims == []
        assert r.report["sample_errors"] == 3
        assert r.report["final_stage"] == "sample"

    def test_all_draws_unparseable_returns_empty(self):
        def model(prompt):
            return "I refuse."

        r = run_pipeline(model, RAW, draws=2, min_votes=1)
        assert r.claims == []
        assert r.report["parsed_draws"] == 0
