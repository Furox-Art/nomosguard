"""Signature matching: Sigma-style, deterministic, model-free.

These tests lock down the contract of the signature layer:

1. every built-in signature has a positive line (it fires) and a
   negative line (it does not) — a signature that never fires is dead
   weight, one that always fires is noise, and both are bugs;
2. matching is deterministic: same input twice -> same result;
3. every claim cites the exact line it matched;
4. signature claims become engine facts;
5. the new security rule and policy rule fire end-to-end for a critical
   signature plus reachability — and do NOT fire without reachability;
6. an unknown signature id in a claim does not crash the extractor.

Run: PYTHONPATH=src python3 -m pytest tests/test_signatures.py -q
"""

from __future__ import annotations

import pytest

from nomosguard.signatures import (
    Match,
    Signature,
    SignatureError,
    match_all,
    match_signature,
    validate_signatures,
)
from nomosguard.signatures_builtin import builtin_signatures
from nomosguard.signature_bridge import (
    claim_kind,
    run_signatures_into_ledger,
    signature_claims,
    subject_of,
)
from nomosguard import signature_bridge  # noqa: F401 — register extractors
from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.rules import RuleEngine
from nomosguard.rules_security import security_rules
from nomosguard.gate import Decision, PolicyGate
from nomosguard.policy_security import containment_policy_rules
from nomosguard import facts_security  # noqa: F401 — register extractors


# -- per-signature positive / negative lines --------------------------------
#
# One entry per built-in signature. A signature missing from this table
# fails the coverage test below; a signature whose line does not fire
# (or whose negative line does) fails the table-driven test. This is the
# "every signature must be tested against at least one POSITIVE line and
# one NEGATIVE line" rule, enforced mechanically.

CASES: dict[str, tuple[str, str]] = {
    "NG-0001": (
        "[08:14:01] auth: src=203.0.113.77:1234 failed password for admin",
        "[08:14:01] auth: src=203.0.113.77:1234 accepted password for admin",
    ),
    "NG-0002": (
        "[08:14:31] auth: src=203.0.113.77:1234 accepted password for admin",
        "[08:14:31] auth: src=203.0.113.77:1234 failed password for admin",
    ),
    "NG-0003": (
        "2026-10-09T03:11:00 proc: powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
        "2026-10-09T03:11:00 proc: powershell.exe -File C:\\Users\\deploy\\run.ps1",
    ),
    "NG-0004": (
        'proxy: GET /admin HTTP/1.1 user-agent="sqlmap/1.7.2#stable" src=198.51.100.9',
        'proxy: GET /index.html HTTP/1.1 user-agent="Mozilla/5.0 (X11; Linux x86_64)" src=198.51.100.9',
    ),
    "NG-0005": (
        "netflow: src=10.0.0.5 dst=93.184.216.34:443 proto=tcp dbytes=1250000",
        "netflow: src=10.0.0.5 dst=10.0.0.9:22 proto=tcp dbytes=1250000",
    ),
    "NG-0006": (
        "iam: event=grant user=svc-backup privilege=administrator host=web01",
        "iam: event=grant user=svc-backup privilege=read-only host=web01",
    ),
    "NG-0007": (
        "firewall: action=deny src=203.0.113.77:5352 dst=10.0.0.5:22 proto=tcp",
        "firewall: action=allow src=203.0.113.77:5352 dst=10.0.0.5:22 proto=tcp",
    ),
    "NG-0008": (
        "auth: summary src=203.0.113.77: 7 failed authentication attempts in 60s",
        "auth: summary src=203.0.113.77: 2 failed authentication attempts in 60s",
    ),
    "NG-0009": (
        "windows: event=service installed name=UpdaterSvc path=C:\\Windows\\Temp\\upd.exe",
        "windows: event=logon user=deploy host=web01",
    ),
    "NG-0010": (
        "proc: httpd spawned /bin/sh -c /tmp/x",
        "proc: nginx spawned worker process 4242",
    ),
    "NG-0011": (
        "file: created C:\\Users\\Public\\_readme.txt size=4210 user=deploy",
        "file: created /var/www/docs/readme.txt size=4210 user=deploy",
    ),
    "NG-0012": (
        "process: exec C:\\Users\\deploy\\mimikatz.exe by deploy on web01",
        "process: exec C:\\Users\\deploy\\deploy.exe by deploy on web01",
    ),
}


class TestSignatureSchema:
    def test_builtin_set_validates(self):
        sigs = builtin_signatures()
        validate_signatures(sigs)  # raises on any malformed signature
        assert sigs  # non-empty

    def test_builtin_ids_are_stable_and_ordered(self):
        sigs = builtin_signatures()
        ids = [s.id for s in sigs]
        assert ids == [f"NG-{i:04d}" for i in range(1, len(sigs) + 1)]
        assert len(set(ids)) == len(ids)

    def test_signature_is_frozen(self):
        sig = builtin_signatures()[0]
        with pytest.raises(Exception):
            sig.level = "critical"  # type: ignore[misc]

    def test_invalid_level_rejected(self):
        with pytest.raises(SignatureError):
            Signature(id="NG-T1", title="t", level="apocalyptic").validate()

    def test_invalid_regex_rejected_at_validate(self):
        with pytest.raises(SignatureError):
            Signature(
                id="NG-T2",
                title="t",
                detection=(("auth", "failed("),),  # unbalanced group
            ).validate()

    def test_duplicate_id_rejected(self):
        sig = builtin_signatures()[0]
        with pytest.raises(SignatureError):
            validate_signatures([sig, sig])

    def test_empty_detection_rejected_by_validate(self):
        with pytest.raises(SignatureError):
            validate_signatures([Signature(id="NG-T3", title="t")])


class TestMatchSignature:
    def test_positive_and_negative_for_every_builtin(self):
        """THE coverage rule: each built-in signature fires on its
        positive line and stays silent on its negative line."""
        sigs = {s.id: s for s in builtin_signatures()}
        assert set(CASES) == set(sigs), (
            f"CASES must cover every built-in signature; "
            f"missing={set(sigs) - set(CASES)}, extra={set(CASES) - set(sigs)}"
        )
        for sig_id, (positive, negative) in CASES.items():
            assert match_signature(positive, sigs[sig_id]), (
                f"{sig_id} did not fire on its positive line: {positive!r}"
            )
            assert not match_signature(negative, sigs[sig_id]), (
                f"{sig_id} fired on its negative line: {negative!r}"
            )

    def test_empty_detection_never_fires(self):
        sig = Signature(id="NG-T4", title="t")
        assert not match_signature("anything at all", sig)

    def test_detection_is_conjunction(self):
        sig = Signature(
            id="NG-T5",
            title="t",
            detection=(("src=", "failed"), ("dst=", "port 22")),
        )
        assert match_signature("src=1.2.3.4 dst=10.0.0.1 failed on port 22", sig)
        assert not match_signature("src=1.2.3.4 failed on port 80", sig)
        assert not match_signature("src=1.2.3.4 dst=10.0.0.1 accepted on port 22", sig)

    def test_filter_vetoes(self):
        sig = Signature(
            id="NG-T6",
            title="t",
            detection=(("auth", "failed"),),
            filter=(("internal", "retry"),),
        )
        assert match_signature("auth: src=1.2.3.4 failed", sig)
        assert not match_signature(
            "auth: src=10.0.0.1 failed internal retry", sig
        )

    def test_filter_needs_both_patterns(self):
        """A filter pair is the same field+value conjunction — one
        pattern alone is not a veto."""
        sig = Signature(
            id="NG-T7",
            title="t",
            detection=(("auth", "failed"),),
            filter=(("src=10.0.0.1", "internal"),),
        )
        # both filter patterns present -> veto
        assert not match_signature("auth: src=10.0.0.1 failed internal", sig)
        # only the value pattern present -> no veto
        assert match_signature("auth: src=1.2.3.4 failed internal", sig)

    def test_regex_semantics_not_literal(self):
        sig = builtin_signatures()[4]  # NG-0005, dbytes
        assert match_signature(
            "netflow: src=10.0.0.5 dst=1.2.3.4 dbytes=9999999", sig
        )
        assert not match_signature(
            "netflow: src=10.0.0.5 dst=1.2.3.4 dbytes=999999", sig
        )

    def test_match_is_deterministic(self):
        """Same line + same signature -> same result, every call."""
        sig = builtin_signatures()[2]  # NG-0003, encoded powershell
        line = CASES["NG-0003"][0]
        results = [match_signature(line, sig) for _ in range(50)]
        assert all(results)

    def test_matching_is_case_sensitive(self):
        """Determinism includes case: 'FAILED' is not 'failed' unless
        the signature says so."""
        sig = Signature(
            id="NG-T8", title="t", detection=(("auth", "failed password"),)
        )
        assert match_signature("auth: failed password", sig)
        assert not match_signature("auth: FAILED PASSWORD", sig)


class TestMatchAll:
    LINES = [
        "[08:14:01] auth: src=203.0.113.77:1234 failed password for admin",
        "[08:14:31] auth: src=203.0.113.77:1234 accepted password for admin",
        "proxy: GET /x HTTP/1.1 user-agent=\"sqlmap/1.7.2\" src=198.51.100.9",
    ]

    def _all_builtin(self) -> list[Signature]:
        return builtin_signatures()

    def test_output_order_is_signature_then_line(self):
        """Contract: (signature order, then line order) — stable output."""
        matches = match_all(self.LINES, self._all_builtin())
        order = [(m.signature_id, m.line) for m in matches]
        assert order == sorted(
            order,
            key=lambda x: (
                [s.id for s in self._all_builtin()].index(x[0]),
                self.LINES.index(x[1]),
            ),
        )
        # the set of fired signatures is the expected one
        assert {m.signature_id for m in matches} >= {"NG-0001", "NG-0002", "NG-0004"}

    def test_match_carries_line_and_id(self):
        matches = match_all(self.LINES, self._all_builtin())
        m = next(m for m in matches if m.signature_id == "NG-0004")
        assert m.line == self.LINES[2]
        assert isinstance(m.signature_id, str)

    def test_captures_present_when_pattern_declares_groups(self):
        sig = Signature(
            id="NG-T9",
            title="t",
            detection=(("src=(\\S+?):", "failed password"),),
        )
        matches = match_all(self.LINES[:1], [sig])
        assert len(matches) == 1
        assert "203.0.113.77" in matches[0].captured

    def test_no_match_returns_empty_list(self):
        assert match_all(["nothing interesting here"], self._all_builtin()) == []

    def test_match_all_is_deterministic(self):
        r1 = match_all(self.LINES, self._all_builtin())
        r2 = match_all(self.LINES, self._all_builtin())
        assert [(m.signature_id, m.line, m.captured) for m in r1] == [
            (m.signature_id, m.line, m.captured) for m in r2
        ]


class TestSubjectOf:
    def test_src_value_is_the_subject(self):
        assert subject_of("auth: src=203.0.113.77:1234 failed") == "203.0.113.77"

    def test_no_src_falls_back_to_whole_line(self):
        line = "auth: failed password for admin"
        assert subject_of(line) == line


class TestSignatureBridgeClaims:
    def test_claims_carry_exact_line_as_evidence(self):
        """Every claim cites the exact line it matched — not a summary."""
        lines = [
            "[08:14:01] auth: src=203.0.113.77:1234 failed password for admin",
            "proxy: GET /x HTTP/1.1 user-agent=\"sqlmap/1.7.2\" src=198.51.100.9",
        ]
        claims = signature_claims(lines, builtin_signatures())
        assert claims
        for c in claims:
            assert c.evidence in lines, (
                f"claim evidence is not the matched line: {c.evidence!r}"
            )
            assert c.kind.startswith("signature_")

    def test_claim_kind_is_lowercased_signature_id(self):
        assert claim_kind("NG-0003") == "signature_ng-0003"

    def test_claim_payload_shape(self):
        lines = [CASES["NG-0001"][0]]
        claims = signature_claims(lines, builtin_signatures())
        # the line fires NG-0001 (a single failed auth) — and, because it
        # also reads as an auth line, only NG-0001 among the auth rules
        ids = [c.payload["signature_id"] for c in claims]
        assert "NG-0001" in ids
        c = next(c for c in claims if c.payload["signature_id"] == "NG-0001")
        assert c.payload["level"] == "medium"
        assert c.payload["logsource"] == "auth"
        assert c.payload["subject"] == "203.0.113.77"

    def test_no_matches_no_claims(self):
        assert signature_claims(["nothing here"], builtin_signatures()) == []

    def test_claims_rejected_without_evidence_by_ledger(self):
        """A signature claim with empty evidence is refused by the
        ledger — the evidence discipline holds at insert time too."""
        ledger = EvidenceLedger()
        with pytest.raises(Exception):
            ledger.append(Claim(kind="signature_ng-0001", payload={}, evidence=""))

    def test_match_referencing_unknown_signature_is_skipped(self):
        """A match whose signature is not in the set cannot be described
        honestly — it is skipped, not guessed."""
        lines = ["anything"]
        sigs = builtin_signatures()
        bogus = [Match(signature_id="NG-9999", line="anything")]
        assert signature_claims(lines, sigs, matches=bogus) == []


class TestSignatureExtractor:
    def _engine(self, claims: list[Claim]) -> RuleEngine:
        engine = RuleEngine(rules=security_rules())
        ledger = EvidenceLedger()
        for c in claims:
            ledger.append(c)
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        return engine

    def test_signature_claim_produces_signatureMatched_fact(self):
        lines = [CASES["NG-0001"][0]]
        claims = signature_claims(lines, builtin_signatures())
        engine = self._engine(claims)
        matched = [f for f in engine.facts if f.relation == "signatureMatched"]
        assert matched
        assert matched[0].subject == "203.0.113.77"
        assert matched[0].object == "NG-0001"

    def test_critical_signature_also_produces_maliciousActivity(self):
        """A critical-level signature additionally asserts the actor's
        maliciousActivity — the fact the signature rule reasons over."""
        lines = [CASES["NG-0003"][0]]
        claims = signature_claims(lines, builtin_signatures())
        engine = self._engine(claims)
        facts = [
            f for f in engine.facts if f.relation == "maliciousActivity"
        ]
        assert facts
        assert facts[0].subject == "203.0.113.77" or facts[0].subject  # actor

    def test_non_critical_signature_does_not_produce_maliciousActivity(self):
        lines = [CASES["NG-0001"][0]]  # medium level
        claims = signature_claims(lines, builtin_signatures())
        engine = self._engine(claims)
        assert not any(f.relation == "maliciousActivity" for f in engine.facts)

    def test_unknown_signature_id_does_not_crash(self):
        """A claim for a signature id this build does not know must not
        crash — through the extractor directly, and through the engine.

        Engine contract: an unregistered claim kind yields no facts
        (rules._extract_facts returns [] for unknown kinds). Directly,
        the extractor is registry-independent and still produces the
        behavioural fact the payload describes — which is what lets a
        future rule set's claims keep working if they are ever routed
        through this extractor.
        """
        from nomosguard.signature_bridge import _extract_signature_claim

        payload = {
            "signature_id": "NG-9999",
            "level": "critical",
            "logsource": "auth",
            "subject": "203.0.113.77",
            "title": "Unknown future signature",
        }
        facts = _extract_signature_claim(payload, "some log line")
        assert facts
        assert facts[0].relation == "signatureMatched"
        assert facts[0].object == "NG-9999"

        # and the engine path: unregistered kind -> no facts, no crash
        engine = RuleEngine(rules=security_rules())
        ledger = EvidenceLedger()
        ledger.append(
            Claim(
                kind="signature_ng-9999",
                payload=payload,
                evidence="some log line",
            )
        )
        engine.add_facts_from_ledger(ledger)  # must not raise
        engine.derive()
        assert not any(f.relation == "signatureMatched" for f in engine.facts)

    def test_claim_without_subject_produces_no_facts(self):
        engine = RuleEngine(rules=security_rules())
        ledger = EvidenceLedger()
        ledger.append(
            Claim(
                kind="signature_ng-0001",
                payload={"signature_id": "NG-0001", "level": "medium"},
                evidence="some log line",
            )
        )
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        assert not engine.facts


class TestEndToEndSignatureChain:
    """The full chain: logs -> signatures -> ledger -> engine -> gate.

    A critical signature match (encoded PowerShell) from an actor with
    network reachability to a host must produce an ESCALATE decision —
    and must NOT escalate when the actor cannot reach anything.
    """

    ENCODED_PS_LINE = (
        "2026-10-09T03:11:00 proc: powershell.exe -EncodedCommand "
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA= src=203.0.113.77"
    )
    NETWORK = (
        "network",
        {"host": "web01", "protocol": "tcp", "port": 443, "allowed_from": "203.0.113.77"},
        "firewall: 203.0.113.77 -> web01:443/tcp",
    )

    def _run(self, with_reachability: bool):
        ledger, _matches = run_signatures_into_ledger(
            [self.ENCODED_PS_LINE], builtin_signatures()
        )
        if with_reachability:
            from nomosguard.ledger import Claim as _Claim

            kind, payload, evidence = self.NETWORK
            ledger.append(_Claim(kind=kind, payload=payload, evidence=evidence))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        gate = PolicyGate(
            policy_rules=containment_policy_rules(), fallback=Decision.ALERT
        )
        return ledger, engine, gate.evaluate_with_fallback(engine)

    def test_ledger_chain_intact(self):
        ledger, _, _ = self._run(with_reachability=True)
        ok, detail = ledger.verify()
        assert ok, detail

    def test_signature_facts_in_engine(self):
        _, engine, _ = self._run(with_reachability=True)
        assert any(f.relation == "signatureMatched" for f in engine.facts)
        assert any(f.relation == "maliciousActivity" for f in engine.facts)

    def test_critical_signature_plus_reachability_escalates(self):
        """The new rule + policy rule fire end-to-end."""
        _, _, result = self._run(with_reachability=True)
        decisions = [d["decision"] for d in result.get("all_decisions", [])]
        assert "ESCALATE" in decisions, f"expected ESCALATE, got {decisions}"
        # the decision is the signature one, and its chain is complete
        esc = next(
            d
            for d in result["all_decisions"]
            if d["decision"] == "ESCALATE"
            and d["policy_rule"] == "escalate_malicious_signature_on_reachable_actor"
        )
        assert esc["missing_evidence"] == []
        assert "signature_ng-0003" in esc["derived_from"]

    def test_signature_without_reachability_does_not_escalate(self):
        """No access path -> no hostUnderMaliciousProbe -> no ESCALATE
        from the signature rule. Signature evidence alone is not an
        attack on a specific host."""
        _, _, result = self._run(with_reachability=False)
        decisions = [d["decision"] for d in result.get("all_decisions", [])]
        assert "ESCALATE" not in decisions

    def test_end_to_end_is_deterministic(self):
        _, _, r1 = self._run(with_reachability=True)
        _, _, r2 = self._run(with_reachability=True)
        assert r1["decision"] == r2["decision"]
        assert r1["all_decisions"] == r2["all_decisions"]

    def test_ledger_hashes_are_content_addressed(self):
        """Same evidence -> same entry hashes, independent of wall clock."""
        ledger, _ = run_signatures_into_ledger(
            [self.ENCODED_PS_LINE], builtin_signatures()
        )
        hashes = [e.entry_hash for e in ledger.entries]
        ledger2, _ = run_signatures_into_ledger(
            [self.ENCODED_PS_LINE], builtin_signatures()
        )
        assert hashes == [e.entry_hash for e in ledger2.entries]
