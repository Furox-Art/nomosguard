"""Tests for the NVD grounding layer: client, service map, severity rule.

Everything here runs with ZERO network access. The NVD responses are
recorded fixtures (real API 2.0 JSON captured from
services.nvd.nist.gov), so the parse paths under test are the real ones
while the transport is never touched.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from nomosguard.vuln_db import (
    CachedNVDClient,
    NVDRateLimitError,
    enrich_claim,
    load_fixture_cache,
    severity_for_score,
)
from nomosguard.service_cve_map import (
    MAP_VERSION,
    SERVICE_MAP,
    all_cve_ids,
    cves_for_service,
    map_summary,
)
from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.rules import RuleEngine
from nomosguard.rules_security import security_rules
from nomosguard import facts_security  # noqa: F401 — registers extractors

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "nvd"
FIXTURE_CVES = load_fixture_cache(FIXTURE_DIR / "cves.json")


# --------------------------------------------------------------------------
# Fixtures / helpers
# --------------------------------------------------------------------------

def _offline_client(cache: dict | None = None) -> CachedNVDClient:
    """A client that can never touch the network."""
    return CachedNVDClient(offline=True, cache=cache)


@pytest.fixture(autouse=True)
def _no_network_guard(monkeypatch):
    """Fail the test if any code path actually tries to open a socket."""
    import urllib.request

    def _blocked(*args, **kwargs):
        raise AssertionError("network access attempted during offline test")

    monkeypatch.setattr(urllib.request, "urlopen", _blocked)
    # Belt and braces: the cache dir is never written during these tests.
    yield


def _derive(claims):
    ledger = EvidenceLedger()
    for kind, payload, evidence in claims:
        ledger.append(Claim(kind=kind, payload=payload, evidence=evidence))
    engine = RuleEngine(rules=security_rules())
    engine.add_facts_from_ledger(ledger)
    engine.derive()
    return engine


# --------------------------------------------------------------------------
# CachedNVDClient — offline behaviour
# --------------------------------------------------------------------------

class TestCachedNVDClientOffline:
    def test_fixture_cache_returns_known_severity(self):
        """A cache dict yields the real NVD severity with no network."""
        client = _offline_client(cache=FIXTURE_CVES)
        # CVE-2021-41773 — Apache path traversal -> RCE, CVSS 9.8 CRITICAL
        assert client.get_severity("CVE-2021-41773") == "CRITICAL"
        assert client.get_cvss("CVE-2021-41773") == 9.8

    def test_cache_hit_issues_no_requests(self):
        client = _offline_client(cache=FIXTURE_CVES)
        client.get_cve("CVE-2021-41773")
        client.get_severity("CVE-2021-41773")
        client.get_cvss("CVE-2021-41773")
        assert client.request_count == 0

    def test_unknown_cve_returns_none_not_raise(self):
        client = _offline_client(cache=FIXTURE_CVES)
        assert client.get_cve("CVE-9999-00000") is None
        assert client.get_cvss("CVE-9999-00000") is None
        assert client.get_severity("CVE-9999-00000") == "UNKNOWN"

    def test_empty_string_cve_returns_none(self):
        client = _offline_client(cache=FIXTURE_CVES)
        assert client.get_cve("") is None
        assert client.get_cve("   ") is None
        assert client.get_cve(None) is None  # type: ignore[arg-type]
        assert client.get_severity("") == "UNKNOWN"

    def test_offline_miss_does_not_raise(self):
        """An offline client with an empty cache must fail closed, not throw."""
        client = _offline_client(cache={})
        assert client.get_cve("CVE-2021-41773") is None
        assert client.get_severity("CVE-2021-41773") == "UNKNOWN"
        assert client.request_count == 0

    def test_offline_is_the_default(self):
        """The default mode is offline — safe by construction."""
        client = CachedNVDClient(cache={})
        assert client.offline is True
        assert client.get_severity("CVE-2021-41773") == "UNKNOWN"

    def test_unknown_cve_in_offline_search(self):
        client = _offline_client(cache=FIXTURE_CVES)
        assert client.search_by_keyword("openssh") == []
        assert client.search_by_keyword("") == []
        assert client.search_by_keyword("openssh", limit=0) == []

    def test_disk_cache_hit_is_zero_io(self, tmp_path):
        """A cache file on disk is served without any network access."""
        cache_dir = tmp_path / "nvd"
        cache_dir.mkdir()
        cve = FIXTURE_CVES["CVE-2021-41773"]
        (cache_dir / "CVE-2021-41773.json").write_text(
            json.dumps({"cve": cve}), encoding="utf-8"
        )
        client = CachedNVDClient(cache_dir=cache_dir, offline=False)
        assert client.get_severity("CVE-2021-41773") == "CRITICAL"
        assert client.request_count == 0

    def test_corrupt_cache_file_falls_through(self, tmp_path):
        cache_dir = tmp_path / "nvd"
        cache_dir.mkdir()
        (cache_dir / "CVE-2021-41773.json").write_text("{not json", encoding="utf-8")
        client = CachedNVDClient(cache_dir=cache_dir, offline=True)
        assert client.get_cve("CVE-2021-41773") is None


# --------------------------------------------------------------------------
# CVSS score -> severity banding
# --------------------------------------------------------------------------

class TestSeverityBands:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (10.0, "CRITICAL"),
            (9.8, "CRITICAL"),
            (9.0, "CRITICAL"),
            (8.9, "HIGH"),
            (7.0, "HIGH"),
            (6.9, "MEDIUM"),
            (4.0, "MEDIUM"),
            (3.9, "LOW"),
            (0.1, "LOW"),
            (0.0, "UNKNOWN"),
            (-1.0, "UNKNOWN"),
            (None, "UNKNOWN"),
        ],
    )
    def test_band_boundaries(self, score, expected):
        assert severity_for_score(score) == expected

    def test_non_numeric_is_unknown(self):
        assert severity_for_score("9.8") == "UNKNOWN"  # type: ignore[arg-type]
        assert severity_for_score(True) == "UNKNOWN"   # bool is not a score


# --------------------------------------------------------------------------
# Real CVEs from the recorded fixtures
# --------------------------------------------------------------------------

class TestRealCveSeverities:
    """The severities NVD actually publishes for the CVEs we map."""

    def test_critical_cves(self):
        client = _offline_client(cache=FIXTURE_CVES)
        for cve in ("CVE-2021-41773", "CVE-2021-42013", "CVE-2023-38408",
                    "CVE-2017-7494", "CVE-2011-2523"):
            assert client.get_severity(cve) == "CRITICAL", cve

    def test_high_cves(self):
        client = _offline_client(cache=FIXTURE_CVES)
        for cve in ("CVE-2024-6387", "CVE-2018-1058", "CVE-2021-30047"):
            assert client.get_severity(cve) == "HIGH", cve

    def test_medium_cves(self):
        client = _offline_client(cache=FIXTURE_CVES)
        assert client.get_severity("CVE-2018-15473") == "MEDIUM"
        assert client.get_severity("CVE-2012-2122") == "MEDIUM"

    def test_cvss_v3_preferred_over_v2(self):
        """A record carrying both v3.x and v2 must report the v3.1 score."""
        client = _offline_client(cache=FIXTURE_CVES)
        # CVE-2014-0160 (Heartbleed) carries v3.1 (7.5) and v2 (5.0).
        assert client.get_cvss("CVE-2014-0160") == 7.5

    def test_v2_only_record_still_scores(self):
        """Older records with only cvssMetricV2 must still produce a score."""
        client = _offline_client(cache=FIXTURE_CVES)
        # CVE-2013-4547 has v2 only (7.5).
        assert client.get_cvss("CVE-2013-4547") == 7.5
        assert client.get_severity("CVE-2013-4547") == "HIGH"

    def test_all_fixture_cves_resolve(self):
        client = _offline_client(cache=FIXTURE_CVES)
        for cve_id in FIXTURE_CVES:
            assert client.get_cve(cve_id) is not None, cve_id
            assert client.get_cvss(cve_id) is not None, cve_id


# --------------------------------------------------------------------------
# Keyword search
# --------------------------------------------------------------------------

class TestKeywordSearch:
    def test_offline_search_returns_empty_list(self):
        client = _offline_client(cache=FIXTURE_CVES)
        assert client.search_by_keyword("openssh") == []

    def test_keyword_fixture_has_real_ids(self):
        """The recorded keyword response contains genuine CVE ids."""
        path = FIXTURE_DIR / "keyword_openssh.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["cve_ids"], "keyword fixture is empty"
        assert all(c.startswith("CVE-") for c in payload["cve_ids"])
        assert payload["totalResults"] > 0

    def test_limit_is_respected(self):
        """A keyword search is capped at the requested limit."""
        class _FakeHTTP:
            def __init__(self):
                self.seen = []

        # Exercise the slicing logic without a network by stubbing _request.
        client = _offline_client(cache=FIXTURE_CVES)
        payload = json.loads((FIXTURE_DIR / "keyword_openssh.json").read_text())
        ids = payload["cve_ids"]
        # Verify the client's own slicing contract on a stubbed response.
        client._request = lambda params: {  # type: ignore[assignment]
            "vulnerabilities": [{"cve": {"id": c}} for c in ids]
        }
        got = client.search_by_keyword("openssh", limit=3, offline=False)
        assert len(got) == 3
        assert got == ids[:3]


# --------------------------------------------------------------------------
# Rate limiting / network error handling
# --------------------------------------------------------------------------

class TestRateLimitContract:
    def test_public_rate_limit_constants(self):
        from nomosguard import vuln_db

        assert vuln_db.PUBLIC_RATE_LIMIT_REQUESTS == 5
        assert vuln_db.PUBLIC_RATE_LIMIT_WINDOW_S == 30.0

    def test_403_raises_rate_limit_error(self, monkeypatch):
        import urllib.error
        import urllib.request as req

        def _raise_403(url, timeout=None):
            raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)

        monkeypatch.setattr(req, "urlopen", _raise_403)
        client = CachedNVDClient(offline=False, cache={})
        with pytest.raises(NVDRateLimitError):
            client.get_cve("CVE-2021-41773")

    def test_network_failure_returns_none(self, monkeypatch):
        import urllib.request as req

        def _boom(url, timeout=None):
            raise OSError("no route to host")

        monkeypatch.setattr(req, "urlopen", _boom)
        client = CachedNVDClient(offline=False, cache={})
        # A transport failure must degrade to "unknown", never propagate.
        assert client.get_cve("CVE-2021-41773") is None
        assert client.get_severity("CVE-2021-41773") == "UNKNOWN"


# --------------------------------------------------------------------------
# service_cve_map
# --------------------------------------------------------------------------

class TestServiceCveMap:
    def test_case_insensitive_service_match(self):
        """\"OpenSSH\" must match the same entry as \"openssh\"."""
        upper = cves_for_service("OpenSSH")
        lower = cves_for_service("openssh")
        assert upper == lower
        assert upper, "OpenSSH must resolve to at least one CVE"

    def test_banner_style_match(self):
        """A version banner should still hit the service entry."""
        assert "CVE-2024-6387" in cves_for_service("SSH-2.0-OpenSSH_8.9p1")
        assert "CVE-2021-41773" in cves_for_service("Apache/2.4.49 (Unix)")

    def test_required_services_covered(self):
        for service in ("OpenSSH", "OpenSSL", "nginx", "Apache httpd",
                        "PostgreSQL", "MySQL", "vsftpd", "Samba"):
            assert cves_for_service(service), f"{service} has no mapped CVEs"

    def test_version_range_narrows_results(self):
        """A version outside the affected range must not match."""
        # CVE-2024-6387 affects 8.5p1 <= v < 9.8p1
        assert "CVE-2024-6387" in cves_for_service("openssh", "9.6p1")
        assert "CVE-2024-6387" not in cves_for_service("openssh", "9.9p1")
        assert "CVE-2024-6387" not in cves_for_service("openssh", "8.4p1")

    def test_version_range_openssh_patch_suffix(self):
        """The pN patch suffix must be handled (9.6p1 > 9.6)."""
        assert "CVE-2024-6387" in cves_for_service("openssh", "9.7p1")

    def test_openssl_letter_suffix(self):
        """A rebuild letter (1.0.1g) must compare against 1.0.1."""
        assert "CVE-2014-0160" in cves_for_service("openssl", "1.0.1f")
        assert "CVE-2014-0160" not in cves_for_service("openssl", "1.0.2a")

    def test_no_version_returns_all(self):
        """Without a version every CVE for the service is a candidate."""
        entry = next(e for e in SERVICE_MAP if e.service == "vsftpd")
        assert len(cves_for_service("vsftpd")) == len(entry.cves)

    def test_unknown_service_returns_empty(self):
        assert cves_for_service("not-a-real-service") == []
        assert cves_for_service("") == []

    def test_unparseable_version_does_not_hide_exposure(self):
        """An unparseable version must not silently drop a real CVE."""
        assert "CVE-2024-6387" in cves_for_service("openssh", "totally-bogus")

    def test_all_cve_ids_are_well_formed(self):
        ids = all_cve_ids()
        assert ids
        for cid in ids:
            assert cid.startswith("CVE-") and cid.count("-") == 2, cid

    def test_map_is_versioned(self):
        summary = map_summary()
        assert summary["map_version"] == MAP_VERSION
        assert summary["verified_on"]
        assert summary["cve_count"] == len(all_cve_ids())


class TestMapCvesExistInNvd:
    """Every id in the map must resolve against the recorded NVD fixtures.

    This is the guard that keeps the map honest: if someone adds an invented
    CVE id, this test fails because it will not be in the fixture set.
    """

    def test_every_mapped_cve_is_in_the_fixtures(self):
        missing = [c for c in all_cve_ids() if c not in FIXTURE_CVES]
        assert not missing, (
            f"these CVE ids are in the map but not verified against NVD: {missing}"
        )

    def test_fixture_cves_carry_a_score(self):
        client = _offline_client(cache=FIXTURE_CVES)
        for cid in all_cve_ids():
            assert client.get_cvss(cid) is not None, cid


# --------------------------------------------------------------------------
# vuln_severity extractor + severity rule
# --------------------------------------------------------------------------

class TestVulnSeverityExtractor:
    def test_extractor_produces_the_right_fact(self):
        engine = _derive([
            ("vuln_severity", {"host": "web01", "cve": "CVE-2021-41773",
                               "cvss": 9.8, "severity": "CRITICAL"}, "nvd"),
        ])
        facts = [f for f in engine.facts if f.relation == "vulnSeverity"]
        assert len(facts) == 1
        assert facts[0].subject == "web01"
        assert facts[0].object == "CRITICAL"
        assert facts[0].sources == ("vuln_severity",)

    def test_severity_is_uppercased(self):
        engine = _derive([
            ("vuln_severity", {"host": "web01", "cve": "CVE-2021-41773",
                               "cvss": 9.8, "severity": "critical"}, "nvd"),
        ])
        facts = [f for f in engine.facts if f.relation == "vulnSeverity"]
        assert facts and facts[0].object == "CRITICAL"

    def test_unknown_severity_produces_no_fact(self):
        """An ungrounded severity must not enter the fact base."""
        engine = _derive([
            ("vuln_severity", {"host": "web01", "cve": "CVE-9999-00000",
                               "severity": "UNKNOWN"}, "nvd"),
        ])
        assert not any(f.relation == "vulnSeverity" for f in engine.facts)

    def test_missing_severity_produces_no_fact(self):
        engine = _derive([("vuln_severity", {"host": "web01"}, "nvd")])
        assert not any(f.relation == "vulnSeverity" for f in engine.facts)

    def test_empty_host_produces_no_fact(self):
        engine = _derive([
            ("vuln_severity", {"host": "", "cve": "CVE-2021-41773",
                               "severity": "CRITICAL"}, "nvd"),
        ])
        assert not any(f.relation == "vulnSeverity" for f in engine.facts)


class TestExploitCriticalVulnerabilityRule:
    def test_critical_rule_fires(self):
        engine = _derive([
            ("network", {"host": "web01", "protocol": "tcp", "port": 443,
                         "allowed_from": "attacker"}, "fw"),
            ("vuln_severity", {"host": "web01", "cve": "CVE-2021-41773",
                               "cvss": 9.8, "severity": "CRITICAL"}, "nvd"),
        ])
        fired = {f.relation for f in engine.facts}
        assert "vulnSeverity" in fired
        assert "execCode" in fired
        trace = [t for t in engine.derivation_trace
                 if t["rule"] == "exploit_critical_vulnerability"]
        assert trace, "exploit_critical_vulnerability did not fire"
        assert trace[0]["derived"] == "Fact(web01 -execCode-> attacker)"

    def test_non_critical_severity_does_not_fire_the_critical_rule(self):
        """A HIGH severity must not trip the CRITICAL-gated rule."""
        engine = _derive([
            ("network", {"host": "web01", "protocol": "tcp", "port": 443,
                         "allowed_from": "attacker"}, "fw"),
            ("vuln_severity", {"host": "web01", "cve": "CVE-2024-6387",
                               "cvss": 8.1, "severity": "HIGH"}, "nvd"),
        ])
        rules_fired = {t["rule"] for t in engine.derivation_trace}
        assert "exploit_critical_vulnerability" not in rules_fired
        # But the severity fact itself is still recorded.
        assert any(f.relation == "vulnSeverity" for f in engine.facts)

    def test_regression_exploit_rule_still_fires_for_any_vuln(self):
        """The original exploit_vulnerability rule must be unchanged."""
        engine = _derive([
            ("network", {"host": "web01", "protocol": "tcp", "port": 443,
                         "allowed_from": "attacker"}, "fw"),
            ("vuln_host", {"host": "web01", "cve": "CVE-2024-6387"}, "nvd"),
        ])
        exec_code = [f for f in engine.facts if f.relation == "execCode"]
        assert len(exec_code) == 1
        rules_fired = {t["rule"] for t in engine.derivation_trace}
        assert "exploit_vulnerability" in rules_fired
        assert "exploit_critical_vulnerability" not in rules_fired

    def test_regression_medium_vuln_still_derives_exec_code(self):
        """A MEDIUM CVE still yields execCode via the general rule."""
        engine = _derive([
            ("network", {"host": "web01", "protocol": "tcp", "port": 443,
                         "allowed_from": "attacker"}, "fw"),
            ("vuln_host", {"host": "web01", "cve": "CVE-2018-15473"}, "nvd"),
        ])
        assert any(f.relation == "execCode" for f in engine.facts)

    def test_severity_and_bare_vuln_together_derive_exec_code_once(self):
        """vuln_host + vuln_severity must not double-derive execCode."""
        engine = _derive([
            ("network", {"host": "web01", "protocol": "tcp", "port": 443,
                         "allowed_from": "attacker"}, "fw"),
            ("vuln_host", {"host": "web01", "cve": "CVE-2021-41773"}, "nvd"),
            ("vuln_severity", {"host": "web01", "cve": "CVE-2021-41773",
                               "cvss": 9.8, "severity": "CRITICAL"}, "nvd"),
        ])
        exec_code = [f for f in engine.facts if f.relation == "execCode"]
        assert len(exec_code) == 1, "execCode must be derived once, not twice"

    def test_no_reachability_no_exec_code(self):
        """Severity alone, without reachability, derives nothing."""
        engine = _derive([
            ("vuln_severity", {"host": "web01", "cve": "CVE-2021-41773",
                               "cvss": 9.8, "severity": "CRITICAL"}, "nvd"),
        ])
        assert not any(f.relation == "execCode" for f in engine.facts)

    def test_existing_rules_are_untouched(self):
        """The pre-existing security rules must all still be present."""
        names = {r.name for r in security_rules()}
        for expected in ("exploit_vulnerability", "lateral_movement",
                         "privilege_via_exec", "brute_force_attempting_access",
                         "scan_of_reachable_host", "active_exfiltration"):
            assert expected in names, f"rule {expected} was removed"
        assert "exploit_critical_vulnerability" in names


# --------------------------------------------------------------------------
# enrich_claim
# --------------------------------------------------------------------------

class TestEnrichClaim:
    def test_enrich_with_stub_cache(self):
        """A stub cache must produce the enriched payload, no network."""
        client = _offline_client(cache=FIXTURE_CVES)
        out = client.enrich_claim({"host": "web01", "cve": "CVE-2021-41773"})
        assert out == {
            "host": "web01",
            "cve": "CVE-2021-41773",
            "cvss": 9.8,
            "severity": "CRITICAL",
        }

    def test_enrich_module_function(self):
        """The module-level helper works with the recorded fixtures."""
        client = _offline_client(cache=FIXTURE_CVES)
        out = enrich_claim({"host": "db01", "cve": "cve-2024-6387"}, nvd=client)
        assert out is not None
        assert out["cve"] == "CVE-2024-6387"  # normalised to upper case
        assert out["severity"] == "HIGH"
        assert out["cvss"] == 8.1

    def test_enrich_unknown_cve_returns_none(self):
        client = _offline_client(cache=FIXTURE_CVES)
        assert client.enrich_claim({"host": "web01", "cve": "CVE-2026-31142"}) is None

    def test_enrich_missing_fields_returns_none(self):
        client = _offline_client(cache=FIXTURE_CVES)
        assert client.enrich_claim({"host": "web01"}) is None
        assert client.enrich_claim({"cve": "CVE-2021-41773"}) is None
        assert client.enrich_claim({}) is None
        assert client.enrich_claim(None) is None  # type: ignore[arg-type]

    def test_enrich_is_pure(self):
        """Same inputs + same cache -> identical output."""
        client = _offline_client(cache=FIXTURE_CVES)
        payload = {"host": "web01", "cve": "CVE-2021-41773"}
        assert client.enrich_claim(payload) == client.enrich_claim(payload)

    def test_enrich_offline_default_returns_none(self):
        """With no cache and offline (the default), enrichment fails closed."""
        out = enrich_claim({"host": "web01", "cve": "CVE-2021-41773"})
        assert out is None

    def test_enriched_payload_round_trips_through_the_engine(self):
        """The enriched payload feeds the severity rule end to end."""
        client = _offline_client(cache=FIXTURE_CVES)
        enriched = client.enrich_claim({"host": "web01", "cve": "CVE-2021-41773"})
        assert enriched is not None
        engine = _derive([
            ("network", {"host": "web01", "protocol": "tcp", "port": 443,
                         "allowed_from": "attacker"}, "fw"),
            ("vuln_severity", enriched, f"nvd: {enriched['cve']}"),
        ])
        assert any(f.relation == "execCode" for f in engine.facts)

    def test_enrich_then_ungrounded_falls_back_to_silence(self):
        """An ungrounded CVE leaves the host with no severity fact."""
        client = _offline_client(cache=FIXTURE_CVES)
        assert client.enrich_claim({"host": "web01", "cve": "CVE-9999-00000"}) is None


# --------------------------------------------------------------------------
# Determinism: the NVD layer must not perturb the core
# --------------------------------------------------------------------------

class TestDeterminismUnaffected:
    def test_severity_derivation_is_repeatable(self):
        claims = [
            ("network", {"host": "web01", "protocol": "tcp", "port": 443,
                         "allowed_from": "attacker"}, "fw"),
            ("vuln_severity", {"host": "web01", "cve": "CVE-2021-41773",
                               "cvss": 9.8, "severity": "CRITICAL"}, "nvd"),
        ]
        snap1 = sorted(str(f) for f in _derive(claims).facts)
        snap2 = sorted(str(f) for f in _derive(claims).facts)
        assert snap1 == snap2

    def test_client_makes_no_requests_when_cached(self):
        client = _offline_client(cache=FIXTURE_CVES)
        for _ in range(3):
            client.get_severity("CVE-2021-41773")
        assert client.request_count == 0


# --------------------------------------------------------------------------
# Fixture integrity
# --------------------------------------------------------------------------

class TestFixtureIntegrity:
    def test_fixture_file_exists_and_parses(self):
        assert FIXTURE_CVES, "no CVE fixtures were loaded"
        assert len(FIXTURE_CVES) >= 30, "expected a substantial fixture set"

    def test_fixture_metadata(self):
        payload = json.loads((FIXTURE_DIR / "cves.json").read_text(encoding="utf-8"))
        assert payload["source"].startswith("https://services.nvd.nist.gov/")

    def test_known_cve_ids_file_matches(self):
        path = FIXTURE_DIR / "known_cve_ids.txt"
        ids = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert set(ids) == set(FIXTURE_CVES)

    def test_env_key_not_required(self):
        """The client must work with no NVD_API_KEY in the environment."""
        saved = os.environ.pop("NVD_API_KEY", None)
        try:
            client = CachedNVDClient(offline=True, cache=FIXTURE_CVES)
            assert client.api_key is None
            assert client.get_severity("CVE-2021-41773") == "CRITICAL"
        finally:
            if saved is not None:
                os.environ["NVD_API_KEY"] = saved
