"""Real NVD request/cache control flow tested with a sealed HTTP transport."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest

from nomosguard import vuln_db


def _client(path: Path, **kwargs) -> vuln_db.CachedNVDClient:
    return vuln_db.CachedNVDClient(cache_dir=path, offline=False, **kwargs)


def _fake_response(payload: object):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            if isinstance(payload, bytes):
                return payload
            return json.dumps(payload).encode()

    return Response()


def test_online_fixture_fetch_and_persistent_offline_reload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cve = {
        "id": "CVE-2026-0001",
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.2}}]},
    }
    requests = []

    def mocked_fetch(req, timeout):
        requests.append((req.full_url, req.get_header("Apikey"), timeout))
        return _fake_response({"vulnerabilities": [{"cve": cve}]})

    monkeypatch.setattr(vuln_db.urllib.request, "urlopen", mocked_fetch)
    monkeypatch.setattr(vuln_db.CachedNVDClient, "_throttle", lambda self: None)
    online = _client(tmp_path, api_key="fixture-key", cache_ttl_s=None)
    assert online.get_cve(" CVE-2026-0001 ") == cve
    assert online.get_severity("CVE-2026-0001") == "HIGH"
    assert requests and requests[0][1] == "fixture-key"
    assert online.request_count == 1

    def no_network(*args, **kwargs):
        raise AssertionError("Offline cached read attempted network access")

    monkeypatch.setattr(vuln_db.urllib.request, "urlopen", no_network)
    offline = vuln_db.CachedNVDClient(cache_dir=tmp_path, offline=True)
    assert offline.get_cve("CVE-2026-0001") == cve
    assert offline.request_count == 0


@pytest.mark.parametrize("http_status", [403, 404, 503])
def test_nvd_transport_preserves_distinct_rate_limit_and_error_contracts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    http_status: int,
) -> None:
    def error(req, timeout):
        raise urllib.error.HTTPError(
            req.full_url, http_status, "offline fixture", {}, None
        )

    monkeypatch.setattr(vuln_db.urllib.request, "urlopen", error)
    monkeypatch.setattr(vuln_db.CachedNVDClient, "_throttle", lambda self: None)
    client = _client(tmp_path)
    if http_status == 403:
        with pytest.raises(vuln_db.NVDRateLimitError, match="rate limit"):
            client.get_cve("CVE-2026-0001")
    elif http_status == 404:
        assert client.get_cve("CVE-2026-0001") is None
    else:
        with pytest.raises(vuln_db.NVDUnexpectedStatusError, match="503"):
            client.get_cve("CVE-2026-0001")


@pytest.mark.parametrize(
    "payload",
    [
        b"<not-json>",
        b"\xff",
        b"[]",
        b"null",
        b"{}",
        {"vulnerabilities": [{"cve": {"id": "CVE-OTHER"}}]},
    ],
)
def test_bad_nvd_transport_payload_never_invents_a_matching_cve(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    payload: object,
) -> None:
    monkeypatch.setattr(
        vuln_db.urllib.request, "urlopen", lambda req, timeout: _fake_response(payload)
    )
    monkeypatch.setattr(vuln_db.CachedNVDClient, "_throttle", lambda self: None)
    assert _client(tmp_path).get_cve("CVE-2026-0001") is None


@pytest.mark.parametrize(
    "failure",
    [
        urllib.error.URLError("DNS disabled"),
        TimeoutError("request timed out"),
        ValueError("malformed URL"),
    ],
)
def test_nvd_transport_failures_cannot_break_offline_severity_logic(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: Exception,
) -> None:
    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(vuln_db.urllib.request, "urlopen", fail)
    monkeypatch.setattr(vuln_db.CachedNVDClient, "_throttle", lambda self: None)
    client = _client(tmp_path)
    assert client.get_severity("CVE-2026-0001") == "UNKNOWN"


def test_throttle_simulates_clock_without_real_wait(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = []
    monkeypatch.setattr(vuln_db.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(vuln_db.time, "sleep", lambda seconds: observed.append(seconds))
    client = _client(tmp_path)
    client._last_request_at = 9.0
    client._throttle()
    assert observed == [pytest.approx(vuln_db.PUBLIC_MIN_INTERVAL_S - 1.0)]
    client._last_request_at = 0.0
    client._throttle()
    assert len(observed) == 1


def test_cache_rejects_invalid_expired_and_missing_cached_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = vuln_db.CachedNVDClient(cache_dir=tmp_path, offline=True, cache_ttl_s=5.0)
    path = client._cache_path("CVE-2026-0001")
    assert path.parent == tmp_path
    assert client._cache_path("../escape").parent == tmp_path
    for payload in (
        "invalid JSON",
        "[]",
        "{}",
        '{"cve":[]}',
        json.dumps({"cve": {"id": "CVE-2026-0001"}, "cached_at": 1.0}),
    ):
        path.write_text(payload)
        assert client.get_cve("CVE-2026-0001") is None
    monkeypatch.setattr(vuln_db.time, "time", lambda: 100)
    path.write_text(json.dumps({"cve": {"id": "CVE-2026-0001"}, "cached_at": 99.0}))
    assert client.get_cve("CVE-2026-0001") == {"id": "CVE-2026-0001"}


def test_cve_search_ignores_malformed_rows_and_respects_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    client = _client(tmp_path)
    monkeypatch.setattr(
        client,
        "_request",
        lambda params: {
            "vulnerabilities": [
                None,
                {"cve": []},
                {"cve": {"id": 3}},
                {"cve": {"id": "CVE-1"}},
                {"cve": {"id": "CVE-2"}},
                {"cve": {"id": "CVE-3"}},
            ],
        },
    )
    assert client.search_by_keyword("agent", limit=2) == ["CVE-1", "CVE-2"]
    assert client.search_by_keyword("", limit=2) == []
    assert client.search_by_keyword("agent", limit=0) == []


def test_nvd_fixture_loader_rejects_bad_records(tmp_path: Path) -> None:
    path = tmp_path / "cves.json"
    assert vuln_db.load_fixture_cache(path) == {}
    path.write_text("invalid")
    assert vuln_db.load_fixture_cache(path) == {}
    path.write_text(json.dumps({"cves": [None, {}, {"id": True}, {"id": "cve-1"}]}))
    parsed = vuln_db.load_fixture_cache(path)
    assert parsed["CVE-1"]["id"] == "cve-1"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"host": 0, "cve": "CVE-1"},
        {"host": "server", "cve": None},
        {"host": "  ", "cve": "CVE-1"},
    ],
)
def test_enrichment_never_invents_cve_or_host(
    tmp_path: Path,
    payload: dict,
) -> None:
    assert (
        _client(tmp_path, cache={"CVE-1": {"id": "CVE-1"}}).enrich_claim(payload)
        is None
    )


def test_unknown_severity_is_not_a_valid_numeric_cvss_signal() -> None:
    assert vuln_db.severity_for_score(None) == vuln_db.SEVERITY_UNKNOWN
    assert vuln_db.severity_for_score(True) == vuln_db.SEVERITY_UNKNOWN
    assert (
        vuln_db.cvss_from_cve(
            {
                "metrics": {
                    "cvssMetricV31": ["wrong", {"cvssData": {"baseScore": False}}]
                }
            }
        )
        is None
    )
