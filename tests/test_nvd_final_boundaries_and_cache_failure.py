"""NVD 2.0 parser and cache fault boundaries are deterministic and offline."""

from __future__ import annotations

from pathlib import Path

import pytest

from nomosguard import vuln_db


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (None, None),
        ([], None),
        ({"metrics": "not a mapping"}, None),
        ({"metrics": {"cvssMetricV31": []}}, None),
        ({"metrics": {"cvssMetricV31": [None, {"cvssData": "bad"}]}}, None),
        ({"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": True}}]}}, None),
        ({"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]}}, 7.5),
    ],
)
def test_cvss_nested_metric_types_never_coerce_booleans(
    record: object, expected: float | None
) -> None:
    assert vuln_db.cvss_from_cve(record) == expected


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (None, ""),
        (False, ""),
        ({"descriptions": []}, ""),
        ({"descriptions": [{"lang": "fr", "value": "French"}]}, ""),
        ({"descriptions": [{"lang": "en", "value": 3}]}, ""),
        ({"descriptions": [{"lang": "en", "value": "English"}]}, "English"),
        ({"descriptions": [False, {"lang": "en", "value": "Real"}]}, "Real"),
    ],
)
def test_description_only_accepts_english_text(record: object, expected: str) -> None:
    assert vuln_db.describe_cve(record) == expected


def test_offline_client_ignores_disk_cache_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = vuln_db.CachedNVDClient(cache_dir=tmp_path / "restricted")

    def deny_mkdir(*args, **kwargs):
        raise PermissionError("cache dir deliberately not writable")

    monkeypatch.setattr(Path, "mkdir", deny_mkdir)
    client._write_disk_cache("CVE-2021-41773", {"id": "CVE-2021-41773"})
    assert not (tmp_path / "restricted").exists()


def test_online_keyword_search_rejects_garbled_payloads_and_preserves_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = vuln_db.CachedNVDClient(cache_dir=tmp_path, offline=False)
    monkeypatch.setattr(client, "_request", lambda params: None)
    assert client.search_by_keyword("server") == []
    monkeypatch.setattr(
        client,
        "_request",
        lambda params: {
            "vulnerabilities": [
                "invalid",
                {"cve": None},
                {"cve": {"id": 9}},
                {"cve": {"id": "CVE-2025-001"}},
                {"cve": {"id": "CVE-2025-002"}},
            ],
        },
    )
    assert client.search_by_keyword(" server ", limit=1) == ["CVE-2025-001"]
    assert client.search_by_keyword("server", limit=2) == [
        "CVE-2025-001",
        "CVE-2025-002",
    ]
    assert client.search_by_keyword("", limit=2) == []
    assert client.search_by_keyword("server", limit=0) == []


def test_recorded_fixture_contract_is_root_relative() -> None:
    root = vuln_db.fixture_cache_dir()
    assert root.parts[-3:] == ("tests", "fixtures", "nvd")
    fixture = root / "cves.json"
    assert fixture.is_file()
    records = vuln_db.load_fixture_cache(fixture)
    assert isinstance(records, dict) and records
    assert all(key == key.upper() for key in records)
