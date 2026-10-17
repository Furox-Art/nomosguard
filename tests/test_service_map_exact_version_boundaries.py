"""Offline CVE candidates must preserve half-open version semantics and duplicates."""

from __future__ import annotations

import pytest

from nomosguard import service_cve_map as mapping


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        (None, None),
        ("", None),
        (" ", None),
        ("v", None),
        ("?", None),
        ("1.2.3", (1, 2, 3, 0)),
        ("v1.2", (1, 2, 0, 0)),
        ("v1.2.3g", (1, 2, 3, 7)),
        ("9.6p1", (9, 6, 1, 0)),
        ("1.a", (1, 0, 0, 0)),
    ],
)
def test_version_parser_has_explicit_unknown_states(
    version: str | None, expected: tuple[int, ...] | None
) -> None:
    assert mapping._parse_version(version) == expected


@pytest.mark.parametrize(
    ("version", "start", "end", "match"),
    [
        ("9.9", None, None, True),
        ("invalid", "9", "10", True),
        ("8.8", "8.9", None, False),
        ("9.4", "8.9", "9.4", False),
        ("9.4", "8.9", "9.5", True),
        ("9.4", "invalid", "9.5", True),
        ("9.4", "8.9", "invalid", True),
        ("9.4", None, "9.5", True),
        ("9.4", "8.9", None, True),
    ],
)
def test_half_open_ranges_do_not_hide_unparseable_versions(
    version: str, start: str | None, end: str | None, match: bool
) -> None:
    assert mapping._version_in_range(version, start, end) is match


def test_service_matching_does_not_invent_results_from_empty_inputs() -> None:
    entry = mapping.ServiceEntry("Custom", ("custom", "banner"))
    assert not mapping._matches_service(entry, "  ")
    assert mapping._matches_service(entry, "CUSTOM")
    assert mapping._matches_service(entry, "service-banner")
    assert not mapping._matches_service(entry, "unrelated")
    assert mapping.service_entries(None) == []
    assert mapping.service_entries(" ") == []
    assert mapping.cves_for_service(100) == []
    assert mapping.cves_for_service("  ") == []


def test_duplicate_candidates_keep_original_map_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = (
        mapping.ServiceEntry(
            "Custom",
            ("custom",),
            cves=(
                ("CVE-2024-0001", None, None),
                ("CVE-2024-0002", "2.0", "3.0"),
            ),
        ),
        mapping.ServiceEntry(
            "Custom-addendum",
            ("custom",),
            cves=(
                ("CVE-2024-0001", None, None),
                ("CVE-2024-0003", "3.0", None),
            ),
        ),
    )
    monkeypatch.setattr(mapping, "SERVICE_MAP", entries)
    assert mapping.cves_for_service("Custom", "2.5") == [
        "CVE-2024-0001",
        "CVE-2024-0002",
    ]
    assert mapping.cves_for_service("Custom", "3.0") == [
        "CVE-2024-0001",
        "CVE-2024-0003",
    ]
    assert mapping.service_entries("Custom") == list(entries)
    assert mapping.all_cve_ids() == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
    result = mapping.map_summary()
    assert result["cve_count"] == 3
    assert result["services"] == ["Custom", "Custom-addendum"]
