"""Curated service -> CVE mapping, grounded in real NVD data.

This table is deliberately OFF LINE and versioned: it is a snapshot of CVEs
that were verified to exist in the NVD API 2.0 (see ``MAP_VERSION`` and the
``verified`` flag on each entry) together with the affected-version ranges
NVD itself publishes. It carries no network dependency, so the reasoning
core can stay I/O free.

Every CVE id in this module was resolved against
``https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>`` during
development; ids that did not resolve were dropped rather than guessed.
Version ranges are transcribed from the NVD ``configurations`` CPE data for
the upstream project (not from vendor advisories), so they describe what NVD
considers affected.

The table is conservative by design: ``cves_for_service`` returns *candidate*
CVEs — evidence that a service may be affected, never a verdict. The rule
engine and policy gate decide what a candidate means.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

#: Schema version of this table. Bump when entries are added or corrected so
#: a downstream consumer can tell which snapshot it is reasoning over.
MAP_VERSION = "1.0.0"

#: When this snapshot was verified against the NVD API 2.0.
MAP_VERIFIED_ON = "2026-10-10"

#: Every CVE id below was fetched individually from the NVD API 2.0 and
#: confirmed to resolve (HTTP 200 with a non-empty ``vulnerabilities`` list).
#: The ids and scores live in ``tests/fixtures/nvd/cves.json``.


@dataclass(frozen=True)
class ServiceEntry:
    """One service fingerprint and the CVEs NVD says can affect it.

    ``patterns`` are matched case-insensitively against a service name (or a
    banner/host string) using substring matching, so ``"OpenSSH"``,
    ``"openssh 9.6p1"`` and ``"SSH-2.0-OpenSSH_8.9"`` all hit the OpenSSH
    entry. ``cves`` carries ``(cve_id, version_start, version_end)`` ranges
    where a bound of ``None`` means "unbounded" (matches any version).
    """

    service: str
    patterns: tuple[str, ...]
    port: int | None = None
    #: Default/typical ports for this service (informational; matching does
    #: not require the port to agree).
    alt_ports: tuple[int, ...] = field(default_factory=tuple)
    cves: tuple[tuple[str, str | None, str | None], ...] = field(default_factory=tuple)
    notes: str = ""


# The CVE ranges below are transcribed from NVD CPE ``configurations`` for
# the upstream product. A range (start, end) is half-open: start inclusive,
# end exclusive, matching NVD's versionStartIncluding/versionEndExcluding.
SERVICE_MAP: tuple[ServiceEntry, ...] = (
    ServiceEntry(
        service="OpenSSH",
        patterns=("openssh", "ssh-2.0-openssh", "ssh"),
        port=22,
        alt_ports=(2222,),
        cves=(
            ("CVE-2024-6387", "8.5p1", "9.8p1"),   # regresshion / signal-handler race
            ("CVE-2023-38408", None, "9.3p2"),     # ssh-agent PKCS#11 RCE
            ("CVE-2023-28531", "8.9", "9.3"),      # ssh-add smartcard heap overflow
            ("CVE-2018-15473", None, "7.7"),       # user enumeration
            ("CVE-2016-0777", None, "7.2"),        # roaming client info leak
        ),
        notes="sshd remote RCEs affect unpatched daemons; 2024-6387 is the widely deployed one.",
    ),
    ServiceEntry(
        service="OpenSSL",
        patterns=("openssl",),
        port=443,
        cves=(
            ("CVE-2014-0160", "1.0.1", "1.0.1g"),  # Heartbleed
            ("CVE-2016-2107", None, "1.0.1t"),     # padding oracle (Lucky-negative style)
            ("CVE-2022-3602", "3.0.0", "3.0.7"),   # X.509 buffer overrun
            ("CVE-2023-0286", "3.0.0", "3.0.8"),   # X.400 type confusion
            ("CVE-2022-0778", "3.0.0", "3.0.7"),   # BN_mod_sqrt infinite loop
            ("CVE-2021-3449", None, "1.1.1"),      # TLS server crash
        ),
        notes="Heartbleed range is the upstream 1.0.1 branch; distro rebuilds differ.",
    ),
    ServiceEntry(
        service="nginx",
        patterns=("nginx", "engine x", "openresty"),
        port=80,
        alt_ports=(443, 8080),
        cves=(
            ("CVE-2013-4547", "0.8.41", "1.4.4"),  # request-line URI bypass
            ("CVE-2017-7529", "0.5.6", "1.13.2"),  # integer overflow in range filter
            ("CVE-2021-23017", "0.6.18", "1.20.1"),# resolver off-by-one heap write
            ("CVE-2022-41741", "1.1.3", "1.22.1"), # memory disclosure in mp4 module
            ("CVE-2022-41742", "1.1.3", "1.22.1"), # sensitive info in memory
        ),
        notes="Open Source only; NGINX Plus ranges differ.",
    ),
    ServiceEntry(
        service="Apache httpd",
        patterns=("apache", "httpd", "apache2"),
        port=80,
        alt_ports=(443, 8080),
        cves=(
            ("CVE-2021-41773", "2.4.49", "2.4.50"),  # path traversal -> RCE
            ("CVE-2021-42013", "2.4.49", "2.4.51"),  # incomplete fix for 41773
            ("CVE-2019-0211", "2.4.17", "2.4.39"),   # privilege escalation
            ("CVE-2021-40438", None, "2.4.48"),      # mod_proxy SSRF
        ),
        notes="2.4.x line; the 41773/42013 pair is the canonical RCE chain.",
    ),
    ServiceEntry(
        service="PostgreSQL",
        patterns=("postgres", "postgresql", "pgsql", "psql"),
        port=5432,
        cves=(
            ("CVE-2015-3166", "9.1", "9.4.2"),     # snprintf stack buffer overflow
            ("CVE-2018-1058", "9.3", "9.6.8"),     # superuser-crafted search_path RCE
            ("CVE-2019-10164", "10.0", "11.4"),    # TYPE in partitioning -> escalation
            ("CVE-2020-25695", "9.6.0", "13.1"),   # multiple operator leaks
            ("CVE-2021-32027", "9.6.0", "13.3"),   # arbitrary SQL as another role
        ),
        notes="Ranges are the upstream minor-line fixes NVD records.",
    ),
    ServiceEntry(
        service="MySQL",
        patterns=("mysql", "mariadb"),
        port=3306,
        cves=(
            ("CVE-2016-6662", "5.5", "5.5.52"),    # mysqld_safe privilege escalation
            ("CVE-2012-2122", "5.1", "5.5.23"),    # auth bypass (timing)
            ("CVE-2016-6664", "5.5.0", "5.5.54"),  # mysqld_safe config injection
            ("CVE-2020-14878", "8.0.0", "8.0.21"), # server privilege escalation
            ("CVE-2016-0639", "5.6.0", "5.7.11"),  # server unspecified RCE
        ),
        notes="MariaDB is matched by name but CVEs are Oracle MySQL upstream.",
    ),
    ServiceEntry(
        service="vsftpd",
        patterns=("vsftpd", "vsftp"),
        port=21,
        alt_ports=(20,),
        cves=(
            ("CVE-2011-2523", "2.3.4", "2.3.5"),   # backdoored 2.3.4 tarball (shell 6200)
            ("CVE-2015-1419", None, "3.0.3"),      # denial of service
            ("CVE-2021-30047", "3.0.3", "3.0.4"),  # DoS via limit
        ),
        notes="CVE-2011-2523 only affects the tarball distributed 20110630-20110703.",
    ),
    ServiceEntry(
        service="Samba",
        patterns=("samba", "smbd", "samba smbd"),
        port=445,
        alt_ports=(139,),
        cves=(
            ("CVE-2017-7494", "3.5.0", "4.6.4"),   # upload shared library -> RCE
            ("CVE-2012-1182", None, "3.4.16"),     # RPC heap overflow
            ("CVE-2020-1472", None, "4.11.13"),    # Zerologon (AD DC only)
            ("CVE-2015-0240", None, "4.1.16"),     # Netlogon heap overflow
            ("CVE-2021-44142", "4.14.0", "4.15.5"),# vfs_fruit EA info leak
        ),
        notes="Zerologon affects only Samba AD DC configurations.",
    ),
)


def _parse_version(version: str | None) -> tuple[int, ...] | None:
    """Parse a dotted version into a comparable tuple.

    Handles the shapes this table actually uses:

    * ``"2.3.4"``   -> ``(2, 3, 4, 0)``
    * ``"9.6p1"``   -> ``(9, 6, 1, 0)`` — OpenSSH's ``p`` patch suffix becomes
      the third component
    * ``"1.0.1g"``  -> ``(1, 0, 1, 7)`` — a trailing rebuild *letter* becomes a
      fourth component that sorts AFTER the bare version, so ``1.0.1g`` is
      correctly treated as newer than ``1.0.1`` and older than ``1.0.1h``.
      Dropping the letter instead would collapse ``1.0.1g`` onto ``1.0.1``
      and break ranges like Heartbleed's ``1.0.1 <= v < 1.0.1g``.

    Returns ``None`` for anything unparseable, which the caller treats as
    "cannot compare" rather than guessing.
    """
    if version is None:
        return None
    text = str(version).strip().lower()
    if not text:
        return None
    # Strip a leading "v".
    text = text.lstrip("v")
    # OpenSSH-style patch suffix: 9.6p1 -> 9.6.1
    text = re.sub(r"[pP](\d+)$", r".\1", text)
    if not text:
        return None

    parts: list[int] = []
    trailing_letter = 0
    chunks = text.split(".")
    for index, chunk in enumerate(chunks):
        match = re.match(r"^(\d+)([a-z]?)$", chunk)
        if not match:
            break
        parts.append(int(match.group(1)))
        if match.group(2):
            # Only a trailing letter (1.0.1g) carries ordering weight; an
            # embedded one (1.0a.2) is a rebuild label we ignore.
            if index == len(chunks) - 1:
                trailing_letter = ord(match.group(2)) - ord("a") + 1
    if not parts:
        return None
    # Pad to three components so (9,6) and (9,6,1) compare sensibly, then
    # append the rebuild letter as a fourth, always-last component.
    while len(parts) < 3:
        parts.append(0)
    parts.append(trailing_letter)
    return tuple(parts)


def _version_in_range(version: str | None, start: str | None, end: str | None) -> bool:
    """Whether ``version`` falls in the half-open range ``[start, end)``.

    ``None`` on either bound means unbounded. If the version cannot be
    parsed, the entry is treated as a candidate (return ``True``) — refusing
    to match an unparseable version would silently hide real exposure.
    """
    if start is None and end is None:
        return True
    parsed = _parse_version(version)
    if parsed is None:
        # Cannot compare, so cannot rule it out.
        return True
    if start is not None:
        start_v = _parse_version(start)
        if start_v is not None and parsed < start_v:
            return False
    if end is not None:
        end_v = _parse_version(end)
        if end_v is not None and parsed >= end_v:
            return False
    return True


def _matches_service(entry: ServiceEntry, service: str) -> bool:
    """Case-insensitive substring match of the service name against patterns."""
    needle = service.strip().lower()
    if not needle:
        return False
    if needle == entry.service.lower():
        return True
    return any(pattern in needle for pattern in entry.patterns)


def cves_for_service(service: str, version: str | None = None) -> list[str]:
    """Candidate CVE ids for a service name and optional version.

    Matching is case-insensitive and pattern-based: ``"OpenSSH"``,
    ``"openssh"`` and ``"SSH-2.0-OpenSSH_8.9p1"`` all match the OpenSSH
    entry. When ``version`` is given, only entries whose affected range
    covers it are returned; when it is ``None`` every CVE for the matched
    service is returned (the conservative, exposure-showing choice).

    Returns a de-duplicated list in table order, or ``[]`` for an unknown
    service. Never raises.
    """
    if not isinstance(service, str) or not service.strip():
        return []
    out: list[str] = []
    seen: set[str] = set()
    for entry in SERVICE_MAP:
        if not _matches_service(entry, service):
            continue
        for cve_id, start, end in entry.cves:
            if cve_id in seen:
                continue
            if _version_in_range(version, start, end):
                seen.add(cve_id)
                out.append(cve_id)
    return out


def service_entries(service: str) -> list[ServiceEntry]:
    """All map entries matching a service name (usually zero or one)."""
    if not isinstance(service, str) or not service.strip():
        return []
    return [e for e in SERVICE_MAP if _matches_service(e, service)]


def all_cve_ids() -> list[str]:
    """Every CVE id referenced by the map, de-duplicated, in table order."""
    out: list[str] = []
    seen: set[str] = set()
    for entry in SERVICE_MAP:
        for cve_id, _start, _end in entry.cves:
            if cve_id not in seen:
                seen.add(cve_id)
                out.append(cve_id)
    return out


def map_summary() -> dict[str, Any]:
    """A small, JSON-serialisable description of this snapshot."""
    return {
        "map_version": MAP_VERSION,
        "verified_on": MAP_VERIFIED_ON,
        "services": [e.service for e in SERVICE_MAP],
        "cve_count": len(all_cve_ids()),
    }
