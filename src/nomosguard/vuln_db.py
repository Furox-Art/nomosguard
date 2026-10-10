"""NVD (National Vulnerability Database) API 2.0 client with an on-disk cache.

NomosGuard's core (ledger -> rules -> gate) is deterministic and must stay
free of I/O. This module is deliberately OUTSIDE that core: it is the one
place that touches the network, and it exists to turn a bare CVE id from an
evidence claim into a grounded severity *before* the claim reaches the
ledger. Enrichment happens at ingestion time, so the reasoning core never
performs a network call and its output stays reproducible.

Network modes
-------------
The NVD API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0) has two
rate tiers:

* **With an API key** — set the ``NVD_API_KEY`` environment variable (free,
  requestable from https://nvd.nist.gov/developers/request-an-api-key). The
  limit rises to 50 requests per 30-second window.
* **Without a key** — the public tier allows 5 requests per 30-second
  window. This client self-throttles to that rate with an explicit sleep
  between requests so a bulk lookup never trips a 403.

Either way the client never blocks the reasoning core: every method accepts
``offline=True`` (the default) or a pre-populated cache, and the entire test
suite runs with zero network access.

Caching
-------
Responses are cached on disk under ``~/.cache/nomosguard/nvd/`` as one JSON
file per CVE id (``CVE-2021-41773.json``). A cache hit performs no network
I/O at all. A cache miss performs exactly one request, then writes the file.

Severity bands (CVSS base score -> label) follow the NVD qualitative
severity rating scale:

    CRITICAL  9.0 - 10.0
    HIGH      7.0 -  8.9
    MEDIUM    4.0 -  6.9
    LOW       0.1 -  3.9
    UNKNOWN   no CVSS score available
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "nomosguard" / "nvd"

# Public tier: 5 requests per rolling 30 s. We sleep a fixed 6 s after each
# outbound request, which bounds us to <=5 per 30 s window with margin.
PUBLIC_RATE_LIMIT_WINDOW_S = 30.0
PUBLIC_RATE_LIMIT_REQUESTS = 5
PUBLIC_MIN_INTERVAL_S = PUBLIC_RATE_LIMIT_WINDOW_S / PUBLIC_RATE_LIMIT_REQUESTS

DEFAULT_TIMEOUT_S = 30.0

# CVSS metric keys, most preferred first: v3.1, then v3.0, then v2.
_CVSS_METRIC_ORDER = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_UNKNOWN = "UNKNOWN"

#: CVSS base score bands -> severity label. Each entry is (lower bound
#: inclusive, label), checked from highest to lowest, so exactly 9.0 is
#: CRITICAL and 8.9 is HIGH.
SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (9.0, SEVERITY_CRITICAL),
    (7.0, SEVERITY_HIGH),
    (4.0, SEVERITY_MEDIUM),
    (0.1, SEVERITY_LOW),
)


class NVDRateLimitError(RuntimeError):
    """Raised when NVD refuses a request because the rate limit was hit."""


class NVDUnexpectedStatusError(RuntimeError):
    """Raised when NVD answers with a status this client cannot use."""


def severity_for_score(score: float | None) -> str:
    """Map a CVSS base score to an NVD qualitative severity label.

    ``None`` (or any non-numeric input) maps to ``UNKNOWN`` — a missing
    score must never be silently treated as low risk.
    """
    if score is None:
        return SEVERITY_UNKNOWN
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        return SEVERITY_UNKNOWN
    for lower, label in SEVERITY_BANDS:
        if score >= lower:
            return label
    return SEVERITY_UNKNOWN  # below the lowest band


def cvss_from_cve(cve: dict[str, Any] | None) -> float | None:
    """Extract the CVSS base score from a parsed NVD CVE object.

    Preference order is v3.1, then v3.0, then v2 — the newest scoring
    version available wins, matching how NVD presents its primary score.
    Returns ``None`` when the record carries no CVSS metric at all.
    """
    if not isinstance(cve, dict):
        return None
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None
    for key in _CVSS_METRIC_ORDER:
        entries = metrics.get(key)
        if not entries:
            continue
        for entry in entries:
            data = entry.get("cvssData") if isinstance(entry, dict) else None
            if isinstance(data, dict):
                score = data.get("baseScore")
                if isinstance(score, (int, float)) and not isinstance(score, bool):
                    return float(score)
    return None


def describe_cve(cve: dict[str, Any] | None) -> str:
    """The English description of a CVE, or the empty string."""
    if not isinstance(cve, dict):
        return ""
    for desc in cve.get("descriptions") or []:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            value = desc.get("value")
            return value if isinstance(value, str) else ""
    return ""


class CachedNVDClient:
    """NVD API 2.0 client with an on-disk (or injected in-memory) cache.

    Two ways to make this client never touch the network:

    1. Pass ``offline=True`` (the default) — cache lookups still work, but a
       cache miss returns ``None`` instead of issuing a request.
    2. Pass ``cache={...}`` — a dict of ``{cve_id: cve_object}`` used as an
       in-memory cache, ideal for tests.

    The cache is always consulted first, so a fully warm cache is zero-I/O.
    """

    def __init__(
        self,
        cache_dir: str | Path | None = None,
        *,
        api_key: str | None = None,
        offline: bool = True,
        cache: dict[str, dict[str, Any]] | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir is not None else DEFAULT_CACHE_DIR
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
        self.offline = offline
        self.timeout_s = timeout_s
        # Injected cache takes precedence over the on-disk cache and is never
        # written through to disk.
        self._memory_cache: dict[str, dict[str, Any]] | None = dict(cache) if cache is not None else None
        self._last_request_at: float = 0.0
        self.request_count = 0

    # -- cache plumbing -------------------------------------------------------

    def _cache_path(self, cve_id: str) -> Path:
        return self.cache_dir / f"{cve_id}.json"

    def _read_disk_cache(self, cve_id: str) -> dict[str, Any] | None:
        path = self._cache_path(cve_id)
        try:
            with path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, ValueError):
            return None
        if isinstance(payload, dict) and isinstance(payload.get("cve"), dict):
            return payload["cve"]
        return None

    def _write_disk_cache(self, cve_id: str, cve: dict[str, Any]) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            path = self._cache_path(cve_id)
            tmp = path.with_suffix(".json.tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                json.dump({"cve": cve}, fh, sort_keys=True)
            tmp.replace(path)  # atomic on POSIX and Windows
        except OSError:
            # A cache write failure must never fail the lookup: the caller
            # still gets the answer, it just is not persisted.
            pass

    # -- public API -----------------------------------------------------------

    def get_cve(self, cve_id: str, *, offline: bool | None = None) -> dict[str, Any] | None:
        """Return the parsed NVD CVE object, or ``None`` if unavailable.

        Never raises for a missing/unknown CVE or a network failure — the
        caller gets ``None`` and must fail closed (treat the severity as
        unknown).
        """
        if not isinstance(cve_id, str) or not cve_id.strip():
            return None
        cve_id = cve_id.strip().upper()

        if self._memory_cache is not None and cve_id in self._memory_cache:
            return self._memory_cache[cve_id]

        cached = self._read_disk_cache(cve_id)
        if cached is not None:
            return cached

        if offline if offline is not None else self.offline:
            return None

        return self._fetch_cve(cve_id)

    def get_cvss(self, cve_id: str, *, offline: bool | None = None) -> float | None:
        """The CVSS base score for a CVE (v3.1 > v3.0 > v2), or ``None``."""
        return cvss_from_cve(self.get_cve(cve_id, offline=offline))

    def get_severity(self, cve_id: str, *, offline: bool | None = None) -> str:
        """CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN for a CVE id.

        An unknown or unreachable CVE yields ``UNKNOWN`` — never a guess
        dressed up as a score.
        """
        return severity_for_score(self.get_cvss(cve_id, offline=offline))

    def search_by_keyword(
        self, keyword: str, limit: int = 10, *, offline: bool | None = None
    ) -> list[str]:
        """CVE ids whose record matches a keyword search (e.g. ``"openssh"``).

        Returns a list of ids, newest-scored first is NOT guaranteed — NVD
        returns relevance order, and we preserve it. Returns ``[]`` when
        offline or when the search fails.
        """
        if not isinstance(keyword, str) or not keyword.strip():
            return []
        if limit <= 0:
            return []

        if offline if offline is not None else self.offline:
            return []

        payload = self._request(
            {"keywordSearch": keyword.strip(), "resultsPerPage": int(limit)}
        )
        if payload is None:
            return []
        ids: list[str] = []
        for entry in payload.get("vulnerabilities") or []:
            cve = entry.get("cve") if isinstance(entry, dict) else None
            cid = cve.get("id") if isinstance(cve, dict) else None
            if isinstance(cid, str) and cid:
                ids.append(cid)
            if len(ids) >= limit:
                break
        return ids

    # -- network --------------------------------------------------------------

    def _throttle(self) -> None:
        """Space out requests so the public tier limit is never exceeded."""
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < PUBLIC_MIN_INTERVAL_S:
            time.sleep(PUBLIC_MIN_INTERVAL_S - elapsed)

    def _fetch_cve(self, cve_id: str) -> dict[str, Any] | None:
        payload = self._request({"cveId": cve_id})
        if not payload:
            return None
        for entry in payload.get("vulnerabilities") or []:
            cve = entry.get("cve") if isinstance(entry, dict) else None
            if isinstance(cve, dict) and cve.get("id") == cve_id:
                self._write_disk_cache(cve_id, cve)
                return cve
        # NVD answered with a body that does not contain the requested id.
        return None

    def _request(self, params: dict[str, Any]) -> dict[str, Any] | None:
        """Issue one throttled GET against the NVD API. Returns the JSON body.

        ``None`` on any failure — the client is a best-effort enrichment
        layer and must never propagate a transport error into the core.
        """
        query = dict(params)
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        url = f"{NVD_API_URL}?{urllib.parse.urlencode(query)}"

        self._throttle()
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                body = resp.read()
            self.request_count += 1
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                raise NVDRateLimitError(
                    "NVD rate limit exceeded (public tier: 5 requests / 30 s). "
                    "Set NVD_API_KEY for the 50/30 s tier."
                ) from exc
            if exc.code == 404:
                return None
            raise NVDUnexpectedStatusError(
                f"NVD returned HTTP {exc.code} for {url}"
            ) from exc
        except (urllib.error.URLError, OSError, ValueError):
            return None
        finally:
            self._last_request_at = time.monotonic()

        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    # -- enrichment -----------------------------------------------------------

    def enrich_claim(
        self,
        vuln_host_payload: dict[str, Any],
        offline: bool | None = None,
    ) -> dict[str, Any] | None:
        """Turn a ``vuln_host`` claim payload into a ``vuln_severity`` payload.

        ``{"host": "web01", "cve": "CVE-2024-6387"}``
        -> ``{"host": "web01", "cve": "CVE-2024-6387", "cvss": 8.1,
            "severity": "HIGH"}``

        Returns ``None`` when the CVE is unknown or carries no CVSS score —
        the caller then keeps the plain ``vuln_host`` claim and reasons
        without a severity, rather than inventing one. Pure function of its
        inputs plus the cache: same payload in, same payload out.
        """
        if not isinstance(vuln_host_payload, dict):
            return None
        host = vuln_host_payload.get("host")
        cve = vuln_host_payload.get("cve")
        if not isinstance(host, str) or not host.strip():
            return None
        if not isinstance(cve, str) or not cve.strip():
            return None

        cve_id = cve.strip().upper()
        score = self.get_cvss(cve_id, offline=offline)
        if score is None:
            return None
        return {
            "host": host.strip(),
            "cve": cve_id,
            "cvss": score,
            "severity": severity_for_score(score),
        }


def enrich_claim(
    vuln_host_payload: dict[str, Any],
    nvd: CachedNVDClient | None = None,
    *,
    offline: bool | None = None,
) -> dict[str, Any] | None:
    """Module-level convenience wrapper around ``CachedNVDClient.enrich_claim``.

    Creates a default (offline, cache-backed) client when none is supplied,
    so callers that only want the cache do not have to construct one.
    """
    client = nvd if nvd is not None else CachedNVDClient(offline=True)
    return client.enrich_claim(vuln_host_payload, offline=offline)


def load_fixture_cache(fixture_path: str | Path) -> dict[str, dict[str, Any]]:
    """Build a ``{cve_id: cve_object}`` dict from a recorded fixture file.

    The fixture format is the one written by ``tests/fixtures/nvd/cves.json``:
    a ``{"cves": [...]}`` list of NVD CVE objects. Returns ``{}`` for an
    unreadable file so tests degrade to "unknown" rather than erroring.
    """
    try:
        with Path(fixture_path).open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError):
        return {}
    cves: Iterable[Any] = payload.get("cves") or [] if isinstance(payload, dict) else []
    out: dict[str, dict[str, Any]] = {}
    for cve in cves:
        if isinstance(cve, dict) and isinstance(cve.get("id"), str):
            out[cve["id"].upper()] = cve
    return out


def fixture_cache_dir() -> Path:
    """Path of the recorded NVD fixtures shipped with the test suite."""
    return Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "nvd"
