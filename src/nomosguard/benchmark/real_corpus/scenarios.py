"""Real-corpus scenarios from UNSW-NB15 (network telemetry, HuggingFace).

The synthetic corpus could not establish performance on real telemetry.
These scenarios are built from real UNSW-NB15 flow records, with ground
truth taken from the dataset's own attack labels — a flow labeled
'Exploits' from src to dst means the attacker (src) can reach the
destination service (dst:port), and the target carries an exploitable
vulnerability.

Fetch: python3 -m nomosguard.benchmark.real_corpus.fetch
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RealScenario:
    name: str
    raw_logs: str
    expected_claims: tuple[tuple[str, dict], ...]
    source: str


def fetch_unsw_rows(count: int = 300, cache_dir: str | Path | None = None) -> list[dict]:
    """Fetch real UNSW-NB15 rows (no key, no registration)."""
    cache_dir = Path(cache_dir or "~/.cache/nomosguard").expanduser()
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache = cache_dir / f"unsw_{count}.json"
    if cache.is_file():
        return json.loads(cache.read_text())

    rows: list[dict] = []
    api = "https://datasets-server.huggingface.co/rows"
    offset = 0
    while len(rows) < count:
        length = min(100, count - len(rows))
        url = (f"{api}?dataset=Mouwiya%2FUNSW-NB15&config=default"
               f"&split=train&offset={offset}&length={length}")
        with urllib.request.urlopen(url, timeout=60) as r:
            data = json.loads(r.read())
        batch = [x["row"] for x in data.get("rows", [])]
        if not batch:
            break
        rows.extend(batch)
        offset += length
    cache.write_text(json.dumps(rows))
    return rows


def row_to_logline(r: dict, idx: int) -> str:
    return (
        f"[flow {idx}] {r.get('proto', '?')} "
        f"src={r.get('srcip', '?')}:{r.get('sport', '?')} "
        f"dst={r.get('dstip', '?')}:{r.get('dsport', '?')} "
        f"service={r.get('service', '?')} state={r.get('state', '?')} "
        f"sbytes={r.get('sbytes', 0)} dbytes={r.get('dbytes', 0)} "
        f"label={r.get('label', 0)} cat={r.get('attack_cat') or 'normal'}"
    )


def row_to_claims(r: dict) -> list[tuple[str, dict]]:
    """Ground truth from the dataset label."""
    if not r.get("label", 0):
        return []
    claims = [("network", {
        "host": r["dstip"],
        "port": int(r["dsport"]) if str(r.get("dsport", "")).isdigit() else 0,
        "allowed_from": r["srcip"],
        "protocol": r.get("proto", "tcp"),
    })]
    if r.get("attack_cat") == "Exploits":
        claims.append(("vuln_host", {"host": r["dstip"], "cve": "UNSW-EXPLOIT"}))
    return claims


def build_scenarios(rows: list[dict]) -> list[RealScenario]:
    from collections import defaultdict

    by_cat: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    for i, r in enumerate(rows):
        if r.get("label", 0) == 1:
            by_cat[r.get("attack_cat", "Unknown")].append((i, r))

    scenarios = []
    for cat, entries in sorted(by_cat.items()):
        if not entries:
            continue
        logs = [row_to_logline(r, i) for i, r in entries[:5]]
        expected: list[tuple[str, dict]] = []
        seen: set[str] = set()
        for _, r in entries[:5]:
            for kind, payload in row_to_claims(r):
                key = f"{kind}:{json.dumps(payload, sort_keys=True)}"
                if key not in seen:
                    seen.add(key)
                    expected.append((kind, payload))
        if not expected:
            continue
        scenarios.append(RealScenario(
            name=f"unsw_{cat.lower()}",
            raw_logs="\n".join(logs),
            expected_claims=tuple(expected),
            source="UNSW-NB15 (real network telemetry, HuggingFace)",
        ))
    return scenarios


def load_scenarios(count: int = 300) -> list[RealScenario]:
    """Fetch (or load cached) real telemetry and build scenarios."""
    rows = fetch_unsw_rows(count)
    return build_scenarios(rows)
