"""Temporal rules: time-window correlation over timestamped events.

The static rule engine asks "what facts exist?". Temporal rules ask
"what happened too often, too fast, or in a suspicious order?". A brute
force is not one failed login — it is 14 failed logins in 40 seconds
from one source. That pattern only exists in the TIME dimension.

This module is deterministic: it groups events by a key within a time
window, counts them, and emits facts when thresholds are crossed. No
model, no probability — the same events always produce the same facts.

The emitted facts flow into the same ledger and rule engine as
extractor claims, so a brute-force fact can participate in attack
graph derivation like any other evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Timestamp extraction: [HH:MM:SS] prefix, ISO-8601, or epoch seconds.
_TS_PATTERNS = [
    re.compile(r"\[(\d{2}):(\d{2}):(\d{2})\]"),          # [08:14:02]
    re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"),  # ISO
    re.compile(r"^(\d{9,13})(?:\s|$|\|)"),                  # epoch seconds
]


def _to_seconds(line: str) -> int | None:
    """Extract a timestamp as epoch-ish seconds (relative or absolute)."""
    for pat in _TS_PATTERNS:
        m = pat.search(line)
        if not m:
            continue
        groups = m.groups()
        if len(groups) == 3:  # HH:MM:SS
            h, mi, s = (int(g) for g in groups)
            return h * 3600 + mi * 60 + s
        if len(groups) == 6:  # ISO
            import datetime
            y, mo, d, h, mi, s = (int(g) for g in groups)
            try:
                return int(datetime.datetime(y, mo, d, h, mi, s,
                                             tzinfo=datetime.timezone.utc).timestamp())
            except ValueError:
                return None
        if len(groups) == 1:  # epoch
            v = int(groups[0])
            return v // 1000 if v > 10_000_000_000 else v
    return None


@dataclass(frozen=True)
class TemporalRule:
    """A threshold rule over a time window.

    group_by: a regex capturing the grouping key (e.g. the source IP)
              from each event line.
    match:    a regex the event line must contain to count.
    threshold: how many matching events within `window_s` seconds.
    emits:    (kind, payload_builder) — the fact to produce when the
              threshold is crossed.
    """

    name: str
    group_by: str            # regex with one capture group
    match: str               # regex the line must match
    threshold: int
    window_s: int
    fact_relation: str       # e.g. "bruteForceDetected"
    fact_object: str = "brute_force"
    description: str = ""


@dataclass
class TemporalResult:
    facts: list[tuple[str, str, str]] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {"temporal_facts": len(self.facts), **self.report}


def evaluate_temporal(
    lines: list[str],
    rules: list[TemporalRule],
) -> TemporalResult:
    """Apply temporal rules to timestamped event lines.

    Deterministic: same lines + same rules -> same facts, always.
    """
    parsed: list[tuple[int, str]] = []
    for ln in lines:
        ts = _to_seconds(ln)
        if ts is not None:
            parsed.append((ts, ln))

    all_facts: list[tuple[str, str, str]] = []
    report: dict[str, Any] = {}

    for rule in rules:
        match_re = re.compile(rule.match)
        group_re = re.compile(rule.group_by)
        # group events by the rule's key
        groups: dict[str, list[tuple[int, str]]] = {}
        for ts, ln in parsed:
            if not match_re.search(ln):
                continue
            gm = group_re.search(ln)
            if not gm:
                continue
            groups.setdefault(gm.group(1), []).append((ts, ln))

        fired: list[str] = []
        for key, events in groups.items():
            events.sort(key=lambda e: e[0])
            # sliding window: check any window of `threshold` events
            # fitting inside window_s
            hit = False
            for i in range(len(events)):
                window_events = [
                    e for e in events[i:]
                    if e[0] - events[i][0] <= rule.window_s
                ]
                if len(window_events) >= rule.threshold:
                    hit = True
                    break
            if hit:
                all_facts.append((key, rule.fact_relation, rule.fact_object))
                fired.append(key)
        report[rule.name] = {
            "groups": len(groups),
            "fired_for": fired,
        }

    return TemporalResult(facts=all_facts, report=report)


def default_temporal_rules() -> list[TemporalRule]:
    """The built-in temporal rules (deterministic, no model)."""
    return [
        TemporalRule(
            name="brute_force",
            group_by=r"src=(\S+?):",          # the source address
            match=r"failed|FAILED|failure",       # failed auth events
            threshold=5,
            window_s=120,                         # within 2 minutes
            fact_relation="bruteForceDetected",
            fact_object="brute_force",
            description="5+ failed auth events from one source within 2 minutes",
        ),
        TemporalRule(
            name="port_scan",
            group_by=r"src=(\S+?):",
            match=r"scan|probe|recon|SYN",        # scanning behavior
            threshold=10,
            window_s=60,
            fact_relation="scanDetected",
            fact_object="port_scan",
            description="10+ scan/probe events from one source within 1 minute",
        ),
        TemporalRule(
            name="exfil_burst",
            group_by=r"dst=(\S+?):",          # the destination
            match=r"dbytes=\d{6,}",             # large outbound transfers
            threshold=3,
            window_s=300,
            fact_relation="exfilSuspected",
            fact_object="exfiltration",
            description="3+ large outbound transfers to one destination within 5 minutes",
        ),
    ]
