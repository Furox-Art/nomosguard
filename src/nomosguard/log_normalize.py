"""Log normalization: different formats -> the shape the engine expects.

The extractors and temporal rules match lines like:
    [08:14:01] auth: src=203.0.113.77:1234 failed password for admin

Real telemetry arrives in other shapes — syslog, CEF, JSON, key=value
with different field names. This module is a deterministic, model-free
adapter layer: each parser is a pure function of its input text, and
the SAME input always normalizes to the SAME output.

The normalized contract (what every format becomes):

    [HH:MM:SS] <category>: src=<ip>:<port> <event keywords> [dbytes=N]

with the keywords the built-in extractors/temporal rules understand:
`failed password`, `SUCCESS password`, `dbytes=`, `action=SCAN`,
`granted`, etc. Parsing is regex-based, not heuristic.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

# -- the normalized shape ------------------------------------------------------
# A normalized line always begins with a bracketed time, then a category,
# then the canonical key=value fields plus event keywords.

_TIME_PATTERNS = [
    re.compile(r"\[(\d{2}:\d{2}:\d{2})\]"),
    re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"),
    re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
]

# common event keyword vocabularies -> canonical keywords
_AUTH_FAIL = re.compile(r"failed|FAILED|failure|auth.?fail", re.I)
_AUTH_SUCCESS = re.compile(r"SUCCESS|accepted|login ok|session opened", re.I)
_SCAN = re.compile(r"scan|probe|SYN|recon|portscan", re.I)
_GRANT = re.compile(r"granted|added to group|privilege", re.I)


@dataclass(frozen=True)
class NormalizedLine:
    """One log line in the canonical shape."""

    time: str
    category: str
    src_ip: str = ""
    src_port: str = ""
    dst_ip: str = ""
    dst_port: str = ""
    dbytes: str = ""
    keywords: tuple[str, ...] = ()

    def render(self) -> str:
        parts = [f"[{self.time}]", f"{self.category}:"]
        if self.src_ip:
            parts.append(f"src={self.src_ip}" + (f":{self.src_port}" if self.src_port else ""))
        if self.dst_ip:
            parts.append(f"dst={self.dst_ip}" + (f":{self.dst_port}" if self.dst_port else ""))
        parts.extend(self.keywords)
        if self.dbytes:
            parts.append(f"dbytes={self.dbytes}")
        return " ".join(parts)


def _canonical_time(text: str) -> str:
    """Extract a time and canonicalize it to [HH:MM:SS] so the temporal
    engine's [HH:MM:SS] pattern matches every normalized line, whatever
    the source format was."""
    import re as _re

    # [HH:MM:SS] already canonical
    m = _re.search(r"\[(\d{2}:\d{2}:\d{2})\]", text)
    if m:
        return m.group(1)
    # ISO: 2026-10-09T08:14:02
    m = _re.search(r"\d{4}-\d{2}-\d{2}[T ](\d{2}:\d{2}:\d{2})", text)
    if m:
        return m.group(1)
    # syslog: 'Oct  9 08:14:01'
    m = _re.search(r"\w{3}\s+\d{1,2}\s+(\d{2}:\d{2}:\d{2})", text)
    if m:
        return m.group(1)
    # bare HH:MM:SS
    m = _re.search(r"(?:^|\s)(\d{2}:\d{2}:\d{2})(?:\s|$)", text)
    if m:
        return m.group(1)
    return "00:00:00"


def _pick_time(text: str) -> str:
    return _canonical_time(text)


def _keywords(text: str) -> tuple[str, ...]:
    kws = []
    if _AUTH_FAIL.search(text):
        kws.append("failed password")
    if _AUTH_SUCCESS.search(text):
        kws.append("SUCCESS password")
    if _SCAN.search(text):
        kws.append("action=SCAN")
    if _GRANT.search(text):
        kws.append("granted privilege")
    return tuple(kws)


# -- format parsers --------------------------------------------------------------

_IP = r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"


def normalize_syslog(line: str) -> NormalizedLine | None:
    """`<time> <host> <proc>[pid]: message` — classic syslog."""
    m = re.match(
        r"^(?P<time>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
        r"(?P<proc>[\w\-]+)(?:\[\d+\])?:\s*(?P<msg>.*)$",
        line,
    )
    if not m:
        return None
    msg = m.group("msg")
    src = dst = sport = dport = dbytes = ""
    m2 = re.search(rf"from\s+({_IP})(?:\s+port\s+(\d+)|:(\d+))?", msg)
    if m2:
        src = m2.group(1)
        sport = m2.group(2) or m2.group(3) or ""
    m3 = re.search(rf"to\s+({_IP})(?:\s+port\s+(\d+)|:(\d+))?", msg)
    if m3:
        dst = m3.group(1)
        dport = m3.group(2) or m3.group(3) or ""
    m4 = re.search(r"bytes[= ](\d{6,})", msg)
    if m4:
        dbytes = m4.group(1)
    return NormalizedLine(
        time=_canonical_time(m.group("time")), category=m.group("proc"),
        src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
        dbytes=dbytes, keywords=_keywords(msg),
    )


def normalize_cef(line: str) -> NormalizedLine | None:
    """`CEF:0|vendor|product|version|sigid|name|severity|extension`"""
    if not line.startswith("CEF:"):
        return None
    fields = line.split("|")
    if len(fields) < 7:
        return None
    name = fields[5]
    ext = fields[7] if len(fields) > 7 else ""
    src = sport = dst = dport = dbytes = ""
    m = re.search(rf"(?:^|\s)src=({_IP})(?::(\d+))?(?![\d.])", ext)
    if m:
        src, sport = m.group(1), m.group(2) or ""
    m = re.search(rf"(?:^|\s)dst=({_IP})(?::(\d+))?(?![\d.])", ext)
    if m:
        dst, dport = m.group(1), m.group(2) or ""
    m = re.search(r"(?:^|\s)out=(\d{6,})", ext)
    if m:
        dbytes = m.group(1)
    return NormalizedLine(
        time=_pick_time(ext), category=name or "cef",
        src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
        dbytes=dbytes, keywords=_keywords(ext + " " + name),
    )


def normalize_json(line: str) -> NormalizedLine | None:
    """A JSON object per line (structured logging)."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(rec, dict):
        return None
    ts = str(rec.get("timestamp") or rec.get("time") or rec.get("@timestamp") or "")
    cat = str(rec.get("event") or rec.get("category") or rec.get("type") or "json")
    src = str(rec.get("src_ip") or rec.get("source_ip") or rec.get("client_ip") or "")
    dst = str(rec.get("dst_ip") or rec.get("dest_ip") or rec.get("server_ip") or "")
    dbytes = str(rec.get("bytes_out") or rec.get("dbytes") or rec.get("out_bytes") or "")
    msg = " ".join(str(v) for v in rec.values() if isinstance(v, str))
    return NormalizedLine(
        time=ts or _pick_time(line), category=cat,
        src_ip=src, dst_ip=dst, dbytes=dbytes, keywords=_keywords(msg),
    )


def normalize_kv(line: str) -> NormalizedLine | None:
    """Generic `key=value key=value` lines (logfmt, firewall dumps)."""
    if "=" not in line:
        return None
    kvs = dict(re.findall(r"(\w+)=(\S+)", line))
    src = kvs.get("src", kvs.get("source", kvs.get("srcip", "")))
    if ":" in src:
        src, sport = src.split(":", 1)
    else:
        sport = kvs.get("sport", "")
    dst = kvs.get("dst", kvs.get("dest", kvs.get("dstip", "")))
    if ":" in dst:
        dst, dport = dst.split(":", 1)
    else:
        dport = kvs.get("dport", "")
    cat = kvs.get("action", kvs.get("category", kvs.get("event", "kv")))
    return NormalizedLine(
        time=kvs.get("time", _pick_time(line)), category=cat,
        src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
        dbytes=kvs.get("dbytes", ""), keywords=_keywords(line),
    )


# The parser chain, tried in order; first match wins.
PARSERS = (normalize_json, normalize_cef, normalize_syslog, normalize_kv)


def normalize_line(line: str) -> NormalizedLine | None:
    """Try each format parser; return the first normalized result."""
    for parser in PARSERS:
        result = parser(line)
        if result is not None:
            return result
    return None


def normalize_logs(lines: list[str]) -> list[str]:
    """Normalize a list of log lines to the canonical shape.

    Lines that no parser understands pass through UNCHANGED (they may
    already be canonical, or they may be noise — either way, silently
    dropping evidence-bearing lines is worse than passing them through).
    Deterministic: same input -> same output.
    """
    out = []
    for line in lines:
        if not line.strip():
            continue
        normalized = normalize_line(line)
        out.append(normalized.render() if normalized else line)
    return out
