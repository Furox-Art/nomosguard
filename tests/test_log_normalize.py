"""Log normalization: syslog, CEF, JSON, key=value -> canonical shape.

The property that matters: the normalized output drives the SAME
temporal rules and extractors as natively-canonical logs, so a
normalized syslog line about a brute force produces the same
bruteForceDetected fact as a canonical one.
"""

from __future__ import annotations

import re

from nomosguard.log_normalize import (
    normalize_cef,
    normalize_json,
    normalize_kv,
    normalize_logs,
    normalize_syslog,
)


class TestSyslog:
    def test_failed_auth_extracts_src_and_keyword(self):
        r = normalize_syslog(
            "Oct  9 08:14:01 fw sshd[1234]: Failed password for admin from 203.0.113.77 port 1234"
        )
        assert r is not None
        assert r.src_ip == "203.0.113.77"
        assert r.src_port == "1234"
        assert "failed password" in r.keywords
        assert "203.0.113.77:1234" in r.render()

    def test_success_auth(self):
        r = normalize_syslog(
            "Oct  9 08:14:25 fw sshd[9]: Accepted password for admin from 203.0.113.77 port 1234"
        )
        assert r is not None
        assert "SUCCESS password" in r.keywords

    def test_not_syslog_returns_none(self):
        assert normalize_syslog('{"a": 1}') is None


class TestCef:
    def test_src_dst_extracted(self):
        r = normalize_cef(
            "CEF:0|Acme|FW|1.0|100|Blocked SSH|7|src=203.0.113.77:1234 dst=10.0.0.5:22"
        )
        assert r is not None
        assert r.src_ip == "203.0.113.77"
        assert r.src_port == "1234"
        assert r.dst_ip == "10.0.0.5"

    def test_not_cef_returns_none(self):
        assert normalize_cef("plain log line") is None


class TestJson:
    def test_structured_fields(self):
        r = normalize_json(
            '{"timestamp": "08:20:11", "event": "netflow", "src_ip": "10.0.0.5",'
            ' "dst_ip": "10.0.0.9", "bytes_out": 3500000}'
        )
        assert r is not None
        assert r.src_ip == "10.0.0.5"
        assert r.dst_ip == "10.0.0.9"
        assert r.dbytes == "3500000"

    def test_invalid_json_returns_none(self):
        assert normalize_json("{not json") is None


class TestKv:
    def test_key_value_fields(self):
        r = normalize_kv("time=08:33:10 action=SCAN src=203.0.113.77 dst=web02:443")
        assert r is not None
        assert r.src_ip == "203.0.113.77"
        assert r.dst_ip == "web02"       # port is split off
        assert r.dst_port == "443"
        assert "action=SCAN" in r.keywords


class TestNormalizeLogs:
    def test_mixed_formats_all_normalized(self):
        out = normalize_logs([
            "Oct  9 08:14:01 fw sshd[1]: Failed password for admin from 203.0.113.77 port 1234",
            '{"timestamp": "08:20:11", "event": "netflow", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "bytes_out": 3500000}',
            "time=08:33:10 action=SCAN src=203.0.113.77 dst=web02:443",
        ])
        assert len(out) == 3
        assert "203.0.113.77:1234" in out[0]
        assert "dbytes=3500000" in out[1]
        assert "action=SCAN" in out[2]

    def test_unknown_format_passes_through(self):
        """Unparseable lines pass through unchanged — never drop evidence."""
        out = normalize_logs(["some completely free-form log line"])
        assert out == ["some completely free-form log line"]

    def test_blank_lines_skipped(self):
        assert normalize_logs(["", "   "]) == []

    def test_deterministic(self):
        lines = [
            "Oct  9 08:14:01 fw sshd[1]: Failed password for admin from 203.0.113.77 port 1234",
        ]
        assert normalize_logs(lines) == normalize_logs(lines)


class TestEndToEndWithTemporal:
    def test_normalized_syslog_feeds_temporal(self):
        """The whole point: a syslog brute force, after normalization,
        drives the temporal rule engine exactly like a canonical log."""
        from nomosguard.temporal import default_temporal_rules
        from nomosguard.temporal_bridge import run_temporal_into_ledger

        syslog_lines = [
            f"Oct  9 08:14:0{i} fw sshd[1]: Failed password for admin from 203.0.113.77 port 1234"
            for i in range(1, 6)
        ]
        normalized = normalize_logs(syslog_lines)
        ledger, _temporal = run_temporal_into_ledger(normalized, default_temporal_rules())
        assert any("brute_force" in str(e.claim.kind) for e in ledger.entries)


# -- additional formats (v2) ---------------------------------------------------

from nomosguard.log_normalize import normalize_xml, normalize_gelf, normalize_pipe


class TestXml:
    def test_firewall_event(self):
        r = normalize_xml(
            "<Event><TimeStamp>2026-10-09T08:33:10</TimeStamp><Provider>Firewall</Provider>"
            "<SourceIp>203.0.113.77</SourceIp><DestAddress>web02</DestAddress>"
            "<Action>SCAN</Action></Event>"
        )
        assert r is not None
        assert r.src_ip == "203.0.113.77"
        assert "action=SCAN" in r.keywords

    def test_not_xml_returns_none(self):
        assert normalize_xml("plain text") is None


class TestGelf:
    def test_epoch_timestamp_canonicalized(self):
        r = normalize_gelf(
            '{"version": "1.1", "host": "fw1", "timestamp": 1728466442.5,'
            ' "short_message": "failed password for admin", "_src_ip": "203.0.113.77"}'
        )
        assert r is not None
        assert re.match(r"^\d{2}:\d{2}:\d{2}$", r.time)
        assert r.src_ip == "203.0.113.77"
        assert "failed password" in r.keywords

    def test_plain_json_is_not_gelf(self):
        assert normalize_gelf('{"a": 1}') is None


class TestPipe:
    def test_windows_style_record(self):
        r = normalize_pipe(
            "Time:08:33:10|Action:SCAN|SourceAddress:203.0.113.77|DestAddress:web02|DestPort:443"
        )
        assert r is not None
        assert r.src_ip == "203.0.113.77"
        assert r.dst_ip == "web02"
        assert "action=SCAN" in r.keywords

    def test_not_pipe_returns_none(self):
        assert normalize_pipe("no delimiters here") is None
