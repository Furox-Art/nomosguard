"""Real format parser boundaries, evidence-preserving normalization and timestamps."""

from __future__ import annotations

import json

import pytest

from nomosguard import log_normalize as n


def test_render_all_optional_fields_and_event_keywords():
    rec = n.NormalizedLine(
        time="08:14:03", category="auth", src_ip="192.0.2.1", src_port="443",
        dst_ip="198.51.100.20", dst_port="80", dbytes="900000",
        keywords=("failed password",),
    )
    rendered = rec.render()
    for part in ("[08:14:03]", "src=192.0.2.1:443", "dst=198.51.100.20:80", "failed password", "dbytes=900000"):
        assert part in rendered


def test_render_without_ports_preserves_host_only_identifiers():
    rec = n.NormalizedLine(time="00:00:00", category="net", dst_ip="198.51.100.1")
    assert rec.render() == "[00:00:00] net: dst=198.51.100.1"


@pytest.mark.parametrize("text,expected", [
    ("[01:02:03] auth", "01:02:03"),
    ("2026-10-18T04:05:06 firewall", "04:05:06"),
    ("Oct  9 08:14:01 host", "08:14:01"),
    ("manual 11:12:13 recorded", "11:12:13"),
    ("not timestamped", "00:00:00"),
])
def test_timestamps_are_canonical_or_honestly_unknown(text, expected):
    assert n._canonical_time(text) == expected


def test_granted_privilege_detection_is_not_dropped():
    assert "granted privilege" in n._keywords("user was added to group admin")


def test_syslog_retains_destination_address_port_and_large_byte_count():
    line = "Oct  9 08:14:01 host firewall[11]: from 192.0.2.1:51515 to 198.51.100.1 port 443 bytes=1000000"
    out = n.normalize_syslog(line)
    assert out is not None
    assert (out.src_ip, out.src_port, out.dst_ip, out.dst_port, out.dbytes) == ("192.0.2.1", "51515", "198.51.100.1", "443", "1000000")


def test_cef_rejects_incomplete_extension_fields():
    assert n.normalize_cef("CEF:0|vendor") is None


def test_cef_extension_preserves_large_output_and_destination():
    line = "CEF:0|vendor|product|version|sig|portscan|8|src=192.0.2.1:100 dst=198.51.100.1:443 out=1000000"
    out = n.normalize_cef(line)
    assert out is not None
    assert (out.src_port, out.dst_ip, out.dst_port, out.dbytes) == ("100", "198.51.100.1", "443", "1000000")
    assert "action=SCAN" in out.keywords


def test_cef_seven_field_record_remains_parseable():
    out = n.normalize_cef("CEF:0|v|p|1|s|scan|4")
    assert out is not None
    assert "action=SCAN" in out.keywords
    assert out.src_ip == ""


def test_bad_json_shape_does_not_produce_fabricated_evidence(monkeypatch):
    monkeypatch.setattr(n.json, "loads", lambda line: [])
    assert n.normalize_json("{arbitrary}") is None


def test_json_with_explicit_event_and_ips():
    out = n.normalize_json(json.dumps({"time":"2026-10-18T01:02:03", "event":"auth-failure", "client_ip":"192.0.2.9", "server_ip":"198.51.100.2", "out_bytes":987654}))
    assert out is not None
    assert out.category == "auth-failure"
    assert out.src_ip == "192.0.2.9"
    assert out.dst_ip == "198.51.100.2"
    assert out.dbytes == "987654"


def test_key_value_src_and_dst_port_fields_preserved():
    out = n.normalize_kv("src=192.0.2.1:1024 dst=198.51.100.3:22 action=SCAN")
    assert out is not None
    assert (out.src_ip, out.src_port, out.dst_ip, out.dst_port) == ("192.0.2.1", "1024", "198.51.100.3", "22")


def test_xml_flat_record_without_timestamp_is_not_guessed():
    assert n.normalize_xml("<Event><Action>SCAN</Action></Event>") is None


def test_xml_flat_record_converts_timestamp_and_output_bytes():
    out = n.normalize_xml("<Event><TimeStamp>2026-10-18T11:12:13</TimeStamp><EventID>auth</EventID><SourceIp>192.0.2.2</SourceIp><BytesSent>1000000</BytesSent></Event>")
    assert out is not None
    assert out.time == "11:12:13"
    assert out.dbytes == "1000000"


def test_gelf_timestamp_overflow_is_not_silently_substituted(monkeypatch):
    row = json.dumps({"version":"1.1","host":"server","timestamp":"9"*400,"short_message":"failure"})
    out = n.normalize_gelf(row)
    assert out is not None
    assert out.category == "gelf"


def test_gelf_non_record_is_rejected(monkeypatch):
    monkeypatch.setattr(n.json, "loads", lambda line: [])
    assert n.normalize_gelf("{anything}") is None


def test_pipe_single_field_is_not_accepted():
    assert n.normalize_pipe("Time:08:14:01|bad") is None


def test_pipe_without_timestamp_is_not_accepted():
    assert n.normalize_pipe("Event:SCAN|SourceAddress:192.0.2.1") is None


def test_pipe_empty_parts_are_not_counted_as_fields():
    assert n.normalize_pipe("||Time:08:14:01||") is None


def test_pipe_scan_contains_one_canonical_scan_keyword():
    out = n.normalize_pipe("Time:08:14:01|Action:SCAN|SourceAddress:192.0.2.1")
    assert out is not None
    assert out.keywords.count("action=SCAN") == 1


def test_unrecognized_line_is_preserved_not_discarded():
    noise = "opaque telemetry without delimiters"
    assert n.normalize_line(noise) is None
    assert n.normalize_logs([noise]) == [noise]
