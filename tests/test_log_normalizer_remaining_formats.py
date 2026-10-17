"""Deterministic cross-format normalization for adversarial network telemetry."""

from __future__ import annotations

import json

import pytest

from nomosguard import log_normalize as logs


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("[08:14:01] custom", "08:14:01"),
        ("2026-10-17T08:14:02 event", "08:14:02"),
        ("Oct  9 08:14:03 auth event", "08:14:03"),
        ("08:14:04 event", "08:14:04"),
        ("unparseable event", "00:00:00"),
    ],
)
def test_time_precedence_preserves_real_clock_metadata(
    source: str, expected: str
) -> None:
    assert logs._canonical_time(source) == expected


def test_render_preserves_source_destination_ports_and_traffic_bytes() -> None:
    obj = logs.NormalizedLine(
        "08:14:01",
        "firewall",
        src_ip="192.0.2.1",
        src_port="1234",
        dst_ip="192.0.2.2",
        dst_port="443",
        dbytes="1000000",
        keywords=("failed password",),
    )
    assert obj.render() == (
        "[08:14:01] firewall: src=192.0.2.1:1234 "
        "dst=192.0.2.2:443 failed password dbytes=1000000"
    )
    assert logs.NormalizedLine("01:02:03", "test").render() == "[01:02:03] test:"


def test_auth_and_grant_keywords_are_not_silently_dropped() -> None:
    assert logs._keywords("Login ok; access granted privilege") == (
        "SUCCESS password",
        "granted privilege",
    )
    assert logs._keywords("failed password, scan started") == (
        "failed password",
        "action=SCAN",
    )


@pytest.mark.parametrize(
    ("message", "src", "dst", "bytes_count"),
    [
        (
            "from 192.0.2.1:3300 to 198.51.100.1:443 bytes 1234567",
            "192.0.2.1",
            "198.51.100.1",
            "1234567",
        ),
        (
            "from 192.0.2.1 to 198.51.100.2 port 80 bytes=999999",
            "192.0.2.1",
            "198.51.100.2",
            "999999",
        ),
        ("no network addresses", "", "", ""),
    ],
)
def test_syslog_optional_network_fields_and_large_transfer(
    message: str,
    src: str,
    dst: str,
    bytes_count: str,
) -> None:
    result = logs.normalize_syslog(f"Oct  9 08:14:01 proxy netflow[12]: {message}")
    assert result is not None
    assert result.src_ip == src
    assert result.dst_ip == dst
    assert result.dbytes == bytes_count


def test_cef_invalid_short_record_and_full_extension() -> None:
    assert logs.normalize_cef("CEF:0|vendor") is None
    full = (
        "CEF:0|vendor|sensor|1|900|Unauthorized privilege granted|8|"
        "src=192.0.2.1:3300 dst=198.51.100.1:443 "
        "out=2222222 time=08:14:02"
    )
    parsed = logs.normalize_cef(full)
    assert parsed is not None
    assert parsed.src_ip == "192.0.2.1"
    assert parsed.src_port == "3300"
    assert parsed.dst_ip == "198.51.100.1"
    assert parsed.dst_port == "443"
    assert parsed.dbytes == "2222222"
    assert parsed.time == "08:14:02"
    assert "granted privilege" in parsed.keywords


def test_cef_without_extension_keeps_event_label() -> None:
    record = logs.normalize_cef("CEF:0|v|p|1|8|Alert|5")
    assert record is not None
    assert record.category == "Alert"
    assert record.src_ip == ""


def test_json_parser_preserves_fallback_keys_and_unknown_input() -> None:
    assert logs.normalize_json("x") is None
    assert logs.normalize_json("{invalid}") is None
    result = logs.normalize_json(
        json.dumps(
            {
                "time": "08:14:02",
                "category": "event",
                "client_ip": "192.0.2.3",
                "server_ip": "192.0.2.4",
                "out_bytes": 2000000,
                "status": "session opened",
            }
        )
    )
    assert result is not None
    assert result.src_ip == "192.0.2.3"
    assert result.dst_ip == "192.0.2.4"
    assert result.dbytes == "2000000"
    assert "SUCCESS password" in result.keywords


def test_kv_parser_accepts_split_ports_and_log_fallback() -> None:
    assert logs.normalize_kv("not a key value") is None
    parsed = logs.normalize_kv("source=192.0.2.1 dest=198.51.100.9 sport=22 dport=3333")
    assert parsed is not None
    assert parsed.src_ip == "192.0.2.1"
    assert parsed.src_port == "22"
    assert parsed.dst_ip == "198.51.100.9"
    assert parsed.dst_port == "3333"


def test_xml_flat_event_fields_are_normalized_without_network() -> None:
    assert logs.normalize_xml("plain text") is None
    assert logs.normalize_xml("<Event><Unknown>x</Unknown></Event>") is None
    record = (
        "<Event><TimeStamp>2026-10-17T08:14:01</TimeStamp>"
        "<EventID>42</EventID><SourceIp>192.0.2.2</SourceIp>"
        "<DestinationIp>198.51.100.1</DestinationIp>"
        "<BytesSent>1200000</BytesSent>"
        "<Message>Failed password</Message></Event>"
    )
    parsed = logs.normalize_xml(record)
    assert parsed is not None
    assert parsed.time == "08:14:01"
    assert parsed.category == "42"
    assert parsed.src_ip == "192.0.2.2"
    assert parsed.dst_ip == "198.51.100.1"
    assert parsed.dbytes == "1200000"
    assert "failed password" in parsed.keywords


@pytest.mark.parametrize("timestamp", ["1729183930", "9" * 500])
def test_gelf_epoch_and_unrepresentable_epoch_do_not_crash(timestamp: str) -> None:
    record = logs.normalize_gelf(
        json.dumps(
            {
                "version": "1.1",
                "host": "sensor",
                "timestamp": timestamp,
                "facility": "edge",
                "_src_ip": "192.0.2.1",
                "short_message": "Failed password",
                "_dbytes": 2200000,
            }
        )
    )
    assert record is not None
    assert record.category == "edge"
    assert record.src_ip == "192.0.2.1"
    assert record.dbytes == "2200000"
    assert "failed password" in record.keywords


def test_pipe_parser_rejects_missing_field_or_time_and_normalizes_scan() -> None:
    assert logs.normalize_pipe("plain") is None
    assert logs.normalize_pipe("time:08:01:02|not-even-a-field") is None
    assert logs.normalize_pipe("action:SCAN|sourceaddress:192.0.2.1") is None
    record = logs.normalize_pipe(
        "Time:08:33:10|Action:DENY|SourceAddress:192.0.2.1|DestAddress:198.51.100.4"
    )
    assert record is not None
    assert record.time == "08:33:10"
    assert "action=SCAN" in record.keywords


def test_normalize_logs_does_not_drop_unknown_nonempty_evidence() -> None:
    assert logs.normalize_line("totally unrecognized text") is None
    assert logs.normalize_logs(["", "   ", "unknown raw evidence"]) == [
        "unknown raw evidence"
    ]


@pytest.mark.parametrize(
    "payload",
    [
        '{"time":"08:14:01","src_ip":"192.0.2.1","src_ip":"203.0.113.2"}',
        '{"time":"08:14:01","nested":{"tag":"good","tag":"bad"}}',
        '{"time":"08:14:01","bytes_out":NaN}',
        '{"time":"08:14:01","bytes_out":Infinity}',
        '{"time":"08:14:01","bytes_out":1e400}',
    ],
)
def test_ambiguous_or_nonfinite_json_is_not_misrepresented(payload: str) -> None:
    assert logs.normalize_json(payload) is None
    assert logs.normalize_logs([payload]) == [payload]


@pytest.mark.parametrize(
    "payload",
    [
        '{"version":"1.1","host":"sensor","_src_ip":"1","_src_ip":"2"}',
        '{"version":"1.1","host":"sensor","timestamp":NaN}',
        '{"version":"1.1","host":"sensor","timestamp":1e400}',
    ],
)
def test_gelf_rejects_ambiguous_and_nonfinite_records(payload: str) -> None:
    assert logs.normalize_gelf(payload) is None
    assert logs.normalize_logs([payload]) == [payload]


def test_logfmt_embedded_ports_do_not_shift_source_or_destination() -> None:
    result = logs.normalize_kv(
        "time=08:14:01 action=DENY src=192.0.2.9:5234 dst=203.0.113.5:443"
    )
    assert result is not None
    assert (result.src_ip, result.src_port) == ("192.0.2.9", "5234")
    assert (result.dst_ip, result.dst_port) == ("203.0.113.5", "443")
    assert result.render().count("src=") == 1
    assert result.render().count("dst=") == 1


def test_nonblocking_pipe_action_never_invents_scan_signal() -> None:
    result = logs.normalize_pipe(
        "Time:08:14:01|Action:ALLOW|SourceAddress:192.0.2.9|DestAddress:203.0.113.5"
    )
    assert result is not None
    assert "action=SCAN" not in result.keywords


def test_gelf_iso_timestamp_is_preserved_across_format_conversion() -> None:
    payload = json.dumps(
        {"version": "1.1", "host": "edge", "timestamp": "2026-10-17T08:14:02"}
    )
    result = logs.normalize_gelf(payload)
    assert result is not None
    assert result.time == "08:14:02"
