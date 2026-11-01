"""Watch state, session records, and fail-closed report outcomes."""

from __future__ import annotations

import datetime as dt
import json
import os
import types
from pathlib import Path

import pytest

from nomosguard.constants import (
    CLAIM_KIND_TRAFFIC_REQUEST,
    CLAIM_KIND_TRAFFIC_SESSION,
    TRAFFIC_CLASSES,
)
from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.traffic import watch
from nomosguard.traffic.watch import (
    REPORT_SCHEMA,
    append_session,
    build_report,
    build_session_id,
    default_ledger_path,
    load_state,
    load_trust_marker,
    log_path,
    pid_is_alive,
    session_payload,
    state_path,
    stop_path,
    trust_path,
    watch_dir,
    write_state,
    write_trust_marker,
)


def request_payload(**overrides):
    payload = {
        "session_id": "s1",
        "class": "prompt",
        "host": "api.test",
        "secret_hits": [],
    }
    payload.update(overrides)
    return payload


def session_payload_for(session_id, requests, **overrides):
    payload = {
        "session_id": session_id,
        "requests": requests,
        "enforcement": False,
        "started_at": "2026-01-01T00:00:00+00:00",
        "stopped_at": "2026-01-01T00:01:00+00:00",
        "classes": {name: 0 for name in TRAFFIC_CLASSES},
        "hosts": {},
    }
    payload.update(overrides)
    return payload


def save_ledger(path: Path, claims) -> EvidenceLedger:
    ledger = EvidenceLedger()
    for kind, payload in claims:
        ledger.append(Claim(kind, payload, f"evidence for {kind}"))
    ledger.save(path)
    return ledger


def save_claims(path: Path, request_payloads, session_payloads) -> EvidenceLedger:
    claims = [
        (CLAIM_KIND_TRAFFIC_REQUEST, payload) for payload in request_payloads
    ] + [(CLAIM_KIND_TRAFFIC_SESSION, payload) for payload in session_payloads]
    return save_ledger(path, claims)


class TestPathsAndState:
    def test_paths(self, tmp_path):
        root = tmp_path / "ws"
        assert watch_dir(root) == root.resolve() / ".nomosguard" / "watch"
        assert state_path(root).name == "state.json"
        assert stop_path(root).name == "stop.flag"
        assert log_path(root).name == "watch.log"
        assert trust_path(root).name == "trust.json"
        assert default_ledger_path(root).name == "ledger.jsonl"

    def test_state_roundtrip(self, tmp_path):
        write_state(tmp_path, {"running": True, "pid": 123})
        assert load_state(tmp_path) == {"running": True, "pid": 123}

    def test_state_missing_and_invalid(self, tmp_path):
        assert load_state(tmp_path) is None
        state_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
        state_path(tmp_path).write_text("{not json", encoding="utf-8")
        assert load_state(tmp_path) is None
        state_path(tmp_path).write_text("[1, 2]", encoding="utf-8")
        assert load_state(tmp_path) is None

    def test_trust_marker_roundtrip(self, tmp_path):
        write_trust_marker(tmp_path, {"fingerprint": "ABC"})
        assert load_trust_marker(tmp_path) == {"fingerprint": "ABC"}

    def test_trust_marker_missing_and_invalid(self, tmp_path):
        assert load_trust_marker(tmp_path) is None
        trust_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
        trust_path(tmp_path).write_text("nope", encoding="utf-8")
        assert load_trust_marker(tmp_path) is None
        trust_path(tmp_path).write_text('"string"', encoding="utf-8")
        assert load_trust_marker(tmp_path) is None


class TestPidAndSession:
    def test_pid_is_alive_rejects_non_pids(self):
        assert pid_is_alive(True) is False
        assert pid_is_alive("123") is False
        assert pid_is_alive(0) is False
        assert pid_is_alive(-1) is False
        assert pid_is_alive(None) is False

    def test_current_process_is_alive(self):
        assert pid_is_alive(os.getpid()) is True

    def test_dead_pid(self):
        assert pid_is_alive(999_999_999) is False

    def test_windows_dead_pid_error_is_dead(self, monkeypatch):
        class InvalidPid(OSError):
            winerror = 87

        def kill(pid, sig):
            raise InvalidPid("invalid pid")

        monkeypatch.setattr(watch.os, "kill", kill)
        assert pid_is_alive(123) is False

    def test_missing_process_is_dead(self, monkeypatch):
        def kill(pid, sig):
            raise ProcessLookupError

        monkeypatch.setattr(watch.os, "kill", kill)
        assert pid_is_alive(123) is False

    def test_unprovable_error_is_alive(self, monkeypatch):
        def kill(pid, sig):
            raise OSError("ambiguous")

        monkeypatch.setattr(watch.os, "kill", kill)
        assert pid_is_alive(123) is True

    def test_build_session_id_with_fixed_clock(self):
        moment = dt.datetime(2026, 1, 2, 3, 4, 5, 6000, tzinfo=dt.timezone.utc)
        assert build_session_id(moment, 123) == "watch-20260102T030405006000Z-123"

    def test_build_session_id_defaults(self):
        value = build_session_id()
        assert value.startswith("watch-")
        assert value.endswith(f"-{os.getpid()}")

    def test_session_payload_counts_and_silence(self):
        captures = [
            types.SimpleNamespace(payload={"class": "prompt", "host": "api.test"}),
            types.SimpleNamespace(payload={"class": "weird", "host": "api.test"}),
            types.SimpleNamespace(payload={}),
        ]
        payload = session_payload(
            session_id="s",
            started_at="a",
            stopped_at="b",
            enforcement=True,
            captures=captures,
        )
        assert payload["requests"] == 3
        assert payload["classes"]["prompt"] == 1
        assert payload["classes"]["unknown"] == 2
        assert payload["hosts"] == {"api.test": 2}
        assert payload["enforcement"] is True
        assert payload["silent"] is False

        empty = session_payload(
            session_id="s", started_at="a", stopped_at="b", enforcement=False, captures=[]
        )
        assert empty["requests"] == 0
        assert empty["silent"] is True
        assert empty["classes"] == {name: 0 for name in TRAFFIC_CLASSES}

    def test_append_session_returns_entry(self):
        ledger = EvidenceLedger()
        entry = append_session(ledger, session_payload_for("s", 1))
        assert entry.claim.kind == CLAIM_KIND_TRAFFIC_SESSION
        assert "1 captured request" in entry.claim.evidence

    def test_append_session_persists(self, tmp_path):
        ledger = EvidenceLedger()
        path = tmp_path / "ledger.jsonl"
        append_session(ledger, session_payload_for("s", 2), ledger_path=path)
        loaded = EvidenceLedger.load(path)
        assert len(loaded.entries) == 1


class TestReportOutcomes:
    def test_invalid_day(self, tmp_path):
        with pytest.raises(ValueError, match="ISO date"):
            build_report(tmp_path, day="01-01-2026")

    def test_missing_ledger_is_unverified(self, tmp_path):
        report = build_report(tmp_path)
        assert report["schema"] == REPORT_SCHEMA
        assert report["outcome"] == "UNVERIFIED"
        assert report["ok"] is False
        assert report["chain"]["valid"] is False

    def test_state_declared_ledger_is_used(self, tmp_path):
        path = tmp_path / "custom" / "ledger.jsonl"
        path.parent.mkdir()
        save_claims(path, [request_payload()], [session_payload_for("s1", 1)])
        write_state(tmp_path, {"ledger": str(path)})
        report = build_report(tmp_path)
        assert report["ledger"] == str(path)
        assert report["outcome"] == "OK"

    def test_state_without_ledger_uses_default(self, tmp_path):
        write_state(tmp_path, {"running": False})
        report = build_report(tmp_path)
        assert report["ledger"] == str(default_ledger_path(tmp_path))

    def test_explicit_path_overrides_state(self, tmp_path):
        first = tmp_path / "one.jsonl"
        second = tmp_path / "two.jsonl"
        save_claims(first, [request_payload()], [session_payload_for("s1", 1)])
        save_claims(second, [request_payload()], [session_payload_for("s1", 1)])
        write_state(tmp_path, {"ledger": str(first)})
        report = build_report(tmp_path, ledger_path=second)
        assert report["ledger"] == str(second)

    def test_tampered_chain_is_reported(self, tmp_path, monkeypatch):
        class FakeLedger:
            entries = ()

            def verify(self):
                return False, "chain broken"

        monkeypatch.setattr(watch.EvidenceLedger, "load", classmethod(lambda cls, path: FakeLedger()))
        report = build_report(tmp_path / "unused", ledger_path=tmp_path / "fake.jsonl")
        assert report["outcome"] == "TAMPERED"
        assert report["chain"] == {"valid": False, "detail": "chain broken"}

    def test_ok_requires_matching_session(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        save_claims(path, [request_payload()], [session_payload_for("s1", 1)])
        report = build_report(tmp_path, ledger_path=path)
        assert report["outcome"] == "OK"
        assert report["ok"] is True
        assert report["total_requests"] == 1
        assert report["requests"] == 1
        assert report["by_class"]["prompt"] == 1

    def test_no_requests_is_silent(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        save_claims(path, [], [session_payload_for("s1", 0)])
        report = build_report(tmp_path, ledger_path=path)
        assert report["outcome"] == "SILENT"
        assert report["silent_sessions"] == ["s1"]
        assert report["total_requests"] == 0

    def test_missing_closing_session_is_incomplete(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        save_claims(path, [request_payload()], [])
        report = build_report(tmp_path, ledger_path=path)
        assert report["outcome"] == "INCOMPLETE"
        assert report["sessions"] == []

    def test_count_mismatch_is_incomplete(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        save_claims(path, [request_payload()], [session_payload_for("s1", 2)])
        report = build_report(tmp_path, ledger_path=path)
        assert report["outcome"] == "INCOMPLETE"
        assert report["mismatched_sessions"] == ["s1"]
        assert report["sessions"][0]["declared_requests"] == 2
        assert report["sessions"][0]["observed_requests"] == 1

    def test_any_silent_session_fails_the_run(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        save_claims(
            path,
            [request_payload()],
            [session_payload_for("s1", 1), session_payload_for("s2", 0)],
        )
        report = build_report(tmp_path, ledger_path=path)
        assert report["outcome"] == "SILENT"
        assert report["silent_sessions"] == ["s2"]


class TestReportAggregation:
    def _rich_report(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        request_payloads = [
            request_payload(
                session_id="s1",
                secret_hits=[
                    {"name": "github-token", "masked": "ghp_…1234"},
                    7,
                    {"name": "", "masked": "x"},
                    {"name": "k", "masked": ""},
                ],
            ),
            request_payload(
                session_id="s1",
                **{"class": "tool-result"},
                secret_hits=[{"name": "github-token", "masked": "ghp_…1234"}],
            ),
            request_payload(session_id="s2", **{"class": "weird"}, host="telemetry.test"),
            request_payload(session_id="s3", **{"class": ""}, host=""),
            request_payload(session_id="s3", **{"class": 7}),
            request_payload(session_id="s7", **{"class": "telemetry"}, host="t.test"),
            request_payload(session_id="s7", **{"class": "prompt"}, host="t.test"),
        ]
        session_payloads = [
            session_payload_for("s1", 2),
            session_payload_for("s2", 1),
            session_payload_for("s3", 3),
            session_payload_for("s4", 0),
            session_payload_for("s5", True),
            session_payload_for("s6", -1),
            session_payload_for("s7", "2"),
            session_payload_for("s8", 1),
        ]
        ledger = save_claims(path, request_payloads, session_payloads)
        return path, ledger

    def test_aggregates_days_classes_hosts_and_secret_hits(self, tmp_path):
        path, ledger = self._rich_report(tmp_path)
        report = build_report(tmp_path, ledger_path=path)
        assert report["total_requests"] == 7
        assert report["by_class"]["prompt"] == 2
        assert report["by_class"]["tool-result"] == 1
        assert report["by_class"]["telemetry"] == 1
        assert report["by_class"]["unknown"] == 3
        assert report["hosts"] == {"api.test": 3, "t.test": 2, "telemetry.test": 1}
        assert report["secret_hits"] == [
            {"name": "github-token", "masked": "ghp_…1234", "count": 2}
        ]
        assert report["unrecognized_classes"] == ["weird"]
        assert len(report["by_day"]) == 1
        day = next(iter(report["by_day"]))
        assert report["by_day"][day]["requests"] == 7
        assert report["by_day"][day]["hosts"] == {
            "api.test": 3,
            "t.test": 2,
            "telemetry.test": 1,
        }
        assert ledger.verify()[0] is True

    def test_sessions_report_declared_and_observed(self, tmp_path):
        path, _ = self._rich_report(tmp_path)
        report = build_report(tmp_path, ledger_path=path)
        sessions = {item["session_id"]: item for item in report["sessions"]}
        assert sessions["s1"]["declared_requests"] == 2
        assert sessions["s1"]["observed_requests"] == 2
        assert sessions["s3"]["declared_requests"] == 3
        assert sessions["s3"]["observed_requests"] == 2
        assert sessions["s5"]["declared_requests"] == -1  # bool is not a count
        assert sessions["s7"]["declared_requests"] == -1  # string is not a count
        assert set(report["silent_sessions"]) == {"s4", "s5", "s6", "s8"}
        assert set(report["mismatched_sessions"]) == {"s3", "s5", "s6", "s7", "s8"}
        assert report["outcome"] == "INCOMPLETE"

    def test_day_filter_limits_only_the_presented_counters(self, tmp_path):
        path, _ = self._rich_report(tmp_path)
        today = next(iter(build_report(tmp_path, ledger_path=path)["by_day"]))
        filtered = build_report(tmp_path, ledger_path=path, day=today)
        assert filtered["requests"] == 7
        assert filtered["by_class"]["prompt"] == 2
        empty = build_report(tmp_path, ledger_path=path, day="2000-01-01")
        assert empty["requests"] == 0
        assert empty["by_class"] == {name: 0 for name in TRAFFIC_CLASSES}
        assert empty["total_requests"] == 7
        assert empty["outcome"] == "INCOMPLETE"


def test_report_json_serializable(tmp_path):
    path = tmp_path / "ledger.jsonl"
    save_claims(path, [request_payload()], [session_payload_for("s1", 1)])
    report = build_report(tmp_path, ledger_path=path)
    assert json.loads(json.dumps(report))["outcome"] == "OK"
