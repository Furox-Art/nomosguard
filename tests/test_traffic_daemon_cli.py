"""Watch daemon and ``nomosguard watch`` CLI behavior, including failure paths."""

from __future__ import annotations

import json
import runpy
import socket
import sys
import types

import pytest

from nomosguard import cli
from nomosguard.ledger import EvidenceLedger
from nomosguard.traffic import daemon
from nomosguard.traffic.certs import CertificateAuthority, CertificateError
from nomosguard.traffic.watch import (
    default_ledger_path,
    load_state,
    load_trust_marker,
    log_path,
    pki_dir,
    state_path,
    stop_path,
    trust_path,
    watch_dir,
    write_state,
    write_trust_marker,
)


class FakeChild:
    pid = 4242

    def __init__(self, poll_result=None):
        self.poll_result = poll_result
        self.terminated = False

    def poll(self):
        return self.poll_result

    def terminate(self):
        self.terminated = True


def ns(**overrides):
    base = {
        "dir": ".",
        "port": 0,
        "ledger": None,
        "enforcement": False,
        "install_ca": False,
        "remove_ca": False,
        "timeout": 1.0,
        "day": None,
    }
    base.update(overrides)
    return types.SimpleNamespace(**base)


class TestDaemon:
    def test_stop_requested_by_file_or_signal(self, tmp_path, monkeypatch):
        monkeypatch.setattr(daemon, "_workspace", tmp_path)
        monkeypatch.setattr(daemon, "_STOP_EVENT", False)
        assert daemon._stop_requested() is False
        stop_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
        stop_path(tmp_path).write_text("stop", encoding="utf-8")
        assert daemon._stop_requested() is True
        stop_path(tmp_path).unlink()
        monkeypatch.setattr(daemon, "_STOP_EVENT", True)
        assert daemon._stop_requested() is True

    def test_signal_handler_sets_stop(self, monkeypatch):
        monkeypatch.setattr(daemon, "_STOP_EVENT", False)
        daemon._handle_signal(2, None)
        assert daemon._STOP_EVENT is True

    def test_run_closes_session_and_state(self, tmp_path, monkeypatch):
        state_dir = watch_dir(tmp_path)
        state_dir.mkdir(parents=True)
        write_state(tmp_path, {"running": True, "pid": 1, "trust_installed": True,
                               "trust_detail": "ok"})
        stop_path(tmp_path).write_text("stop", encoding="utf-8")
        ledger_path = tmp_path / "ledger.jsonl"

        code = daemon.run(
            tmp_path,
            port=0,
            ledger_path=ledger_path,
            enforcement=False,
            session_id="s-1",
            started_at="2026-01-01T00:00:00+00:00",
        )
        assert code == 0
        assert not stop_path(tmp_path).exists()
        state = load_state(tmp_path)
        assert state["running"] is False
        assert state["starting"] is False
        assert state["session_id"] == "s-1"
        assert state["requests"] == 0
        assert state["silent"] is True
        assert state["trust_installed"] is True
        assert state["trust_detail"] == "ok"
        assert "error" not in state
        ledger = EvidenceLedger.load(ledger_path)
        assert len(ledger.entries) == 1
        assert ledger.entries[0].claim.kind == "traffic_session"
        assert ledger.entries[0].claim.payload["requests"] == 0

    def test_run_waits_until_the_stop_file_appears(self, tmp_path, monkeypatch):
        watch_dir(tmp_path).mkdir(parents=True)

        def sleep(_seconds):
            stop_path(tmp_path).write_text("stop", encoding="utf-8")

        monkeypatch.setattr(daemon.time, "sleep", sleep)
        code = daemon.run(
            tmp_path,
            port=0,
            ledger_path=tmp_path / "ledger.jsonl",
            enforcement=False,
            session_id="s-1",
            started_at="t",
        )
        assert code == 0
        assert load_state(tmp_path)["running"] is False
        assert not stop_path(tmp_path).exists()

    def test_run_survives_signal_registration_failure(self, tmp_path, monkeypatch):
        watch_dir(tmp_path).mkdir(parents=True)
        stop_path(tmp_path).write_text("stop", encoding="utf-8")

        def refuse(signum, handler):
            raise ValueError("unsupported")

        monkeypatch.setattr(daemon.signal, "signal", refuse)
        code = daemon.run(
            tmp_path,
            port=0,
            ledger_path=tmp_path / "ledger.jsonl",
            enforcement=False,
            session_id="s-1",
            started_at="t",
        )
        assert code == 0

    def test_run_records_closing_record_failure(self, tmp_path, monkeypatch):
        watch_dir(tmp_path).mkdir(parents=True)
        stop_path(tmp_path).write_text("stop", encoding="utf-8")

        def fail(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(daemon, "append_session", fail)
        code = daemon.run(
            tmp_path,
            port=0,
            ledger_path=tmp_path / "ledger.jsonl",
            enforcement=False,
            session_id="s-1",
            started_at="t",
        )
        assert code == 0
        state = load_state(tmp_path)
        assert "could not persist the closing session record" in state["error"]

    def test_run_refuses_a_corrupt_ledger(self, tmp_path):
        bad = tmp_path / "ledger.jsonl"
        bad.write_text("not json\n", encoding="utf-8")
        code = daemon.run(
            tmp_path,
            port=0,
            ledger_path=bad,
            enforcement=False,
            session_id="s-1",
            started_at="t",
        )
        assert code == 3
        state = load_state(tmp_path)
        assert state["running"] is False
        assert state["error"]
        assert not pki_dir(tmp_path).exists()

    def test_main_and_module_entrypoint_return_error_code(self, tmp_path, monkeypatch):
        bad = tmp_path / "ledger.jsonl"
        bad.write_text("not json\n", encoding="utf-8")
        argv = [
            "--workspace", str(tmp_path), "--ledger", str(bad),
            "--session-id", "s", "--started-at", "t",
        ]
        assert daemon.main(argv) == 3
        monkeypatch.setattr(sys, "argv", ["nomosguard-watch-daemon", *argv])
        with pytest.raises(SystemExit) as exc:
            runpy.run_module("nomosguard.traffic.daemon", run_name="__main__")
        assert exc.value.code == 3


class TestCliHelpers:
    def test_ledger_path(self, tmp_path):
        assert cli._ledger_path(tmp_path, None) == default_ledger_path(tmp_path)
        assert cli._ledger_path(tmp_path, "rel.jsonl") == tmp_path / "rel.jsonl"
        assert cli._ledger_path(tmp_path, str(tmp_path / "abs.jsonl")) == tmp_path / "abs.jsonl"

    def test_old_state_running(self, monkeypatch):
        assert cli._old_state_running(None) is False
        assert cli._old_state_running("state") is False
        assert cli._old_state_running({"running": False, "pid": 1}) is False
        monkeypatch.setattr(cli, "pid_is_alive", lambda pid: False)
        assert cli._old_state_running({"running": True, "pid": 1}) is False
        monkeypatch.setattr(cli, "pid_is_alive", lambda pid: True)
        assert cli._old_state_running({"running": True, "pid": 1}) is True

    def test_tail(self, tmp_path):
        assert cli._tail(tmp_path / "missing.log") == ""
        path = tmp_path / "log.txt"
        path.write_text("x" * 1200, encoding="utf-8")
        assert cli._tail(path) == "x" * 1000

    def test_spawn_daemon_windows_and_posix(self, tmp_path, monkeypatch):
        calls = []

        class FakePopen:
            def __init__(self, argv, **kwargs):
                calls.append((argv, kwargs))

        monkeypatch.setattr(cli.subprocess, "Popen", FakePopen)
        monkeypatch.setattr(cli, "os", types.SimpleNamespace(name="nt"))
        root = tmp_path / "ws"
        cli._spawn_daemon(
            root, watch_dir(root), port=0, ledger=root / "l.jsonl",
            enforcement=True, session_id="s", started_at="t",
        )
        assert calls[-1][1]["creationflags"] >= 0
        assert "--enforcement" in calls[-1][0]
        assert calls[-1][0][1:3] == ["-m", "nomosguard.traffic.daemon"]

        monkeypatch.setattr(cli, "os", types.SimpleNamespace(name="posix"))
        cli._spawn_daemon(
            root, watch_dir(root), port=0, ledger=root / "l.jsonl",
            enforcement=False, session_id="s", started_at="t",
        )
        assert calls[-1][1]["start_new_session"] is True
        assert "creationflags" not in calls[-1][1]
        assert "--enforcement" not in calls[-1][0]


class TestCmdStart:
    def _prepare(self, tmp_path, monkeypatch, *, state_sequence, child=None):
        root = tmp_path / "ws"
        root.mkdir()
        child = child or FakeChild(poll_result=None)
        monkeypatch.setattr(cli, "_spawn_daemon", lambda *a, **k: child)
        sequence = list(state_sequence)

        def fake_load_state(_root):
            return sequence.pop(0) if sequence else None

        monkeypatch.setattr(cli, "load_state", fake_load_state)
        return root, child

    def test_rejects_missing_directory(self, tmp_path):
        assert cli.cmd_start(ns(dir=str(tmp_path / "missing"))) == 2

    def test_rejects_bad_port(self, tmp_path):
        root = tmp_path / "ws"
        root.mkdir()
        assert cli.cmd_start(ns(dir=str(root), port=-1)) == 2
        assert cli.cmd_start(ns(dir=str(root), port=70000)) == 2

    def test_rejects_already_running(self, tmp_path, monkeypatch):
        root = tmp_path / "ws"
        root.mkdir()
        monkeypatch.setattr(cli, "load_state", lambda _root: {"running": True, "pid": 1})
        monkeypatch.setattr(cli, "pid_is_alive", lambda pid: True)
        assert cli.cmd_start(ns(dir=str(root))) == 2

    def test_ca_failure(self, tmp_path, monkeypatch):
        root = tmp_path / "ws"
        root.mkdir()

        def fail(self):
            raise CertificateError("no openssl")

        monkeypatch.setattr(CertificateAuthority, "ensure", fail)
        assert cli.cmd_start(ns(dir=str(root))) == 2

    def test_corrupt_ledger_is_refused(self, tmp_path):
        root = tmp_path / "ws"
        root.mkdir()
        ledger = tmp_path / "ledger.jsonl"
        ledger.write_text("garbage\n", encoding="utf-8")
        assert cli.cmd_start(ns(dir=str(root), ledger=str(ledger))) == 2

    def test_unchained_ledger_is_refused(self, tmp_path, monkeypatch):
        root = tmp_path / "ws"
        root.mkdir()
        ledger = tmp_path / "ledger.jsonl"
        ledger.write_text("{}\n", encoding="utf-8")

        class FakeLoaded:
            def verify(self):
                return False, "bad chain"

        monkeypatch.setattr(cli.EvidenceLedger, "load", classmethod(lambda cls, path: FakeLoaded()))
        assert cli.cmd_start(ns(dir=str(root), ledger=str(ledger))) == 2

    def test_install_ca_failure_does_not_start(self, tmp_path, monkeypatch):
        root = tmp_path / "ws"
        root.mkdir()
        monkeypatch.setattr(cli, "install_trust", lambda path, ca=None: (False, "denied"))
        monkeypatch.setattr(
            cli, "_spawn_daemon", lambda *a, **k: pytest.fail("must not spawn")
        )
        assert cli.cmd_start(ns(dir=str(root), install_ca=True)) == 2

    def test_install_ca_success_records_marker(self, tmp_path, monkeypatch):
        root, child = self._prepare(
            tmp_path, monkeypatch, state_sequence=[None, {"running": True, "pid": 4242}]
        )
        monkeypatch.setattr(cli, "install_trust", lambda path, ca=None: (True, "trusted"))
        assert cli.cmd_start(ns(dir=str(root), install_ca=True)) == 0
        marker = load_trust_marker(root)
        assert marker["detail"] == "trusted"
        state = json.loads(state_path(root).read_text(encoding="utf-8"))
        assert state["trust_installed"] is True
        assert state["trust_detail"] == "trusted"
        assert child.terminated is False

    def test_existing_matching_marker_is_trusted(self, tmp_path, monkeypatch):
        root, _ = self._prepare(
            tmp_path, monkeypatch, state_sequence=[None, {"running": True, "pid": 4242}]
        )
        ca = CertificateAuthority(pki_dir(root))
        ca.ensure()
        write_trust_marker(root, {"fingerprint": ca.fingerprint()})
        assert cli.cmd_start(ns(dir=str(root))) == 0
        state = json.loads(state_path(root).read_text(encoding="utf-8"))
        assert state["trust_installed"] is True
        assert state["trust_detail"] == "installed by nomosguard"

    def test_existing_nonmatching_marker_is_not_trusted(self, tmp_path, monkeypatch):
        root, _ = self._prepare(
            tmp_path, monkeypatch, state_sequence=[None, {"running": True, "pid": 4242}]
        )
        write_trust_marker(root, {"fingerprint": "OTHER"})
        assert cli.cmd_start(ns(dir=str(root))) == 0
        state = json.loads(state_path(root).read_text(encoding="utf-8"))
        assert state["trust_installed"] is False
        assert "not installed" in state["trust_detail"]

    def test_no_marker_is_not_trusted(self, tmp_path, monkeypatch):
        root, _ = self._prepare(
            tmp_path, monkeypatch, state_sequence=[None, {"running": True, "pid": 4242}]
        )
        assert cli.cmd_start(ns(dir=str(root))) == 0
        state = json.loads(state_path(root).read_text(encoding="utf-8"))
        assert state["trust_installed"] is False

    def test_spawn_failure(self, tmp_path, monkeypatch):
        root = tmp_path / "ws"
        root.mkdir()

        def fail(*args, **kwargs):
            raise OSError("cannot spawn")

        monkeypatch.setattr(cli, "_spawn_daemon", fail)
        assert cli.cmd_start(ns(dir=str(root))) == 2

    def test_readiness_waits_for_a_later_state(self, tmp_path, monkeypatch):
        root, _ = self._prepare(
            tmp_path,
            monkeypatch,
            state_sequence=[None, None, {"running": True, "pid": 4242}],
        )
        assert cli.cmd_start(ns(dir=str(root))) == 0

    def test_daemon_exits_before_ready(self, tmp_path, monkeypatch):
        root, child = self._prepare(
            tmp_path, monkeypatch, state_sequence=[None], child=FakeChild(poll_result=1)
        )
        assert cli.cmd_start(ns(dir=str(root))) == 2
        assert child.terminated is False

    def test_readiness_timeout_terminates_and_reports_log(self, tmp_path, monkeypatch):
        root, child = self._prepare(
            tmp_path, monkeypatch, state_sequence=[None], child=FakeChild(poll_result=None)
        )
        monkeypatch.setattr(cli, "START_TIMEOUT_SECONDS", 0.0)
        watch_dir(root).mkdir(parents=True, exist_ok=True)
        log_path(root).write_text("boom\n", encoding="utf-8")
        assert cli.cmd_start(ns(dir=str(root))) == 2
        assert child.terminated is True


class TestWaitStopped:
    def test_returns_state_for_matching_pid(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cli, "load_state", lambda _root: {"running": False, "pid": 5})
        assert cli._wait_stopped(tmp_path, 5, 1.0)["pid"] == 5

    def test_dead_pid_reads_final_state(self, tmp_path, monkeypatch):
        states = iter([{"running": True, "pid": 9}, {"running": False, "pid": 9}])
        monkeypatch.setattr(cli, "load_state", lambda _root: next(states))
        monkeypatch.setattr(cli, "pid_is_alive", lambda pid: False)
        assert cli._wait_stopped(tmp_path, 9, 1.0) == {"running": False, "pid": 9}

    def test_dead_pid_without_final_state(self, tmp_path, monkeypatch):
        states = iter([{"running": True, "pid": 9}, None])
        monkeypatch.setattr(cli, "load_state", lambda _root: next(states))
        monkeypatch.setattr(cli, "pid_is_alive", lambda pid: False)
        assert cli._wait_stopped(tmp_path, 9, 1.0) is None

    def test_timeout(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cli, "load_state", lambda _root: None)
        monkeypatch.setattr(cli, "pid_is_alive", lambda pid: True)
        ticks = iter([0.0, 0.0, 2.0])
        monkeypatch.setattr(cli.time, "monotonic", lambda: next(ticks))
        monkeypatch.setattr(cli.time, "sleep", lambda seconds: None)
        assert cli._wait_stopped(tmp_path, 9, 1.0) is None


class TestCmdStop:
    def _state(self, tmp_path, **overrides):
        state = {"running": False, "pid": 1, "port": None}
        state.update(overrides)
        write_state(tmp_path, state)
        return state

    def test_no_state(self, tmp_path):
        assert cli.cmd_stop(ns(dir=str(tmp_path))) == 1

    def test_not_running_prints_state(self, tmp_path):
        self._state(tmp_path)
        assert cli.cmd_stop(ns(dir=str(tmp_path))) == 0

    def test_dead_daemon_is_marked_stale(self, tmp_path, monkeypatch):
        self._state(tmp_path, running=True, pid=9)
        monkeypatch.setattr(cli, "pid_is_alive", lambda pid: False)
        assert cli.cmd_stop(ns(dir=str(tmp_path))) == 0
        state = load_state(tmp_path)
        assert state["running"] is False
        assert state["stale"] is True
        assert "without closing" in state["error"]

    def test_running_stop_closes_cleanly(self, tmp_path, monkeypatch):
        self._state(tmp_path, running=True, pid=9)
        monkeypatch.setattr(cli, "pid_is_alive", lambda pid: True)
        monkeypatch.setattr(
            cli, "_wait_stopped", lambda root, pid, timeout: {"running": False, "pid": 9}
        )
        assert cli.cmd_stop(ns(dir=str(tmp_path))) == 0
        assert stop_path(tmp_path).is_file()

    def test_running_timeout_then_sigterm(self, tmp_path, monkeypatch):
        self._state(tmp_path, running=True, pid=9)
        monkeypatch.setattr(cli, "pid_is_alive", lambda pid: True)
        results = iter([None, {"running": False, "pid": 9}])
        monkeypatch.setattr(cli, "_wait_stopped", lambda root, pid, timeout: next(results))
        killed = []
        monkeypatch.setattr(cli.os, "kill", lambda pid, sig: killed.append((pid, sig)))
        assert cli.cmd_stop(ns(dir=str(tmp_path))) == 0
        assert killed and killed[0][0] == 9

    def test_running_never_stops(self, tmp_path, monkeypatch):
        self._state(tmp_path, running=True, pid=9)
        monkeypatch.setattr(cli, "pid_is_alive", lambda pid: True)
        monkeypatch.setattr(cli, "_wait_stopped", lambda root, pid, timeout: None)

        def fail(pid, sig):
            raise OSError("no signal")

        monkeypatch.setattr(cli.os, "kill", fail)
        assert cli.cmd_stop(ns(dir=str(tmp_path))) == 2

    def test_remove_ca_without_marker(self, tmp_path):
        self._state(tmp_path)
        assert cli.cmd_stop(ns(dir=str(tmp_path), remove_ca=True)) == 0
        state = load_state(tmp_path)
        assert state["ca_removed"] is True
        assert state["trust_installed"] is False
        assert state["trust_removed"] is False
        assert "no nomosguard trust-install marker" in state["trust_detail"]

    def test_remove_ca_with_missing_certificate(self, tmp_path):
        self._state(tmp_path)
        write_trust_marker(tmp_path, {"fingerprint": "X"})
        assert cli.cmd_stop(ns(dir=str(tmp_path), remove_ca=True)) == 2

    def test_remove_ca_when_uninstall_fails(self, tmp_path, monkeypatch):
        self._state(tmp_path)
        pki_dir(tmp_path).mkdir(parents=True)
        ca = CertificateAuthority(pki_dir(tmp_path))
        ca.ca_dir.mkdir(parents=True)
        ca.cert_path.write_text("dummy", encoding="utf-8")
        ca.key_path.write_text("dummy", encoding="utf-8")
        write_trust_marker(tmp_path, {"fingerprint": "X"})
        monkeypatch.setattr(cli, "uninstall_trust", lambda path, ca=None: (False, "denied"))
        assert cli.cmd_stop(ns(dir=str(tmp_path), remove_ca=True)) == 2
        assert ca.cert_path.is_file()

    def test_remove_ca_success_cleans_everything(self, tmp_path, monkeypatch):
        self._state(tmp_path)
        pki_dir(tmp_path).mkdir(parents=True)
        ca = CertificateAuthority(pki_dir(tmp_path))
        ca.ca_dir.mkdir(parents=True)
        ca.cert_path.write_text("dummy", encoding="utf-8")
        ca.key_path.write_text("dummy", encoding="utf-8")
        write_trust_marker(tmp_path, {"fingerprint": "X"})
        monkeypatch.setattr(cli, "uninstall_trust", lambda path, ca=None: (True, "gone"))
        assert cli.cmd_stop(ns(dir=str(tmp_path), remove_ca=True)) == 0
        assert not trust_path(tmp_path).exists()
        assert not pki_dir(tmp_path).exists()
        state = load_state(tmp_path)
        assert state["ca_removed"] is True
        assert state["trust_removed"] is True
        assert state["trust_detail"] == "gone"
        # The ledger directory itself must survive CA removal.
        assert state_path(tmp_path).is_file()

    def test_remove_ca_incomplete(self, tmp_path, monkeypatch):
        self._state(tmp_path)
        pki_dir(tmp_path).mkdir(parents=True)
        ca = CertificateAuthority(pki_dir(tmp_path))
        ca.ca_dir.mkdir(parents=True)
        ca.cert_path.write_text("dummy", encoding="utf-8")
        monkeypatch.setattr(CertificateAuthority, "remove", lambda self: None)
        assert cli.cmd_stop(ns(dir=str(tmp_path), remove_ca=True)) == 2


class TestCmdStatus:
    def test_no_state(self, tmp_path):
        assert cli.cmd_status(ns(dir=str(tmp_path))) == 1

    def test_stopped_without_marker(self, tmp_path):
        write_state(tmp_path, {"running": False, "pid": 1})
        assert cli.cmd_status(ns(dir=str(tmp_path))) == 1

    def test_running_with_real_listener_and_marker(self, tmp_path, monkeypatch):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        try:
            write_state(
                tmp_path,
                {"running": True, "pid": 1, "port": port, "ca_fingerprint": "ABC"},
            )
            write_trust_marker(tmp_path, {"fingerprint": "ABC"})
            monkeypatch.setattr(cli, "pid_is_alive", lambda pid: True)
            assert cli.cmd_status(ns(dir=str(tmp_path))) == 0
        finally:
            listener.close()

    def test_running_with_closed_port_and_no_marker(self, tmp_path, monkeypatch):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        write_state(tmp_path, {"running": True, "pid": 1, "port": port})
        monkeypatch.setattr(cli, "pid_is_alive", lambda pid: True)
        assert cli.cmd_status(ns(dir=str(tmp_path))) == 0
        write_trust_marker(tmp_path, {"fingerprint": "OTHER"})
        assert cli.cmd_status(ns(dir=str(tmp_path))) == 0

    def test_non_integer_port(self, tmp_path, monkeypatch):
        write_state(tmp_path, {"running": True, "pid": 1, "port": "nope"})
        monkeypatch.setattr(cli, "pid_is_alive", lambda pid: True)
        assert cli.cmd_status(ns(dir=str(tmp_path))) == 0


class TestCmdReport:
    def test_value_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            cli, "build_report", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad"))
        )
        assert cli.cmd_report(ns(dir=str(tmp_path))) == 2

    @pytest.mark.parametrize(
        ("outcome", "code"),
        [
            ("OK", 0),
            ("SILENT", 1),
            ("INCOMPLETE", 1),
            ("UNVERIFIED", 2),
            ("TAMPERED", 2),
        ],
    )
    def test_outcome_codes(self, tmp_path, monkeypatch, outcome, code):
        monkeypatch.setattr(cli, "build_report", lambda *a, **k: {"outcome": outcome})
        assert cli.cmd_report(ns(dir=str(tmp_path))) == code


class TestMainDispatch:
    def test_dispatch(self, monkeypatch):
        calls = []

        def make(name):
            def handler(args):
                calls.append((name, args.action, getattr(args, "day", None)))
                return 0

            return handler

        monkeypatch.setattr(cli, "cmd_start", make("start"))
        monkeypatch.setattr(cli, "cmd_stop", make("stop"))
        monkeypatch.setattr(cli, "cmd_status", make("status"))
        monkeypatch.setattr(cli, "cmd_report", make("report"))
        assert cli.main(["watch", "start", "."]) == 0
        assert cli.main(["watch", "stop", ".", "--remove-ca"]) == 0
        assert cli.main(["watch", "status", "."]) == 0
        assert cli.main(["watch", "report", ".", "--day", "2026-01-01"]) == 0
        assert calls[-1] == ("report", "report", "2026-01-01")

    def test_module_entrypoint(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["nomosguard", "watch", "report", str(tmp_path)])
        with pytest.raises(SystemExit) as exc:
            runpy.run_module("nomosguard.cli", run_name="__main__")
        assert exc.value.code == 2
