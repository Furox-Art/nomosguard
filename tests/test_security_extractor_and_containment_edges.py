"""Security facts must derive only from stated fields; commands never run by default."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from nomosguard import containment as actions
from nomosguard import facts_security as facts
from nomosguard.rules import ClaimValueError


def test_host_extractor_ignores_missing_services_but_rejects_malformed_services() -> (
    None
):
    assert facts._extract_host({"hostname": "node", "services": None}, "") == []
    assert facts._extract_host({"hostname": ""}, "") == []
    for payload in (
        {"hostname": "node", "services": "postgres"},
        {"hostname": "node", "services": [12]},
    ):
        with pytest.raises(ClaimValueError, match="services"):
            facts._extract_host(payload, "direct")


def test_host_extractor_does_not_emit_blank_service() -> None:
    rows = facts._extract_host(
        {"hostname": "node", "services": [" ", " SSH ", ""]}, "direct"
    )
    assert [(f.subject, f.object) for f in rows] == [("node", "SSH")]


@pytest.mark.parametrize("bad", [True, False, 3.1, "443"])
def test_network_port_must_be_integer_and_not_boolean(bad) -> None:
    with pytest.raises(ClaimValueError, match="port"):
        facts._extract_network(
            {"host": "web", "protocol": "tcp", "port": bad, "allowed_from": "attacker"},
            "direct",
        )


@pytest.mark.parametrize(
    ("payload", "relation", "count"),
    [
        ({"host": "server", "protocol": "tcp", "port": None}, "netAccess", 0),
        ({"host": "server", "protocol": "tcp", "port": 443}, "netAccess", 1),
        (
            {
                "host": "server",
                "protocol": "tcp",
                "port": 443,
                "allowed_from": "internet",
            },
            "canAccessHost",
            2,
        ),
    ],
)
def test_network_access_never_infers_unprovided_source(
    payload: dict,
    relation: str,
    count: int,
) -> None:
    rows = facts._extract_network(payload, "direct")
    assert len(rows) == count
    assert any(row.relation == relation for row in rows) if count else rows == []


@pytest.mark.parametrize(
    ("extractor", "payload"),
    [
        (facts._extract_exec_code, {"host": "server"}),
        (facts._extract_exec_code, {"user": "user"}),
        (facts._extract_privilege, {"user": "user"}),
        (facts._extract_privilege, {"privilege": "admin"}),
        (facts._extract_vuln_host, {"host": "host"}),
        (facts._extract_vuln_host, {"cve": "CVE-1"}),
        (facts._extract_vuln_severity, {"host": "host", "severity": "UNKNOWN"}),
        (facts._extract_vuln_severity, {"host": "host"}),
    ],
)
def test_missing_evidence_fields_do_not_create_unjustified_security_facts(
    extractor,
    payload: dict,
) -> None:
    assert extractor(payload, "evidence") == []


def test_positive_security_extractor_facts_preserve_provenance() -> None:
    for extractor, payload, relation in (
        (facts._extract_exec_code, {"host": "h", "user": "u"}, "execCode"),
        (facts._extract_privilege, {"user": "u", "privilege": "admin"}, "hasPrivilege"),
        (facts._extract_vuln_host, {"host": "h", "cve": "CVE-1"}, "vulExists"),
        (
            facts._extract_vuln_severity,
            {"host": "h", "severity": "critical"},
            "vulnSeverity",
        ),
    ):
        entries = extractor(payload, "direct evidence")
        assert len(entries) == 1
        assert entries[0].relation == relation
        assert entries[0].sources


def test_containment_never_executes_without_explicit_allowlist() -> None:
    command = actions.ContainmentCommand(
        description="network isolate",
        decision="ISOLATE_HOST",
        subject="h",
        policy_rule="test",
        chain=(),
        argv=("untrusted-command", "arg"),
        reversible=True,
        undo=("undo-command", "arg"),
    )
    assert not actions.Executor().execute(command)["executed"]
    assert not actions.Executor(enabled=True, allowlist=("different",)).execute(
        command
    )["executed"]
    assert not actions.Executor().undo(command)["executed"]
    assert not actions.Executor(enabled=True, allowlist=("different",)).undo(command)[
        "executed"
    ]


@pytest.mark.parametrize("operation", ["execute", "undo"])
def test_containment_subprocess_failure_is_reported_not_hidden(
    operation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cmd = actions.ContainmentCommand(
        description="revoke",
        decision="REVOKE_ACCESS",
        subject="h",
        policy_rule="test",
        chain=(),
        argv=("noop",),
        reversible=True,
        undo=("noop", "--restore"),
    )

    def failed(*args, **kwargs):
        raise OSError("permission denied for controlled test")

    monkeypatch.setattr(actions.subprocess, "run", failed)
    result = getattr(actions.Executor(enabled=True, allowlist=("noop",)), operation)(
        cmd
    )
    assert result["executed"] is False
    assert "failed" in result["reason"]


@pytest.mark.parametrize("operation", ["execute", "undo"])
def test_containment_allowlisted_subprocess_preserves_real_exit_code(
    operation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cmd = actions.ContainmentCommand(
        description="revoke",
        decision="REVOKE_ACCESS",
        subject="h",
        policy_rule="test",
        chain=(),
        argv=("noop",),
        reversible=True,
        undo=("noop", "--restore"),
    )
    monkeypatch.setattr(
        actions.subprocess,
        "run",
        lambda *args, **kwargs: Mock(returncode=7, stdout="ok", stderr="problem"),
    )
    response = getattr(actions.Executor(enabled=True, allowlist=("noop",)), operation)(
        cmd
    )
    assert response["executed"] is True
    assert response["returncode"] == 7
