"""Security attack scenarios with known ground truth (MulVAL-style).

Each scenario is a small security telemetry set (hosts, network config,
vulnerabilities, privileges) plus the expected derived facts.
Ground truth is hand-derived from the facts, not from the engine.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ClaimSpec:
    kind: str
    payload: dict
    evidence: str


@dataclass(frozen=True)
class SecurityScenario:
    name: str
    description: str
    claims: tuple[ClaimSpec, ...]
    expected_exec_code: frozenset
    expected_can_access: frozenset
    expected_grants: frozenset


def _net(host: str, port: int, allowed_from: str, proto: str = "tcp") -> ClaimSpec:
    return ClaimSpec(
        kind="network",
        payload={"host": host, "protocol": proto, "port": port, "allowed_from": allowed_from},
        evidence=f"firewall: {allowed_from} -> {host}:{port}/{proto}",
    )


def _vuln(host: str, cve: str) -> ClaimSpec:
    return ClaimSpec(
        kind="vuln_host",
        payload={"host": host, "cve": cve},
        evidence=f"NVD: {cve} affects {host}",
    )


def _priv(user: str, privilege: str, host: str) -> ClaimSpec:
    return ClaimSpec(
        kind="privilege",
        payload={"user": user, "privilege": privilege, "host": host},
        evidence=f"iam: {user} has {privilege} on {host}",
    )


def build_security_scenarios() -> list[SecurityScenario]:
    """The security corpus. Deterministic."""
    return [
        SecurityScenario(
            name="single_host_exploit",
            description="An attacker can reach a host with a known CVE -> code execution.",
            claims=(
                _net("web01", 443, "attacker"),
                _vuln("web01", "CVE-2026-1"),
            ),
            expected_exec_code=frozenset({("web01", "attacker")}),
            expected_can_access=frozenset({("attacker", "web01")}),
            expected_grants=frozenset(),
        ),
        SecurityScenario(
            name="lateral_movement",
            description=(
                "Attacker compromises host1 (exposed 443 + CVE), then pivots "
                "to host2 which also exposes 443."
            ),
            claims=(
                _net("host1", 443, "attacker"),
                _vuln("host1", "CVE-2026-1"),
                _net("host2", 443, "internal"),
            ),
            expected_exec_code=frozenset({("host1", "attacker")}),
            expected_can_access=frozenset({
                ("attacker", "host1"),
                ("attacker", "host2"),
                ("internal", "host2"),
            }),
            expected_grants=frozenset(),
        ),
        SecurityScenario(
            name="privilege_escalation",
            description="Code execution on a host grants the executing user's privileges.",
            claims=(
                _net("db01", 5432, "attacker"),
                _vuln("db01", "CVE-2026-2"),
                _priv("attacker", "admin", "db01"),
            ),
            expected_exec_code=frozenset({("db01", "attacker")}),
            expected_can_access=frozenset({("attacker", "db01")}),
            expected_grants=frozenset({("db01", "admin")}),
        ),
        SecurityScenario(
            name="no_reach_no_compromise",
            description=(
                "The attacker cannot reach internal-db (only admin-laptop can). "
                "admin-laptop CAN reach it and DOES derive code execution — the "
                "engine must not conflate 'attacker cannot reach' with 'nobody "
                "can reach'."
            ),
            claims=(
                _net("internal-db", 5432, "admin-laptop"),
                _vuln("internal-db", "CVE-2026-3"),
            ),
            expected_exec_code=frozenset({("internal-db", "admin-laptop")}),
            expected_can_access=frozenset({("admin-laptop", "internal-db")}),
            expected_grants=frozenset(),
        ),
        SecurityScenario(
            name="reach_but_no_vuln",
            description="A reachable host with no vulnerability derives no code execution.",
            claims=(
                _net("web02", 443, "attacker"),
            ),
            expected_exec_code=frozenset(),
            expected_can_access=frozenset({("attacker", "web02")}),
            expected_grants=frozenset(),
        ),
    ]
