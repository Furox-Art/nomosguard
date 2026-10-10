"""Security-level facts: host, network, user, service, privilege.

These extend the (subject, relation, object) model with the vocabulary
network security analysis needs. The extractors are pure functions of
the claim payload — same discipline as the tool-call extractors.

Fact vocabulary:
    (host, execCode, user)           — code executes on host as user
    (host, netAccess, protocol:port) — host accepts network connections
    (host, vulExists, cve)           — host has a known vulnerability
    (host, vulnSeverity, severity)   — host has a vulnerability at an NVD
                                       CVSS band (CRITICAL/HIGH/MEDIUM/LOW),
                                       grounded by nomosguard.vuln_db
    (attacker, canAccessHost, host)  — attacker can reach the host
    (user, hasPrivilege, privilege)  — user holds a privilege
    (host, runsService, service)     — host runs a service
"""

from __future__ import annotations

from typing import Any

from .rules import Fact, register_extractor


@register_extractor("host")
def _extract_host(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from a host inventory record.

    Payload convention:
      {"hostname": str, "ip": str, "os": str, "services": [str, ...]}
    Produces: (hostname, runsService, service) for each service.
    """
    hostname = str(payload.get("hostname", ""))
    services = payload.get("services", [])
    facts = []
    if hostname and isinstance(services, list):
        for svc in services:
            if isinstance(svc, str) and svc.strip():
                facts.append(Fact(hostname, "runsService", svc.strip(), ("host",)))
    return facts


@register_extractor("network")
def _extract_network(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from a network access record.

    Payload convention:
      {"host": str, "protocol": "tcp|udp", "port": int, "allowed_from": str}
    Produces: (host, netAccess, protocol:port), (allowed_from, canAccessHost, host).
    """
    host = str(payload.get("host", ""))
    protocol = str(payload.get("protocol", "")).lower()
    port = payload.get("port")
    allowed_from = str(payload.get("allowed_from", ""))
    facts = []
    if host and protocol and isinstance(port, int):
        facts.append(Fact(host, "netAccess", f"{protocol}:{port}", ("network",)))
        if allowed_from:
            facts.append(Fact(allowed_from, "canAccessHost", host, ("network",)))
    return facts


@register_extractor("exec_code")
def _extract_exec_code(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from a code-execution event.

    Payload convention:
      {"host": str, "user": str, "process": str}
    Produces: (host, execCode, user).
    """
    host = str(payload.get("host", ""))
    user = str(payload.get("user", ""))
    facts = []
    if host and user:
        facts.append(Fact(host, "execCode", user, ("exec_code",)))
    return facts


@register_extractor("privilege")
def _extract_privilege(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from a privilege assignment record.

    Payload convention:
      {"user": str, "privilege": str, "host": str}
    Produces: (user, hasPrivilege, privilege).
    """
    user = str(payload.get("user", ""))
    privilege = str(payload.get("privilege", ""))
    facts = []
    if user and privilege:
        facts.append(Fact(user, "hasPrivilege", privilege, ("privilege",)))
    return facts


@register_extractor("vuln_host")
def _extract_vuln_host(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract security-level facts from a host vulnerability record.

    Payload convention: {"host": str, "cve": str}
    Produces: (host, vulExists, cve) — the MulVAL-style relation.
    """
    host = str(payload.get("host", ""))
    cve = str(payload.get("cve", ""))
    facts = []
    if host and cve:
        facts.append(Fact(host, "vulExists", cve, ("vuln_host",)))
    return facts


# -- NVD-grounded severity ----------------------------------------------------
# The vuln_host claim says only "some CVE is present". The vuln_severity
# claim adds the NVD-grounded CVSS band, so the engine can distinguish
# "has a CVE" from "has a CRITICAL CVE" — a distinction the bare relation
# could not express. The severity is grounded by nomosguard.vuln_db
# (NVD API 2.0, offline-cached) before the claim reaches the ledger; this
# extractor is a pure function of the already-enriched payload, so no I/O
# and no nondeterminism enters the core.

@register_extractor("vuln_severity")
def _extract_vuln_severity(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract severity facts from an NVD-enriched vulnerability record.

    Payload convention:
      {"host": str, "cve": str, "cvss": float, "severity": "CRITICAL"|...}

    Produces: (host, vulnSeverity, severity) — e.g.
      Fact("web01", "vulnSeverity", "CRITICAL").

    The extractor trusts the severity already carried by the payload (it was
    grounded by the NVD layer at ingestion time) rather than re-deriving it,
    which keeps the core free of the NVD dependency. A payload missing the
    severity field yields no fact — the engine stays silent instead of
    guessing a band.
    """
    host = str(payload.get("host", ""))
    severity = str(payload.get("severity", "")).strip().upper()
    facts = []
    if host and severity and severity != "UNKNOWN":
        facts.append(Fact(host, "vulnSeverity", severity, ("vuln_severity",)))
    return facts
