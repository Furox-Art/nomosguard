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

from .constants import (
    CLAIM_KIND_EXEC_CODE,
    CLAIM_KIND_HOST,
    CLAIM_KIND_NETWORK,
    CLAIM_KIND_PRIVILEGE,
    CLAIM_KIND_VULN_HOST,
    CLAIM_KIND_VULN_SEVERITY,
)
from .rules import ClaimValueError, Fact, _string_field, register_extractor


def _int_field(payload: dict[str, Any], field: str, claim_kind: str) -> int | None:
    """Read an integer field, refusing non-integers (and bools).

    `True` is an int in Python, so a boolean port would stringify to the
    "port" `True` — a fact about a port nobody stated. Absent (None) keeps
    the no-fact semantics; a present non-integer is refused by name.
    """
    value = payload.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ClaimValueError(
            f"{claim_kind}: field {field!r} must be an integer, got {value!r}"
        )
    return value


@register_extractor(CLAIM_KIND_HOST)
def _extract_host(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from a host inventory record.

    Payload convention:
      {"hostname": str, "ip": str, "os": str, "services": [str, ...]}
    Produces: (hostname, runsService, service) for each service.
    """
    hostname = _string_field(payload, "hostname", CLAIM_KIND_HOST)
    services = payload.get("services", [])
    if services is None:
        services = []
    if not isinstance(services, list):
        raise ClaimValueError(
            f"{CLAIM_KIND_HOST}: field 'services' must be a list of strings, "
            f"got {services!r}"
        )
    facts = []
    if hostname:
        for svc in services:
            if not isinstance(svc, str):
                raise ClaimValueError(
                    f"{CLAIM_KIND_HOST}: field 'services' must contain "
                    f"strings, got {svc!r}"
                )
            if svc.strip():
                facts.append(Fact(hostname, "runsService", svc.strip(), (CLAIM_KIND_HOST,)))
    return facts


@register_extractor(CLAIM_KIND_NETWORK)
def _extract_network(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from a network access record.

    Payload convention:
      {"host": str, "protocol": "tcp|udp", "port": int, "allowed_from": str}
    Produces: (host, netAccess, protocol:port), (allowed_from, canAccessHost, host).
    """
    host = _string_field(payload, "host", CLAIM_KIND_NETWORK)
    protocol = _string_field(payload, "protocol", CLAIM_KIND_NETWORK).lower()
    port = _int_field(payload, "port", CLAIM_KIND_NETWORK)
    allowed_from = _string_field(payload, "allowed_from", CLAIM_KIND_NETWORK)
    facts = []
    if host and protocol and port is not None:
        facts.append(Fact(host, "netAccess", f"{protocol}:{port}", (CLAIM_KIND_NETWORK,)))
        if allowed_from:
            facts.append(Fact(allowed_from, "canAccessHost", host, (CLAIM_KIND_NETWORK,)))
    return facts


@register_extractor(CLAIM_KIND_EXEC_CODE)
def _extract_exec_code(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from a code-execution event.

    Payload convention:
      {"host": str, "user": str, "process": str}
    Produces: (host, execCode, user).
    """
    host = _string_field(payload, "host", CLAIM_KIND_EXEC_CODE)
    user = _string_field(payload, "user", CLAIM_KIND_EXEC_CODE)
    facts = []
    if host and user:
        facts.append(Fact(host, "execCode", user, (CLAIM_KIND_EXEC_CODE,)))
    return facts


@register_extractor(CLAIM_KIND_PRIVILEGE)
def _extract_privilege(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from a privilege assignment record.

    Payload convention:
      {"user": str, "privilege": str, "host": str}
    Produces: (user, hasPrivilege, privilege).
    """
    user = _string_field(payload, "user", CLAIM_KIND_PRIVILEGE)
    privilege = _string_field(payload, "privilege", CLAIM_KIND_PRIVILEGE)
    facts = []
    if user and privilege:
        facts.append(Fact(user, "hasPrivilege", privilege, (CLAIM_KIND_PRIVILEGE,)))
    return facts


@register_extractor(CLAIM_KIND_VULN_HOST)
def _extract_vuln_host(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract security-level facts from a host vulnerability record.

    Payload convention: {"host": str, "cve": str}
    Produces: (host, vulExists, cve) — the MulVAL-style relation.
    """
    host = _string_field(payload, "host", CLAIM_KIND_VULN_HOST)
    cve = _string_field(payload, "cve", CLAIM_KIND_VULN_HOST)
    facts = []
    if host and cve:
        facts.append(Fact(host, "vulExists", cve, (CLAIM_KIND_VULN_HOST,)))
    return facts


# -- NVD-grounded severity ----------------------------------------------------
# The vuln_host claim says only "some CVE is present". The vuln_severity
# claim adds the NVD-grounded CVSS band, so the engine can distinguish
# "has a CVE" from "has a CRITICAL CVE" — a distinction the bare relation
# could not express. The severity is grounded by nomosguard.vuln_db
# (NVD API 2.0, offline-cached) before the claim reaches the ledger; this
# extractor is a pure function of the already-enriched payload, so no I/O
# and no nondeterminism enters the core.

@register_extractor(CLAIM_KIND_VULN_SEVERITY)
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
    host = _string_field(payload, "host", CLAIM_KIND_VULN_SEVERITY)
    severity = _string_field(payload, "severity", CLAIM_KIND_VULN_SEVERITY).strip().upper()
    facts = []
    if host and severity and severity != "UNKNOWN":
        facts.append(Fact(host, "vulnSeverity", severity, (CLAIM_KIND_VULN_SEVERITY,)))
    return facts
