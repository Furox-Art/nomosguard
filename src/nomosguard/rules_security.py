"""MulVAL-style security inference rules.

These rules implement the classic MulVAL attack-graph semantics in the
unification engine:

    canAccessHost(attacker, host)  :-  netAccess(host, protocol:port),
                                       canAccessHost(attacker, host)   [base: network reachability]

    execCode(host, user)           :-  canAccessHost(attacker, host),
                                       vulExists(host, vulID)          [exploit a vulnerability]

    canAccessHost(attacker, host2) :-  canAccessHost(attacker, host1),
                                       execCode(host1, user)           [lateral movement]

    hasPrivilege(user, priv)       :-  execCode(host, user),
                                       hasPrivilege(user, priv)        [privilege via code execution]

Every derived fact traces back to its source claims (host inventory,
network config, CVE records) — the same discipline as the tool-call rules.
"""

from __future__ import annotations

from typing import Any

from .rules import Pattern, Rule


def security_rules() -> list[Rule]:
    """The MulVAL-style security rule set.

    Deterministic: same evidence, same derivations, always.
    """
    return [
        # Network reachability is given (from network config records):
        # attacker canAccessHost host is already a base fact from the
        # network extractor. No rule needed for the base case.

        # Exploit: attacker can reach a host with a known vulnerability
        # -> code execution on that host
        Rule(
            name="exploit_vulnerability",
            body=(
                Pattern("?attacker", "canAccessHost", "?host"),
                Pattern("?host", "vulExists", "?cve"),
            ),
            head=Pattern("?host", "execCode", "?attacker"),
            description="An attacker that can reach a vulnerable host achieves code execution.",
        ),

        # Lateral movement: attacker can reach host1, executes code there,
        # -> can reach host2 (pivot through the compromised host)
        Rule(
            name="lateral_movement",
            body=(
                Pattern("?attacker", "canAccessHost", "?host1"),
                Pattern("?host1", "execCode", "?user"),
                Pattern("?host1", "netAccess", "?port"),
                Pattern("?host2", "netAccess", "?port"),
            ),
            head=Pattern("?attacker", "canAccessHost", "?host2"),
            description="An attacker who compromised host1 can pivot to host2 sharing the same exposed port.",
        ),

        # Privilege escalation: code execution as user + user holds privilege
        # -> attacker gains the privilege
        Rule(
            name="privilege_via_exec",
            body=(
                Pattern("?host", "execCode", "?user"),
                Pattern("?user", "hasPrivilege", "?priv"),
            ),
            head=Pattern("?host", "grantsPrivilege", "?priv"),
            description="Code execution on a host grants the executing user's privileges to that host.",
        ),
    ]
