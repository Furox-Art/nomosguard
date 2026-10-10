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

    execCode(host, user)           :-  canAccessHost(attacker, host),
                                       vulnSeverity(host, "CRITICAL")   [exploit a CRITICAL CVE]

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

        # -- temporal rules ---------------------------------------------------
        # Patterns that exist only in the time dimension. These do NOT
        # assert compromise on their own; they mark an ACTOR as hostile
        # in progress, which the gate escalates. The evidence (event
        # counts, window) comes from nomosguard.temporal.

        # Brute force + reachability: an actor brute-forcing auth who can
        # reach a host is attempting access right now -> escalate.
        Rule(
            name="brute_force_attempting_access",
            body=(
                Pattern("?actor", "bruteForceDetected", "brute_force"),
                Pattern("?actor", "canAccessHost", "?host"),
            ),
            head=Pattern("?actor", "accessAttemptInProgress", "?host"),
            description="An actor exhibiting brute-force behavior with network reachability is attempting access now.",
        ),

        # Scan + reachability: a scanning actor that can reach a host is
        # enumerating it -> the access path must be revoked.
        Rule(
            name="scan_of_reachable_host",
            body=(
                Pattern("?actor", "scanDetected", "port_scan"),
                Pattern("?actor", "canAccessHost", "?host"),
            ),
            head=Pattern("?actor", "enumeratingHost", "?host"),
            description="A scanning actor with reachability is enumerating a live host.",
        ),

        # Exfil suspicion + compromise: a host suspected of exfiltration
        # that also runs attacker code is actively leaking -> isolate.
        Rule(
            name="active_exfiltration",
            body=(
                Pattern("?host", "exfilSuspected", "exfiltration"),
                Pattern("?host", "execCode", "?actor"),
            ),
            head=Pattern("?host", "dataExfilInProgress", "?actor"),
            description="A host with suspected exfiltration bursts and derived code execution is actively leaking data.",
        ),

        # -- signature rules --------------------------------------------------
        # Evidence from nomosguard.signatures / signature_bridge: a
        # signature match over raw log lines, with no model involved. The
        # facts it produces are behavioural, like the temporal ones — they
        # say an actor DID something, not that the actor is hostile
        # everywhere.
        #
        # ONE rule, chosen deliberately. Three plausible candidates were
        # considered:
        #   (a) signatureMatched + canAccessHost -> probe/attempt fact
        #   (b) maliciousActivity + canAccessHost -> compromise-ish fact
        #   (c) maliciousActivity -> standalone alert
        #
        # (b) is the one added. Why: it is the only one of the three that
        # is not already covered by an existing rule. (a) duplicates
        # brute_force_attempting_access — a signature match against a
        # reachable actor is the same conclusion the temporal brute-force
        # rule already reaches, and duplicating it would mean two rules
        # deriving near-identical facts from overlapping evidence. (c) is
        # a policy concern, not an inference one: "this actor is doing
        # something malicious" needs no access graph, so it belongs in
        # policy_security.py as an escalation, not here.
        #
        # (b) answers a question no other rule answers: a CRITICAL
        # signature (encoded PowerShell, credential dumping, ransomware
        # notes — behaviour that is malicious on its face, not merely
        # suspicious) from an actor that can actually REACH a host means
        # the malicious activity is aimed at a live target. Reachability
        # is what turns "someone somewhere is running encoded PowerShell"
        # into "this actor is attacking a host we protect", and the
        # derived fact says exactly that, per host.
        Rule(
            name="signature_malicious_actor",
            body=(
                Pattern("?actor", "maliciousActivity", "?sig"),
                Pattern("?actor", "canAccessHost", "?host"),
            ),
            head=Pattern("?actor", "hostUnderMaliciousProbe", "?host"),
            description=(
                "An actor with a critical signature match (malicious activity) "
                "and network reachability is attacking a host that can be "
                "reached — the signature evidence and the access graph point "
                "at the same target."
            ),
        ),

        # -- severity-gated exploit -------------------------------------------
        # Same shape as exploit_vulnerability, but gated on the NVD-grounded
        # CVSS band carried by the vulnSeverity relation. The distinction
        # matters operationally: a MEDIUM information disclosure and a
        # CRITICAL pre-auth RCE are both "a CVE is present" to the bare
        # vulExists relation, but only the latter justifies treating the
        # reachability as an immediate code-execution path.
        #
        # exploit_vulnerability still fires for ANY vulnerable host — this
        # rule adds the severity signal on top, it does not replace the
        # general case, so a host with only a MEDIUM CVE still derives
        # execCode through the original rule.
        Rule(
            name="exploit_critical_vulnerability",
            body=(
                Pattern("?attacker", "canAccessHost", "?host"),
                Pattern("?host", "vulnSeverity", "CRITICAL"),
            ),
            head=Pattern("?host", "execCode", "?attacker"),
            description=(
                "An attacker that can reach a host carrying a CRITICAL "
                "vulnerability (NVD CVSS base score >= 9.0) achieves code "
                "execution — severity-gated variant of exploit_vulnerability."
            ),
        ),
    ]
