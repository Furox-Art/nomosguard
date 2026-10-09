"""Containment policy: the gate rules for security decisions.

The gate applies these rules to the MulVAL-style derived facts:

    execCode(host, attacker)        -> ISOLATE_HOST  (the host is compromised)
    canAccessHost(attacker, host)   -> REVOKE_ACCESS (the attacker's path exists)
    grantsPrivilege(host, priv)     -> ESCALATE       (privileged compromise)

Every decision carries the full derivation chain — the same fail-closed
discipline as the existing gate.
"""

from __future__ import annotations

from .gate import Decision, PolicyRule


def containment_policy_rules() -> list[PolicyRule]:
    """The security containment gate rules. Deterministic."""
    return [
        PolicyRule(
            name="isolate_compromised_host",
            match_relation="execCode",
            decision=Decision.ISOLATE_HOST,
            description="A host with derived code execution is compromised — isolate it.",
            # execCode is trustworthy when it is *derived* (exploit) or
            # directly attested (exec_code claim). A bare access path is
            # NOT enough — see revoke_attacker_access, which requires no
            # compromise evidence.
            requires=("network", "exec_code"),
        ),
        PolicyRule(
            name="revoke_attacker_access",
            match_relation="canAccessHost",
            decision=Decision.REVOKE_ACCESS,
            description="An attacker with a derived access path must have it revoked.",
            # Access paths need only network evidence; vulnerability or
            # execution evidence is not required to revoke a path.
            requires=("network",),
        ),
        PolicyRule(
            name="escalate_privileged_compromise",
            match_relation="grantsPrivilege",
            decision=Decision.ESCALATE,
            description="A privileged compromise needs human escalation.",
            requires=("network", "privilege"),
        ),
    ]
