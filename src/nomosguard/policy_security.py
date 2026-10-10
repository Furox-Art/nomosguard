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
        PolicyRule(
            name="escalate_access_attempt_in_progress",
            match_relation="accessAttemptInProgress",
            decision=Decision.ESCALATE,
            description="An actor brute-forcing with reachability is attempting access right now — a human must decide before it becomes a compromise.",
            requires=("temporal_brute_force", "network"),
        ),
        PolicyRule(
            name="revoke_enumeration_path",
            match_relation="enumeratingHost",
            decision=Decision.REVOKE_ACCESS,
            description="A scanning actor enumerating a live host must have the path revoked.",
            requires=("temporal_port_scan", "network"),
        ),
        PolicyRule(
            name="isolate_active_exfiltration",
            match_relation="dataExfilInProgress",
            decision=Decision.ISOLATE_HOST,
            description="A host actively exfiltrating data while running attacker code must be isolated.",
            requires=("temporal_exfil_burst", "exec_code"),
        ),
        # -- signature rules --------------------------------------------------
        # Evidence from nomosguard.signatures / signature_bridge. The
        # claim kind is per-signature ("signature_ng-0003"), so the
        # requirement is expressed on the CONCRETE kind backing the
        # derivation: "signature_ng-0003". The gate's requires-match is
        # an exact membership test over the derived fact's sources
        # (gate.PolicyRule.requires), not a prefix test, so a generic
        # "signature" entry would always read as missing evidence and
        # mask a genuinely complete chain. The per-kind requirement is
        # honest and exact: it names the evidence this rule demands.
        PolicyRule(
            name="escalate_malicious_signature_on_reachable_actor",
            match_relation="hostUnderMaliciousProbe",
            decision=Decision.ESCALATE,
            description=(
                "A critical signature match (encoded PowerShell, credential "
                "dumping, ransomware) on an actor with a derived access path "
                "to a host: the hostile behaviour and the reachability point "
                "at the same target, so a human must decide now — before it "
                "becomes a compromise."
            ),
            requires=("signature_ng-0003", "network"),
        ),
    ]
