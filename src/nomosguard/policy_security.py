"""Containment policy: the gate rules for security decisions.

The gate applies these rules to the MulVAL-style derived facts:

    execCode(host, attacker)        -> ISOLATE_HOST  (the host is compromised)
    canAccessHost(attacker, host)   -> REVOKE_ACCESS (the attacker's path exists)
    grantsPrivilege(host, priv)     -> ESCALATE       (privileged compromise)

Every decision carries the full derivation chain — the same fail-closed
discipline as the existing gate.
"""

from __future__ import annotations

from .constants import (
    CLAIM_KIND_EXEC_CODE,
    CLAIM_KIND_NETWORK,
    CLAIM_KIND_PRIVILEGE,
    CLAIM_KIND_TEMPORAL_BRUTE_FORCE,
    CLAIM_KIND_TEMPORAL_EXFIL_BURST,
    CLAIM_KIND_TEMPORAL_PORT_SCAN,
)
from .gate import Decision, PolicyRule


def _signature_requirement(signature_id: str) -> str:
    """The claim-kind requirement for one signature (NG-0003 -> ...ng-0003).

    Built through the same function the bridge builds the claim kind
    with, so a typo cannot make a rule demand evidence that no extractor
    can ever emit.
    """
    from .signature_bridge import claim_kind

    return claim_kind(signature_id)


#: Evidence requirement for the critical-signature rule: the concrete
#: kind of NG-0003's claim, not a generic "signature".
NUMBERED_SIGNATURE_KIND = _signature_requirement("NG-0003")


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
            requires=(CLAIM_KIND_NETWORK, CLAIM_KIND_EXEC_CODE),
        ),
        PolicyRule(
            name="revoke_attacker_access",
            match_relation="canAccessHost",
            decision=Decision.REVOKE_ACCESS,
            description="An attacker with a derived access path must have it revoked.",
            # Access paths need only network evidence; vulnerability or
            # execution evidence is not required to revoke a path.
            requires=(CLAIM_KIND_NETWORK,),
        ),
        PolicyRule(
            name="escalate_privileged_compromise",
            match_relation="grantsPrivilege",
            decision=Decision.ESCALATE,
            description="A privileged compromise needs human escalation.",
            requires=(CLAIM_KIND_NETWORK, CLAIM_KIND_PRIVILEGE),
        ),
        PolicyRule(
            name="escalate_access_attempt_in_progress",
            match_relation="accessAttemptInProgress",
            decision=Decision.ESCALATE,
            description="An actor brute-forcing with reachability is attempting access right now — a human must decide before it becomes a compromise.",
            requires=(CLAIM_KIND_TEMPORAL_BRUTE_FORCE, CLAIM_KIND_NETWORK),
        ),
        PolicyRule(
            name="revoke_enumeration_path",
            match_relation="enumeratingHost",
            decision=Decision.REVOKE_ACCESS,
            description="A scanning actor enumerating a live host must have the path revoked.",
            requires=(CLAIM_KIND_TEMPORAL_PORT_SCAN, CLAIM_KIND_NETWORK),
        ),
        PolicyRule(
            name="isolate_active_exfiltration",
            match_relation="dataExfilInProgress",
            decision=Decision.ISOLATE_HOST,
            description="A host actively exfiltrating data while running attacker code must be isolated.",
            requires=(CLAIM_KIND_TEMPORAL_EXFIL_BURST, CLAIM_KIND_EXEC_CODE),
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
            requires=(NUMBERED_SIGNATURE_KIND, CLAIM_KIND_NETWORK),
        ),
    ]
