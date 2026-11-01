"""Single definition of the vocabularies and default rule sets.

Why this module exists: the tool-call rule set, the gate rules that
consume its derived facts, and the claim-kind vocabulary used to say
"this decision is incomplete" were each written out again in every
consumer (policy.py, mcp_server.py, demo.py, benchmark/run_suite.py,
ingest/cli.py). Five copies drift — and they already had: the demo's
copy had silently lost a rule, and the order differed between files.

One definition, imported everywhere. A rule that appears in two places
is a rule that will disagree with itself; a rule defined once is a rule
you can audit.

Nothing in here is stateful or environment-dependent. The vocabularies
are plain constants; the rule sets are built once on first use and then
shared as the same immutable objects (a lazy build keeps this module free
of imports from `.gate`/`.rules`, which must stay import-cycle-free).
"""

from __future__ import annotations

from typing import Any

# The vocabularies live in ._vocab: `.rules` needs them too, and defining
# them here would make these two modules import each other. Re-exported
# unchanged, so `nomosguard.constants.CLAIM_KIND_*` stays the public name.
from ._vocab import (
    CLAIM_KIND_EXEC_CODE,
    CLAIM_KIND_HOST,
    CLAIM_KIND_NETWORK,
    CLAIM_KIND_POLICY_RULE,
    CLAIM_KIND_PRIVILEGE,
    CLAIM_KIND_SIGNATURE_PREFIX,
    CLAIM_KIND_TEMPORAL_BRUTE_FORCE,
    CLAIM_KIND_TEMPORAL_EXFIL_BURST,
    CLAIM_KIND_TEMPORAL_PORT_SCAN,
    CLAIM_KIND_TEMPORAL_PREFIX,
    CLAIM_KIND_TOOL_CALL,
    CLAIM_KIND_TRAFFIC_REQUEST,
    CLAIM_KIND_TRAFFIC_SESSION,
    CLAIM_KIND_VULN_HOST,
    CLAIM_KIND_VULN_SEVERITY,
    CLAIM_KIND_VULNERABILITY,
    CLAIM_KINDS,
    POLICY_EFFECT_ALLOW,
    POLICY_EFFECT_DENY,
    TRAFFIC_CLASS_PROMPT,
    TRAFFIC_CLASS_TELEMETRY,
    TRAFFIC_CLASS_TOOL_RESULT,
    TRAFFIC_CLASS_TRANSCRIPT_UPLOAD,
    TRAFFIC_CLASS_UNKNOWN,
    TRAFFIC_CLASSES,
    VALID_POLICY_EFFECTS,
)

__all__ = [
    "CLAIM_KINDS",
    "CLAIM_KIND_EXEC_CODE",
    "CLAIM_KIND_HOST",
    "CLAIM_KIND_NETWORK",
    "CLAIM_KIND_POLICY_RULE",
    "CLAIM_KIND_PRIVILEGE",
    "CLAIM_KIND_SIGNATURE_PREFIX",
    "CLAIM_KIND_TEMPORAL_BRUTE_FORCE",
    "CLAIM_KIND_TEMPORAL_EXFIL_BURST",
    "CLAIM_KIND_TEMPORAL_PORT_SCAN",
    "CLAIM_KIND_TEMPORAL_PREFIX",
    "CLAIM_KIND_TOOL_CALL",
    "CLAIM_KIND_TRAFFIC_REQUEST",
    "CLAIM_KIND_TRAFFIC_SESSION",
    "CLAIM_KIND_VULNERABILITY",
    "CLAIM_KIND_VULN_HOST",
    "CLAIM_KIND_VULN_SEVERITY",
    "POLICY_EFFECT_ALLOW",
    "POLICY_EFFECT_DENY",
    "POLICY_FORMAT",
    "POLICY_FORMAT_VERSION",
    "TRAFFIC_CLASSES",
    "TRAFFIC_CLASS_PROMPT",
    "TRAFFIC_CLASS_TELEMETRY",
    "TRAFFIC_CLASS_TOOL_RESULT",
    "TRAFFIC_CLASS_TRANSCRIPT_UPLOAD",
    "TRAFFIC_CLASS_UNKNOWN",
    "VALID_POLICY_EFFECTS",
    "canonical_tool_call_gate_rules",
    "canonical_tool_call_rules",
    "is_known_claim_kind",
    "tool_call_gate_rules",
    "tool_call_rules",
    "traffic_gate_rules",
    "traffic_policy",
    "traffic_rules",
]

# -- policy file format (the pin checked by policy.load_policy) ----------------
POLICY_FORMAT = "nomosguard-policy"
POLICY_FORMAT_VERSION = 1

# -- the canonical tool-call rule set ----------------------------------------
# Defined ONCE and built on first use. Consumers take these very objects
# (tool_call_rules() returns a fresh list holding the same Rule
# instances), so every consumer provably runs the same policy — see
# tests/test_defaults.py.

_TOOL_CALL_RULES: tuple[Any, ...] | None = None
_TOOL_CALL_GATE_RULES: tuple[Any, ...] | None = None


def _build_tool_call_rules() -> tuple[Any, ...]:
    from .rules import Pattern, Rule

    return (
        Rule(
            name="tool_on_vulnerable_component",
            body=(
                Pattern("?agent", "calls", "?tool"),
                Pattern("?agent", "operates_on", "?component"),
                Pattern("?component", "has_vulnerability", "?cve"),
            ),
            head=Pattern("?agent", "exposes", "?component"),
            description="An agent operating a tool on a vulnerable component exposes it.",
        ),
        # The called tool and the denied action are bound by the SAME
        # variable (?tool): the rule fires only when the tool the agent
        # actually called IS the denied action. With two variables it
        # fired on any tool call plus any denial by the same subject —
        # an alert the evidence never stated (see rules._extract_policy_rule
        # for the action-scoped fact that makes this unification possible).
        Rule(
            name="policy_denied_action",
            body=(
                Pattern("?agent", "calls", "?tool"),
                Pattern("?agent", "policy_denies_action", "?tool"),
            ),
            head=Pattern("?agent", "violates", "policy"),
            description="An agent calling a tool whose action is policy-denied violates policy.",
        ),
        Rule(
            name="reaches_base",
            body=(Pattern("?from", "operates_on", "?to"),),
            head=Pattern("?from", "reaches", "?to"),
            description="Direct operation implies reachability.",
        ),
        Rule(
            name="reaches_transitive",
            body=(
                Pattern("?from", "reaches", "?mid"),
                Pattern("?mid", "reaches", "?to"),
            ),
            head=Pattern("?from", "reaches", "?to"),
            description="Transitive reachability: X reaches Z when X reaches Y and Y reaches Z.",
        ),
        Rule(
            name="transitive_exposure",
            body=(
                Pattern("?agent", "calls", "?tool"),
                Pattern("?agent", "reaches", "?component"),
                Pattern("?component", "has_vulnerability", "?cve"),
            ),
            head=Pattern("?agent", "exposes", "?component"),
            description="An agent that can reach a vulnerable component (directly or through a chain) exposes it.",
        ),
    )


def _build_tool_call_gate_rules() -> tuple[Any, ...]:
    from .gate import Decision, PolicyRule

    return (
        PolicyRule(
            name="block_vulnerable_exposure",
            match_relation="exposes",
            decision=Decision.BLOCK,
            description="Exposure of a vulnerable component is blocked.",
        ),
        PolicyRule(
            name="alert_policy_violation",
            match_relation="violates",
            decision=Decision.ALERT,
            description="Policy violations raise an alert.",
        ),
    )


def canonical_tool_call_rules() -> tuple[Any, ...]:
    """The canonical rule set as a cached tuple (one instance per process)."""
    global _TOOL_CALL_RULES
    if _TOOL_CALL_RULES is None:
        _TOOL_CALL_RULES = _build_tool_call_rules()
    return _TOOL_CALL_RULES


def tool_call_rules() -> list[Any]:
    """The canonical tool-call rule set (the same Rule objects every time)."""
    return list(canonical_tool_call_rules())


def canonical_tool_call_gate_rules() -> tuple[Any, ...]:
    """The canonical gate rules as a cached tuple."""
    global _TOOL_CALL_GATE_RULES
    if _TOOL_CALL_GATE_RULES is None:
        _TOOL_CALL_GATE_RULES = _build_tool_call_gate_rules()
    return _TOOL_CALL_GATE_RULES


def tool_call_gate_rules() -> list[Any]:
    """The canonical gate rules for the tool-call vocabulary."""
    return list(canonical_tool_call_gate_rules())


# -- the canonical outbound-traffic rule set --------------------------------
# A transcript upload is a derived risk, not just a label: the rule makes the
# derivation (and its evidence source) visible in the same trace the tool-call
# rules use. The gate rules then map every observed class to a decision. They
# are defined here once for the same reason as the tool-call set: a policy rule
# written in two places will disagree with itself.

_TRAFFIC_RULES: tuple[Any, ...] | None = None
_TRAFFIC_GATE_RULES: dict[bool, tuple[Any, ...]] = {}


def _build_traffic_rules() -> tuple[Any, ...]:
    from .rules import Pattern, Rule

    return (
        Rule(
            name="transcript_upload_leaks_transcript",
            body=(Pattern("?host", "requestClass", TRAFFIC_CLASS_TRANSCRIPT_UPLOAD),),
            head=Pattern("?host", "transcriptLeak", "true"),
            description="A request classified as a transcript upload leaks conversation data.",
        ),
    )


def _build_traffic_gate_rules(enforcement: bool) -> tuple[Any, ...]:
    from .gate import Decision, PolicyRule

    risk = Decision.BLOCK if enforcement else Decision.ALERT
    return (
        PolicyRule(
            name="allow_prompt_traffic",
            match_relation="requestClass",
            match_object=TRAFFIC_CLASS_PROMPT,
            decision=Decision.ALLOW,
            requires=(CLAIM_KIND_TRAFFIC_REQUEST,),
            description="Model prompt traffic is expected and allowed.",
        ),
        PolicyRule(
            name="allow_tool_result_traffic",
            match_relation="requestClass",
            match_object=TRAFFIC_CLASS_TOOL_RESULT,
            decision=Decision.ALLOW,
            requires=(CLAIM_KIND_TRAFFIC_REQUEST,),
            description="Tool-result traffic to a model endpoint is expected.",
        ),
        PolicyRule(
            name="allow_telemetry_traffic",
            match_relation="requestClass",
            match_object=TRAFFIC_CLASS_TELEMETRY,
            decision=Decision.ALLOW,
            requires=(CLAIM_KIND_TRAFFIC_REQUEST,),
            description="Telemetry traffic is recorded without a risk decision.",
        ),
        PolicyRule(
            name="block_transcript_upload",
            match_relation="transcriptLeak",
            decision=risk,
            requires=(CLAIM_KIND_TRAFFIC_REQUEST,),
            description="Transcript uploads are alerted, or blocked in enforcement mode.",
        ),
        PolicyRule(
            name="block_unknown_traffic",
            match_relation="requestClass",
            match_object=TRAFFIC_CLASS_UNKNOWN,
            decision=risk,
            requires=(CLAIM_KIND_TRAFFIC_REQUEST,),
            description="Unclassified outbound requests are alerted, or blocked in enforcement mode.",
        ),
        PolicyRule(
            name="block_secret_exposure",
            match_relation="secretExposure",
            decision=risk,
            requires=(CLAIM_KIND_TRAFFIC_REQUEST,),
            description="Any masked secret hit in outbound payloads is alerted, or blocked in enforcement mode.",
        ),
        PolicyRule(
            name="block_watch_silence",
            match_relation="trafficSilent",
            decision=risk,
            requires=(CLAIM_KIND_TRAFFIC_SESSION,),
            description="A watch session that captured nothing is never treated as success.",
        ),
    )


def canonical_traffic_rules() -> tuple[Any, ...]:
    """The canonical traffic derivation rules as a cached tuple."""
    global _TRAFFIC_RULES
    if _TRAFFIC_RULES is None:
        _TRAFFIC_RULES = _build_traffic_rules()
    return _TRAFFIC_RULES


def traffic_rules() -> list[Any]:
    """The canonical outbound-traffic derivation rules."""
    return list(canonical_traffic_rules())


def traffic_gate_rules(enforcement: bool = False) -> list[Any]:
    """Traffic gate rules for warning (default) or enforcement mode."""
    key = bool(enforcement)
    if key not in _TRAFFIC_GATE_RULES:
        _TRAFFIC_GATE_RULES[key] = _build_traffic_gate_rules(key)
    return list(_TRAFFIC_GATE_RULES[key])


def traffic_policy(enforcement: bool = False) -> tuple[list[Any], list[Any]]:
    """The complete traffic policy: derivation rules plus gate rules."""
    return traffic_rules(), traffic_gate_rules(enforcement)


def is_known_claim_kind(kind: str) -> bool:
    """Whether `kind` names a claim kind the shipped extractors understand.

    Runtime-built kinds (temporal_<rule>, signature_<id>) are matched on
    their prefix: a claim the extractors cannot dispatch on would
    silently derive nothing, so callers can check before asserting.
    """
    if kind in CLAIM_KINDS:
        return True
    return kind.startswith(
        (CLAIM_KIND_TEMPORAL_PREFIX, CLAIM_KIND_SIGNATURE_PREFIX)
    )
