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

# -- claim kinds --------------------------------------------------------------
# The ledger's claim-kind namespace. A claim kind IS the namespace: the
# fact extractors dispatch on it (rules._extract_facts), the WAL/header
# checks reference it, and the policy gate's `requires` names the kinds a
# decision needs before it is considered complete. Spelling one here
# means no module has to invent (or misspell) its own literal.

CLAIM_KIND_TOOL_CALL = "tool_call"
CLAIM_KIND_VULNERABILITY = "vulnerability"
CLAIM_KIND_POLICY_RULE = "policy_rule"

CLAIM_KIND_HOST = "host"
CLAIM_KIND_NETWORK = "network"
CLAIM_KIND_EXEC_CODE = "exec_code"
CLAIM_KIND_PRIVILEGE = "privilege"
CLAIM_KIND_VULN_HOST = "vuln_host"
CLAIM_KIND_VULN_SEVERITY = "vuln_severity"

# The per-finding bridges build their kinds at runtime:
#   temporal  -> f"{CLAIM_KIND_TEMPORAL_PREFIX}{rule_name}"
#   signature -> f"{CLAIM_KIND_SIGNATURE_PREFIX}{signature_id.lower()}"
CLAIM_KIND_TEMPORAL_PREFIX = "temporal_"
CLAIM_KIND_SIGNATURE_PREFIX = "signature_"

# The temporal kinds the shipped rules emit (the policy gate names these
# in its `requires`; see nomosguard.temporal_bridge).
CLAIM_KIND_TEMPORAL_BRUTE_FORCE = CLAIM_KIND_TEMPORAL_PREFIX + "brute_force"
CLAIM_KIND_TEMPORAL_PORT_SCAN = CLAIM_KIND_TEMPORAL_PREFIX + "port_scan"
CLAIM_KIND_TEMPORAL_EXFIL_BURST = CLAIM_KIND_TEMPORAL_PREFIX + "exfil_burst"

#: Every claim kind the shipped extractors understand (the runtime-built
#: temporal/signature kinds are covered by the prefixes above).
CLAIM_KINDS: tuple[str, ...] = (
    CLAIM_KIND_TOOL_CALL,
    CLAIM_KIND_VULNERABILITY,
    CLAIM_KIND_POLICY_RULE,
    CLAIM_KIND_HOST,
    CLAIM_KIND_NETWORK,
    CLAIM_KIND_EXEC_CODE,
    CLAIM_KIND_PRIVILEGE,
    CLAIM_KIND_VULN_HOST,
    CLAIM_KIND_VULN_SEVERITY,
    CLAIM_KIND_TEMPORAL_BRUTE_FORCE,
    CLAIM_KIND_TEMPORAL_PORT_SCAN,
    CLAIM_KIND_TEMPORAL_EXFIL_BURST,
)

# -- policy effect vocabulary -------------------------------------------------
# The only two effects a policy_rule claim may carry. Anything else is a
# malformed record, not a default (see rules._extract_policy_rule).
POLICY_EFFECT_ALLOW = "allow"
POLICY_EFFECT_DENY = "deny"
VALID_POLICY_EFFECTS: tuple[str, ...] = (POLICY_EFFECT_ALLOW, POLICY_EFFECT_DENY)

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
