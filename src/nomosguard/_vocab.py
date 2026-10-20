"""Claim-kind and policy-effect vocabulary.

Both ``constants`` (which builds the default rule sets from ``.rules``)
and ``rules`` (whose extractors dispatch on the claim kinds) need these
literals. Defining them in ``constants`` made the two modules import
each other; this module imports nothing from nomosguard, so it can sit
below both in the import graph. ``constants`` re-exports every name here,
so ``nomosguard.constants.CLAIM_KIND_*`` remains the public spelling.
"""

from __future__ import annotations

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
