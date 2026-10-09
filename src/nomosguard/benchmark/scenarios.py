"""The benchmark corpus: scenarios with known ground truth.

Each scenario is a small evidence set (claims the way a caller would assert
them) plus the expected outcome — the set of (agent, component) pairs the
rules SHOULD derive as "exposes", computed by hand from the facts, not by
running the engine.

Fact model (the extractor emits):
    (agent, calls, tool)             — the agent invoked the tool
    (agent, operates_on, target)     — the AGENT operates on the target

The agent-scoped operates_on is deliberate: a tool invoked by two agents
on different targets does NOT make both agents operate on both targets.
The evidence stays honest — an agent operates only on what it called.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ClaimSpec:
    kind: str
    payload: dict
    evidence: str


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    claims: tuple[ClaimSpec, ...]
    expected_exposed: frozenset  # (agent, component) pairs the rules MUST derive
    incomplete: bool = False      # True: gate must apply its fail-closed default


def _tool_call(agent: str, tool: str, target: str, line: int) -> ClaimSpec:
    return ClaimSpec(
        kind="tool_call",
        payload={"agent": agent, "tool": tool, "target": target},
        evidence=f"log line {line}: {agent} invoked {tool} on {target}",
    )


def _vuln(component: str, cve: str) -> ClaimSpec:
    return ClaimSpec(
        kind="vulnerability",
        payload={"component": component, "cve": cve, "severity": "high"},
        evidence=f"NVD record {cve} affects {component}",
    )


def _policy_deny(agent: str, action: str) -> ClaimSpec:
    return ClaimSpec(
        kind="policy_rule",
        payload={"subject": agent, "action": action, "resource": "*", "effect": "deny"},
        evidence=f"policy doc: {agent} is denied {action}",
    )


def build_all_scenarios() -> list[Scenario]:
    """The full corpus. Deterministic: no randomness, no files, no network.

    Expected sets are hand-derived from the facts:
      exposed(a, c) <=> a calls some tool, a operates_on c, c has_vulnerability
    """
    return [
        Scenario(
            name="positive_vulnerable_exposure",
            description="An agent calls a tool on a component with a known CVE.",
            claims=(
                _tool_call("researcher", "sql_query", "orders_db", 42),
                _vuln("orders_db", "CVE-2026-1234"),
            ),
            expected_exposed=frozenset({("researcher", "orders_db")}),
        ),
        Scenario(
            name="negative_benign_workflow",
            description="A benign multi-tool workflow on non-vulnerable components must not fire.",
            claims=(
                _tool_call("researcher", "sql_query", "analytics_db", 1),
                _tool_call("researcher", "file_reader", "/data/clean.csv", 2),
                _tool_call("researcher", "chart_maker", "/data/charts", 3),
            ),
            expected_exposed=frozenset(),
        ),
        Scenario(
            name="multi_agent_only_one_exposed",
            description=(
                "Two agents call the same tool on different targets; only one "
                "target is vulnerable. The fact model must NOT make agent_b "
                "exposed to agent_a's target — operates_on is agent-scoped."
            ),
            claims=(
                _tool_call("agent_a", "sql_query", "orders_db", 1),
                _tool_call("agent_b", "sql_query", "customers_db", 2),
                _vuln("orders_db", "CVE-2026-1234"),
            ),
            expected_exposed=frozenset({("agent_a", "orders_db")}),
        ),
        Scenario(
            name="multi_hop_chain_detected",
            description=(
                "A 3-hop chain: researcher -> orders_db -> analytics_db, where "
                "analytics_db has the CVE. The transitive reaches rules must "
                "carry the exposure through the chain — the pre-index engine "
                "could not see this at all."
            ),
            claims=(
                _tool_call("researcher", "sql_query", "orders_db", 1),
                _tool_call("orders_db", "replicate_to", "analytics_db", 2),
                _vuln("analytics_db", "CVE-2026-7777"),
            ),
            # researcher reaches analytics_db through orders_db and is exposed
            expected_exposed=frozenset({
                ("researcher", "analytics_db"),
                ("orders_db", "analytics_db"),
            }),
        ),
        Scenario(
            name="incomplete_evidence",
            description="A tool call with no vulnerability record — fail-closed default applies.",
            claims=(
                _tool_call("researcher", "sql_query", "orders_db", 1),
            ),
            expected_exposed=frozenset(),
            incomplete=True,
        ),
        Scenario(
            name="policy_violation",
            description="An agent calls a tool whose action is policy-denied.",
            claims=(
                _tool_call("researcher", "sql_query", "orders_db", 1),
                _policy_deny("researcher", "sql_query"),
            ),
            expected_exposed=frozenset(),
        ),
        Scenario(
            name="deep_four_hop_chain",
            description=(
                "A 4-hop chain: researcher -> db1 -> db2 -> db3 (CVE here). "
                "The transitive closure must carry the exposure across three "
                "intermediate hops."
            ),
            claims=(
                _tool_call("researcher", "sql_query", "db1", 1),
                _tool_call("db1", "replicate_to", "db2", 2),
                _tool_call("db2", "replicate_to", "db3", 3),
                _vuln("db3", "CVE-2026-5000"),
            ),
            expected_exposed=frozenset({
                ("researcher", "db3"),
                ("db1", "db3"),
                ("db2", "db3"),
            }),
        ),
        Scenario(
            name="chain_to_non_vulnerable_component",
            description=(
                "A chain that ends at a NON-vulnerable component must derive "
                "nothing — the transitive closure must not manufacture exposure."
            ),
            claims=(
                _tool_call("researcher", "sql_query", "orders_db", 1),
                _tool_call("orders_db", "replicate_to", "analytics_db", 2),
                _vuln("orders_db", "CVE-2026-1234"),  # orders_db itself vulnerable
            ),
            # researcher reaches analytics_db (no CVE) AND orders_db (CVE).
            # Only orders_db exposure is expected; analytics_db must not fire.
            expected_exposed=frozenset({("researcher", "orders_db")}),
        ),
        Scenario(
            name="shared_component_two_agents",
            description=(
                "Two agents operate on the same vulnerable component; both are "
                "exposed. Both direct-exposure and transitive rules must agree."
            ),
            claims=(
                _tool_call("agent_a", "sql_query", "orders_db", 1),
                _tool_call("agent_b", "sql_query", "orders_db", 2),
                _vuln("orders_db", "CVE-2026-1234"),
            ),
            expected_exposed=frozenset({
                ("agent_a", "orders_db"),
                ("agent_b", "orders_db"),
            }),
        ),
        Scenario(
            name="policy_deny_via_transitive_reach",
            description=(
                "An agent reaches a policy-denied action through a tool call; "
                "the violation must be derived."
            ),
            claims=(
                _tool_call("researcher", "sql_query", "orders_db", 1),
                _policy_deny("researcher", "sql_query"),
            ),
            expected_exposed=frozenset(),
        ),
        Scenario(
            name="no_vulnerability_no_exposure",
            description="A tool call on a component with NO vulnerability record derives nothing.",
            claims=(
                _tool_call("researcher", "sql_query", "orders_db", 1),
                _vuln("customers_db", "CVE-2026-9999"),
            ),
            expected_exposed=frozenset(),
        ),
    ]
