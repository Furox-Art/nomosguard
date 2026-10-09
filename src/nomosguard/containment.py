"""Actionable containment: turn gate decisions into executable commands.

NomosGuard decides; something else acts. This module is the boundary
between them, and it is deliberately conservative:

1. **Dry-run is the default.** `render_commands()` produces the exact
   commands a decision implies. Nothing executes unless
   `execute=True` is passed explicitly.
2. **Every command is traced.** Each carries the decision, the policy
   rule, and the derivation chain that produced it — the same
   tamper-evident discipline as the ledger.
3. **No shell by default.** Commands render to structured dicts
   (argv arrays), not shell strings, so they can be audited, logged,
   and rejected by an operator before anything runs.

This is not an IPS. It is a translator from deterministic decisions to
operator-reviewable action plans.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Any

from .gate import Decision

# Command templates per decision. {subject} is the entity the decision
# targets (a host, an attacker address, a user).
#
# These templates are examples of the SHAPE an action plan takes. They
# are not wired to any real infrastructure — running them requires a
# configured executor (see Executor below).
TEMPLATES: dict[Decision, list[dict[str, Any]]] = {
    Decision.ISOLATE_HOST: [
        {
            "argv": ["iptables", "-A", "INPUT", "-s", "{subject}", "-j", "DROP"],
            "description": "Drop all traffic from the compromised host",
            "reversible": True,
            "undo": ["iptables", "-D", "INPUT", "-s", "{subject}", "-j", "DROP"],
        },
    ],
    Decision.REVOKE_ACCESS: [
        {
            "argv": ["revoke-session", "--principal", "{subject}"],
            "description": "Revoke active sessions for this principal",
            "reversible": False,
            "undo": None,
        },
    ],
    Decision.ESCALATE: [
        {
            "argv": ["notify", "--severity", "critical", "--message",
                     "Privileged compromise: {subject}"],
            "description": "Page the on-call security engineer",
            "reversible": False,
            "undo": None,
        },
    ],
    Decision.BLOCK: [
        {
            "argv": ["deny-request", "--principal", "{subject}"],
            "description": "Deny the gated request",
            "reversible": False,
            "undo": None,
        },
    ],
}


@dataclass(frozen=True)
class ContainmentCommand:
    """One executable action, fully traced to its decision."""

    argv: tuple[str, ...]
    description: str
    decision: str
    subject: str
    policy_rule: str
    chain: tuple[str, ...]
    reversible: bool
    undo: tuple[str, ...] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "description": self.description,
            "decision": self.decision,
            "subject": self.subject,
            "policy_rule": self.policy_rule,
            "chain": list(self.chain),
            "reversible": self.reversible,
            "undo": list(self.undo) if self.undo else None,
        }


def render_commands(gate_result: dict[str, Any]) -> list[ContainmentCommand]:
    """Translate a gate result into a list of containment commands.

    Pure function — renders, never executes. The output is an action
    plan an operator reviews.
    """
    commands: list[ContainmentCommand] = []
    for d in gate_result.get("all_decisions", []):
        try:
            decision = Decision(d["decision"])
        except ValueError:
            continue  # decisions without a template are reported, not acted on
        templates = TEMPLATES.get(decision, [])
        for t in templates:
            subject = d["subject"]
            argv = [a.format(subject=subject) for a in t["argv"]]
            undo = ([u.format(subject=subject) for u in t["undo"]]
                    if t.get("undo") else None)
            commands.append(
                ContainmentCommand(
                    argv=tuple(argv),
                    description=t["description"],
                    decision=d["decision"],
                    subject=subject,
                    policy_rule=d["policy_rule"],
                    chain=tuple(d.get("chain", [])),
                    reversible=t.get("reversible", False),
                    undo=tuple(undo) if undo else None,
                )
            )
    return commands


def render_plan(gate_result: dict[str, Any]) -> dict[str, Any]:
    """A complete, reviewable action plan."""
    commands = render_commands(gate_result)
    return {
        "decision": gate_result.get("decision"),
        "missing_evidence": gate_result.get("missing_evidence", []),
        "commands": [c.as_dict() for c in commands],
        "count": len(commands),
        "reversible_count": sum(1 for c in commands if c.reversible),
        "dry_run": True,
    }


class Executor:
    """Runs containment commands with an allowlist.

    Disabled by default. When enabled, only commands whose argv[0] is in
    `allowlist` run; everything else is rejected and logged. This is the
    last line of defence between a decision and a real system change.
    """

    def __init__(self, allowlist: tuple[str, ...] = (), enabled: bool = False) -> None:
        self.allowlist = set(allowlist)
        self.enabled = enabled

    def execute(self, command: ContainmentCommand) -> dict[str, Any]:
        if not self.enabled:
            return {"executed": False, "reason": "executor disabled (dry-run)"}
        if command.argv[0] not in self.allowlist:
            return {"executed": False,
                    "reason": f"{command.argv[0]} not in allowlist {sorted(self.allowlist)}"}
        try:
            proc = subprocess.run(
                list(command.argv), capture_output=True, text=True, timeout=30,
            )
            return {
                "executed": True,
                "returncode": proc.returncode,
                "stdout": proc.stdout[:500],
                "stderr": proc.stderr[:500],
            }
        except Exception as exc:
            return {"executed": False, "reason": f"exec failed: {exc}"}

    def undo(self, command: ContainmentCommand) -> dict[str, Any]:
        if not command.reversible or not command.undo:
            return {"executed": False, "reason": "not reversible"}
        if not self.enabled:
            return {"executed": False, "reason": "executor disabled (dry-run)"}
        try:
            proc = subprocess.run(
                list(command.undo), capture_output=True, text=True, timeout=30,
            )
            return {"executed": True, "returncode": proc.returncode}
        except Exception as exc:
            return {"executed": False, "reason": f"undo failed: {exc}"}
