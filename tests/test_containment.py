"""Containment tests: dry-run rendering, executor allowlist, reversibility.

Nothing executes in these tests — the Executor is disabled by default
and that is the property under test.
"""

from __future__ import annotations

from nomosguard.containment import (
    render_commands, render_plan, Executor, ContainmentCommand,
)
from nomosguard.gate import Decision


GATE_RESULT = {
    "decision": "ISOLATE_HOST",
    "missing_evidence": [],
    "all_decisions": [
        {
            "subject": "web01",
            "decision": "ISOLATE_HOST",
            "policy_rule": "isolate_compromised_host",
            "chain": ["derived: web01 -execCode-> 203.0.113.77",
                      "rule exploit_vulnerability: matched [...]"],
        },
        {
            "subject": "203.0.113.77",
            "decision": "REVOKE_ACCESS",
            "policy_rule": "revoke_attacker_access",
            "chain": ["derived: 203.0.113.77 -canAccessHost-> web01"],
        },
    ],
}


class TestRender:
    def test_renders_one_command_per_decision(self):
        cmds = render_commands(GATE_RESULT)
        assert len(cmds) == 2
        assert cmds[0].decision == "ISOLATE_HOST"
        assert cmds[1].decision == "REVOKE_ACCESS"

    def test_subject_substituted(self):
        cmds = render_commands(GATE_RESULT)
        assert "web01" in cmds[0].argv
        assert "203.0.113.77" in cmds[1].argv

    def test_chain_carried_through(self):
        cmds = render_commands(GATE_RESULT)
        assert any("exploit_vulnerability" in c for c in cmds[0].chain)
        assert cmds[1].chain != ()

    def test_plan_marks_dry_run(self):
        plan = render_plan(GATE_RESULT)
        assert plan["dry_run"] is True
        assert plan["count"] == 2
        assert plan["reversible_count"] == 1  # only ISOLATE is reversible

    def test_unknown_decision_skipped(self):
        result = dict(GATE_RESULT)
        result["all_decisions"] = [{
            "subject": "x", "decision": "NOT_A_DECISION",
            "policy_rule": "p", "chain": [],
        }]
        assert render_commands(result) == []


class TestExecutor:
    def test_disabled_by_default(self):
        ex = Executor()
        cmd = ContainmentCommand(
            argv=("echo", "hi"), description="test", decision="ISOLATE_HOST",
            subject="web01", policy_rule="p", chain=(), reversible=False,
        )
        r = ex.execute(cmd)
        assert r["executed"] is False
        assert "disabled" in r["reason"]

    def test_allowlist_blocks_unlisted(self):
        ex = Executor(allowlist=("iptables",), enabled=True)
        cmd = ContainmentCommand(
            argv=("rm", "-rf", "/"), description="danger",
            decision="ISOLATE_HOST", subject="web01", policy_rule="p",
            chain=(), reversible=False,
        )
        r = ex.execute(cmd)
        assert r["executed"] is False
        assert "allowlist" in r["reason"]

    def test_allowlist_permits_listed(self):
        ex = Executor(allowlist=("echo",), enabled=True)
        cmd = ContainmentCommand(
            argv=("echo", "contained"), description="test",
            decision="REVOKE_ACCESS", subject="user1", policy_rule="p",
            chain=(), reversible=False,
        )
        r = ex.execute(cmd)
        assert r["executed"] is True
        assert r["returncode"] == 0

    def test_undo_only_for_reversible(self):
        ex = Executor(allowlist=("echo",), enabled=True)
        irreversible = ContainmentCommand(
            argv=("echo", "x"), description="d", decision="ESCALATE",
            subject="s", policy_rule="p", chain=(), reversible=False, undo=None,
        )
        assert ex.undo(irreversible)["executed"] is False

    def test_undo_runs_undo_argv(self):
        ex = Executor(allowlist=("echo",), enabled=True)
        reversible = ContainmentCommand(
            argv=("echo", "do"), description="d", decision="ISOLATE_HOST",
            subject="web01", policy_rule="p", chain=(), reversible=True,
            undo=("echo", "undo"),
        )
        r = ex.undo(reversible)
        assert r["executed"] is True


class TestEndToEndPlan:
    def test_full_plan_from_gate_result(self):
        """The plan an operator reviews: decision, commands, evidence gaps."""
        plan = render_plan(GATE_RESULT)
        assert plan["decision"] == "ISOLATE_HOST"
        assert plan["missing_evidence"] == []
        assert all(c["argv"] for c in plan["commands"])
        assert all("policy_rule" in c for c in plan["commands"])
        # every command is traceable to its chain
        assert all(c["chain"] for c in plan["commands"])
