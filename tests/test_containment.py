"""Containment tests: dry-run rendering, executor allowlist, reversibility.

Nothing executes in these tests — the Executor is disabled by default
and that is the property under test.
"""

from __future__ import annotations

import pytest

from nomosguard.containment import (
    ContainmentCommand,
    Executor,
    render_commands,
    render_plan,
)

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


class TestSubjectValidation:
    """The subject is substituted into argv: it must be a plain token."""

    def _result(self, subject):
        return {
            "decision": "ISOLATE_HOST",
            "all_decisions": [{
                "subject": subject, "decision": "ISOLATE_HOST",
                "policy_rule": "p", "chain": [],
            }],
        }

    def test_subject_looking_like_an_option_is_refused(self):
        with pytest.raises(ValueError, match="looks like an option"):
            render_commands(self._result("--flush-all"))

    def test_subject_with_whitespace_is_refused(self):
        with pytest.raises(ValueError, match="whitespace or control"):
            render_commands(self._result("web01 -j ACCEPT"))

    def test_subject_with_control_characters_is_refused(self):
        with pytest.raises(ValueError, match="whitespace or control"):
            render_commands(self._result("web01\x00"))

    def test_empty_or_non_string_subject_is_refused(self):
        with pytest.raises(ValueError, match="non-empty string"):
            render_commands(self._result(""))
        with pytest.raises(ValueError, match="non-empty string"):
            render_commands(self._result(42))

    def test_plain_subject_still_renders(self):
        cmds = render_commands(self._result("web01"))
        assert "web01" in cmds[0].argv


class TestUndoHonoursTheAllowlist:
    """The reversal of an allowlisted action must itself be allowlisted."""

    def _reversible(self, undo_argv):
        return ContainmentCommand(
            argv=("iptables", "-A", "INPUT"), description="d",
            decision="ISOLATE_HOST", subject="web01", policy_rule="p",
            chain=(), reversible=True, undo=undo_argv,
        )

    def test_undo_outside_the_allowlist_is_rejected(self):
        ex = Executor(allowlist=("iptables",), enabled=True)
        r = ex.undo(self._reversible(("rm", "-rf", "/")))
        assert r["executed"] is False
        assert "allowlist" in r["reason"]

    def test_undo_inside_the_allowlist_runs(self):
        ex = Executor(allowlist=("echo",), enabled=True)
        r = ex.undo(self._reversible(("echo", "undo")))
        assert r["executed"] is True
