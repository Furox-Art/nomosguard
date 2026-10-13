"""NomosGuard MCP server: exposes the deterministic core as MCP tools.

Every tool is a thin, deterministic wrapper around the core. The MCP
layer adds NO decision logic — it only serializes and deserializes. The
invariant holds at the tool boundary:

  - `evidence_ingest` accepts claims + evidence, stores them in the ledger
  - `assert_claim` validates a claim (evidence required) and appends it
  - `derive_paths` runs the rule engine (pure logic, no model)
  - `decide` runs the policy gate (fail-closed, no model)
  - `explain` renders a decision chain in human-readable form (narration
    only — the LLM at the explanation edge may reword it, but the chain
    itself comes from the ledger and cannot be altered)

Run with:  python -m nomosguard.mcp_server
Configure an MCP client to run it over stdio.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import facts_security  # noqa: F401  — register security extractors
from .constants import tool_call_gate_rules, tool_call_rules
from .gate import Decision, GateDenied, PolicyGate, PolicyRule
from .ledger import Claim, EvidenceLedger, LedgerFileError, UnevidencedClaimError
from .ledger_lock import append_locked
from .policy_security import containment_policy_rules
from .rules import ClaimValueError, Rule, RuleDefinitionError, RuleEngine
from .rules_security import security_rules

# MCP protocol constants
JSONRPC_VERSION = "2.0"
PROTOCOL_VERSION = "2025-06-18"

SERVER_INFO = {
    "name": "nomosguard",
    "version": "0.1.0",
    "description": (
        "Deterministic security reasoning core exposed as MCP tools. "
        "LLMs may produce evidence and explain decisions; the ledger, "
        "rule engine, and policy gate never consult a model."
    ),
}


def _writable_ledger_target(path: Path) -> None:
    """Check that `path` can become a ledger file, or raise LedgerFileError.

    Used when a caller explicitly opts into creating a new ledger: the
    target must not be a directory, and its parent must exist and be
    writable. A path that cannot possibly work is a broken configuration,
    which fails loudly instead of at the first save.
    """
    from .ledger import LedgerFileError

    if path.is_dir():
        raise LedgerFileError(
            f"ledger path is a directory, not a file: {path}"
        )
    parent = path.parent
    if not parent.is_dir():
        raise LedgerFileError(
            f"ledger directory does not exist: {parent} "
            "(refusing to create a ledger in a path that is not there)"
        )
    if path.exists():
        return  # a file, and not a directory: load will verify it
    probe = parent / f".{path.name}.write-test"
    try:
        with probe.open("w", encoding="utf-8") as fh:
            fh.write("")
    except OSError as exc:
        raise LedgerFileError(
            f"ledger directory is not writable: {parent} ({exc})"
        ) from exc
    finally:
        try:
            probe.unlink()
        except OSError:
            pass


class NomosGuardSession:
    """A single session holding one ledger + engine + gate instance.

    The MCP server holds one session (or a registry keyed by session id
    for multi-tenant use). All state lives here; the protocol layer is
    stateless.

    This class is the SDK boundary: `decide`, `derive_paths` and
    `explain` return a *result*, never a control-flow surprise. The gate
    raises `GateDenied` when it refuses to invent a decision, and a
    malformed rule set raises `RuleDefinitionError` — both are caught
    here and converted to a fail-closed result, so an agent that only
    knows how to read a GateResult cannot be crashed by one.
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        policy_rules: list[PolicyRule] | None = None,
        ledger_path: str | Path | None = None,
        *,
        create_if_missing: bool = False,
    ) -> None:
        self.ledger_path = Path(ledger_path) if ledger_path else None
        if self.ledger_path is None:
            self.ledger = EvidenceLedger()
        elif self.ledger_path.is_file():
            # An explicitly configured ledger path is LOADED: a corrupt or
            # unreadable file raises LedgerFileError here, loudly, instead
            # of silently starting an empty (and therefore lying) ledger.
            self.ledger = EvidenceLedger.load(self.ledger_path)
        elif create_if_missing:
            _writable_ledger_target(self.ledger_path)
            self.ledger = EvidenceLedger()
        else:
            # Fail closed: a configured path that is not there is a broken
            # configuration, not a fresh ledger. Starting empty would let
            # a typo'd path look like "no evidence, no findings".
            raise LedgerFileError(
                f"ledger path configured but not found: {self.ledger_path} "
                "(pass create_if_missing=True to start a new ledger there)"
            )
        self.rules = list(rules) if rules else []
        self.policy_rules = list(policy_rules) if policy_rules else []

    def _append_persisted(self, claim: Claim) -> None:
        """Append one accepted claim to the on-disk ledger, writer-serialized.

        This replaces a full-file ``save()`` that rewrote the whole ledger from
        one session's in-memory copy. Two sessions sharing a path then raced:
        the second writer's snapshot dropped everything the first writer had
        appended since it loaded — silent evidence loss, on a product whose
        promise is a hash-chained audit trail. ``append_locked`` takes the
        exclusive lock, re-reads the file under it, appends exactly this claim
        and writes the WAL, so concurrent sessions interleave instead of
        overwrite. Called per claim (not once per batch) so an ingest that
        dies halfway leaves what it already accepted on disk.
        """
        if self.ledger_path is None:
            return
        append_locked(self.ledger_path, claim, wal=True)

    # -- the fail-closed gate result ------------------------------------------

    def _gate_result(
        self, fallback: str | Decision = Decision.BLOCK
    ) -> dict[str, Any]:
        """Run engine + gate and ALWAYS return a GateResult dict.

        The gate's own refusals (`GateDenied`: unknown decision name) and
        a malformed rule set (`RuleDefinitionError`) are converted here,
        at the SDK boundary, into the fail-closed result:

            {"decision": "BLOCK", "denied": True, "reason": <why>, ...}

        The chain stays empty and `ledger_verified` still reports the real
        chain state, so the caller can see WHY it was denied rather than
        being handed a bare exception.
        """
        try:
            engine = RuleEngine(rules=self.rules)
        except RuleDefinitionError as exc:
            return self._denied(f"malformed rule set: {exc}")
        try:
            gate = PolicyGate(policy_rules=self.policy_rules, fallback=fallback)
        except GateDenied as exc:
            return self._denied(str(exc))
        try:
            engine.add_facts_from_ledger(self.ledger)
        except ClaimValueError as exc:
            # A recorded claim the extractors refuse to interpret (an
            # unknown policy effect, an unreadable value) is evidence the
            # session cannot reason over: deny, and name the claim.
            return self._denied(f"uninterpretable claim: {exc}")
        engine.derive()
        result = gate.evaluate_with_fallback(engine)
        result["denied"] = False
        result["ledger_verified"] = self.ledger.verify()[0]
        return result

    def _denied(self, reason: str) -> dict[str, Any]:
        """The fail-closed result: deny, and say why."""
        return {
            "decision": Decision.BLOCK.value,
            "reason": f"gate denied: {reason}",
            "policy_rule": "GATE_DENIED",
            "chain": [],
            "derived_from": [],
            "missing_evidence": [],
            "denied": True,
            "ledger_verified": self.ledger.verify()[0],
        }

    # -- tool implementations -------------------------------------------------

    def evidence_ingest(self, claims: list[dict[str, Any]]) -> dict[str, Any]:
        """Ingest multiple claims at once. Returns accepted/rejected counts."""
        accepted = 0
        rejected: list[dict[str, Any]] = []
        for i, raw in enumerate(claims):
            try:
                claim = Claim(
                    kind=str(raw.get("kind", "")),
                    payload=dict(raw.get("payload", {})),
                    evidence=str(raw.get("evidence", "")),
                )
                self.ledger.append(claim)
                accepted += 1
                # Persist per claim, not per batch: a malformed entry later in
                # the list must not discard the ones already accepted.
                self._append_persisted(claim)
            except UnevidencedClaimError as exc:
                rejected.append({"index": i, "reason": str(exc)})
        return {
            "accepted": accepted,
            "rejected": rejected,
            "ledger_size": len(self.ledger.entries),
        }

    def assert_claim(self, kind: str, payload: dict[str, Any], evidence: str) -> dict[str, Any]:
        """Assert a single claim. Rejected (fail-closed) without evidence."""
        claim = Claim(kind=kind, payload=payload, evidence=evidence)
        try:
            entry = self.ledger.append(claim)
        except UnevidencedClaimError as exc:
            return {"accepted": False, "reason": str(exc)}
        self._append_persisted(claim)
        return {
            "accepted": True,
            "seq": entry.seq,
            "entry_hash": entry.entry_hash,
            "ledger_size": len(self.ledger.entries),
        }

    def derive_paths(self) -> dict[str, Any]:
        """Run the rule engine over the current ledger. Pure logic.

        A malformed rule set is reported as a fail-closed result (no
        derived facts, the reason included) rather than an exception at
        the SDK caller.
        """
        try:
            engine = RuleEngine(rules=self.rules)
        except RuleDefinitionError as exc:
            return {
                "derived_facts": [],
                "rules_fired": {},
                "trace": [],
                "ledger_verified": self.ledger.verify()[0],
                "denied": True,
                "reason": f"malformed rule set: {exc}",
            }
        try:
            engine.add_facts_from_ledger(self.ledger)
        except ClaimValueError as exc:
            return {
                "derived_facts": [],
                "rules_fired": {},
                "trace": [],
                "ledger_verified": self.ledger.verify()[0],
                "denied": True,
                "reason": f"uninterpretable claim: {exc}",
            }
        summary = engine.derive()
        return {
            "derived_facts": [str(f) for f in engine.facts],
            "rules_fired": summary["rules_fired"],
            "trace": summary["trace"],
            "ledger_verified": self.ledger.verify()[0],
            "denied": False,
        }

    def decide(self, fallback: str = "BLOCK") -> dict[str, Any]:
        """Run the policy gate. Fail-closed; never consults a model.

        Always returns a GateResult dict — a decision the gate refuses to
        make (`GateDenied`) or a malformed rule set becomes a BLOCK with
        `denied: True` and the reason, not an exception at the caller.
        """
        return self._gate_result(fallback)

    def explain(self) -> dict[str, Any]:
        """Render the current state as a human-readable audit summary.

        This is narration, not decision. The text is generated from the
        ledger and derivation trace; an LLM at the explanation edge may
        reword it, but the facts cited cannot be changed.
        """
        ok, detail = self.ledger.verify()
        decision = self._gate_result(Decision.BLOCK)
        try:
            engine = RuleEngine(rules=self.rules)
        except RuleDefinitionError:
            engine = None
        if engine is None:
            lines = [
                f"Ledger: {detail}",
                "Rules: refused — malformed rule set (see decide)",
                f"Gate decision: {decision['decision']} ({decision['reason']})",
            ]
            return {
                "summary": "\n".join(lines),
                "ledger_verified": ok,
                "decision": decision["decision"],
                "denied": True,
            }
        try:
            engine.add_facts_from_ledger(self.ledger)
        except ClaimValueError as exc:
            lines = [
                f"Ledger: {detail}",
                "Facts: refused — a claim cannot be interpreted",
                f"Gate decision: {decision['decision']} ({decision['reason']})",
            ]
            return {
                "summary": "\n".join(lines),
                "ledger_verified": ok,
                "decision": decision["decision"],
                "denied": True,
                "reason": f"uninterpretable claim: {exc}",
            }
        summary = engine.derive()
        lines = [
            f"Ledger: {detail}",
            f"Base facts: {len([f for f in engine.facts if not f.sources])}",
            f"Derived facts: {len([f for f in engine.facts if f.sources])}",
            f"Rules fired: {summary['rules_fired']}",
            f"Gate decision: {decision['decision']} ({decision['reason']})",
        ]
        for d in decision.get("all_decisions", []):
            lines.append(f"  - {d['subject']}: {d['decision']} via {d['policy_rule']}")
            for step in d.get("chain", []):
                lines.append(f"      {step}")
        return {
            "summary": "\n".join(lines),
            "ledger_verified": ok,
            "decision": decision["decision"],
            "denied": decision.get("denied", False),
        }

    def export_ledger(self) -> dict[str, Any]:
        """Export the full ledger for audit/archive."""
        ok, detail = self.ledger.verify()
        return {
            "verified": ok,
            "detail": detail,
            "entries": self.ledger.export(),
        }


# -- default rule and policy sets (tool-call security, the v1 path) ----------

def default_rules() -> list[Rule]:
    """Tool-call + security rules — one engine, two vocabularies.

    The tool-call rules handle AI-agent security (exposure chains);
    the security rules handle network security (attack graphs). Both
    use the same ledger and the same gate — one deterministic core.

    The tool-call half is the canonical set from `nomosguard.constants`,
    not a second copy of it.
    """
    return tool_call_rules() + security_rules()


def default_policy_rules() -> list[PolicyRule]:
    """Tool-call + containment decisions together."""
    return tool_call_gate_rules() + containment_policy_rules()

