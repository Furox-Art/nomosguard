"""Evidence production pipeline: make the LLM edge trustworthy.

The single-pass extraction benchmark showed every model hallucinates.
This pipeline reduces hallucinations and raises effective precision with
four deterministic stages around the model:

  1. SAMPLE    — call the model N times (temperature sampling); each call
                is an independent draw. Diversity is the point.
  2. VOTE      — a claim is kept only if >= M of the N draws produced it.
                One-off claims (likely hallucinations) drop out.
  3. AUDIT     — a second prompt asks the model to re-check its own
                claims against the raw logs and drop the unfaithful ones.
  4. GROUND    — deterministic, no model: a claim survives only if its
                evidence field is a verbatim substring of the raw logs.
                This is the hard floor — fabricated evidence dies here.

The output is a claim set with a per-claim support count, plus a report
of what each stage removed. Everything is measured, not asserted.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .run_benchmark import _norm, _extract_json_array
from .scenarios import REQUIRED_FIELDS

# --------------------------------------------------------------------------
# claim identity: (kind, host/user key, normalized payload) — stable across
# formatting differences so voting can compare draws fairly.
# --------------------------------------------------------------------------

def _claim_key(kind: str, payload: dict) -> tuple[str, str, str]:
    """A claim's voting identity — same claim, different formatting, same key."""
    host = _norm(payload.get("host", payload.get("user", "?")))
    port = str(payload.get("port", ""))
    key_fields = {"cve": _norm(payload.get("cve", "")), "port": port,
                  "allowed_from": _norm(payload.get("allowed_from", "")),
                  "privilege": _norm(payload.get("privilege", ""))}
    relevant = {k: v for k, v in key_fields.items() if v}
    return (kind, host, json.dumps(relevant, sort_keys=True))


def parse_claims(output: str) -> list[dict] | None:
    """Parse model output into a list of claim dicts, or None if invalid."""
    claims = _extract_json_array(output)
    if claims is None:
        return None
    parsed = []
    for c in claims:
        if isinstance(c, dict) and "kind" in c and "payload" in c and "evidence" in c:
            if isinstance(c["payload"], dict):
                parsed.append(c)
    return parsed or None


@dataclass
class PipelineResult:
    claims: list[dict] = field(default_factory=list)
    support: dict[str, int] = field(default_factory=dict)  # claim key -> votes
    report: dict[str, Any] = field(default_factory=dict)
    flagged: list[dict] = field(default_factory=list)  # suspicious claims, kept

    def summary(self) -> dict[str, Any]:
        return {
            "final_claims": len(self.claims),
            "flagged_claims": len(self.flagged),
            "support": dict(self.support),
            **self.report,
        }


# The audit prompt asks the model to FLAG suspicious claims, not delete
# them. Deletion by an LLM is recall-unsafe (measured: the audit stage
# removed correct claims). Flagging keeps every claim; suspicion is
# carried as metadata.
AUDIT_PROMPT = """You previously extracted security claims from raw logs. Below are the raw logs again and your extracted claims. For EACH claim, decide only whether it is SUSPICIOUS. A claim is suspicious if its evidence is NOT present verbatim in the raw logs, or its kind/payload contradicts the evidence. Do not judge claims you merely find uncertain — only clearly contradicted ones.

Output a JSON array only. Each element: {{"index": <0-based claim number>, "suspicious": true|false, "reason": "<short>"}}. One element per claim, in order.

RAW LOGS:
{raw_logs}

YOUR CLAIMS:
{claims_json}

Output the JSON array only."""


def run_pipeline(
    model_fn: Callable[[str], str],
    raw_logs: str,
    *,
    draws: int = 3,
    min_votes: int = 2,
    audit: bool = True,
    ground: bool = True,
    prompt_template: str | None = None,
) -> PipelineResult:
    """Run the four-stage evidence pipeline.

    model_fn: a callable that takes a prompt string and returns model text.
    """
    report: dict[str, Any] = {"draws": draws, "min_votes": min_votes,
                              "audit": audit, "ground": ground}
    prompt = (prompt_template or _DEFAULT_EXTRACT_PROMPT).format(raw_logs=raw_logs)

    # -- stage 1: sample -----------------------------------------------------
    draw_outputs: list[str] = []
    draw_errors = 0
    for _ in range(draws):
        try:
            draw_outputs.append(model_fn(prompt))
        except Exception:
            draw_errors += 1
    report["sample_errors"] = draw_errors

    parsed_draws = []
    for out in draw_outputs:
        parsed = parse_claims(out)
        if parsed is not None:
            parsed_draws.append(parsed)
    report["parsed_draws"] = len(parsed_draws)
    if not parsed_draws:
        return PipelineResult(claims=[], support={}, report={**report, "final_stage": "sample"})

    # -- stage 2: vote -------------------------------------------------------
    votes: dict[tuple, int] = {}
    best_claim: dict[tuple, dict] = {}
    for draw in parsed_draws:
        keys_seen = set()
        for c in draw:
            try:
                key = _claim_key(c["kind"], c["payload"])
            except Exception:
                continue
            if key in keys_seen:
                continue  # one vote per claim per draw
            keys_seen.add(key)
            votes[key] = votes.get(key, 0) + 1
            if key not in best_claim:
                best_claim[key] = c

    survivors = {k: c for k, c in best_claim.items() if votes[k] >= min_votes}
    report["after_vote"] = len(survivors)
    report["vote_removed"] = len(best_claim) - len(survivors)
    if not survivors:
        return PipelineResult(claims=[], support={},
                              report={**report, "final_stage": "vote"})

    # -- stage 3: audit (flag-only — recall safe) ----------------------------
    flagged: set[tuple] = set()
    if audit and survivors:
        claims_json = json.dumps(list(survivors.values()), indent=1)
        try:
            audit_out = model_fn(AUDIT_PROMPT.format(raw_logs=raw_logs, claims_json=claims_json))
            verdicts = _extract_json_array(audit_out)
            if verdicts is not None:
                keys = list(survivors.keys())
                for v in verdicts:
                    if isinstance(v, dict) and v.get("suspicious") is True:
                        idx = v.get("index")
                        if isinstance(idx, int) and 0 <= idx < len(keys):
                            flagged.add(keys[idx])
                report["audit_flagged"] = len(flagged)
            else:
                report["audit_skipped"] = "unparseable audit output — no flags"
        except Exception as exc:
            report["audit_skipped"] = f"audit call failed: {exc}"

    # Only DETERMINISTIC grounding removes claims — never the LLM.
    if flagged:
        report["flagged_claims"] = [str(k) for k in flagged]

    # -- stage 4: ground -----------------------------------------------------
    if ground and survivors:
        before = len(survivors)
        grounded = {}
        for k, c in survivors.items():
            ev = str(c.get("evidence", "")).strip()
            if ev and ev in raw_logs:
                grounded[k] = c
        survivors = grounded
        report["after_ground"] = len(survivors)
        report["ground_removed"] = before - len(survivors)
        if not survivors:
            return PipelineResult(claims=[], support={},
                                  report={**report, "final_stage": "ground"})

    claims = [best_claim[k] for k in survivors]
    support = {str(k): votes[k] for k in survivors}
    flagged_claims = [best_claim[k] for k in survivors if k in flagged]
    return PipelineResult(claims=claims, support=support, flagged=flagged_claims,
                          report={**report, "final_stage": "done"})


_DEFAULT_EXTRACT_PROMPT = """You are a security telemetry parser. Read these raw log lines and output ONLY a JSON array (no markdown fences, no explanation). Each element must have exactly the keys kind, payload, evidence.

Use ONLY these kinds and payload fields:
- kind=network, payload fields: host, protocol, port, allowed_from  (who may reach which host/port)
- kind=vuln_host, payload fields: host, cve
- kind=privilege, payload fields: user, privilege, host
- kind=exec_code, payload fields: host, user

The evidence field must be the exact raw log line the claim came from.

RAW LOGS:
{raw_logs}

Output the JSON array only."""
