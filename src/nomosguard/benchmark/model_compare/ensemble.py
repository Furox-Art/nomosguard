"""Multi-model ensemble: cross-model voting for evidence extraction.

The single-model pipeline (pipeline.py) samples one model N times. That
fixes random noise but not *systematic* misreading: if one model
consistently reads a log wrong, its draws all agree on the wrong answer.

This module runs SEVERAL models on the same logs and votes across them:

    model A: [claim1, claim2, claim3]
    model B: [claim1, claim3]            -> claim2 is one-model-only
    model C: [claim1, claim2, claim3, claim4] -> claim4 is one-model-only

A claim surviving in >= min_models draws is kept. Single-model claims
are kept only if `keep_singletons` is True (default False — that is the
whole point of cross-model voting).

Different architectures misread different ways, so cross-model
disagreement is real signal, unlike one model agreeing with itself.

Everything is measured: the report carries which claims each model
produced, which survived, and which models backed each survivor.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from .pipeline import (
    parse_claims, _claim_key, AUDIT_PROMPT, _extract_json_array,
    _DEFAULT_EXTRACT_PROMPT,
)


@dataclass
class EnsembleResult:
    claims: list[dict] = field(default_factory=list)
    support: dict[str, int] = field(default_factory=dict)      # claim key -> model count
    backers: dict[str, list[str]] = field(default_factory=dict)  # claim key -> model names
    flagged: list[dict] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "final_claims": len(self.claims),
            "flagged_claims": len(self.flagged),
            "support": dict(self.support),
            **self.report,
        }


def _run_models(
    model_fns: dict[str, Callable[[str], str]],
    prompt: str,
) -> tuple[dict[str, list[dict]], list[str]]:
    """Run every model once. Returns (model -> claims) and error list."""
    per_model: dict[str, list[dict]] = {}
    errors: list[str] = []
    for name, fn in model_fns.items():
        try:
            out = fn(prompt)
            parsed = parse_claims(out)
            if parsed is not None:
                per_model[name] = parsed
            else:
                per_model[name] = []
                errors.append(f"{name}: unparseable output")
        except Exception as exc:
            per_model[name] = []
            errors.append(f"{name}: {exc}")
    return per_model, errors


def run_ensemble(
    model_fns: dict[str, Callable[[str], str]],
    raw_logs: str,
    *,
    min_models: int = 2,
    keep_singletons: bool = False,
    audit: bool = True,
    ground: bool = True,
    prompt_template: str | None = None,
    auditor: str | None = None,
) -> EnsembleResult:
    """Run several models on the same logs, vote across them.

    model_fns: {name: callable(prompt) -> text}
    min_models: how many DISTINCT models must produce a claim for it to
                survive (2 = cross-model agreement required)
    audit/ground: same semantics as run_pipeline
    auditor: which model in model_fns runs the audit (default: first)
    """
    report: dict[str, Any] = {
        "models": list(model_fns.keys()),
        "min_models": min_models,
        "keep_singletons": keep_singletons,
    }
    prompt = (prompt_template or _DEFAULT_EXTRACT_PROMPT).format(raw_logs=raw_logs)

    # -- stage 1: every model extracts once --------------------------------
    per_model, errors = _run_models(model_fns, prompt)
    report["extract_errors"] = errors
    report["per_model_counts"] = {k: len(v) for k, v in per_model.items()}

    if all(not v for v in per_model.values()):
        return EnsembleResult(report={**report, "final_stage": "extract"})

    # -- stage 2: cross-model vote ------------------------------------------
    votes: dict[tuple, int] = {}
    backers: dict[tuple, list[str]] = {}
    best_claim: dict[tuple, dict] = {}
    for name, claims in per_model.items():
        for c in claims:
            try:
                key = _claim_key(c["kind"], c["payload"])
            except Exception:
                continue
            if name not in backers.setdefault(key, []):
                votes[key] = votes.get(key, 0) + 1
                backers[key].append(name)
            if key not in best_claim:
                best_claim[key] = c

    survivors = {k: c for k, c in best_claim.items() if votes[k] >= min_models}
    if keep_singletons:
        for k, c in best_claim.items():
            if k not in survivors:
                survivors[k] = c
    report["after_vote"] = len(survivors)
    report["vote_removed"] = len(best_claim) - len(survivors)
    report["singletons_removed"] = sum(
        1 for k in best_claim if votes[k] < min_models and k not in survivors
    )
    if not survivors:
        return EnsembleResult(report={**report, "final_stage": "vote"})

    # -- stage 3: audit (flag only — recall safe) ---------------------------
    flagged: set[tuple] = set()
    if audit:
        audit_name = auditor or next(iter(model_fns))
        claims_json = json.dumps(list(survivors.values()), indent=1)
        try:
            audit_out = model_fns[audit_name](
                AUDIT_PROMPT.format(raw_logs=raw_logs, claims_json=claims_json)
            )
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
                report["audit_skipped"] = "unparseable audit output"
        except Exception as exc:
            report["audit_skipped"] = f"audit call failed: {exc}"

    # -- stage 4: deterministic grounding (hard floor) ----------------------
    if ground:
        before = len(survivors)
        survivors = {
            k: c for k, c in survivors.items()
            if str(c.get("evidence", "")).strip() in raw_logs
        }
        report["after_ground"] = len(survivors)
        report["ground_removed"] = before - len(survivors)
        if not survivors:
            return EnsembleResult(report={**report, "final_stage": "ground"})

    claims = [best_claim[k] for k in survivors]
    return EnsembleResult(
        claims=claims,
        support={str(k): votes[k] for k in survivors},
        backers={str(k): backers[k] for k in survivors},
        flagged=[best_claim[k] for k in survivors if k in flagged],
        report={**report, "final_stage": "done"},
    )
