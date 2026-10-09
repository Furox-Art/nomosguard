"""Model benchmark runner: score many models on the same telemetry task.

CLI adapters call each model with the SAME prompt (see scenarios.py for
ground truth + required fields). Each adapter returns the model's raw
text output; this script parses, scores, and writes a comparison table.
Nothing is scored by hand.

Scoring:
- json_valid          output parsed as a JSON array
- schema_ok           every claim has a known kind + required payload fields
- recall              matched ground-truth claims / total
- precision           matched / produced claims
- evidence_verbatim   claims citing a log line verbatim (exact substring)
- hallucinations      produced (kind, host) with no ground-truth counterpart
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .scenarios import SCENARIOS, REQUIRED_FIELDS

PROMPT = """You are a security telemetry parser. Read these raw log lines and output ONLY a JSON array (no markdown fences, no explanation). Each element must have exactly the keys kind, payload, evidence.

Use ONLY these kinds and payload fields:
- kind=network, payload fields: host, protocol, port, allowed_from  (who may reach which host/port)
- kind=vuln_host, payload fields: host, cve
- kind=privilege, payload fields: user, privilege, host
- kind=exec_code, payload fields: host, user

The evidence field must be the exact raw log line the claim came from.

RAW LOGS:
{raw_logs}

Output the JSON array only."""


def _extract_json_array(text: str) -> list | None:
    """Extract a JSON array from model output (tolerates markdown fences)."""
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if m:
        text = m.group(1).strip()
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, list) else None


def _norm(value: Any) -> str:
    """Normalize a field value for comparison."""
    s = str(value).strip().lower()
    s = s.rstrip(".,;:")
    if "(" in s:
        s = s[: s.find("(")].strip()
    return s


def score_scenario(scenario, model_output: str) -> dict[str, Any]:
    claims = _extract_json_array(model_output)

    result: dict[str, Any] = {
        "scenario": scenario.name,
        "json_valid": claims is not None,
    }
    if claims is None:
        result.update({
            "schema_ok": False, "produced": 0, "expected": len(scenario.expected_claims),
            "recall": 0.0, "precision": 0.0, "evidence_verbatim": 0,
            "hallucinations": 0, "matched": 0,
        })
        return result

    expected = set()
    expected_hosts = set()
    for kind, payload in scenario.expected_claims:
        key = (kind, tuple(sorted((k, _norm(v)) for k, v in payload.items() if k != "protocol")))
        expected.add(key)
        if "host" in payload:
            expected_hosts.add(_norm(payload["host"]))

    schema_ok = True
    matched = set()
    evidence_ok = 0
    hallucinations = 0

    for c in claims:
        if not isinstance(c, dict) or "kind" not in c or "payload" not in c or "evidence" not in c:
            schema_ok = False
            continue
        kind = c["kind"]
        payload = c.get("payload", {})
        if not isinstance(payload, dict):
            schema_ok = False
            continue
        req = REQUIRED_FIELDS.get(kind)
        if req is None or not req.issubset(set(payload.keys())):
            schema_ok = False
        key = (kind, tuple(sorted((k, _norm(v)) for k, v in payload.items() if k != "protocol")))
        if key in expected:
            matched.add(key)
        elif kind in REQUIRED_FIELDS and "host" in payload:
            # a claim on a host/kind the scenario's ground truth does not contain
            if not any(k == kind and _norm(p.get("host", "")) == _norm(payload["host"])
                       for k, p in scenario.expected_claims):
                hallucinations += 1
        ev = str(c.get("evidence", ""))
        if ev and ev in scenario.raw_logs:
            evidence_ok += 1

    total_expected = len(expected)
    recall = len(matched) / total_expected if total_expected else 0.0
    precision = len(matched) / len(claims) if claims else 0.0

    result.update({
        "schema_ok": schema_ok,
        "produced": len(claims),
        "expected": total_expected,
        "matched": len(matched),
        "recall": recall,
        "precision": precision,
        "evidence_verbatim": evidence_ok,
        "hallucinations": hallucinations,
    })
    return result


# ---- CLI adapters -----------------------------------------------------------

def _run_opencode(model: str, prompt: str, timeout: int = 300) -> str:
    proc = subprocess.run(
        ["opencode", "run", "--model", model, prompt],
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"opencode failed: {proc.stderr[:200]}")
    return proc.stdout


def _run_antigravity(model: str, prompt: str, timeout: int = 300,
                     effort: str = "low") -> str:
    """Antigravity CLI (agy) — runs on the user's Google/Anthropic quota.

    Invocation learned from `agy --help`: the prompt must be attached to
    the --print flag (`--print="..."`) and the model list from the UI maps
    to model slugs like gemini-3.8-flash / claude-opus-4.6. Some models
    (Gemini family) REQUIRE an explicit --effort flag.
    """
    import os
    env = dict(os.environ)
    # agy lives in ~/.local/bin, not always on PATH in subprocesses
    env["PATH"] = os.path.expanduser("~/.local/bin") + ":" + env.get("PATH", "")
    display = AGY_MODELS.get(model, model)
    cmd = ["agy", "--model", display, f"--print={prompt}"]
    if effort and "(Thinking)" not in display and "(High)" not in display and "(Medium)" not in display and "(Low)" not in display:
        cmd += ["--effort", effort]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"agy failed: {proc.stderr[:200]}")
    return proc.stdout


def _run_vibe(model: str, prompt: str, timeout: int = 300) -> str:
    """Mistral Vibe CLI — programmatic mode."""
    import os
    env = dict(os.environ)
    env["PATH"] = os.path.expanduser("~/.local/bin") + ":" + env.get("PATH", "")
    proc = subprocess.run(
        ["vibe", "-p", prompt],
        capture_output=True, text=True, timeout=timeout, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"vibe failed: {proc.stderr[:200]}")
    return proc.stdout


def _run_hermes(model: str, prompt: str, timeout: int = 300) -> str:
    """Hermes/Nous free models via the local inference API."""
    api_key = os.environ.get("NOUS_API_KEY", "")
    if not api_key:
        raise RuntimeError("NOUS_API_KEY not set")
    base_url = os.environ.get("NOUS_BASE_URL", "https://inference-api.nousresearch.com/v1")
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


ADAPTERS = {
    "opencode": _run_opencode,
    "antigravity": _run_antigravity,
    "hermes": _run_hermes,
    "vibe": _run_vibe,
}

# agy takes full display names, not slugs
AGY_MODELS = {
    "gemini-3.8-flash": "Gemini 3.8 Flash (High)",
    "gemini-3.8-flash-medium": "Gemini 3.8 Flash (Medium)",
    "gemini-3.8-flash-low": "Gemini 3.8 Flash (Low)",
    "gemini-3.7-flash": "Gemini 3.7 Flash (High)",
    "gemini-3.6-flash": "Gemini 3.6 Flash (High)",
    "gemini-3.1-pro": "Gemini 3.1 Pro (High)",
    "claude-sonnet-4.6": "Claude Sonnet 4.6 (Thinking)",
    "claude-opus-4.6": "Claude Opus 4.6 (Thinking)",
    "gpt-oss-120b": "GPT-OSS 120B (Medium)",
}

# Default free models across the three CLIs
DEFAULT_MODELS = [
    ("opencode", "opencode/mimo-v2.6-flash-free"),
    ("opencode", "opencode/step-5-preview-free"),
    ("opencode", "opencode/ling-3.1-flash-free"),
    ("antigravity", "gemini-3.8-flash"),
    ("antigravity", "gemini-3.1-pro"),
    ("antigravity", "claude-sonnet-4.6"),
    ("antigravity", "claude-opus-4.6"),
    ("antigravity", "gemini-3.7-flash"),
    ("antigravity", "gemini-3.6-flash"),
    ("antigravity", "gpt-oss-120b"),
    ("vibe", "mistral-medium-3.5"),
    ("hermes", "solar-pro4:free"),
    ("hermes", "step-5-preview:free"),
]


@dataclass
class ModelResult:
    model: str
    adapter: str
    scenario: str
    output: str
    scored: dict[str, Any] | None = None
    error: str | None = None
    latency_s: float | None = None


def run_one(adapter: str, model: str, scenario, timeout: int = 300) -> ModelResult:
    import time
    prompt = PROMPT.format(raw_logs=scenario.raw_logs)
    t0 = time.perf_counter()
    try:
        fn = ADAPTERS[adapter]
        output = fn(model, prompt, timeout=timeout)
        elapsed = time.perf_counter() - t0
        scored = score_scenario(scenario, output)
        scored["latency_s"] = round(elapsed, 2)
        scored["prompt_chars"] = len(prompt)
        scored["output_chars"] = len(output)
        return ModelResult(model=model, adapter=adapter, scenario=scenario.name,
                           output=output, scored=scored)
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        return ModelResult(model=model, adapter=adapter, scenario=scenario.name,
                           output="", error=str(exc), latency_s=round(elapsed, 2))


def run_benchmark(
    models: list[tuple[str, str]] | None = None,
    output_dir: str | Path | None = None,
    timeout: int = 300,
) -> dict[str, Any]:
    models = models or DEFAULT_MODELS
    all_results = []
    for adapter_name, model_id in models:
        for scenario in SCENARIOS:
            r = run_one(adapter_name, model_id, scenario, timeout=timeout)
            all_results.append({
                "model": model_id,
                "adapter": adapter_name,
                "scenario": scenario.name,
                "error": r.error,
                "output": r.output[:2000],
                **(r.scored or {}),
            })
            print(f"  [{adapter_name}/{model_id}] {scenario.name}: "
                  f"{'ERROR: ' + r.error[:50] if r.error else 'recall=' + str(r.scored['recall'])}",
                  flush=True)

    summary = _aggregate(all_results)
    if output_dir is not None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "model_benchmark.json").write_text(json.dumps({
            "summary": summary, "results": all_results,
        }, indent=2), encoding="utf-8")
        (out / "MODEL_BENCHMARK.md").write_text(_render_markdown(summary), encoding="utf-8")
        (out / "MODEL_BENCHMARK.html").write_text(_render_html(summary, all_results), encoding="utf-8")
    return {"summary": summary, "results": all_results}


def _aggregate(results: list[dict]) -> dict[str, Any]:
    by_model: dict[str, list[dict]] = {}
    for r in results:
        by_model.setdefault(r["model"], []).append(r)
    summary = {}
    for model, rs in by_model.items():
        valid = [r for r in rs if "recall" in r]
        errored = [r for r in rs if "error" in r]
        if not valid:
            summary[model] = {"error": f"{len(errored)}/{len(rs)} scenarios errored",
                              "adapter": rs[0]["adapter"] if rs else ""}
            continue
        n = len(valid)
        latencies = [r["latency_s"] for r in valid if "latency_s" in r]
        summary[model] = {
            "adapter": rs[0]["adapter"],
            "scenarios": n,
            "json_valid": sum(1 for r in valid if r["json_valid"]) / n,
            "schema_ok": sum(1 for r in valid if r["schema_ok"]) / n,
            "recall": sum(r["recall"] for r in valid) / n,
            "precision": sum(r["precision"] for r in valid) / n,
            "evidence_verbatim": sum(1 for r in valid if r["evidence_verbatim"] > 0) / n,
            "hallucinations": sum(r["hallucinations"] for r in valid),
            "errors": len(errored),
            "latency_median_s": sorted(latencies)[len(latencies) // 2] if latencies else None,
            "latency_total_s": round(sum(latencies), 1) if latencies else None,
        }
    return summary


def _render_markdown(summary: dict) -> str:
    lines = ["# LLM-edge model benchmark", ""]
    lines.append("| model | json | schema | recall | precision | evidence verbatim | hallucinations | errors |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for model, s in sorted(summary.items(), key=lambda kv: -kv[1].get("recall", 0)):
        if "error" in s:
            lines.append(f"| {model} | — | — | — | — | — | — | {s['error']} |")
            continue
        lines.append(
            f"| {model} | {s['json_valid']:.0%} | {s['schema_ok']:.0%} | "
            f"{s['recall']:.0%} | {s['precision']:.0%} | {s['evidence_verbatim']:.0%} | "
            f"{s['hallucinations']} | {s['errors']} |"
        )
    lines.append("")
    return "\n".join(lines)


def _render_html(summary: dict, results: list[dict]) -> str:
    """Claude-style benchmark table: highlight column, clean grid, measured values."""
    rows = []
    for model, s in sorted(summary.items(), key=lambda kv: -kv[1].get("recall", 0)):
        if "error" in s:
            rows.append(
                f"<tr><td class='model'>{model}</td>"
                f"<td colspan='6' class='err'>{s['error']}</td></tr>"
            )
            continue
        rows.append(
            f"<tr>"
            f"<td class='model'>{model}</td>"
            f"<td>{s['json_valid']:.0%}</td>"
            f"<td>{s['schema_ok']:.0%}</td>"
            f"<td class='hl'>{s['recall']:.0%}</td>"
            f"<td>{s['precision']:.0%}</td>"
            f"<td>{s['evidence_verbatim']:.0%}</td>"
            f"<td>{s['hallucinations']}</td>"
            f"<td>{s['errors']}</td>"
            f"</tr>"
        )

    per_scenario = []
    for r in results:
        if r.get("error"):
            per_scenario.append(
                f"<tr><td>{r['model']}</td><td>{r['scenario']}</td>"
                f"<td colspan='4' class='err'>ERROR</td></tr>"
            )
        else:
            per_scenario.append(
                f"<tr><td>{r['model']}</td><td>{r['scenario']}</td>"
                f"<td>{r['matched']}/{r['expected']}</td>"
                f"<td>{r['recall']:.0%}</td><td>{r['precision']:.0%}</td>"
                f"<td>{r['hallucinations']}</td></tr>"
            )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NomosGuard — LLM benchmark</title>
<style>
  :root {{
    --fg: #1a1a1a; --muted: #6b7280; --border: #e5e7eb;
    --bg: #ffffff; --card: #f9fafb; --hl: #eff6ff;
  }}
  body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
          color: var(--fg); background: var(--bg); margin: 24px; font-size: 14px; }}
  h1 {{ font-size: 18px; margin: 0 0 4px; }}
  p.sub {{ color: var(--muted); margin: 0 0 20px; font-size: 13px; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 28px; }}
  th {{ text-align: left; font-size: 11px; text-transform: uppercase;
        letter-spacing: .04em; color: var(--muted); font-weight: 600;
        border-bottom: 2px solid var(--border); padding: 8px 12px; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); }}
  tr:last-child td {{ border-bottom: none; }}
  .model {{ font-weight: 500; font-family: ui-monospace, "SF Mono", Menlo, monospace;
            font-size: 13px; }}
  .hl {{ background: var(--hl); font-weight: 600; }}
  .err {{ color: #dc2626; }}
  h2 {{ font-size: 14px; margin: 28px 0 8px; }}
  .note {{ color: var(--muted); font-size: 12px; margin-top: 16px;
           border-top: 1px solid var(--border); padding-top: 12px; }}
</style>
</head>
<body>
<h1>LLM-edge benchmark — security telemetry parsing</h1>
<p class="sub">Same task, many models. All values measured by script; none hand-scored.</p>

<table>
  <thead><tr>
    <th>Model</th><th>JSON</th><th>Schema</th><th>Recall</th>
    <th>Precision</th><th>Evidence verbatim</th><th>Halluc.</th><th>Errors</th>
  </tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table>

<h2>Per scenario</h2>
<table>
  <thead><tr>
    <th>Model</th><th>Scenario</th><th>Matched</th><th>Recall</th>
    <th>Precision</th><th>Halluc.</th>
  </tr></thead>
  <tbody>{''.join(per_scenario)}</tbody>
</table>

<div class="note">
  Methodology: 4 scenarios with hand-derived ground truth; each model runs the
  same prompt; outputs scored by script (JSON validity, schema conformance,
  claim recall/precision, evidence verbatim citation, hallucination count).
  All numbers are from actual model runs — nothing hand-computed.
</div>
</body>
</html>"""
