# LLM-edge benchmark methodology

## What is measured

Each model receives the **same prompt** on the **same 4 hand-derived
scenarios** and is scored by script — never by hand — on:

| Metric | Meaning |
|---|---|
| `json_valid` | the output parsed as a JSON array of claims |
| `schema_ok` | every claim has a known `kind` and all required payload fields |
| `recall` | matched ground-truth claims / total ground-truth claims |
| `precision` | matched / produced claims |
| `evidence_verbatim` | claims whose `evidence` field is an exact substring of the raw logs |
| `hallucinations` | produced claims on (kind, host) pairs with no ground-truth counterpart |
| `latency_median_s` | median per-scenario call latency |

## Ground truth discipline

Ground truth was derived from each raw log file **before any model
output was seen** — the same discipline as the tool-call and security
corpora. When the first benchmark run exposed an extractor bug
(tool-level `operates_on`), the **engine** was fixed, not the ground
truth: re-deriving truth from engine output would measure the engine's
self-consistency instead of correctness.

## Scenario corpus

4 scenarios, 16 ground-truth claims total:

1. `brute_force_then_pivot` — 5 claims (SSH brute force -> CVE -> db pivot)
2. `benign_admin_window` — 2 claims (scheduled admin activity)
3. `lateral_movement_pair` — 3 claims (attacker reach -> vuln -> second host)
4. `privilege_escalation` — 3 claims (reach -> CVE -> granted privilege)

**The corpus is synthetic-but-realistic.** It was hand-derived from
realistic log formats (SIEM alerts, firewall lines, NVD records, IAM
records), but it is not captured production telemetry. Results establish
model ranking on this corpus; they do not establish performance on real
production data. Closing that gap requires a real telemetry benchmark.

## Models and sources

16 models across 3 execution paths, all on free/user-quota accounts:

- **OpenCode Zen** (free tier): step-5-preview, mimo-v2.6-flash,
  ling-3.1-flash, nemotron-3-ultra, space-bunny, big-pickle, and others
- **Antigravity CLI** (user account): gemini-3.8-flash, gemini-3.1-pro,
  claude-opus-4.6, claude-sonnet-4.6, gpt-oss-120b, and others
- **Vibe CLI** (Mistral): mistral-medium-3.5

Failed runs are recorded as errors, never silently dropped: ling-3.0-flash-fin
was upstream-unavailable, exo returned error code 91, nemotron-3.5-lightning
timed out, gemini-3.7-flash and gemini-3.6-flash produced empty output.

## Reproducing

```bash
# single model (opencode CLI must be authenticated)
PYTHONPATH=src python3 -m nomosguard.benchmark.model_compare.main \
    --model opencode/step-5-preview-free \
    --output results/

# across models/adapters (edit DEFAULT_MODELS in run_benchmark.py)
PYTHONPATH=src python3 -m nomosguard.benchmark.model_compare.main
```

Adapters: `opencode` (opencode CLI), `antigravity` (agy CLI),
`hermes` (Nous inference API, requires `NOUS_API_KEY`), `vibe` (Mistral Vibe CLI).

## What these numbers do and do not establish

**Established:** model ranking on this corpus; that hallucination is
pervasive (15 of 16 models invented at least one claim); that the best
free model competes with the most expensive one on this task.

**Not established:** performance on real telemetry; robustness to
adversarial prompts; latency and token cost at production volume;
behavior under multi-turn agent interaction.
