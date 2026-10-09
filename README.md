# NomosGuard

**LLM produces evidence. Deterministic machinery decides.**

NomosGuard is a deterministic security reasoning core: an append-only
evidence ledger, a rule engine that derives threat/access paths from that
evidence, and a fail-closed policy gate. Language models may *read* events
and *write* structured claims with cited evidence, and may later *explain*
decisions in human language — but a model never crosses the decision
boundary. Every claim without reproducible evidence is discarded; every
decision is hash-chained; the gate defaults to deny.

The name: *nomos* (νόμος) — Greek for rational law, order derived from
reason rather than brute force (physis) — plus *guard*, the fail-closed
gate that enforces it. Together: reasoning that decides, evidence that
must prove itself.

## Why deterministic core + probabilistic edge

A language model's confidence is not evidence — it is an assertion. This
project treats it as such:

- **The LLM edge (top):** reads raw events, configuration, CVE records,
  logs; emits *structured claims* (entities, relations, vulnerabilities,
  tool calls), each citing the exact evidence fragment (log line hash,
  config path, CVE ID) that supports it.
- **The deterministic core:** an append-only, SHA-256 hash-chained ledger
  stores every claim; a rule engine derives attack/access paths
  (MulVAL-style logical inference — pure logic, no randomness, no model);
  a policy gate decides ALLOW / ALERT / BLOCK, fail-closed.
- **The LLM edge (bottom):** explains the decision, drafts remediation
  suggestions, and proposes next analysis steps. It narrates; it never
  decides. If the explanation contradicts the evidence chain, the chain
  wins.

This is the same separation that makes a court work: a lawyer (the model)
presents evidence, but the verdict comes from the rules of law (the core),
and the transcript is tamper-evident.

## Status

Early development — see [VISION.md](VISION.md) for the architecture,
scope, and first-release boundary. The core (evidence ledger, rule
engine, policy gate) is implemented with 51 passing tests and a
reproducible demo scenario, real log ingestion, and a measured benchmark corpus.

### Components

| Module | What it does |
|---|---|
| `nomosguard.ledger` | Append-only SHA-256 hash-chained evidence ledger; rejects unevidenced claims; persistent (atomic save, full-chain-verify load) |
| `nomosguard.rules` | Forward-chaining rule engine with unification; tool-call / CVE / policy extractors |
| `nomosguard.gate` | Fail-closed policy gate: ALLOW / ALERT / BLOCK with full derivation chains |
| `nomosguard.ingest.toolcall_jsonl` | Real tool-call JSONL ingestion: each claim cites sha256 of the raw source line |
| `nomosguard.mcp_server` | MCP session layer: 5 tools (`evidence_ingest`, `assert_claim`, `derive_paths`, `decide`, `explain`) |
| `nomosguard.mcp_stdio` | JSON-RPC stdio server (`python -m nomosguard.mcp_stdio`) |
| `nomosguard.benchmark` | Attack-scenario corpus with measured recall / false-positive / fail-closed results |
| `nomosguard.facts_security` | Host/network/user/service/privilege facts (MulVAL vocabulary) |
| `nomosguard.rules_security` | MulVAL-style rules: exploit, lateral movement, privilege escalation |
| `nomosguard.policy_security` | Containment decisions: ISOLATE_HOST, REVOKE_ACCESS, ESCALATE |
| `SKILL.md` | Agent behavioral contract: when to invoke the deterministic chain vs. narrate |

### Multi-model ensemble (cross-model voting)

The single-model pipeline samples one model N times. That fixes random
noise, not *systematic* misreading: if one model consistently reads a log
wrong, all its draws agree on the wrong answer.

`nomosguard.benchmark.model_compare.ensemble` runs several models on the
same logs and votes **across** them:

```python
from nomosguard.benchmark.model_compare.ensemble import run_ensemble

result = run_ensemble(
    {
        "step5":  lambda p: run_step5(p),
        "mimo":   lambda p: run_mimo(p),
        "gptoss": lambda p: run_gptoss(p),
    },
    raw_logs,
    min_models=2,       # a claim must come from >= 2 DISTINCT models
    audit=True,         # flag suspicious claims (never delete)
    ground=True,        # deterministic verbatim-evidence floor
)
# result.claims   — cross-model agreed claims
# result.backers  — which models produced each claim
# result.flagged  — suspicious claims, kept
```

A claim produced by only one model is dropped at `min_models=2` (or kept
if `keep_singletons=True`). Different architectures misread different
ways, so cross-model disagreement is signal; one model agreeing with
itself is not.


## Actionable containment (dry-run)

The gate decides; something else acts. `nomosguard.containment` translates
decisions into operator-reviewable action plans — and executes nothing
unless explicitly enabled:

```python
from nomosguard.containment import render_plan, Executor

plan = render_plan(gate_result)
# plan.commands  — argv arrays, each traced to its decision + chain
# plan.dry_run   — always True until an executor is configured

# execution is opt-in and allowlist-gated:
executor = Executor(allowlist=("iptables", "revoke-session"), enabled=True)
result = executor.execute(plan.commands[0])  # rejects anything unlisted
```

Commands render as **argv arrays, not shell strings**, so they can be
audited and rejected before anything runs. Reversible decisions
(ISOLATE_HOST) carry their `undo`; irreversible ones (ESCALATE) do not.
The Executor is disabled by default and refuses any command outside its
allowlist — the last line of defence between a decision and a real
system change.

**This is not an IPS.** It is a translator from deterministic decisions
to action plans a human reviews.

## Real-corpus benchmark

The synthetic corpus could not establish performance on real telemetry.
`nomosguard.benchmark.real_corpus` builds scenarios from real UNSW-NB15
network flows (no key, no registration — HuggingFace datasets-server):

```python
from nomosguard.benchmark.real_corpus import load_scenarios

scenarios = load_scenarios(300)
# Real flows grouped by the dataset's own attack labels
# (Exploits / Reconnaissance / DoS / Generic), with ground truth taken
# from the labels rather than hand-derivation.
```

The corpus distinction is deliberate and stated everywhere it matters:
synthetic scenarios establish ranking and pipeline behavior; real
scenarios establish that the same engine works on real telemetry. Neither
alone is sufficient, and the README does not claim otherwise.


## Evidence production pipeline

The LLM edge is where hallucinations live — every model in the 16-model
benchmark invented at least one claim. `nomosguard.benchmark.model_compare.pipeline`
wraps model output in four stages, ordered by how much they can be trusted:

```
1. SAMPLE   N independent draws from the model
2. VOTE     keep a claim only if >= M draws produced it
            (one-off claims are likely hallucinations)
3. AUDIT    a second prompt asks the model to FLAG suspicious claims
            — it never deletes them (measured: deletion cost recall)
4. GROUND   deterministic: a claim survives only if its evidence
            field is a verbatim substring of the raw logs
```

Only stage 4 removes claims by hard rule. Stage 3 attaches suspicion as
metadata (`result.flagged`); the claim survives so no correct evidence
is ever silently lost. A first measured pass (step-5-preview-free,
4 scenarios) showed the pipeline trading −9 recall points for +20
precision points against single-pass extraction — the flag-not-delete
audit design exists to close that recall gap.

```python
from nomosguard.benchmark.model_compare.pipeline import run_pipeline

result = run_pipeline(model_fn, raw_logs, draws=3, min_votes=2)
# result.claims  — surviving claims, each with vote support
# result.flagged — suspicious claims, kept but marked
# result.report  — per-stage removals, for measurement
```


## Benchmark (measured, not asserted)

Run with `python -m nomosguard.benchmark.run_suite_main --output DIR`. The
corpus is committed and deterministic; the expected outcomes are
hand-derived from the facts, not produced by the engine. Latest run:

| metric | value |
|---|---|
| scenarios | 7 |
| recall | 2/2 = 100% |
| false positives | 0 |
| fail-closed on incomplete evidence | OK |
| all scenarios passed | yes |

What the corpus does NOT cover (stated honestly): real-world logs, evidence
tampering *inside* the ledger (that is the ledger's own test suite's job),
and any scenario requiring an LLM to judge.

### Ingestion (three evidence types, one discipline)

Three adapters, each with the same contract: every claim cites
`sha256:<hex>` of the raw source line; malformed records are rejected with
line number and reason (fail-closed); duplicate lines are counted, never
re-appended.

| Adapter | Input (JSONL) | Claim kind |
|---|---|---|
| `ingest.toolcall_jsonl` | `{"agent", "tool", "target", "args"?}` | `tool_call` |
| `ingest.vuln_jsonl` | `{"component", "cve": "CVE-YYYY-NNNN", "severity", "description"?}` | `vulnerability` |
| `ingest.policy_jsonl` | `{"subject", "action", "resource", "effect": "allow\|deny"}` | `policy_rule` |

Committed samples: `examples/sample_toolcalls.jsonl`,
`examples/sample_cves.jsonl`, `examples/sample_policies.jsonl`.



| Module | What it does |
|---|---|
| `nomosguard.ledger` | Append-only SHA-256 hash-chained evidence ledger; rejects unevidenced claims |
| `nomosguard.rules` | Forward-chaining rule engine (MulVAL-style) with tool-call / CVE / policy extractors |
| `nomosguard.gate` | Fail-closed policy gate: ALLOW / ALERT / BLOCK with full derivation chains |
| `nomosguard.mcp_server` | MCP session layer: 5 tools (`evidence_ingest`, `assert_claim`, `derive_paths`, `decide`, `explain`) |
| `nomosguard.mcp_stdio` | JSON-RPC stdio server (`python -m nomosguard.mcp_stdio`) |
| `SKILL.md` | Agent behavioral contract: when to invoke the deterministic chain vs. narrate |

### Run it

```bash
pip install -e .
python -m nomosguard.demo    # committed scenario: derivation + BLOCK
pytest tests/                # 107 tests incl. security suite
python -m nomosguard.benchmark.run_suite_main          # tool-call corpus (11 scenarios)
python -m nomosguard.benchmark.security_main           # security corpus (5 scenarios)
```

### Use it from an MCP client

```json
{"command": "python", "args": ["-m", "nomosguard.mcp_stdio"]}
```

The server never calls a model. Agents load `SKILL.md` for the behavioral
contract: assert claims with evidence, derive paths, read the gate
decision, explain it — never decide it.

## License

Apache-2.0
