---
name: nomosguard
description: Deterministic security reasoning for AI agents — produce evidence-citing claims, then let the hash-chained ledger, rule engine, and fail-closed policy gate decide. The model never crosses the decision boundary.
version: 0.1.0
license: Apache-2.0
---

# NomosGuard Skill

## When to use this skill

Use this skill whenever an agent must make or explain a security-relevant
decision (tool-call gating, access control, threat triage) and the
decision must be **reproducible and tamper-evident** rather than a model
assertion. If the question is "should this action be allowed?" — the
answer must come from the deterministic chain, not from the model.

## The contract (non-negotiable)

```
1. READ     raw events (logs, tool calls, CVE records, configs)
2. ASSERT   structured claims, each citing its exact evidence fragment
3. DERIVE   attack/access paths via the rule engine (pure logic)
4. DECIDE   via the policy gate (fail-closed; BLOCK when evidence incomplete)
5. EXPLAIN  narrate the decision — never alter it
```

**You (the model) operate only at steps 1, 2, and 5. Steps 3 and 4 are
the core's, and you cannot influence them.**

### Rules you must obey

1. **Never assert a claim without evidence.** A claim with an empty or
   vague evidence field is rejected by the ledger. This is the fail-closed
   discipline — write "log line 42" or the exact config path, not
   "it seems suspicious".
2. **Never decide.** You do not output ALLOW/ALERT/BLOCK. You call
   `decide` and report what it returned. If the gate says BLOCK, the
   answer is BLOCK — even if you disagree.
3. **Never explain your way around the chain.** At step 5 you may reword
   the decision's rationale, but the cited facts (log hashes, CVE IDs,
   derivation steps) come from the ledger and are immutable. If the chain
   and your narrative disagree, the chain wins.
4. **Report gaps honestly.** If evidence is missing (no log line, no CVE
   record), say so — the gate will apply its fail-closed default (BLOCK),
   and your report must surface that this was a default, not a finding.
5. **Reproduce before you claim.** Every number or decision you report
   must come from an actual tool call in this session. Never hand-compute
   or estimate a result the core could have produced.

## Tool reference

### `evidence_ingest`
Ingest multiple claims at once. Use for batch ingestion of parsed logs
or records. Returns accepted/rejected counts; rejected claims name the
missing-evidence reason.

### `assert_claim`
Assert one claim. Fail-closed: rejected without a non-empty evidence
fragment.

### `derive_paths`
Run the rule engine over the current ledger. Pure logic, deterministic,
no model call. Returns derived facts + the trace of which rules fired.

### `decide`
Run the policy gate. Returns ALLOW / ALERT / BLOCK with the full
derivation chain. `fallback` parameter controls the no-evidence default
(default BLOCK — do not loosen this without explicit human approval).

### `explain`
Render the ledger, derivation, and gate decision as a human-readable
audit summary. Narration only.

## Worked example

Scenario: an agent invokes `sql_query` on `orders_db`; NVD shows
`orders_db` has CVE-2026-1234.

```
assert_claim(kind="tool_call",
             payload={"agent": "researcher", "tool": "sql_query", "target": "orders_db"},
             evidence="agent log line 42: researcher invoked sql_query on orders_db")

assert_claim(kind="vulnerability",
             payload={"component": "orders_db", "cve": "CVE-2026-1234", "severity": "high"},
             evidence="NVD record CVE-2026-1234 affects orders_db (SQL injection)")

derive_paths()
  -> Fact(researcher -exposes-> vulnerable_component)
     rule tool_on_vulnerable_component matched:
       Fact(researcher -calls-> sql_query),
       Fact(sql_query -operates_on-> orders_db),
       Fact(orders_db -has_vulnerability-> CVE-2026-1234)

decide()
  -> BLOCK via block_vulnerable_exposure
     chain: derived researcher -exposes-> vulnerable_component

explain()
  -> "Ledger: chain verified: 2 entries intact. Gate decision: BLOCK.
      researcher exposes a vulnerable component (orders_db, CVE-2026-1234)
      via sql_query. Sources: tool_call, vulnerability."
```

The report to the human is the explanation **as the gate produced it** —
you may add context, but you may not change the verdict or drop a
cited fact.

## Limitations (state these when relevant)

- The core decides only what the evidence supports. Missing evidence
  yields the fail-closed default, not insight.
- v1 covers tool-call, vulnerability, and policy-rule evidence classes.
  Network topology and asset inventory ingestion are not yet implemented.
- This is analysis and gating, not real-time network enforcement.
