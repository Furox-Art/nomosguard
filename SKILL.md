---
name: nomosguard
description: Deterministic security reasoning for AI agents — produce evidence-citing claims, then let the hash-chained ledger, rule engine, and fail-closed policy gate decide. The model never crosses the decision boundary.
version: 0.2.1
license: Apache-2.0
---

# NomosGuard Skill

## When to use this skill

Use this skill whenever an agent must make or explain a security-relevant
decision (tool-call gating, access control, threat triage, containment)
and the decision must be **reproducible and tamper-evident** rather than a
model assertion. If the question is "should this action be allowed?" or
"which host should be isolated?" — the answer must come from the
deterministic chain, not from the model.

## The contract (non-negotiable)

```
1. READ     raw events (logs, SIEM alarms, threat intel, firewall config)
2. ASSERT   structured claims, each citing its exact evidence fragment
3. DERIVE   attack/access paths via the rule engine (pure logic)
4. DECIDE   via the policy gate (fail-closed; BLOCK on insufficient evidence)
5. EXPLAIN  narrate the decision — never alter it
```

**You (the model) operate only at steps 1, 2, and 5. Steps 3 and 4 are
the core's, and you cannot influence them.**

## Two vocabularies, one core

The engine speaks two security vocabularies through the same ledger:

### AI-agent security (tool-call + CVE + policy evidence)
- Claims: `tool_call`, `vulnerability`, `policy_rule`
- Rules: direct exposure, transitive exposure (multi-hop chains)
- Decisions: BLOCK (exposed), ALERT (policy violation)

### Network/host security (MulVAL-style attack graphs)
- Claims: `network` (firewall), `vuln_host` (CVE on host), `privilege` (IAM)
- Rules: exploit_vulnerability, lateral_movement, privilege_via_exec
- Decisions: ISOLATE_HOST, REVOKE_ACCESS, ESCALATE

## Worked example — threat triage

Scenario: a SIEM alert says attacker 10.0.0.5 reached web01:443; NVD
shows web01 has CVE-2026-1; web02 also exposes 443.

```
assert_claim(kind="network", payload={"host": "web01", "protocol": "tcp",
    "port": 443, "allowed_from": "10.0.0.5"}, evidence="firewall log: 10.0.0.5 -> web01:443")
assert_claim(kind="vuln_host", payload={"host": "web01", "cve": "CVE-2026-1"},
    evidence="NVD record CVE-2026-1")
assert_claim(kind="network", payload={"host": "web02", "protocol": "tcp",
    "port": 443, "allowed_from": "internal"}, evidence="firewall log: internal -> web02:443")

derive_paths()
  -> Fact(web01 -execCode-> 10.0.0.5)          [exploit]
  -> Fact(10.0.0.5 -canAccessHost-> web02)      [lateral movement via shared port]

decide()
  -> ISOLATE_HOST (web01), REVOKE_ACCESS (10.0.0.5 -> web01, 10.0.0.5 -> web02)
```

The report to the analyst is the explanation **as the gate produced it** —
you may add context, but you may not change the verdict or drop a cited
fact.

## Rules you must obey

1. **Never assert a claim without evidence.** Cite the raw log line, the
   NVD record, the firewall rule — not "it looks suspicious."
2. **Never decide.** Call `decide()` and report what it returned.
3. **Never explain your way around the chain.** If the chain and your
   narrative disagree, the chain wins.
4. **Report gaps honestly.** Missing evidence → fail-closed default;
   say so in your report.
5. **Reproduce before you claim.** Every number or decision must come
   from an actual tool call. Never hand-compute.

## Limitations (state these when relevant)

- Analysis and decision layer, not a packet filter or IDS
- Benchmark corpora are synthetic-but-realistic; no real-world telemetry
- v1 covers tool-call, vulnerability, policy, host, network, privilege
  evidence classes; real-time enforcement is out of scope
