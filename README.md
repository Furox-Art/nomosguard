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
engine, policy gate) is implemented with 10 passing tests and a
reproducible demo scenario.

### Run it

```bash
pip install -e .
python -m nomosguard.demo
pytest tests/
```

## License

Apache-2.0
