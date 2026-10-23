# NomosGuard

NomosGuard is a deterministic security reasoning core. Language models may read
events and write structured claims that cite evidence, and may explain
decisions afterwards, but they never cross the decision boundary. The
deterministic side is an append-only SHA-256 hash-chained evidence ledger, a
forward-chaining rule engine that derives attack and access paths, and a
fail-closed policy gate that returns ALLOW, ALERT, or BLOCK. Claims without
reproducible evidence are rejected; the gate defaults to deny.

The project is in early development. The core (ledger, rule engine, policy
gate) is implemented with a reproducible demo, real log ingestion, and a
committed benchmark corpus. It is not an intrusion-prevention system:
containment produces operator-reviewable action plans and executes nothing
unless an allowlist-gated executor is explicitly enabled.

## Documentation

- [Real-corpus accuracy benchmark](REAL_CORPUS.md) — deterministic signatures
  measured against real UNSW-NB15 network telemetry, including the result that
  generic signatures have high false-positive rates while one data-driven
  field separates attack from benign traffic on that corpus.

## Install

```bash
pip install nomosguard
```

The MCP stdio server runs with:

```bash
python -m nomosguard.mcp_stdio
```

See the repository README for the evidence, rule, gate, and containment
examples, and `VISION.md` for the architecture and first-release boundary.
