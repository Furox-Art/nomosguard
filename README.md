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
engine, policy gate) is implemented with 18 passing tests and a
reproducible demo scenario, and is exposed as MCP tools for AI agents.

### Components

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
pytest tests/                # 18 tests incl. full stdio protocol
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
