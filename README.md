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
engine, policy gate) is implemented with 709 tests and a
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
| `nomosguard.temporal` | Time-window correlation: brute force, port scan, exfil bursts (deterministic) |
| `nomosguard.temporal_bridge` | Temporal findings -> ledger claims -> rule engine -> gate: the time dimension is part of the attack graph |
| `nomosguard.containment` | Gate decisions as operator-reviewable action plans (dry-run) |
| `nomosguard.signatures` | Sigma-style deterministic signature matching: 39 built-in detections, opt-in field-scoped (`field:NAME`) matching (no model) |
| `nomosguard.signature_bridge` | Signature matches -> ledger claims -> engine facts |
| `nomosguard.vuln_db` | Real CVE data from the NVD (cached with 7-day TTL; CVSS severity) |
| `nomosguard.service_cve_map` | Offline service/port -> candidate CVE ids |
| `nomosguard.ledger_wal` | Write-ahead log: crash recovery, checkpointing |
| `nomosguard.evidence_export` | Reproducible attestation bundle: byte-identical exports, digest-pinned, re-verifiable from scratch |
| `nomosguard.ledger_lock` | Multi-writer locking (`append_locked`; fcntl/msvcrt) |
| `nomosguard.log_normalize` | Deterministic adapters: syslog / CEF / JSON / GELF / XML / key=value / pipe -> canonical shape |
| `nomosguard.constants` | Single definition of the rule sets and the claim-kind vocabulary (one definition, imported everywhere) |
| `nomosguard.schema` | One message contract for every record this project validates (field + reason + value) |
| `SKILL.md` | Agent behavioral contract: when to invoke the deterministic chain vs. narrate |

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

## Benchmark (measured, not asserted)

Run with `python -m nomosguard.benchmark.run_suite_main --output DIR`. The
corpus is committed and deterministic; the expected outcomes are
hand-derived from the facts, not produced by the engine. Latest run
(committed in `src/nomosguard/benchmark/results/`):

| metric | value |
|---|---|
| scenarios | 11 tool-call + 5 security |
| recall | 10/10 = 100% |
| false positives | 0 |
| fail-closed on incomplete evidence | OK — 3 scenarios run the gate's fallback, all BLOCK (1 flagged `incomplete`) |
| all scenarios passed | yes |

What the corpus does NOT cover (stated honestly): real-world logs, evidence
tampering *inside* the ledger (that is the ledger's own test suite's job),
and any scenario requiring an LLM to judge.

The fail-closed KPI is read off the gate's verdict (`policy_rule ==
FALLBACK`) — in both directions: a scenario that expects a derived path
must not be decided by the fallback, and a fallback must always deny. The
suite also reports how many scenarios the corpus *flags* as fail-closed
(`fail_closed_scenarios`, ground truth) and how many the gate *actually*
ran the fallback for (`fail_closed_exercised`, measured). If the gate
never falls back, the headline says **NOT EXERCISED** — it cannot claim OK
for work it did not do.

## Fail-closed paths: what is actually proven

The claim is deliberately narrow. The table below names each failure path,
the test that triggers it, and the behaviour that proves it — not a
promise. `python -m nomosguard.demo_e2e` runs the same list as stage 8 of
its narrative and prints the outcome of each mode, and returns non-zero if
any of them stops failing closed. (`tests/test_demo_e2e.py` pins this table
to the demo's scenario registry in both directions: a row without a
scenario, or a scenario without a row, fails the suite.)

| failure mode | refuses how | proven by |
|---|---|---|
| claim without evidence | `UnevidencedClaimError` at `append` | `tests/test_core.py`, demo stage 8 |
| claim with empty evidence / non-dict payload / empty kind in a **saved file** | `LedgerFileError` at load, even with a re-hashed, self-consistent chain | `tests/test_ledger_load_validation.py`, `tests/test_tamper_matrix.py` |
| same tampering in the WAL | `WalError`, the forged record is not replayed | `tests/test_ledger_load_validation.py`, `tests/test_tamper_matrix.py` |
| corrupted / tampered ledger file | `LedgerFileError` at load | `tests/test_core.py`, `tests/test_ledger_durability.py`, `tests/test_tamper_matrix.py` |
| ledger file that is not the one you pinned | `LedgerFileError` on digest mismatch — the one tamper an internal chain cannot see (a consistent full rewrite) | `tests/test_tamper_matrix.py`, demo stage 8 |
| ledger path that is missing / a directory / unwritable | `LedgerFileError` at startup (never a silent empty ledger) | `tests/test_mcp.py`, `tests/test_mcp_stdio_boundary.py`, `tests/test_demo_e2e.py` |
| gate with nothing derived | BLOCK (fail-closed default, reason says so) | `tests/test_core.py`, demo stage 8 |
| unknown fallback decision | typed `GateDenied` from the gate, converted to a fail-closed result at the SDK boundary | `tests/test_mcp.py`, demo stage 8 |
| malformed rule set / claim the extractors cannot read | fail-closed result naming the problem (never a crash) | `tests/test_mcp.py`, `tests/test_no_silent_coercion.py`, demo stage 8 |
| policy file that is not the one you pinned | `PolicyConfigError` on digest mismatch or unknown format version | `tests/test_policy.py`, demo stage 8 |
| malformed log line / policy record | `IngestError` with the field, the reason, and the value | `tests/test_schema_messages.py`, demo stage 8 |

The one boundary, stated plainly: the hash chain proves the records agree
with EACH OTHER. A full rewrite that re-hashes every record, every link and
the header consistently is indistinguishable from the original without an
anchor held outside the file — so the ledger takes one, the same way the
policy bundle does (`ledger_digest` / `load(..., expected_digest=...)` /
`NomosGuardSession(..., ledger_digest=...)`). Everything else — a mutated
field, a reorder, a truncation, a duplicate, a forged hash, an emptied
mid-block line — breaks the chain or the claim validation and is refused.

Not proven here: correctness on real-world logs, behaviour under a
concurrent multi-writer crash, or any judgement that needs a model. Those
are out of scope, not assumed.

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

### Run it

```bash
pip install -e .
python -m nomosguard.demo    # committed scenario: derivation + BLOCK
python -m nomosguard.demo_e2e  # one incident through every deterministic layer
                                # (+ stage 8: each failure mode triggered, not promised)
pytest tests/                # 709 tests incl. security + adversarial suites
python -m nomosguard.benchmark.run_suite_main          # tool-call corpus (11 scenarios)
python -m nomosguard.benchmark.security_main           # security corpus (5 scenarios)
```

### Persistent ledgers are never silently recreated

A ledger path you configure is loaded (chain verified) or the process
refuses to start — a path that is not there is a broken configuration,
not an empty ledger:

```bash
python -m nomosguard.mcp_stdio --ledger /var/lib/nomosguard/ledger.jsonl
python -m nomosguard.mcp_stdio --ledger ./new.jsonl --create-ledger   # explicit opt-in
python -m nomosguard.ingest.cli log.jsonl --ledger ./ledger.jsonl --require-ledger
```

The chain proves the records agree with each other. To also prove the
FILE is the one you reviewed, pin its bytes the same way a policy bundle
is pinned:

```python
from nomosguard.ledger import EvidenceLedger, ledger_digest

pin = ledger_digest("ledger.jsonl")          # "sha256:..." — commit this
EvidenceLedger.load("ledger.jsonl", expected_digest=pin)
# or at the SDK boundary: NomosGuardSession(..., ledger_path=..., ledger_digest=pin)
```

A mismatch raises `LedgerFileError` — a consistent full rewrite of the
ledger is the one tamper the chain alone cannot see, and the pin is what
closes it. A torn final line (a crash mid-write) is recovered and
REPORTED (`LedgerLoadReport`, surfaced as `session.load_report`), never
silently dropped.

### A policy file is a pinned bundle

`load_policy` verifies what it is given before it uses it:

```python
from nomosguard.policy import load_policy, policy_digest

pin = policy_digest("policy.json")        # "sha256:..." — commit this
rules, gate = load_policy("policy.json", expected_digest=pin)   # mismatch => PolicyConfigError
```

```bash
python -m nomosguard.ingest.cli log.jsonl \
    --policy default_policy.json \
    --policy-digest @examples/policy_digests.txt
```

An unknown `format` / `format_version` is refused: this tool will not
apply a policy written for another dialect. `examples/default_policy.json`
carries its pin in `examples/policy_digests.txt`.

### One definition, one message contract

The tool-call rule set and its gate rules exist exactly once
(`nomosguard.constants`) and every consumer takes those same objects — a
rule duplicated across five files is a rule that will disagree with
itself. Every record this project validates is rejected with the same
message shape, `<location>: field <name> <reason>[, got <value>]`
(`nomosguard.schema`), so a refused log line and a refused policy file
read alike, and always name the field and the offending value.

### An unknown value is refused, not coerced

A `policy_rule` claim whose `effect` is not `allow`/`deny` raises
`ClaimValueError` instead of falling through to `policy_denies`: a
malformed record must not be able to manufacture an authoritative
denial. The gate's refusals are typed (`GateDenied`) and the SDK boundary
converts them into fail-closed results, so an agent that only knows how
to read a decision cannot be crashed by one.

### The evidence export is reproducible and re-verifiable from scratch

`session.export_ledger()` returns an attestation bundle
(`nomosguard.evidence_export`): the same ledger always exports
byte-identical bytes, and the digest covers only chain-relevant content,
so the same EVIDENCE yields the same digest in any process, at any time.
The wall-clock timestamps — deliberately excluded from the entry hash, so
the chain stays reproducible — are isolated in one declared metadata
block in one pinned format (`iso-8601-utc`) and validated on
verification. A fresh process re-verifies the bundle with nothing but the
file: chain links, every entry hash, claim validity, timestamp coverage,
and the digest:

```python
from nomosguard.evidence_export import export_bundle, read_export_bundle, verify_export_bundle

bundle = export_bundle(ledger)          # reproducible, timestamp-isolated
read_export_bundle("bundle.json")       # typed ExportError on any deviation
verify_export_bundle(bundle)            # recomputes everything, raises on any mismatch
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
