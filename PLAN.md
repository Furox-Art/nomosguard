# NomosGuard — Development Plan (living document)

> Status line is updated as work lands. Every number in this file comes from
> an actual test run or CI run, never hand-computed.

## Current state (verified 2026-10-30)

**Repository:** https://github.com/Furox-Art/nomosguard (public, Apache-2.0)
**Version:** 0.7.10 — on PyPI since 2026-10-21 with a PEP 740 provenance
attestation; GitHub release
[`v0.7.10`](https://github.com/Furox-Art/nomosguard/releases/tag/v0.7.10)
**Tests:** 1115 passed locally on Python 3.12 (2026-10-30)
**CI:** green on Python 3.10 / 3.11 / 3.12 / 3.13 + zero-dependency check
(run 40952174554, commit c60e3ce)
**Plan:** P1–P5 are delivered; each checkbox below records where the
deliverable shipped.

## Starting point (verified 2026-10-09)

### What exists and is proven

| Component | Module | Proven by |
|---|---|---|
| Evidence ledger (in-memory) | `ledger.py` | hash-chain link tests, tamper detection |
| Evidence ledger (persistent) | `ledger.py` | save/load round-trip, append-after-load, tamper rejection, idempotency (7 tests) |
| Rule engine (unification) | `rules.py` | variable consistency, head substitution, multi-match firing, unbound-head rejection (7 tests) |
| Fail-closed policy gate | `gate.py` | fallback BLOCK, block-on-derived-path with full chain |
| MCP server (5 tools + stdio) | `mcp_server.py`, `mcp_stdio.py` | full JSON-RPC protocol end-to-end test |
| Agent skill contract | `SKILL.md` | — (behavioral doc) |
| Vision + architecture doc | `VISION.md` | — |

### What was fixed in this session (both were real defects)

1. **Rule engine matching (commit 1dcb0a8).** The previous Cartesian-product
   matcher had two correctness bugs: (a) body variables could bind different
   values in different literals, producing derivations no single evidence
   chain supports; (b) the head was a constant string, so derived facts lost
   the component/CVE values (`vulnerable_component` instead of `orders_db`).
   Rewritten with backtracking unification + head substitution. Demo now
   derives `Fact(researcher -exposes-> orders_db)`.
2. **Ledger persistence (commit f63547c).** The chain was in-memory only —
   it died with the process, defeating the tamper-evidence property it
   exists for. Now: atomic save, full-chain-verify load, append-continues,
   MCP `--ledger` flag.

---

## The plan (priority order)

The guiding principle from VISION.md: **one ingestion path done flawlessly
beats five shallow ones.** The tool-call path is the v1 path. Order is
correctness-first, then real data, then measurement.

### P1 — Real log ingestion (the promise the project makes)

**Why:** the value proposition is "read real tool-call logs, produce
evidence-citing claims." Today claims are synthetic in-memory dicts. Until
a real parser exists, the demo cannot leave the lab.

Deliverables:
- [x] `ingest/toolcall_jsonl.py` — parse a JSONL file of MCP tool-call
      records into ledger claims. Each claim's `evidence` field carries the
      source line hash (SHA-256 of the raw line), not a paraphrase.
      (shipped; `_line_hash` in `src/nomosguard/ingest/toolcall_jsonl.py`)
- [x] Payload schema validation per claim kind (reject malformed records
      with a per-record error, never silently skip — the gateway's
      fail-closed discipline applies to ingestion too).
- [x] Ingest demo: committed sample log (synthetic but *realistic* — the
      same shapes real MCP gateways emit) → parsed → derived → decided.
- [x] Tests: parser unit tests (well-formed, malformed, empty-line,
      duplicate-record idempotency), and an end-to-end ingest→derive→gate test.
      (`tests/test_ingest.py`, plus the CLI contract tests)

Exit criteria: `python -m nomosguard.ingest.toolcall_jsonl sample.jsonl`
produces a verified ledger; every claim cites a verifiable line hash.

### P2 — Benchmark: attack scenarios with measured catch/miss/false-positive

**Why:** the discipline this project follows (and that the five repos
released today all share) is: publish real measurements, including null
results. A security reasoning core with no corpus is unfalsifiable.

Deliverables:
- [x] `benchmark/scenarios/` — a committed corpus of tool-call attack
      scenarios with known ground truth (which paths should be derived,
      which should not): at minimum (a) vulnerable-component exposure
      (positive), (b) benign multi-tool workflow (negative — must NOT
      fire), (c) chained access path 3+ hops deep (positive), (d)
      incomplete evidence (fail-closed default must apply).
      (shipped as `src/nomosguard/benchmark/scenarios.py`: 11 scenarios)
- [x] `benchmark/run_suite.py` — measures recall (caught / total positive),
      false-positive rate, and fail-closed correctness; writes committed
      JSON + markdown results.
      (results in `src/nomosguard/benchmark/results/`: recall 10/10,
      0 false positives, fail-closed exercised — measured 2026-10-14)
- [x] Honesty gate: results page states what the corpus does NOT cover
      (no real-world logs, no adversarial evidence tampering inside the
      ledger — that is the ledger's own test's job).
      (`docs/REAL_CORPUS.md`: "What this establishes — and what it does
      not", including the 64% false-positive rate when every signature is
      trusted equally)
- [x] README gets a measured-results section ONLY if numbers support a
      claim; otherwise the "not yet demonstrated" disclaimer stays.
      (README "Benchmark (measured, not asserted)")

Exit criteria: corpus runs green in CI; results committed from an actual
run; limitations stated.

### P3 — Declarative policy configuration

**Why:** `default_rules()` is hardcoded in `mcp_server.py`. A security
tool whose rules cannot be inspected or versioned outside the code is a
maintenance trap.

Deliverables:
- [x] Policy file format (JSON): rules (Pattern triples) + gate decisions,
      with a schema validator that rejects malformed rules at load.
      (`policy.load_policy` + `PolicyConfigError`; invalid patterns,
      unknown decisions, duplicate names and unknown fields are refused)
- [x] Policy loading entry point. Shipped as `policy.load_policy()`,
      consumed by the ingest CLI (`--policy`) and the demo; the plan's
      proposed name `NomosGuardSession.from_policy_file(path)` was not
      used, the session keeps taking validated rule objects.
- [x] Tests: valid config loads, malformed config rejected with precise
      error, unknown decision rejected. (`tests/test_policy.py`)

### P4 — Ledger hardening

- [x] Concurrent-append safety: file locking landed instead of a
      single-writer note. `ledger_lock.py` provides exclusive locking
      (`fcntl` on POSIX, `msvcrt` on Windows) and `append_locked`
      re-reads the tail under the lock; CI exercises both backends,
      including a `windows-latest` job.
- [x] `load` performance on large ledgers: `EvidenceLedger.load` streams
      the file through `iter_ledger_records`, so memory stays O(1) per
      entry while the chain verify stays O(n)
      (`tests/test_ledger_load_validation.py` covers the load checks).

### P5 — First release

- [x] PyPI trusted publisher + publish workflow. The package is named
      `nomosguard` (not `furox-nomosguard`); `.github/workflows/release-pypi.yml`
      publishes via trusted OIDC (`id-token: write`, `pypi` environment),
      and 0.7.10 carries a PEP 740 provenance attestation. The plan's gate
      held: the 0.1.0 wheel (2026-10-09) already contains `nomosguard/ingest/`
      and `benchmark/results/`.
- [x] GitHub Release notes link VISION.md + benchmark results.
      (`v0.7.10` notes link VISION.md, the measured benchmark results and
      `docs/REAL_CORPUS.md`)

### Explicitly out of scope (guard against scope creep)

- Real-time network enforcement (batch/stream analysis only)
- Asset inventory / network topology ingestion (v1 is tool-call only)
- Any LLM inference inside the core (the whole design forbids it)
- Multi-writer concurrency (document single-writer instead)

---

## Standing rules for this project (learned the hard way)

1. **Every published number comes from a real run.** No hand-computed
   figures. If a metric can't be measured, say so.
2. **The decision boundary is never crossed by a model.** Reviewers' first
   question is "can an LLM influence the gate?" — the answer must stay no.
3. **Fail closed.** Missing evidence → BLOCK default. Reject unverifiable
   chains. Refuse malformed input loudly.
4. **Zero runtime dependencies.** The core runs on stdlib only; CI checks it
   in a clean venv. Optional extras (matplotlib-style) never enter the core.
5. **Honesty sections are mandatory** in any results/doc page: state what
   was NOT measured and why.
