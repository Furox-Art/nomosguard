# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-10-10

### Added — the time dimension is now part of the attack graph

- `nomosguard.temporal_bridge`: temporal findings become evidenced
  ledger claims (kind `temporal_*`), which registered extractors turn
  into engine facts:
    (actor, bruteForceDetected, brute_force)
    (actor, scanDetected, port_scan)
    (host, exfilSuspected, exfiltration)
- New security rules connecting temporal facts to the access graph:
  - brute_force_attempting_access: brute force + reachability ->
    accessAttemptInProgress
  - scan_of_reachable_host: scan + reachability -> enumeratingHost
  - active_exfiltration: exfil suspicion + execCode -> dataExfilInProgress
- New policy rules: ESCALATE on access attempt in progress, REVOKE_ACCESS
  on enumeration, ISOLATE_HOST on active exfiltration. Each declares its
  required evidence classes, so incomplete chains are reported.

The full chain, verified end-to-end: 6 failed SSH logins in 20 seconds
-> bruteForceDetected -> + network reachability -> accessAttemptInProgress
-> ESCALATE + REVOKE_ACCESS, with the derivation chain and missing-evidence
report. Temporal evidence alone never fires a decision — it needs the
access graph, keeping the decision boundary deterministic.

### Tests

147 pass (was 140). New: 7 temporal-chain tests (offline).

## [0.4.0] - 2026-10-10

### Added — temporal rules (deterministic time-window correlation)

- `nomosguard.temporal`: threshold rules over timestamped events. A
  brute force is not one failed login — it is 5+ failures from one
  source within 2 minutes. That pattern exists only in the time
  dimension, which no static rule engine can see.
- Built-in rules: brute force, port scan, exfil burst. Custom rules
  supported (group-by regex, match regex, threshold, window).
- Fully deterministic: same events + same rules -> same facts; order
  independent. Timestamps parse from [HH:MM:SS], ISO-8601, epoch.

### Removed — LLM benchmark suite

- `benchmark/model_compare/` (16-model comparison, pipeline, ensemble)
- `benchmark/real_corpus/` (UNSW-NB15 scenario builder)
- `docs/benchmark/` (published results + methodology)
- The benchmark work answered its questions (LLMs hallucinate, the
  gate holds, models agree on real telemetry) and is out of scope for
  the core. The original tool-call and security corpora
  (`benchmark/run_suite.py`, `security_run_suite.py`) remain.

### Tests

140 pass. New: 9 temporal tests. Removed: 24 benchmark tests.

## [0.3.1] - 2026-10-10

### Added — multi-model ensemble

- `nomosguard.benchmark.model_compare.ensemble`: cross-model voting.
  Several models extract from the same logs; a claim survives only if
  >= min_models DISTINCT models produced it. Single-model claims are
  dropped (or kept via keep_singletons).
- Backers are recorded per claim; per-model extraction counts and
  singleton removals are reported.
- Measured on real UNSW-NB15 data (3 models, 3 scenarios): precision
  100%, with zero single-model claims on real telemetry — the models
  agreed on real, well-structured logs far more than on synthetic ones.

### Tests

158 pass (was 148). New: 10 ensemble tests (offline, mock models).

## [0.3.0] - 2026-10-09

### Added — actionable containment (dry-run)

- `nomosguard.containment`: gate decisions become operator-reviewable
  action plans. Commands render as argv arrays (not shell strings), each
  traced to its decision, policy rule, and derivation chain.
- Execution is opt-in and allowlist-gated: `Executor` is disabled by
  default and refuses any command whose argv[0] is outside its
  allowlist. Reversible decisions carry their undo.
- Not an IPS — a translator from decisions to plans a human reviews.

### Added — real-corpus benchmark

- `nomosguard.benchmark.real_corpus`: scenarios built from real
  UNSW-NB15 network flows (HuggingFace datasets-server, no key), grouped
  by the dataset's own attack labels, with ground truth from the labels.
- 4 real scenarios (Exploits / Reconnaissance / DoS / Generic).
- This closes the "corpus is synthetic" limitation stated in the 0.2.3
  benchmark methodology.

### Tests

148 pass (was 132). New: 11 containment tests, 5 real-corpus tests
(network-gated — they skip cleanly if the fetch fails).

## [0.2.3] - 2026-10-09

### Fixed — the core is actually deterministic now

- **Ledger hash included the wall-clock timestamp** — the same claims
  produced different hashes on every run, so the decision chain was not
  reproducible. `_entry_hash` now hashes (seq, claim, prev_hash) only;
  the timestamp stays on the entry for audit but is never hashed.
  Caught by the new determinism tests — the claim "deterministic core"
  was previously asserted, not verified.

### Fixed — missing evidence is no longer silent

- Policy rules now declare `requires` (the claim kinds a decision needs).
- The gate unions sources across every fact matching a policy relation
  (previously it deduped by (subject, relation) and kept only the first
  fact's sources — a subject deriving the same relation through two
  independent chains looked like it was missing evidence it had).
- Every decision now carries `missing_evidence`; the aggregate result
  reports the union. An incomplete chain is visible, never swallowed.

### Added — evidence production pipeline

- `benchmark/model_compare/pipeline.py`: four-stage evidence pipeline
  around the LLM — SAMPLE (N draws) -> VOTE (>= M draws agree) ->
  AUDIT (flag suspicious claims, never delete) -> GROUND
  (deterministic verbatim-evidence check, the hard floor).
- Only grounding removes claims by rule; audit attaches suspicion as
  metadata so correct evidence is never silently lost.
- Benchmark harness measures latency and token proxies per call.

### Tests

132 pass (was 113). New: 5 determinism, 5 evidence-completeness,
14 pipeline tests (all offline, mock-model based).

## [0.2.2] - 2026-10-09

### Added — LLM edge integration

- MCP server now includes security rules + containment decisions by
  default: one engine, two vocabularies (tool-call + network security)
- SKILL.md updated with the security behavioral contract: the model
  asserts evidence-citing claims and narrates decisions; it never decides
- End-to-end security triage test through the stdio MCP server (assert
  -> derive -> decide -> explain)

### Fixed

- Gate decision ordering now includes containment decisions
  (ISOLATE_HOST, REVOKE_ACCESS, ESCALATE) — previously raised KeyError
  when a security decision was the strongest

## [0.2.1] - 2026-10-09

### Fixed

- `__version__` was stale at 0.1.0 while pyproject.toml said 0.2.0 — the
  wheel and the module disagreed. Both now read 0.2.1.

## [0.2.0] - 2026-10-09

### Added — security layer (MulVAL-style attack graphs)

- **facts_security.py** — host/network/user/service/privilege fact model
  using the MulVAL vocabulary: `execCode`, `netAccess`, `vulExists`,
  `canAccessHost`, `hasPrivilege`, `runsService`
- **rules_security.py** — three MulVAL-style inference rules:
  - exploit_vulnerability: canAccessHost + vulExists => execCode
  - lateral_movement: canAccessHost(host1) + execCode(host1) + shared port
    => canAccessHost(host2) (pivot through a compromised host)
  - privilege_via_exec: execCode + hasPrivilege => grantsPrivilege
- **policy_security.py** — containment decisions: ISOLATE_HOST (execCode),
  REVOKE_ACCESS (canAccessHost), ESCALATE (grantsPrivilege); each carries
  its full derivation chain
- **Security benchmark** — 5 deterministic scenarios with hand-derived
  ground truth: execCode recall 4/4, canAccess recall 7/7, grants recall
  1/1, false positives 0
  Run: `python -m nomosguard.benchmark.security_main`

### Added — since 0.1.0

- **Hypothesis tracking** (hypothesis.py) — how many independent evidence
  chains support each derived fact; the deterministic core's answer to
  "show me the evidence, not the assertion"
- **CVE + policy ingestion** (ingest/vuln_jsonl.py, ingest/policy_jsonl.py)
  — all three evidence types now read from real JSONL files with the same
  fail-closed, evidence-citing, idempotent discipline
- **Transitive access-chain rules** — reaches_base, reaches_transitive,
  transitive_exposure: multi-hop exposure chains the engine previously
  could not see (3-4 hop chains now detected)
- **Performance indexes** — subject/relation and relation/object indexes
  cut derivation time ~1000x (33k claims: timeout -> 0.09s; 333k claims:
  impossible -> 1.11s)
- **Expanded tool-call corpus** — 11 scenarios (was 7), recall 10/10

### Fixed

- Rule engine matching: variables could bind to different values in
  different body literals, and the head was a constant string — rewritten
  with backtracking unification and head variable substitution
- Ledger persistence: atomic save, full-chain-verify load, append
  continues from the loaded head, streaming load (O(1) memory per entry)

### Measured

- 107 tests pass (was 18); CI green on Python 3.10-3.13 + zero-dependency check
- Tool-call benchmark: 11 scenarios, recall 10/10, false positives 0
- Security benchmark: 5 scenarios, recall 4/4 + 7/7 + 1/1, false positives 0
- Zero runtime dependencies — stdlib only

### Honest limitations

- v1 covers tool-call, vulnerability, policy-rule, host, network, privilege
  evidence classes; real-time network enforcement is out of scope
- This is an analysis and decision layer, not a packet filter or IDS
- Benchmark corpora are synthetic-but-realistic; no real-world telemetry

## [0.1.0] - 2026-10-09

### Added — initial release

- Append-only SHA-256 hash-chained evidence ledger; unevidenced claims
  rejected; persistent (atomic save, full-chain-verify load)
- Forward-chaining rule engine with backtracking unification and head
  variable substitution
- Fail-closed policy gate: ALLOW / ALERT / BLOCK with full derivation chains
- Real tool-call JSONL ingestion: claims cite sha256 of the raw source line
- MCP server: 5 tools over stdio JSON-RPC (`python -m nomosguard.mcp_stdio`)
- Agent skill contract (SKILL.md): models produce evidence and explain
  decisions; they never cross the decision boundary
- Declarative JSON policy configuration with fail-closed validation
