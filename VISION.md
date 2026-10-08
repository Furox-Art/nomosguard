# NomosGuard — Vision & Architecture

> Status: design document. The core (ledger, rule engine, gate) is under
> active development; this document defines *what* is being built and
> *what is deliberately excluded* from v1.

## 1. One sentence

An LLM may read security events and write structured, evidence-citing
claims; a deterministic core — hash-chained ledger, rule engine, fail-closed
policy gate — turns those claims into tamper-evident ALLOW / ALERT / BLOCK
decisions; the LLM may then explain those decisions but can never alter them.

## 2. The invariant

**The decision boundary is never crossed by a language model.** Models
operate only above it (evidence production) and below it (explanation).
Everything at or inside the boundary — what counts as evidence, what
follows from what, and what gets blocked — is deterministic, testable, and
reproducible.

## 3. Architecture

```
┌─ LLM EDGE (probabilistic, untrusted) ──────────────────────────┐
│  raw events / configs / CVE / logs / tool-call records         │
│        │  structured, evidence-citing claims                   │
└────────┼───────────────────────────────────────────────────────┘
         ▼
┌─ DETERMINISTIC CORE (trusted, zero-dependency Python) ─────────┐
│                                                                │
│  1. EVIDENCE LEDGER     append-only, SHA-256 hash-chained      │
│     - every claim + its cited evidence fragment               │
│     - claims without reproducible evidence are REJECTED       │
│                                                                │
│  2. RULE ENGINE         MulVAL-style logical derivation       │
│     - attack/access path derivation, pure logic, no randomness│
│     - hypothesis set kept alive (multi-branch, not winner-    │
│       take-all), revived if new evidence supports it          │
│                                                                │
│  3. POLICY GATE         fail-closed decision                  │
│     - ALLOW / ALERT / BLOCK per policy rules                  │
│     - defaults to DENY when evidence is incomplete            │
│     - every decision carries the full derivation chain        │
│                                                                │
└────────┼───────────────────────────────────────────────────────┘
         ▼
┌─ LLM EDGE (probabilistic, untrusted) ──────────────────────────┐
│  explanation, remediation drafts, next-step proposals          │
│  (narration only — contradicted by the ledger, the ledger wins)│
└────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Responsibility | Determinism |
|---|---|---|
| Evidence ledger | Store claims + cited evidence, hash-chain, reject unevidenced claims | Fully deterministic |
| Rule engine | Derive attack/access paths from evidence via logical rules | Fully deterministic |
| Hypothesis tracker | Keep multiple candidate paths alive; revive rejected ones on new evidence | Fully deterministic |
| Policy gate | ALLOW/ALERT/BLOCK decision, fail-closed, with derivation chain | Fully deterministic |
| MCP tools | Expose `evidence_ingest`, `assert_claim`, `derive_paths`, `evaluate`, `decide`, `explain` to agents | Deterministic wrappers |
| Agent skill | Behavioral contract: when to invoke the deterministic chain vs. narrate | Skill, not decision-maker |

## 4. Scope and first-release boundary

**In scope (general capability):**
- Three evidence classes, all ingestible: tool-call records, policy rules,
  CVE/configuration records — the core is ingestion-agnostic; each evidence
  *type* has its own adapter and validation schema.
- Attack/access path derivation over the merged evidence graph.
- Fail-closed gate with full derivation chains.

**First release (narrow but perfect):**
- One ingestion path done *flawlessly*: tool-call records (MCP tool calls,
  agent actions) — the path closest to the existing ecosystem
  (plan-auditor, axiomize) and the most testable end-to-end.
- Core primitives (ledger, rule engine, gate) built general-purpose so the
  other two ingestion paths slot in without redesign.
- Honest README: what v1 does *not* cover (full network topology ingestion,
  asset inventory management, etc.) is stated explicitly.

**Explicitly out of scope for v1 (stated so nobody over-trusts it):**
- Replacing a SIEM/EDR, IDS/IPS, or incident response platform.
- Asset inventory, network discovery, or continuous monitoring.
- Real-time enforcement at network speed (batch/stream analysis only).
- Any security guarantee that depends on the LLM edge being correct —
  the whole design exists precisely because it is not.

## 5. Why this is different from "another AI security wrapper"

Most AI security products put the model at the decision center. This
design treats the model as an untrusted component at the edges, for one
reason: in security, a hallucinated "ALLOW" is worse than a missing
detection. A deterministic core fails closed; a model-first system fails
open. The gate never trusts an assertion — it asks for the artifact.

## 6. Relationship to the existing ecosystem

NomosGuard is *not* a rewrite of anything. It composes the patterns:

- **plan-auditor's discipline:** hash-chained evidence, fail-closed gate,
  "done means here is the command output that proves it."
- **quantum-reasoning-skill's engine:** multi-hypothesis tracking —
  several candidate paths stay alive until evidence eliminates them.
- **axiomize's reproducibility:** versioned, replayable run records —
  a decision must be reproducible from its inputs.
- **scientific-computing-system's style:** pure-Python, zero runtime
  dependencies, CI-testable core — the core must run anywhere, fast.

The genuinely new piece: the causal/attack-graph inference engine. That is
what gets built first, and everything else composes around it.

## 7. Success criteria for v1

1. Core runs in CI with zero dependencies (`pip install nomosguard` → tests green).
2. A tool-call ingestion → derivation → gate demo reproduces from committed inputs.
3. Every published number comes from an actual run, never hand-computed.
4. An agent skill (SKILL.md + reference controller) that agents can load,
   following the quantum-reasoning-skill contract pattern.
5. Honest limitations section that a skeptic would consider complete.
