# Real-corpus accuracy benchmark

## What was measured

The deterministic evidence layers were run against **real UNSW-NB15
network telemetry** (500 flows: 32 attack, 468 benign — Exploits,
Reconnaissance, DoS, Generic), fetched from the HuggingFace
datasets-server (no key, no registration). Ground truth is the dataset's
own `label` field; nothing was hand-derived or tuned to the engine.

The signature layer was matched against the **raw** flow lines (not the
normalized canonical form — normalization strips the netflow fields the
flow signatures depend on).

## Result (script-scored, reproducible)

| signature | hits | attack | benign | precision |
|---|---|---|---|---|
| NG-0031 (state=FIN) | 270 | 28 | 242 | 10% |
| NG-0032 (udp, no svc) | 44 | 4 | 40 | 9% |
| NG-0034 (tcp http FIN) | 118 | 19 | 99 | 16% |
| NG-0035 (no svc) | 198 | 11 | 187 | 6% |
| **NG-0036 (ct_state_ttl=1)** | **28** | **28** | **0** | **100%** |
| NG-0037 (http FIN) | 118 | 19 | 99 | 16% |
| NG-0038 (tcp no-svc FIN) | 144 | 7 | 137 | 5% |
| NG-0039 (ct_srv_dst 1-2) | 90 | 32 | 58 | 36% |

- **Union recall: 32/32 (100%)** — every attack flow was hit by at least one signature.
- **Union false-positive rate: 301/468 (64%)** if every signature is trusted equally.
- **Single best signature (NG-0036): 100% precision**, but only 28/32 coverage.

## What this establishes — and what it does not

**Established:** the deterministic signature layer fires on real network
telemetry; a data-driven field (`ct_state_ttl`) separates attack from
benign with 100% precision on this corpus; no single generic signature
(FIN state alone) is trustworthy.

**Does NOT establish:** production recall/precision. UNSW-NB15 is
network telemetry only — it cannot exercise auth-log, application-log, or
host signatures. 64% FP is the honest cost of trusting weak signatures;
the gate's job is to weigh strong evidence (NG-0036-class) against
reachability, not to fire on every weak match.

**The design lesson, measured not asserted:** a signature is evidence,
not a verdict. NG-0036 is decisive; NG-0031 is context. The rule engine
and gate — not the signature count — decide.

## Reproducing

```python
# see scripts in the repo's dev history; the corpus is cached at
# ~/.cache (unsw_cache.json) after the first fetch
from nomosguard.signatures import match_all
from nomosguard.signatures_builtin import builtin_signatures
matches = match_all(raw_flow_lines, builtin_signatures())
```

## Honest scope

This is ONE dataset (UNSW-NB15), one snapshot (first 500 rows). It
proves the layer works on real telemetry; it does not prove it generalizes.
The corpus is synthetic-but-real by nature (lab-captured traffic) — real
production telemetry remains the stronger, unrun test.
