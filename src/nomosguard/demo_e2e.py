#!/usr/bin/env python3
"""End-to-end demo: raw logs through the whole deterministic chain.

One incident, every layer of the system working together:

    raw telemetry (auth log + firewall log + NVD-backed vuln data)
      -> signature matching    (model-free pattern evidence)
      -> NVD enrichment        (real CVE severity)
      -> temporal correlation  (brute-force burst in the time dimension)
      -> rule engine           (MulVAL-style attack graph)
      -> policy gate           (fail-closed, evidence completeness)
      -> containment plan      (operator-reviewable action plan)

Run: python -m nomosguard.demo_e2e

The printed report is the actual tool output — nothing hand-written.
"""

from __future__ import annotations

from nomosguard.ledger import EvidenceLedger, Claim
from nomosguard.rules import RuleEngine
from nomosguard.rules_security import security_rules
from nomosguard.gate import PolicyGate, Decision
from nomosguard.policy_security import containment_policy_rules
from nomosguard.hypothesis import HypothesisTracker
from nomosguard.containment import render_plan

from nomosguard import (
    facts_security,        # registers the security extractors
    temporal_bridge,       # registers the temporal extractors
    signature_bridge,      # registers the signature extractors
)

from nomosguard.signatures import match_all, Match
from nomosguard.signatures_builtin import builtin_signatures
from nomosguard.temporal import default_temporal_rules

# -- the incident -------------------------------------------------------------
# A single attacker (203.0.113.77) brute-forces web01, which carries a
# real CVE; the firewall lets them reach it; exfil-sized transfers start.

RAW_LOGS = [
    "[08:14:01] auth: src=203.0.113.77:1234 failed password for admin",
    "[08:14:05] auth: src=203.0.113.77:1234 failed password for root",
    "[08:14:09] auth: src=203.0.113.77:1234 failed password for admin",
    "[08:14:13] auth: src=203.0.113.77:1234 failed password for oracle",
    "[08:14:17] auth: src=203.0.113.77:1234 failed password for deploy",
    "[08:14:25] auth: src=203.0.113.77:1234 SUCCESS password for admin",
    "[08:20:11] netflow: src=web01:55122 dst=db02:5432 dbytes=3500000 state=ESTABLISHED",
    "[08:33:10] firewall: src=203.0.113.77 dst=web02:443 action=SCAN proto=tcp",
]

# Firewall policy (the network evidence, as an analyst would record it):
NETWORK_CLAIMS = [
    ("network", {"host": "web01", "protocol": "ssh", "port": 22,
                 "allowed_from": "203.0.113.77"},
     "firewall rule: 203.0.113.77 -> web01:22 allowed"),
    ("network", {"host": "web02", "protocol": "https", "port": 443,
                 "allowed_from": "203.0.113.77"},
     "firewall rule: 203.0.113.77 -> web02:443 allowed"),
]

# The vulnerability record: a real, CRITICAL CVE on web01.
VULN_CLAIMS = [
    ("vuln_severity", {"host": "web01", "cve": "CVE-2024-6387",
                       "cvss": 8.1, "severity": "HIGH"},
     "NVD: CVE-2024-6387 regreSSHion, CVSS 8.1 HIGH"),
]


def main() -> int:
    print("=" * 72)
    print("NOMOSGUARD — END-TO-END DEMO")
    print("=" * 72)
    print()
    print("Incident: brute force from 203.0.113.77 against web01 (real CVE),")
    print("firewall allows the path, large transfers begin. Raw logs below.")
    print()
    for ln in RAW_LOGS:
        print(f"  {ln}")
    print()

    # -- stage 1: signatures (model-free) -------------------------------------
    ledger = EvidenceLedger()
    sigs = builtin_signatures()
    by_id = {s.id: s for s in sigs}
    matches: list[Match] = match_all(RAW_LOGS, sigs)
    print(f"[1] signature matching: {len(matches)} match(es) from {len(sigs)} signatures")
    grouped: dict[str, int] = {}
    for m in matches:
        grouped[m.signature_id] = grouped.get(m.signature_id, 0) + 1
    for sid, count in sorted(grouped.items()):
        sig = by_id.get(sid)
        level = sig.level if sig else "?"
        title = sig.title if sig else "?"
        print(f"      {sid} [{level}] {title} — {count} line(s)")
    print()

    # -- stage 2: temporal correlation ----------------------------------------
    temporal_findings = []
    for rule in default_temporal_rules():
        pass  # evaluated inside run_temporal_into_ledger
    from nomosguard.temporal_bridge import run_temporal_into_ledger
    ledger, temporal = run_temporal_into_ledger(
        RAW_LOGS, default_temporal_rules(), ledger
    )
    fired = [
        (name, detail["fired_for"])
        for name, detail in temporal.report.items() if detail.get("fired_for")
    ]
    print(f"[2] temporal correlation: {len(fired)} pattern(s) in the time dimension")
    for name, subjects in fired:
        print(f"      {name}: {subjects}")
    print()

    # -- stage 3: network + vulnerability evidence ------------------------------
    for kind, payload, evidence in NETWORK_CLAIMS + VULN_CLAIMS:
        ledger.append(Claim(kind=kind, payload=payload, evidence=evidence))
    print(f"[3] evidence: {len(NETWORK_CLAIMS)} network rule(s), "
          f"{len(VULN_CLAIMS)} vulnerability record(s) — ledger holds "
          f"{len(ledger.entries)} entries, chain "
          f"{'VERIFIED' if ledger.verify()[0] else 'BROKEN'}")
    print()

    # -- stage 4: derive the attack graph ---------------------------------------
    engine = RuleEngine(rules=security_rules())
    engine.add_facts_from_ledger(ledger)
    engine.derive()
    derived = [f for f in engine.facts if f.sources]
    print(f"[4] attack graph: {len(derived)} derived fact(s)")
    for f in derived:
        print(f"      {f}")
    print()

    # -- stage 5: the gate decides -------------------------------------------------
    gate = PolicyGate(policy_rules=containment_policy_rules(),
                      fallback=Decision.ALERT)
    result = gate.evaluate_with_fallback(engine)
    print(f"[5] gate decision: {result['decision']}")
    for d in result.get("all_decisions", []):
        print(f"      {d['decision']}({d['subject']}) via {d['policy_rule']}")
    print(f"      missing evidence: {result['missing_evidence'] or 'none — chain complete'}")
    print()

    # -- stage 6: how many independent evidence chains? ---------------------------
    tracker = HypothesisTracker.from_engine(engine)
    strongest = tracker.strongest()
    if strongest:
        print(f"[6] strongest hypothesis: {strongest.fact} "
              f"({strongest.chain_count} independent chain(s))")
    else:
        print("[6] no hypothesis tracked")
    print()

    # -- stage 7: the containment plan -------------------------------------------------
    plan = render_plan(result)
    print(f"[7] containment plan ({plan['count']} command(s), dry-run):")
    for c in plan["commands"]:
        print(f"      {' '.join(c['argv'])}")
        print(f"        reason: {c['description']}")
        if c["undo"]:
            print(f"        undo:   {' '.join(c['undo'])}")
    print()
    print("=" * 72)
    print("The model never appears in this chain. Every step is deterministic;")
    print("the same logs always produce the same decision and plan.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
