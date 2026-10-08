# NomosGuard benchmark results

Run at: 2026-10-08T23:54:36.236216+00:00
Scenarios: 6

## Metrics (measured, not asserted)

- recall: 2/2 = 100.0%
- false positives: 0
- fail-closed on incomplete evidence: OK

## Per-scenario

| scenario | expected | derived | passed |
|---|---|---|---|
| positive_vulnerable_exposure | [['researcher', 'orders_db']] | [['researcher', 'orders_db']] | PASS |
| negative_benign_workflow | [] | [] | PASS |
| multi_agent_only_one_exposed | [['agent_a', 'orders_db']] | [['agent_a', 'orders_db']] | PASS |
| incomplete_evidence | [] | [] | PASS |
| policy_violation | [] | [] | PASS |
| no_vulnerability_no_exposure | [] | [] | PASS |
