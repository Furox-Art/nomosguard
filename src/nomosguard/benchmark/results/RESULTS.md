# NomosGuard benchmark results

Run at: 2026-10-13T01:47:35.873631+00:00
Scenarios: 11

## Metrics (measured, not asserted)

- recall: 10/10 = 100.0%
- false positives: 0
- fail-closed on incomplete evidence: OK (3 scenario(s) ran the fallback; 1 flagged incomplete)

## Per-scenario

| scenario | expected | derived | passed | fail-closed |
|---|---|---|---|---|
| positive_vulnerable_exposure | [['researcher', 'orders_db']] | [['researcher', 'orders_db']] | PASS | n/a |
| negative_benign_workflow | [] | [] | PASS | exercised (BLOCK) |
| multi_agent_only_one_exposed | [['agent_a', 'orders_db']] | [['agent_a', 'orders_db']] | PASS | n/a |
| multi_hop_chain_detected | [['orders_db', 'analytics_db'], ['researcher', 'analytics_db']] | [['orders_db', 'analytics_db'], ['researcher', 'analytics_db']] | PASS | n/a |
| incomplete_evidence | [] | [] | PASS | exercised (BLOCK) |
| policy_violation | [] | [] | PASS | n/a |
| deep_four_hop_chain | [['db1', 'db3'], ['db2', 'db3'], ['researcher', 'db3']] | [['db1', 'db3'], ['db2', 'db3'], ['researcher', 'db3']] | PASS | n/a |
| chain_to_non_vulnerable_component | [['researcher', 'orders_db']] | [['researcher', 'orders_db']] | PASS | n/a |
| shared_component_two_agents | [['agent_a', 'orders_db'], ['agent_b', 'orders_db']] | [['agent_a', 'orders_db'], ['agent_b', 'orders_db']] | PASS | n/a |
| policy_deny_via_transitive_reach | [] | [] | PASS | n/a |
| no_vulnerability_no_exposure | [] | [] | PASS | exercised (BLOCK) |
