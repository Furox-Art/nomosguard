# NomosGuard benchmark results

Run at: 2026-10-09T12:18:18.064907+00:00
Scenarios: 11

## Metrics (measured, not asserted)

- recall: 10/10 = 100.0%
- false positives: 0
- fail-closed on incomplete evidence: OK

## Per-scenario

| scenario | expected | derived | passed |
|---|---|---|---|
| positive_vulnerable_exposure | [['researcher', 'orders_db']] | [['researcher', 'orders_db']] | PASS |
| negative_benign_workflow | [] | [] | PASS |
| multi_agent_only_one_exposed | [['agent_a', 'orders_db']] | [['agent_a', 'orders_db']] | PASS |
| multi_hop_chain_detected | [['orders_db', 'analytics_db'], ['researcher', 'analytics_db']] | [['orders_db', 'analytics_db'], ['researcher', 'analytics_db']] | PASS |
| incomplete_evidence | [] | [] | PASS |
| policy_violation | [] | [] | PASS |
| deep_four_hop_chain | [['db1', 'db3'], ['db2', 'db3'], ['researcher', 'db3']] | [['db1', 'db3'], ['db2', 'db3'], ['researcher', 'db3']] | PASS |
| chain_to_non_vulnerable_component | [['researcher', 'orders_db']] | [['researcher', 'orders_db']] | PASS |
| shared_component_two_agents | [['agent_a', 'orders_db'], ['agent_b', 'orders_db']] | [['agent_a', 'orders_db'], ['agent_b', 'orders_db']] | PASS |
| policy_deny_via_transitive_reach | [] | [] | PASS |
| no_vulnerability_no_exposure | [] | [] | PASS |
