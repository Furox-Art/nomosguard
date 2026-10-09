"""Raw security telemetry + hand-derived ground-truth claims.

Ground truth was derived by reading each log file line by line BEFORE any
model output was seen, exactly like the tool-call and security corpora.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelScenario:
    name: str
    raw_logs: str
    # (kind, payload) pairs that MUST be extracted; evidence must cite a real log line
    expected_claims: tuple[tuple[str, dict], ...]


SCENARIOS: tuple[ModelScenario, ...] = (
    ModelScenario(
        name="brute_force_then_pivot",
        raw_logs="""[08:14:02] SIEM ALERT 4421 severity HIGH: source 203.0.113.77 (external, unknown ASN) target web01:22, 14 failed SSH logins in 40s then one SUCCESS from same IP
[08:15:44] VULNSCAN: web01 has CVE-2026-31142 (OpenSSH auth bypass, CVSS 9.1)
[08:20:11] NETFLOW: web01 (10.0.4.21) opened 18 connections to db02:5432
[08:31:55] IAM: root process executed on web01 under user deploy
[08:33:10] SIEM ALERT 4428: web02:443 now seeing scan probes from 203.0.113.77""",
        expected_claims=(
            ("network", {"host": "web01", "port": 22, "allowed_from": "203.0.113.77"}),
            ("vuln_host", {"host": "web01", "cve": "CVE-2026-31142"}),
            ("network", {"host": "db02", "port": 5432, "allowed_from": "web01"}),
            ("exec_code", {"host": "web01", "user": "deploy"}),
            ("network", {"host": "web02", "port": 443, "allowed_from": "203.0.113.77"}),
        ),
    ),
    ModelScenario(
        name="benign_admin_window",
        raw_logs="""[09:00:00] NETFLOW: admin-laptop -> internal-db:5432 allowed (scheduled maintenance)
[09:30:00] VULNSCAN: daily scan complete, 0 critical, 2 medium on admin-laptop
[10:15:00] IAM: admin-laptop user sysadmin ran pg_dump on internal-db""",
        expected_claims=(
            ("network", {"host": "internal-db", "port": 5432, "allowed_from": "admin-laptop"}),
            ("exec_code", {"host": "internal-db", "user": "sysadmin"}),
        ),
    ),
    ModelScenario(
        name="lateral_movement_pair",
        raw_logs="""[10:00:00] FIREWALL: attacker -> host1:443 allowed
[10:05:00] VULNSCAN: host1 has CVE-2026-4242 (nginx RCE)
[10:20:00] FIREWALL: internal -> host2:443 allowed""",
        expected_claims=(
            ("network", {"host": "host1", "port": 443, "allowed_from": "attacker"}),
            ("vuln_host", {"host": "host1", "cve": "CVE-2026-4242"}),
            ("network", {"host": "host2", "port": 443, "allowed_from": "internal"}),
        ),
    ),
    ModelScenario(
        name="privilege_escalation",
        raw_logs="""[11:00:00] FIREWALL: attacker -> db01:5432 allowed
[11:05:00] VULNSCAN: db01 has CVE-2026-7777 (Postgres privesc)
[11:30:00] IAM: attacker granted admin role on db01""",
        expected_claims=(
            ("network", {"host": "db01", "port": 5432, "allowed_from": "attacker"}),
            ("vuln_host", {"host": "db01", "cve": "CVE-2026-7777"}),
            ("privilege", {"host": "db01", "user": "attacker", "privilege": "admin"}),
        ),
    ),
)

# Required payload fields per kind (for schema + field scoring)
REQUIRED_FIELDS = {
    "network": {"host", "port", "allowed_from"},
    "vuln_host": {"host", "cve"},
    "privilege": {"user", "privilege", "host"},
    "exec_code": {"host", "user"},
}
