"""Built-in signature set: the starter detections.

A curated, deterministic set of Sigma-style signatures over the
semi-structured log shapes this project reasons about (auth logs, proxy
logs, netflow, host security events). Every pattern is a plain ``re``
regex; nothing here scores, learns, or calls a model.

Authoring rules enforced by ``tests/test_signatures.py``:

- every signature carries a stable id (``NG-0001`` upward), a level, and
  a description — a signature nobody can read is a signature nobody
  should trust;
- every signature has at least one POSITIVE line (it fires) and at
  least one NEGATIVE line (it does not). A signature that never fires is
  dead weight; one that always fires is noise. Both are bugs, and the
  test suite treats them as such;
- patterns are written for the field-scoping approximation documented in
  ``signatures.py`` — field and value both appearing in the line. Where
  incidental co-presence is plausible, a ``filter`` carves the benign
  case out rather than complicating the positive pattern.

Severity convention used below:

  informational  context, no implication (routine service registration)
  low            notable, not actionable on its own (a single large transfer)
  medium         suspicious behaviour worth correlating (failed auth, scanner UA)
  high           strong hostile signal (encoded PowerShell, admin grant)
  critical       hostile activity that warrants escalation on reachability
"""

from __future__ import annotations

from .signatures import Signature, validate_signatures


def builtin_signatures() -> list[Signature]:
    """The built-in signature set, in stable id order.

    Validated at construction: a bad regex or a duplicate id fails here,
    at import, not silently at match time.
    """
    sigs = [
        Signature(
            id="NG-0001",
            title="SSH failed authentication",
            status="stable",
            level="medium",
            logsource="auth",
            description=(
                "A failed SSH password attempt. One such event is routine "
                "(a typo, a stale credential); it becomes significant only "
                "in volume, which is the temporal layer's job. This "
                "signature supplies the base evidence that layer reasons over."
            ),
            detection=(
                (r"auth|sshd", r"failed password|authentication failure|failed publickey"),
            ),
        ),
        Signature(
            id="NG-0002",
            title="Successful login following failures",
            status="stable",
            level="high",
            logsource="auth",
            description=(
                "A successful authentication where the same source had been "
                "failing — the credential-success side of a brute-force. The "
                "pair (failed, then accepted) is far stronger evidence than "
                "either line alone; this signature matches the accepted line "
                "and relies on the line order in the caller's evidence."
            ),
            detection=(
                (r"auth|sshd", r"accepted password|session opened|authentication succeeded"),
            ),
        ),
        Signature(
            id="NG-0003",
            title="Encoded PowerShell command",
            status="stable",
            level="critical",
            logsource="windows",
            description=(
                "PowerShell invoked with an encoded (-EncodedCommand / -enc / "
                "-e) base64 payload — the standard way to hide a command from "
                "casual log review. Critical: on its own it justifies a "
                "human look, and with reachability it escalates."
            ),
            detection=(
                (r"powershell|pwsh", r"(?i)-enc(?:odedcommand)?\s"),
            ),
        ),
        Signature(
            id="NG-0004",
            title="Known offensive tooling in user agent",
            status="stable",
            level="high",
            logsource="proxy",
            description=(
                "A request carrying the user agent of a well-known offensive "
                "scanner (sqlmap, nikto, nmap, masscan). The tool identifies "
                "itself in the UA field, which makes this a reliable, "
                "cheap detection."
            ),
            detection=(
                (r"user.?agent", r"sqlmap|nikto|nmap|masscan"),
            ),
        ),
        Signature(
            id="NG-0005",
            title="Large outbound transfer",
            status="stable",
            level="low",
            logsource="netflow",
            description=(
                "An outbound transfer of at least 1,000,000 bytes "
                "(dbytes>=1000000). A single large transfer is usually "
                "backup or update traffic — low severity. Its value is as "
                "input to the temporal exfil rule, which looks for bursts."
            ),
            detection=(
                (r"dbytes", r"\d{7,}"),
            ),
            # Internal replication traffic is not exfiltration. The filter
            # keeps RFC1918 destinations out of the low-severity transfer
            # evidence instead of complicating the positive pattern.
            filter=(
                (r"dbytes", r"dst=(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)"),
            ),
        ),
        Signature(
            id="NG-0006",
            title="Privilege grant to an account",
            status="stable",
            level="high",
            logsource="iam",
            description=(
                "An administrator or root grant. Whether it is an attack "
                "depends on context (a change ticket would justify it), so "
                "this is high, not critical — but it is exactly the evidence "
                "the engine needs to reason about privilege."
            ),
            detection=(
                (r"grant|authorize|sudo|su\b|useradd|usermod",
                 r"administrator|admin|root|wheel|sudoers"),
            ),
        ),
        Signature(
            id="NG-0007",
            title="Firewall deny",
            status="stable",
            level="medium",
            logsource="firewall",
            description=(
                "A single denied connection. Alone it is near-noise (port "
                "knockers and misconfigured clients generate them constantly) "
                "— medium rather than low because a deny proves the actor "
                "reached the perimeter and tried something specific."
            ),
            detection=(
                (r"firewall|fw|netfilter", r"\b(?:deny|denied|dropped|reject)\b"),
            ),
        ),
        Signature(
            id="NG-0008",
            title="Repeated authentication failure burst",
            status="stable",
            level="high",
            logsource="auth",
            description=(
                "Several failed authentications from one source recorded "
                "together (the summary/aggregated form). Distinct from "
                "NG-0001, which matches one failure: this matches the "
                "burst-level record that some auth daemons emit."
            ),
            detection=(
                (r"auth|sshd", r"\b(?:[3-9]|\d{2,})\s+(?:failed|invalid)\b"),
            ),
        ),
        Signature(
            id="NG-0009",
            title="Service installation or registration",
            status="experimental",
            level="medium",
            logsource="windows",
            description=(
                "A new service installed or registered on a host. Genuinely "
                "useful when correlated with the host inventory, but the "
                "'first seen' property needs multi-line context this "
                "single-line matcher does not have — hence experimental."
            ),
            detection=(
                (r"service|systemd|unit", r"installed|created|registered|new service"),
            ),
        ),
        Signature(
            id="NG-0010",
            title="Suspicious shell from a web process",
            status="experimental",
            level="high",
            logsource="process",
            description=(
                "A web server process spawning a shell — the canonical "
                "webshell signature. Experimental: the process-name field "
                "is free text across platforms, so the pattern is broader "
                "than a field-scoped Sigma rule would be."
            ),
            detection=(
                (r"httpd|nginx|apache|php|java",
                 r"/bin/(?:ba)?sh|cmd\.exe|powershell"),
            ),
        ),
        Signature(
            id="NG-0011",
            title="Ransomware note or encryption warning",
            status="experimental",
            level="critical",
            logsource="file",
            description=(
                "A file event naming a known ransomware note or a mass "
                "encryption artifact. Critical by consequence: at this "
                "point the damage is done and a human must act. The keyword "
                "list is short, so treat a hit as a strong hint, not proof — "
                "the exact matched line is in the claim's evidence."
            ),
            detection=(
                (r"file|fs|vfs|created|write",
                 r"readme\.txt|how[_-]?to[_-]?decrypt|_readme\.txt|encrypted"),
            ),
            # A README.txt created in a docs path is documentation, not a
            # ransom note.
            filter=(
                (r"file", r"/(?:doc|docs|documents|help|manual)/"),
            ),
        ),
        Signature(
            id="NG-0012",
            title="Credential dumping tooling",
            status="experimental",
            level="critical",
            logsource="process",
            description=(
                "Execution of known credential-dumping tooling (mimikatz, "
                "lsass dump, hash extraction). Critical: on Windows this is "
                "the step before privilege abuse and lateral movement."
            ),
            detection=(
                (r"process|proc|exec|cmd",
                 r"mimikatz|lsass|sekurlsa|procdump|hashdump|ntds\.dit"),
            ),
        ),
    ]
    validate_signatures(sigs)
    return sigs
