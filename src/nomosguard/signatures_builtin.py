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
        # ---- extended detections (v2) -------------------------------------
        Signature(
            id="NG-0013",
            title="SSH successful login after failures",
            status="stable",
            level="high",
            logsource="auth",
            description=(
                "A SUCCESS on the same auth stream that just produced failures "
                "— the completion of a brute-force. Correlate with the temporal "
                "layer for the burst; this signature marks the success event."
            ),
            detection=(
                (r"auth|sshd", r"SUCCESS password|Accepted password|session opened"),
                (r"src=([\d.]+)", r"SUCCESS password|Accepted"),
            ),
        ),
        Signature(
            id="NG-0014",
            title="Root or admin login",
            status="stable",
            level="medium",
            logsource="auth",
            description=(
                "An interactive root/admin login. Routine for admins, "
                "noteworthy after any hostile signal — the gate weighs it "
                "against reachability."
            ),
            detection=(
                (r"auth|sshd|login", r"root|admin"),
                (r"session opened|accepted|login", r"root|admin"),
            ),
        ),
        Signature(
            id="NG-0015",
            title="SQL injection attempt in request",
            status="stable",
            level="high",
            logsource="proxy",
            description=(
                "A request carrying classic SQLi markers (UNION SELECT, "
                "OR 1=1, comment terminators). One of the most common web "
                "attack payloads."
            ),
            detection=(
                (r"GET|POST|request|http|uri", r"union\s+select|or\s+1=1|--\s|/\*|sleep\(|benchmark\("),
            ),
            filter=((r"search|query", r"documentation|tutorial"),),
        ),
        Signature(
            id="NG-0016",
            title="Path traversal attempt",
            status="stable",
            level="high",
            logsource="proxy",
            description=(
                "A request with ../ traversal or encoded variants attempting "
                "to escape the web root."
            ),
            detection=(
                (r"GET|POST|uri|request|path", r"\.\./|%2e%2e|\.\.%2f|/etc/passwd|/etc/shadow"),
            ),
        ),
        Signature(
            id="NG-0017",
            title="Web shell or backdoor access",
            status="experimental",
            level="critical",
            logsource="proxy",
            description=(
                "Access to a path commonly used by web shells (c99, r57, "
                "b374k, eval, or a PHP file taking a cmd= parameter)."
            ),
            detection=(
                (r"GET|uri|request", r"c99|r57\.php|b374k|cmd=|eval\(|system\(|passthru\("),
            ),
        ),
        Signature(
            id="NG-0018",
            title="Kerberoasting indicator",
            status="experimental",
            level="high",
            logsource="windows",
            description=(
                "An unusual volume of TGS (service ticket) requests with "
                "RC4 encryption — the Kerberoasting pattern in Windows logs."
            ),
            detection=(
                (r"4769|tgs|service.?ticket", r"rc4|0x17"),
            ),
        ),
        Signature(
            id="NG-0019",
            title="Pass-the-hash indicator",
            status="experimental",
            level="high",
            logsource="windows",
            description=(
                "NTLM logon with a workstation field mismatch — a classic "
                "pass-the-hash signature (event 4624 logon type 3)."
            ),
            detection=(
                (r"4624|logon", r"(?i)ntlm"),
                (r"logon.?type", r"3"),
            ),
        ),
        Signature(
            id="NG-0020",
            title="New local admin account created",
            status="stable",
            level="high",
            logsource="windows",
            description=(
                "A new account added to a local administrators group — a "
                "persistence mechanism."
            ),
            detection=(
                (r"4732|4720|net localgroup|useradd", r"admin|administrators|root|wheel"),
            ),
        ),
        Signature(
            id="NG-0021",
            title="Ransomware canary file access",
            status="experimental",
            level="critical",
            logsource="host",
            description=(
                "Mass rename/encrypt behavior — many files touched in a "
                "short window with suspicious extensions (.encrypted, "
                ".locked, .crypt)."
            ),
            detection=(
                (r"file|rename|write", r"\.encrypted|\.locked|\.crypt|\.ryuk|\.locky"),
            ),
        ),
        Signature(
            id="NG-0022",
            title="Suspicious scheduled task or cron",
            status="stable",
            level="medium",
            logsource="host",
            description=(
                "A scheduled task or cron entry running a script from a "
                "temp/writable path — a common persistence location."
            ),
            detection=(
                (r"schtasks|cron|crontab|systemd.?timer", r"/tmp/|/var/tmp/|/dev/shm/|powershell|curl|wget|base64"),
            ),
        ),
        Signature(
            id="NG-0023",
            title="Base64-encoded command execution",
            status="stable",
            level="high",
            logsource="host",
            description=(
                "A shell or PowerShell invocation decoding base64 — used to "
                "obfuscate payloads."
            ),
            detection=(
                (r"powershell|bash|sh |cmd|exec", r"-enc|-e |-decode|base64\s+-d|base64\s+--decode"),
            ),
        ),
        Signature(
            id="NG-0024",
            title="DNS query to known-bad TLD pattern",
            status="experimental",
            level="medium",
            logsource="dns",
            description=(
                "A DNS query with a high-entropy or algorithmically "
                "generated subdomain — tunneling / DGA indicator."
            ),
            detection=(
                (r"query|dns|resolve", r"[a-zA-Z0-9]{20,}\.(tk|ml|ga|cf|gq|top|xyz)"),
            ),
        ),
        Signature(
            id="NG-0025",
            title="Outbound connection to rare external port",
            status="experimental",
            level="medium",
            logsource="firewall",
            description=(
                "An outbound connection on a non-standard high port — "
                "possible C2 beacon or data exfil channel."
            ),
            detection=(
                (r"outbound|egress|allow", r"dport=(?:4444|5555|6666|8888|9999|1337|31337)\b"),
            ),
        ),
        Signature(
            id="NG-0026",
            title="Credential dumping tool execution",
            status="stable",
            level="critical",
            logsource="host",
            description=(
                "Execution of a known credential-dumping tool (mimikatz, "
                "procdump+lsass, secretsdump)."
            ),
            detection=(
                (r"process|exec|command", r"mimikatz|procdump.*lsass|secretsdump|comsvcs\.dll.*minidump"),
            ),
        ),
        Signature(
            id="NG-0027",
            title="Firewall configuration change",
            status="stable",
            level="medium",
            logsource="firewall",
            description=(
                "A firewall rule added or modified — relevant when it "
                "opens access that should be closed."
            ),
            detection=(
                (r"firewall|iptables|netsh|pf", r"rule added|allow all|any any|-A |add rule"),
            ),
        ),
        Signature(
            id="NG-0028",
            title="Security tool or logging disabled",
            status="experimental",
            level="critical",
            logsource="host",
            description=(
                "An attempt to stop or disable security tooling (AV, "
                "auditd, sysmon) — defense evasion."
            ),
            detection=(
                (r"process|service|systemctl", r"stop.*(auditd|sysmon|defender|clamav|ossec)|disable.*(audit|monitor)"),
            ),
        ),
        Signature(
            id="NG-0029",
            title="Cloud metadata service access",
            status="experimental",
            level="high",
            logsource="proxy",
            description=(
                "A request to the cloud instance metadata endpoint "
                "(169.254.169.254) — SSRF toward credential theft."
            ),
            detection=(
                (r"GET|uri|request|http", r"169\.254\.169\.254|metadata/latest|/computeMetadata"),
            ),
        ),
        Signature(
            id="NG-0030",
            title="Container escape or privileged exec",
            status="experimental",
            level="high",
            logsource="host",
            description=(
                "A container runtime event with privileged mode, host PID "
                "namespace, or docker.sock access — container escape."
            ),
            detection=(
                (r"docker|containerd|kubectl|exec", r"--privileged|--pid=host|docker\.sock|/var/run/docker"),
            ),
        ),

    ]
    validate_signatures(sigs)
    return sigs
