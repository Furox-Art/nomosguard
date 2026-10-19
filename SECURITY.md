# Security Policy

NomosGuard's claim is narrow and testable: a language model never crosses the
decision boundary, every accepted claim cites reproducible evidence, and the
policy gate fails closed. A way around any of those is a security issue.

## Supported versions

| Version | Supported |
|---|---|
| `0.7.x` | Yes |
| `< 0.7` | No |

The current source version is `0.7.9`, declared consistently in
`pyproject.toml`, `SKILL.md`, and `nomosguard.__version__`. Reproduce a
suspected problem against the latest `0.7.x` source before reporting it.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting:**

<https://github.com/Furox-Art/nomosguard/security/advisories/new>

That opens a private thread with the maintainer, and nothing becomes public
until an advisory is published. Please do not open a public issue for a
suspected vulnerability.

If private reporting is unavailable to you, open a regular issue that contains
only enough detail to ask for a private channel, and no exploit details.

Include, where you can:

- the version you tested and how you installed it (source checkout with
  `pip install -e .`, or a built wheel),
- the operating system and Python version,
- the smallest reproduction: a script, a JSONL input, a policy file, or a
  ledger that shows the problem,
- the expected and actual outcome, including the decision (`ALLOW` / `ALERT` /
  `BLOCK`) or the typed error and its message,
- what an attacker gains, and what access they need in order to do it,
- whether a ledger or policy digest pin (`expected_digest`) was in use.

Redact tokens, hostnames, log contents, and personal data from anything you
paste.

## What to expect

NomosGuard is maintained by [@Furox-Art](https://github.com/Furox-Art). There
is no response-time SLA. Reports are handled by the maintainer on the advisory
thread, and details are not disclosed publicly before a fix or mitigation is
available. Please coordinate disclosure there.

## In scope

- A claim appended with empty or missing evidence, or an ingestion adapter
  that accepts a record without citing `sha256:<hex>` of the raw source line.
- A ledger, WAL, exported attestation bundle, or policy bundle that loads or
  verifies after modification, reordering, truncation, duplication, or
  replacement — including a digest mismatch that is not refused when
  `expected_digest` is supplied.
- A policy with an unknown `format` or `format_version` that is applied
  instead of refused.
- A gate result that does not follow from the derived paths, returns `ALLOW`
  when evidence is incomplete, or turns a typed refusal into anything other
  than a fail-closed result.
- Malformed MCP stdio input (non-object JSON, non-object `params` or
  `arguments`, an unknown `decide` fallback) that crashes the server loop, is
  coerced, or produces `ALLOW`.
- An ingest record that is silently skipped or coerced instead of refused with
  the field, the reason, and the value; a duplicate line that is re-appended.
- Containment: `Executor` running a command outside its allowlist, `undo`
  bypassing the allowlist, or a command rendered as a shell string instead of
  an argv array.
- Nondeterminism: identical evidence producing different derivations or
  decisions, or different export bytes or digests for the same evidence.
- A failure mode listed in the README's fail-closed table that the code and
  tests do not actually enforce.

## Out of scope

- **Tamper-evident, not tamper-proof.** A full rewrite that re-hashes every
  record, every link, and the header consistently cannot be detected from the
  file alone. The documented mitigation is an external digest pin
  (`ledger_digest` / `expected_digest`); a report that assumes no anchor is out
  of scope.
- **Not a SIEM, EDR, IDS/IPS, or real-time enforcement engine.** Detection
  quality on real traffic is not a security boundary. Weak signatures firing on
  benign traffic is documented behaviour in
  [`docs/REAL_CORPUS.md`](docs/REAL_CORPUS.md), not a vulnerability.
- A model producing a wrong or malicious claim. The core exists to reject
  claims without evidence; the vulnerability is the core **accepting** one.
- Correctness on real-world logs, or attacks not represented in the committed
  corpus. The benchmark states its own limits.
- Third-party data sources (NVD, HuggingFace datasets) and vulnerabilities in
  the operating system or Python interpreter.
- Development tooling (`pytest`, `ruff`). The package itself has no runtime
  dependencies.

## Conduct reports

This policy covers vulnerabilities only. For behaviour or harassment, use the
process in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), not the advisory route.
