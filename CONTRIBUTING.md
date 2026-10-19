# Contributing

NomosGuard exists to keep a security decision deterministic and reproducible
when a language model is in the loop. That makes the rules below unusually
strict, and most of them are enforced by tests rather than by review.

## Ground rules

1. **A model never decides.** A change that lets an LLM output, an unevidenced
   claim, or a default upgrade a decision to `ALLOW` is rejected by design. A
   model may produce cited claims and explain a decision; it may not alter one.
2. **Every claim cites reproducible evidence.** An adapter that accepts a claim
   without a `sha256:<hex>` reference to the raw source fragment is not
   mergeable.
3. **Fail closed.** Missing, unknown, or malformed input resolves to a typed
   refusal or `BLOCK`, never to a silent default, and never to a crash that
   skips the gate. Error messages name the field, the reason, and the value.
4. **Zero runtime dependencies.** The package runs on the Python standard
   library alone. CI installs it with `--no-deps` in a clean virtual
   environment and runs the demo to prove it. `pytest` and `ruff` are
   development tools, not runtime dependencies.
5. **The hash chain and export format are contracts.** Entry hashes, file
   digests, and exported bundle bytes are pinned by
   `tests/test_hash_vector.py` and the tamper suites. Changing the canonical
   serialization, the hash input, or a field name is a deliberate format
   change with a migration — not a refactor.
6. **No silent coercion.** A value outside the documented vocabulary is
   refused, not converted. A `policy_rule` effect other than `allow` or `deny`
   must raise, not fall through to a denial.

## Set up a development environment

Python 3.10 or newer is required; CI runs 3.10, 3.11, 3.12, and 3.13 on Linux,
plus 3.12 on Windows.

```bash
git clone https://github.com/Furox-Art/nomosguard.git
cd nomosguard
python -m pip install -e ".[dev]"
```

The `dev` extra installs `pytest>=8.0` (declared in `pyproject.toml`). For a
local coverage run you also need `pytest-cov`, which CI installs separately:

```bash
python -m pip install pytest pytest-cov
python -m pytest tests/ -q --cov=nomosguard --cov-branch --cov-report=term-missing
```

## Run the test suite

```bash
python -m pytest tests/ -q
```

Other checks worth running before you open a pull request:

| Command | What it proves |
|---|---|
| `python -m pytest tests/ -q` | The full unit, security, and adversarial suite. |
| `python -m nomosguard.demo` | The committed scenario still derives a path and blocks. |
| `python -m nomosguard.demo_e2e` | One incident through every deterministic layer, including stage 8: every documented failure mode is triggered and still fails closed. Exits non-zero if one stops doing so. |
| `python -m nomosguard.benchmark.run_suite_main` | The tool-call benchmark still passes its committed expectations. |
| `python -m nomosguard.benchmark.security_main` | The security benchmark still passes its committed expectations. |

The Linux CI job runs the suite with `-rs`, `--cov=nomosguard`,
`--cov-branch`, `--cov-report=term-missing`, and a coverage floor, and it fails
if any test is skipped. The Windows job runs `pytest tests/ -q` so the `msvcrt`
lock path is exercised. The exact invocations are in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

Benchmark results are committed under `src/nomosguard/benchmark/results/`.
Regenerate them from a real run; do not edit expected outcomes or result files
by hand to make a change look better.

## Lint

CI pins `ruff==0.17.0` and runs the default rule set; there is no ruff
configuration file in the repository.

```bash
python -m pip install "ruff==0.17.0"
ruff check .
```

There is no separate type-check step in CI. Do not document one or add a badge
for it.

## Changing behaviour

- **Add a test with the change.** A new decision path needs a passing case and
  a failing case. A new refusal needs a test that asserts the typed error, not
  a bare `Exception`.
- **Failure modes are documented in two places.** The README table "Fail-closed
  paths: what is actually proven" is pinned to the demo's scenario registry by
  `tests/test_demo_e2e.py` in both directions: a row without a scenario, or a
  scenario without a row, fails the suite. If you add or remove a failure mode,
  update the registry and the README table together.
- **A changed CLI flag or MCP tool needs its contract updated.** The MCP stdio
  server, the ingest CLI, and `SKILL.md` describe the same surfaces; a change
  to one that leaves the others stale is incomplete.
- **Do not add a number you did not measure.** Benchmark and corpus figures
  must come from a committed run. If something was not measured, say so.

## Pull requests

Keep a pull request focused on one change. Use the pull request template and
include the real commands and output, including exit codes. Reports that a
change preserves the invariants are more useful than a summary of the diff.

- Add a changelog entry under `## Unreleased` in
  [`CHANGELOG.md`](CHANGELOG.md), following the existing Keep a Changelog
  format.
- Do **not** bump the version in a normal pull request. The version is declared
  in three places — `pyproject.toml`, the `SKILL.md` front matter, and
  `nomosguard.__version__` in `src/nomosguard/__init__.py` — and release
  changes update all three together.
- For a change to a hash input, an export format, a policy format, or an error
  type, explain the compatibility impact and the migration path in the pull
  request.

## Releasing (maintainer)

Publishing is driven by a GitHub Release:
[`.github/workflows/release-pypi.yml`](.github/workflows/release-pypi.yml)
fires on `release: published` (or manual dispatch), builds the sdist and wheel,
runs `twine check`, verifies that the release tag matches the `pyproject.toml`
version, installs the wheel with `--no-deps` in a clean virtual environment,
runs the full suite against that installed wheel, and publishes to PyPI with
trusted publishing (OIDC, `pypi` environment). There is no long-lived PyPI
token in the workflow.

Before publishing, update the changelog and the three version declarations
listed above.

## Where things live

| Path | Contents |
|---|---|
| `src/nomosguard/ledger.py` | Append-only SHA-256 hash-chained evidence ledger |
| `src/nomosguard/rules.py`, `hypothesis.py` | Forward-chaining rule engine and hypothesis tracking |
| `src/nomosguard/gate.py`, `policy.py` | Fail-closed policy gate and pinned policy bundles |
| `src/nomosguard/ingest/` | Tool-call, vulnerability, and policy JSONL adapters and CLI |
| `src/nomosguard/mcp_server.py`, `mcp_stdio.py` | MCP session layer and JSON-RPC stdio server |
| `src/nomosguard/evidence_export.py` | Reproducible, digest-pinned attestation bundles |
| `src/nomosguard/signatures*.py`, `temporal*.py` | Deterministic signature and time-window layers |
| `src/nomosguard/containment.py` | Gate decisions as allowlist-gated, dry-run action plans |
| `tests/` | Unit, tamper, adversarial, determinism, and contract suites |
| `docs/` | Real-corpus measurement and its stated limits |

## Conduct and security

Behaviour expectations are in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Do not
open a public issue for a suspected vulnerability; use the private advisory
route in [SECURITY.md](SECURITY.md).

## Licence

By contributing, you agree that your contributions are licensed under the
[Apache-2.0 licence](LICENSE) of this project.
