<!--
Thanks for contributing. NomosGuard's value comes from what it refuses, so a
change that preserves the decision boundary, evidence requirements, and
fail-closed behaviour is the first thing a review checks.

Read the ground rules in CONTRIBUTING.md before opening this pull request.
-->

## Summary

<!-- One paragraph: what is different after this merges, and for whom. -->

Closes #

## Area

- [ ] Evidence ledger, persistence, WAL, or export
- [ ] Rule engine or hypothesis tracking
- [ ] Policy gate or policy bundle
- [ ] Ingestion adapters or log normalization
- [ ] MCP server or SDK boundary
- [ ] Signatures or temporal correlation
- [ ] Containment plans
- [ ] Benchmark corpus, demo, or results
- [ ] Documentation or governance
- [ ] Packaging or CI

## Trust properties

Tick what this change preserves. If none apply, explain in prose why the
properties still hold.

- [ ] A model or an unevidenced claim cannot create or upgrade a decision.
- [ ] Missing or malformed evidence still fails closed, with a typed refusal.
- [ ] No value is silently coerced; unknown values are refused.
- [ ] The runtime remains standard library only.
- [ ] Existing ledgers, exports, and digest pins keep verifying, or a migration is included.
- [ ] Ledger and policy digest pinning is not weakened.
- [ ] Not applicable: no runtime behaviour changed.

## Compatibility

<!-- Does this change a hash input, ledger/export format, policy format,
     error type, CLI flag, or MCP tool contract? If yes, state the impact and
     the migration. If no, say so. -->

## Evidence

<!-- Paste the command and its real output, including the exit code. A test
     that fails on the old code and passes on the new one is the strongest
     evidence. For a documentation-only change, name the test that keeps the
     documentation true. -->

```
```

## Checks run

- [ ] `python -m pytest tests/ -q`
- [ ] `ruff check .` (ruff 0.17.0, the version CI pins)
- [ ] `python -m nomosguard.demo`
- [ ] `python -m nomosguard.demo_e2e` (if a failure mode or demo stage changed)
- [ ] `python -m nomosguard.benchmark.run_suite_main` (if the corpus or results changed)
- [ ] `python -m nomosguard.benchmark.security_main` (if the security corpus or results changed)
- [ ] Not applicable

```
```

## Changelog and version

- [ ] I added an entry under `## Unreleased` in `CHANGELOG.md`.
- [ ] I did not bump the version; the maintainer updates `pyproject.toml`, `SKILL.md`, and `nomosguard.__version__` together at release time.
- [ ] Not applicable: no user-visible change.

## Review notes

<!-- Anything a reviewer should look at first, anything you deliberately left
     out, and anything you are unsure about. -->
