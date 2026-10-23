#!/usr/bin/env python3
"""Strict mypy ratchet for nomosguard.

Runs ``mypy --strict`` over ``src/nomosguard`` and compares the per-file error count
with the committed baseline in ``.github/mypy-baseline.json``.

The gate fails when a file has more errors than its baseline, or when a file
has errors but no baseline entry at all. Errors may only move down: a file
whose count falls below its baseline is reported as fixed and passes. The
baseline itself is regenerated from a fresh measurement with::

    python .github/scripts/mypy_ratchet.py --write-baseline

Exit codes: 0 when the ratchet holds (or the baseline was written), 1 when it
does not.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = "src/nomosguard"
BASELINE = ROOT / ".github" / "mypy-baseline.json"
MYPY_ARGS = (
    "--strict",
    "--ignore-missing-imports",
    "--no-error-summary",
    "--show-error-codes",
)
ERROR_LINE = re.compile(
    r"^(?P<path>.+?):(?P<line>\d+)(?::\d+)?: error: (?P<message>.*)$"
)
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _normalize_path(raw: str) -> str:
    """Return a repo-relative path with forward slashes."""
    path = Path(raw.replace("\\", "/"))
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(ROOT)
        except ValueError:
            return path.as_posix()
    return path.as_posix()


def _run_mypy() -> tuple[int, Counter[str], list[str], list[str]]:
    """Run mypy and return (exit code, per-file counts, unattributed, output)."""
    env = os.environ.copy()
    # Keep generated cache files out of the working tree; mypy honours this
    # environment variable in place of a --cache-dir argument.
    with tempfile.TemporaryDirectory(prefix="mypy-ratchet-") as cache_dir:
        env["MYPY_CACHE_DIR"] = cache_dir
        proc = subprocess.run(
            [sys.executable, "-m", "mypy", *MYPY_ARGS, SOURCE],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            check=False,
        )

    output = proc.stdout.splitlines() + proc.stderr.splitlines()
    counts: Counter[str] = Counter()
    unattributed: list[str] = []
    for raw_line in output:
        line = ANSI_ESCAPE.sub("", raw_line).strip()
        match = ERROR_LINE.match(line)
        if match:
            counts[_normalize_path(match.group("path"))] += 1
        elif ": error: " in line:
            unattributed.append(line)
    return proc.returncode, counts, unattributed, output


def _measure() -> Counter[str] | None:
    """Measure the tree, or print a failure and return None if mypy broke."""
    returncode, counts, unattributed, output = _run_mypy()
    problems: list[str] = []
    if returncode not in (0, 1):
        problems.append(f"mypy exited with status {returncode} (expected 0 or 1)")
    if unattributed:
        problems.append("mypy emitted errors that could not be attributed to a file")
    if returncode == 1 and not counts and not unattributed:
        problems.append("mypy reported failure but no file-scoped errors were parsed")
    if problems:
        print("FAIL: " + "; ".join(problems), file=sys.stderr)
        for line in output[-25:]:
            print(f"  {line}", file=sys.stderr)
        return None
    return counts


def _load_baseline() -> dict[str, int]:
    """Read the baseline, rejecting malformed or ambiguous entries."""
    relative = BASELINE.relative_to(ROOT)
    if not BASELINE.exists():
        raise SystemExit(
            f"FAIL: {relative} is missing; create it with --write-baseline"
        )
    try:
        raw = json.loads(BASELINE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: cannot read {relative}: {exc}") from None
    if not isinstance(raw, dict):
        raise SystemExit(f"FAIL: {relative} must contain a JSON object")

    baseline: dict[str, int] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, int) or isinstance(value, bool):
            raise SystemExit(
                f"FAIL: {relative} entry {key!r}: count must be a non-negative integer"
            )
        if value < 0:
            raise SystemExit(
                f"FAIL: {relative} entry {key!r}: count must be a non-negative integer"
            )
        path = _normalize_path(key)
        if path in baseline:
            raise SystemExit(f"FAIL: {relative} lists {path!r} more than once")
        baseline[path] = value
    return baseline


def _write_baseline() -> int:
    """Replace the baseline with the current measurement."""
    counts = _measure()
    if counts is None:
        return 1
    payload = {path: counts[path] for path in sorted(counts) if counts[path] > 0}
    BASELINE.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2) + "\n"
    BASELINE.write_text(text, encoding="utf-8", newline="\n")

    relative = BASELINE.relative_to(ROOT)
    total = sum(payload.values())
    print(f"wrote {relative}: {total} error(s) in {len(payload)} file(s)")
    for path, count in payload.items():
        print(f"  {count:>5}  {path}")
    return 0


def _print_diff(counts: Counter[str], baseline: dict[str, int]) -> None:
    """Print one row per file whose count differs from the baseline."""
    paths = sorted(set(counts) | set(baseline))
    rows = [
        (path, baseline.get(path, 0), counts.get(path, 0))
        for path in paths
        if baseline.get(path, 0) != counts.get(path, 0)
    ]
    if not rows:
        print("per-file diff: no changes")
        return

    width = max(len("FILE"), *(len(path) for path, _, _ in rows))
    print(f"{'FILE':<{width}}  {'BASE':>6}  {'NOW':>6}  {'DELTA':>5}  STATUS")
    for path, base, now in rows:
        delta = now - base
        if path not in baseline:
            status = "NEW"
        elif delta > 0:
            status = "REGRESSED"
        else:
            status = "FIXED"
        print(f"{path:<{width}}  {base:>6}  {now:>6}  {delta:>+5}  {status}")


def _check() -> int:
    """Compare a fresh measurement with the baseline."""
    baseline = _load_baseline()
    counts = _measure()
    if counts is None:
        return 1

    total_now = sum(counts.values())
    total_base = sum(baseline.values())
    relative = BASELINE.relative_to(ROOT)
    print(f"mypy --strict {SOURCE}: {total_now} error(s) in {len(counts)} file(s)")
    print(f"baseline {relative}: {total_base} error(s) in {len(baseline)} file(s)")
    _print_diff(counts, baseline)

    regressions: list[tuple[str, int | None, int]] = []
    for path in sorted(set(counts) | set(baseline)):
        base = baseline.get(path)
        now = counts.get(path, 0)
        if now > 0 and base is None:
            regressions.append((path, None, now))
        elif base is not None and now > base:
            regressions.append((path, base, now))

    if regressions:
        sys.stdout.flush()
        print(
            f"FAIL: {len(regressions)} file(s) exceed the mypy baseline",
            file=sys.stderr,
        )
        for path, base, now in regressions:
            if base is None:
                print(f"  - {path}: no baseline entry, {now} error(s)", file=sys.stderr)
            else:
                print(f"  - {path}: baseline {base}, now {now} (+{now - base})", file=sys.stderr)
        print(
            "Fix the new errors, or review and accept the backlog with --write-baseline.",
            file=sys.stderr,
        )
        return 1

    print("PASS: no file exceeds the mypy baseline")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="replace .github/mypy-baseline.json with the current counts",
    )
    args = parser.parse_args(argv)
    if args.write_baseline:
        return _write_baseline()
    return _check()


if __name__ == "__main__":
    raise SystemExit(main())
