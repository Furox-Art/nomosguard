#!/usr/bin/env python3
"""Entry point: python -m benchmark.run_suite_main [--output DIR]"""

import argparse

from .run_suite import run_suite


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the NomosGuard benchmark corpus")
    parser.add_argument(
        "--output",
        default=None,
        help="Directory to write results.json and RESULTS.md (omit to print only)",
    )
    args = parser.parse_args()

    summary = run_suite(output_dir=args.output)
    import json

    print(json.dumps(
        {
            "scenarios": summary["scenarios"],
            "recall": summary["recall"],
            "caught": summary["caught"],
            "expected_total": summary["expected_total"],
            "false_positives": summary["false_positives"],
            "fail_closed_ok": summary["fail_closed_ok"],
            "all_passed": summary["all_passed"],
        },
        indent=2,
    ))
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
