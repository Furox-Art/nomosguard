#!/usr/bin/env python3
"""Entry point: python -m nomosguard.benchmark.security_main [--output DIR]"""

import argparse
import json

from .security_run_suite import run_security_suite


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the NomosGuard security benchmark")
    parser.add_argument("--output", default=None, help="Directory for results files")
    args = parser.parse_args()

    summary = run_security_suite(output_dir=args.output)
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, indent=2))
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
