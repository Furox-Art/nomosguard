#!/usr/bin/env python3
"""Entry point: python -m nomosguard.benchmark.model_compare.main"""

import argparse
import json
import sys

from .run_benchmark import DEFAULT_MODELS, run_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark LLMs on security telemetry parsing")
    parser.add_argument("--output", default=None, help="Directory for results files")
    parser.add_argument("--model", action="append", default=None,
                        help="Override models, e.g. --model opencode/mimo-v2.6-flash-free")
    parser.add_argument("--adapter", action="append", default=None,
                        help="Filter by adapter: opencode, antigravity, hermes")
    parser.add_argument("--timeout", type=int, default=300, help="Per-call timeout seconds")
    args = parser.parse_args()

    models = None
    if args.model:
        models = []
        for m in args.model:
            if "/" in m:
                models.append(tuple(m.split("/", 1)))
            else:
                models.append(("opencode", m))
    if args.adapter:
        if models is None:
            models = DEFAULT_MODELS
        models = [(a, m) for a, m in models if a in args.adapter]

    result = run_benchmark(models=models, output_dir=args.output, timeout=args.timeout)
    print(json.dumps(result["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
