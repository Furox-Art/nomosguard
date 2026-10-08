"""Attack-scenario benchmark: measure what the core catches and misses.

The corpus is deterministic and committed. run_suite.py produces a results
file from an actual run — recall, false-positive rate, and fail-closed
correctness. The honesty section in RESULTS.md states what the corpus does
not cover.
"""

from .scenarios import Scenario, build_all_scenarios
from .run_suite import run_suite

__all__ = ["Scenario", "build_all_scenarios", "run_suite"]
