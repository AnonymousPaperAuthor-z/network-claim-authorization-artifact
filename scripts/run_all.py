#!/usr/bin/env python3
"""Run all CPU-only artifact checks."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(label: str, command: list[str]) -> None:
    print(f"\n=== {label} ===", flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> int:
    run(
        "Budget-aware evidence compiler",
        [sys.executable, "scripts/run_budget_compiler_demo.py"],
    )
    run("Runtime state machine", [sys.executable, "scripts/run_runtime_demo.py"])
    run("VeriClaim-Sec benchmark and final gold", [sys.executable, "scripts/verify_benchmark.py"])
    run("EEV/PASE training-data provenance", [sys.executable, "scripts/verify_training_data.py"])
    run("Paper metrics", [sys.executable, "scripts/reproduce_paper_metrics.py"])
    run("Submission scope", [sys.executable, "scripts/verify_submission_scope.py"])
    run(
        "Unit tests",
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
    )
    # The release gate invokes the specialized data and scope checks again so
    # it also remains safe when run by itself.
    run("Release gate", [sys.executable, "scripts/verify_release.py"])
    print("\nARTIFACT_CHECKS_COMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
