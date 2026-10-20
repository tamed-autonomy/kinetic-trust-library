from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence
import unittest


def run_required_suite(
    *,
    start_dir: Path,
    top_level_dir: Path,
    pattern: str = "test*.py",
    verbosity: int = 2,
) -> unittest.TestResult:
    suite = unittest.defaultTestLoader.discover(
        str(start_dir), pattern=pattern, top_level_dir=str(top_level_dir)
    )
    return unittest.TextTestRunner(verbosity=verbosity).run(suite)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start-dir", type=Path, required=True)
    parser.add_argument("--top-level-dir", type=Path, required=True)
    parser.add_argument("--pattern", default="test*.py")
    parser.add_argument("--verbosity", type=int, default=2)
    arguments = parser.parse_args(argv)
    result = run_required_suite(
        start_dir=arguments.start_dir,
        top_level_dir=arguments.top_level_dir,
        pattern=arguments.pattern,
        verbosity=arguments.verbosity,
    )
    if result.testsRun == 0:
        print("required suite discovered zero tests", file=sys.stderr)
        return 1
    if result.skipped:
        print(
            f"required suite skipped {len(result.skipped)} test"
            f"{'s' if len(result.skipped) != 1 else ''}",
            file=sys.stderr,
        )
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
