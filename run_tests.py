#!/usr/bin/env python3
"""
Test runner for Data Integrity & Anomaly Detection Framework.
Discovers and executes all unit and integration test suites.
"""

import os
import sys
import time
import unittest


def main():
    start_time = time.perf_counter()
    project_root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, project_root)

    print("=" * 65)
    print("🧪  Running Data Integrity & Anomaly Detection Framework Tests")
    print("=" * 65)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.join(project_root, "tests"), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    elapsed = time.perf_counter() - start_time
    print("=" * 65)
    print(f"⏱️  Finished in {elapsed:.3f} seconds.")
    print(f"📊 Results: {result.testsRun} tests run, {len(result.failures)} failures, {len(result.errors)} errors.")
    print("=" * 65)

    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
