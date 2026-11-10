#!/usr/bin/env python3
"""Dependency-free test runner (the test modules are also pytest-compatible).

Discovers ``test_*`` functions in the sibling ``test_*.py`` modules, runs each,
and reports pass/fail. Usage:  python3 tests/run_tests.py
"""
import importlib.util
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def load(path):
    spec = importlib.util.spec_from_file_location(
        "cosa_test_" + os.path.basename(path)[:-3], path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    files = sorted(f for f in os.listdir(HERE)
                   if f.startswith("test_") and f.endswith(".py"))
    passed = failed = 0
    failures = []
    for filename in files:
        module = load(os.path.join(HERE, filename))
        for name in sorted(dir(module)):
            if not name.startswith("test_"):
                continue
            fn = getattr(module, name)
            if not callable(fn):
                continue
            try:
                fn()
                passed += 1
                print(f"PASS {filename}::{name}")
            except Exception:
                failed += 1
                failures.append((filename, name, traceback.format_exc()))
                print(f"FAIL {filename}::{name}")
    print(f"\n{passed} passed, {failed} failed")
    for filename, name, tb in failures:
        print(f"\n===== {filename}::{name} =====\n{tb}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
