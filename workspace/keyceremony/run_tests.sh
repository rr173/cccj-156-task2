#!/usr/bin/env bash
# Run every test: unit scenarios, edge cases, in-process smoke.
set -euo pipefail
cd "$(dirname "$0")"
echo "=== RFC 8032 / primitive correctness is exercised inside the suites ==="
python3 tests/smoke_e2e.py
python3 -m unittest tests.test_ceremonies tests.test_edge
echo "=== HTTP e2e (includes 8-way concurrent publish race) ==="
python3 tests/http_e2e.py "${1:-8301}"
echo "ALL TESTS PASSED"
