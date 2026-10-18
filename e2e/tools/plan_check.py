#!/usr/bin/env python3
"""Check that TEST_PLAN.md and the scenarios agree.

Every scenario in the plan is a `### ID — title` heading followed by a
`Status:` line. Every test that implements one carries
`@pytest.mark.plan("ID", ...)`. This script fails when:

- a status is not one the plan's Conventions define,
- a test names an ID the plan does not have,
- a scenario is marked `automated` but no test names it,
- a test names a scenario that is not marked `automated` (a `deferred`
  one keeps its plan entry, not its tests).

It reads the files as text and needs nothing beyond the standard library,
so it runs without the test environment (`e2e/run plan`).
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

E2E = Path(__file__).resolve().parent.parent
PLAN = E2E / "TEST_PLAN.md"
SCENARIOS = E2E / "scenarios"

HEADING = re.compile(r"^### ([A-Z]+-\d+) — (.+)$")
STATUS = re.compile(r"^\s*-?\s*\*\*Status:\*\*\s*([a-z-]+)")
MARK = re.compile(r"@pytest\.mark\.plan\(([^)]*)\)")
TEST = re.compile(r"^\s*def (test_\w+)")

# The statuses TEST_PLAN.md's Conventions define.
STATUSES = {"automated", "planned", "manual", "blocked", "deferred"}


def plan_entries() -> dict[str, str]:
    entries: dict[str, str] = {}
    current = None
    for line in PLAN.read_text().splitlines():
        if m := HEADING.match(line):
            current = m.group(1)
            if current in entries:
                sys.exit(f"TEST_PLAN.md: {current} appears twice")
            entries[current] = ""
        elif current and not entries[current] and (m := STATUS.match(line)):
            entries[current] = m.group(1)
    missing = [i for i, s in entries.items() if not s]
    if missing:
        sys.exit(f"TEST_PLAN.md: no Status line for {', '.join(missing)}")
    return entries


def test_marks() -> dict[str, list[str]]:
    """Map each plan ID to the tests that claim it."""
    claims: dict[str, list[str]] = defaultdict(list)
    for path in sorted(SCENARIOS.glob("test_*.py")):
        pending: list[str] = []
        for line in path.read_text().splitlines():
            if m := MARK.search(line):
                pending += re.findall(r"[\"']([A-Z]+-\d+)[\"']", m.group(1))
            elif m := TEST.match(line):
                for plan_id in pending:
                    claims[plan_id].append(f"{path.name}::{m.group(1)}")
                pending = []
    return claims


def main() -> int:
    entries = plan_entries()
    claims = test_marks()
    problems = []
    for plan_id, status in entries.items():
        if status not in STATUSES:
            problems.append(f"{plan_id} has status `{status}`, which TEST_PLAN.md's Conventions do not define")
    for plan_id, tests in sorted(claims.items()):
        if plan_id not in entries:
            problems.append(f"{', '.join(tests)} names {plan_id}, which TEST_PLAN.md does not have")
        elif entries[plan_id] != "automated":
            problems.append(f"{plan_id} is `{entries[plan_id]}` in TEST_PLAN.md but {', '.join(tests)} implements it")
    for plan_id, status in entries.items():
        if status == "automated" and plan_id not in claims:
            problems.append(f"{plan_id} is `automated` in TEST_PLAN.md but no test names it")

    counts: dict[str, int] = defaultdict(int)
    for status in entries.values():
        counts[status] += 1
    summary = ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
    print(f"TEST_PLAN.md: {len(entries)} scenarios ({summary})")
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
