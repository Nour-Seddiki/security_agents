"""Rule-based triage: the deterministic pass that always runs, with or without the agent.

It only does things that are explainable in one sentence: drop duplicates, lower
findings in test/example code and code-pattern findings in operator scripts by one
level, and order by severity.
"""

from __future__ import annotations

import re

from .models import Finding, ScanResult

TEST_PATH = re.compile(
    r"(?i)(^|/)(tests?|testing|spec|specs|__tests__|__mocks__|fixtures?|examples?|samples?|docs?|demo)(/|$)"
    r"|(^|/)(test_[^/]*|[^/]*_test\.\w+|[^/]*\.(spec|test)\.\w+|conftest\.py)$"
)
# Code run by an operator from a shell, not by the application serving requests.
OPERATOR_PATH = re.compile(r"(?i)(^|/)(scripts?|migrations?|alembic|tools?|bin|seeds?|management/commands)(/|$)")


def _path(location: str) -> str:
    return location.rsplit(":", 1)[0] if re.search(r":\d+$", location) else location


def in_test_path(location: str) -> bool:
    return bool(TEST_PATH.search(_path(location)))


def in_operator_path(location: str) -> bool:
    return bool(OPERATOR_PATH.search(_path(location)))


def dedupe_and_sort(result: ScanResult) -> None:
    best: dict[str, Finding] = {}
    for finding in result.findings:
        current = best.get(finding.id)
        if current is None or finding.severity > current.severity:
            best[finding.id] = finding
    result.findings = sorted(
        best.values(), key=lambda f: (-f.severity, f.status == "false_positive", f.category, f.title, f.location)
    )


def baseline_triage(result: ScanResult) -> None:
    dedupe_and_sort(result)
    for finding in result.findings:
        if finding.source != "scanner":
            continue
        if finding.category in ("secrets", "code") and in_test_path(finding.location):
            note = "Lowered one level: in a test/example path, so probably not production code."
        elif finding.category == "code" and in_operator_path(finding.location):
            # Secrets stay as they are: a committed key is exposed wherever it lives.
            note = "Lowered one level: in an operator script, not code that handles web requests."
        else:
            continue
        finding.reassess(finding.severity.lowered(), note, by="rules")
        finding.confidence = "tentative"
    dedupe_and_sort(result)
