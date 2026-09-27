"""Rule-based triage: the deterministic pass that always runs, with or without the agent.

It only does things that are explainable in one sentence: drop duplicates, lower code
findings that live in test/example paths by one level, and order by severity.
"""

from __future__ import annotations

import re

from .models import Finding, ScanResult

TEST_PATH = re.compile(
    r"(?i)(^|/)(tests?|testing|spec|specs|__tests__|__mocks__|fixtures?|examples?|samples?|docs?|demo)(/|$)"
    r"|(^|/)(test_[^/]*|[^/]*_test\.\w+|[^/]*\.(spec|test)\.\w+|conftest\.py)$"
)


def in_test_path(location: str) -> bool:
    path = location.rsplit(":", 1)[0] if re.search(r":\d+$", location) else location
    return bool(TEST_PATH.search(path))


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
        if finding.source == "scanner" and finding.category in ("secrets", "code") and in_test_path(finding.location):
            finding.reassess(
                finding.severity.lowered(),
                "Lowered one level: in a test/example path, so probably not production code.",
                by="rules",
            )
            finding.confidence = "tentative"
    dedupe_and_sort(result)
