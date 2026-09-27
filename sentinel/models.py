"""Findings, severities and the record of one scan run."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field, fields
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: "Severity | str") -> "Severity":
        if isinstance(value, Severity):
            return value
        text = str(value).strip().upper()
        if text == "MODERATE":  # GitHub advisory wording
            text = "MEDIUM"
        try:
            return cls[text]
        except KeyError:
            names = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {names})") from None

    @property
    def label(self) -> str:
        return self.name.lower()

    def lowered(self, steps: int = 1) -> "Severity":
        return Severity(max(int(Severity.INFO), int(self) - steps))


CATEGORIES = ("web", "tls", "secrets", "code", "dependency", "config")
STATUSES = ("open", "confirmed", "needs_review", "false_positive")


def fingerprint(*parts: str) -> str:
    """Stable 12-hex id. The same issue at the same place keeps its id across runs."""
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:12]


@dataclass
class Finding:
    check_id: str  # "<family>.<check>.<rule>", e.g. "web.headers.csp_missing"
    title: str
    severity: Severity
    category: str
    target: str  # the origin, URL or repository label the check ran against
    location: str = ""  # URL, "path:line", "manifest: pkg==version"
    evidence: str = ""  # short and already redacted
    description: str = ""  # why it matters
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    confidence: str = "firm"  # certain | firm | tentative
    source: str = "scanner"  # scanner | agent
    key: str = ""  # identity when `location` drifts (line numbers move)
    status: str = "open"  # see STATUSES
    original_severity: Severity | None = None  # set the first time triage changes it
    triage_note: str = ""
    triaged_by: str = ""  # "" | rules | agent
    id: str = ""

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        if self.original_severity is not None:
            self.original_severity = Severity.parse(self.original_severity)
        if not self.id:
            self.id = fingerprint(self.check_id, self.target, self.key or self.location)

    @property
    def group(self) -> str:
        """The check that produces this finding ("web.headers"). A finding can only be
        called fixed when that check ran successfully against the same target."""
        return ".".join(self.check_id.split(".")[:2])

    def reassess(self, severity: "Severity | str", note: str = "", by: str = "") -> None:
        severity = Severity.parse(severity)
        if severity != self.severity:
            if self.original_severity is None:
                self.original_severity = self.severity
            self.severity = severity
        if note:
            self.triage_note = f"{self.triage_note} {note}".strip() if self.triage_note else note
        if by:
            self.triaged_by = by

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.label
        data["original_severity"] = (
            self.original_severity.label if self.original_severity is not None else None
        )
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in names})


@dataclass
class CheckRun:
    group: str
    target: str
    ok: bool
    skipped: bool = False
    detail: str = ""
    findings: int = 0
    seconds: float = 0.0

    @property
    def state(self) -> str:
        if self.ok:
            return "ok"
        return "skipped" if self.skipped else "error"


@dataclass
class AgentOutcome:
    ran: bool = False
    ok: bool = False
    model: str = ""
    summary: str = ""
    risk_chains: list[str] = field(default_factory=list)
    verdicts_applied: int = 0
    new_findings: int = 0
    turns: int = 0
    tool_calls: int = 0
    usage: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    platform: str
    started_at: str
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckRun] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    agent: AgentOutcome = field(default_factory=AgentOutcome)
    suppressed_major: list[str] = field(default_factory=list)  # ids the agent took below the alert bar

    def by_id(self) -> dict[str, Finding]:
        return {f.id: f for f in self.findings}

    def open_major(self, min_severity: Severity) -> list[Finding]:
        return [
            f for f in self.findings if f.status != "false_positive" and f.severity >= min_severity
        ]

    def counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in Severity}
        for f in self.findings:
            if f.status != "false_positive":
                counts[f.severity.label] += 1
        return counts

    def completed(self) -> set[tuple[str, str]]:
        """(group, target) pairs whose check ran to completion this run."""
        return {(c.group, c.target) for c in self.checks if c.ok}

    def coverage(self) -> tuple[int, int, int]:
        ok = sum(1 for c in self.checks if c.ok)
        skipped = sum(1 for c in self.checks if c.skipped)
        return ok, len(self.checks) - ok - skipped, skipped

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "counts": self.counts(),
            "agent": asdict(self.agent),
            "findings": [f.to_dict() for f in self.findings],
            "checks": [{**asdict(c), "state": c.state} for c in self.checks],
            "notes": list(self.notes),
            "suppressed_major": list(self.suppressed_major),
        }
