"""Alert memory: which major findings the admin has already been told about.

Kept as a JSON file. Only real runs write it, and a finding counts as notified only once
an email about it was actually delivered to the SMTP server - a failed send means the
next run alerts again.

Per finding the plan decides:
  new        major and never alerted (or back after being fixed)  -> alert
  escalated  alerted before, severity went up since               -> alert
  reminder   still open, last alert older than remind_after_days  -> alert
  suppressed the agent took a scanner-major finding below the bar -> tell the admin once,
             so AI triage can never silently swallow a critical
  resolved   alerted before, gone now, and its check completed    -> reported as fixed
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .models import Finding, ScanResult, Severity

STATE_VERSION = 1
FORGET_AFTER = timedelta(days=90)


def _parse(stamp) -> datetime | None:
    if not isinstance(stamp, str):
        return None
    try:
        return datetime.fromisoformat(stamp)
    except ValueError:
        return None


@dataclass
class NotifyPlan:
    new: list[Finding] = field(default_factory=list)
    escalated: list[Finding] = field(default_factory=list)
    reminders: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)

    @property
    def alerting(self) -> list[Finding]:
        return self.new + self.escalated + self.reminders

    @property
    def should_send(self) -> bool:
        return bool(self.alerting or self.suppressed)

    def to_dict(self) -> dict:
        return {
            "new": [f.id for f in self.new],
            "escalated": [f.id for f in self.escalated],
            "reminders": [f.id for f in self.reminders],
            "suppressed": [f.id for f in self.suppressed],
            "resolved": [r["id"] for r in self.resolved],
        }


class State:
    def __init__(self, path: Path, records: dict[str, dict] | None = None, notes: list[str] | None = None) -> None:
        self.path = path
        self.records: dict[str, dict] = records or {}
        self.notes: list[str] = notes or []

    @classmethod
    def load(cls, path: Path) -> "State":
        if not path.is_file():
            return cls(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            records = data["findings"]
            if not isinstance(records, dict):
                raise ValueError("findings is not an object")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            # Never let a damaged state file block alerting: set it aside and start over.
            backup = path.with_name(path.name + f".corrupt-{datetime.now():%Y%m%d%H%M%S}")
            try:
                path.replace(backup)
            except OSError:
                backup = path
            return cls(path, notes=[f"state file was unreadable ({exc}); moved to {backup.name} and started fresh"])
        return cls(path, records)

    def plan(self, result: ScanResult, min_severity: Severity, remind_after: timedelta, now: datetime) -> NotifyPlan:
        plan = NotifyPlan()
        current = result.by_id()
        for finding in result.findings:
            record = self.records.get(finding.id, {})
            major = finding.status != "false_positive" and finding.severity >= min_severity
            if not major:
                continue
            notified_at = _parse(record.get("notified_at"))
            notified_severity = record.get("notified_severity")
            if notified_at is None or record.get("open") is False:
                plan.new.append(finding)
            elif notified_severity and finding.severity > Severity.parse(notified_severity):
                plan.escalated.append(finding)
            elif now - notified_at >= remind_after:
                plan.reminders.append(finding)

        alerting = {f.id for f in plan.alerting}
        for fid in dict.fromkeys(result.suppressed_major):
            finding = current.get(fid)
            record = self.records.get(fid, {})
            if finding is not None and not record.get("suppression_notified_at") and fid not in alerting:
                plan.suppressed.append(finding)

        completed = result.completed()
        for fid, record in self.records.items():
            if fid in current or not record.get("open") or not record.get("notified_at"):
                continue
            if record.get("source") == "agent":
                continue  # agent findings aren't reproducible run-to-run; absence proves nothing
            if (record.get("group"), record.get("target")) in completed:
                plan.resolved.append({"id": fid, **record})
        return plan

    def commit(self, result: ScanResult, plan: NotifyPlan, now: datetime, *, emailed: bool) -> None:
        stamp = now.isoformat(timespec="seconds")
        alerted = {f.id for f in plan.alerting} if emailed else set()
        announced = {f.id for f in plan.suppressed} if emailed else set()
        current = result.by_id()
        for finding in result.findings:
            record = self.records.setdefault(finding.id, {"first_seen": stamp})
            record.update(
                title=finding.title[:200],
                severity=finding.severity.label,
                status=finding.status,
                category=finding.category,
                group=finding.group,
                target=finding.target,
                location=finding.location[:300],
                source=finding.source,
                last_seen=stamp,
                open=True,
            )
            record.pop("resolved_at", None)
            if finding.id in alerted:
                record["notified_at"] = stamp
                record["notified_severity"] = finding.severity.label
            if finding.id in announced:
                record["suppression_notified_at"] = stamp

        completed = result.completed()
        for fid, record in list(self.records.items()):
            if fid in current:
                continue
            if record.get("source") == "agent":
                last_seen = _parse(record.get("last_seen"))
                if last_seen is not None and now - last_seen > FORGET_AFTER:
                    del self.records[fid]
                continue
            if record.get("open") and (record.get("group"), record.get("target")) in completed:
                record["open"] = False
                record["resolved_at"] = stamp
            closed = _parse(record.get("resolved_at"))
            if not record.get("open") and closed is not None and now - closed > FORGET_AFTER:
                del self.records[fid]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(
            json.dumps({"version": STATE_VERSION, "findings": self.records}, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.replace(tmp, self.path)
