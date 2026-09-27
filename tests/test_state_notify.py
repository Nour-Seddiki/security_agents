import email
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email import policy
from pathlib import Path
from unittest import mock

from sentinel.config import load_config
from sentinel.models import CheckRun, Finding, ScanResult, Severity
from sentinel.notify import NotifyError, build_email, send_email
from sentinel.state import State

from .helpers import hexs, smtp_server, write_config

T0 = datetime(2026, 9, 1, 2, 0, tzinfo=timezone.utc)


def finding(title="Git repository exposed", severity=Severity.CRITICAL, check="web.exposure.git", target="https://shop.example", **kw) -> Finding:
    return Finding(check_id=check, title=title, severity=severity, category="web", target=target, location=f"{target}/.git/HEAD", **kw)


def result_with(*findings: Finding, checks=None) -> ScanResult:
    result = ScanResult("Shop", T0.isoformat(), findings=list(findings))
    groups = checks if checks is not None else {(f.group, f.target) for f in findings}
    result.checks = [CheckRun(g, t, ok=True) for g, t in groups]
    return result


class StatePlanTest(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp()) / "state.json"
        self.remind = timedelta(days=7)

    def cycle(self, result, now, emailed=True):
        state = State.load(self.path)
        plan = state.plan(result, Severity.HIGH, self.remind, now)
        state.commit(result, plan, now, emailed=emailed)
        state.save()
        return plan

    def test_alert_once_then_remind(self):
        f = finding()
        self.assertEqual([x.id for x in self.cycle(result_with(f), T0).new], [f.id])
        quiet = self.cycle(result_with(finding()), T0 + timedelta(hours=6))
        self.assertFalse(quiet.should_send)
        reminder = self.cycle(result_with(finding()), T0 + timedelta(days=8))
        self.assertEqual([x.id for x in reminder.reminders], [f.id])

    def test_not_marked_notified_unless_the_email_went_out(self):
        self.cycle(result_with(finding()), T0, emailed=False)
        self.assertEqual(len(self.cycle(result_with(finding()), T0 + timedelta(hours=1)).new), 1)

    def test_escalation(self):
        self.cycle(result_with(finding(severity=Severity.HIGH)), T0)
        plan = self.cycle(result_with(finding(severity=Severity.CRITICAL)), T0 + timedelta(hours=1))
        self.assertEqual(len(plan.escalated), 1)

    def test_minor_findings_never_alert(self):
        plan = self.cycle(result_with(finding(severity=Severity.MEDIUM)), T0)
        self.assertFalse(plan.should_send)

    def test_resolved_only_when_the_check_completed(self):
        f = finding()
        self.cycle(result_with(f), T0)
        failed = ScanResult("Shop", "t")
        failed.checks = [CheckRun(f.group, f.target, ok=False, detail="timed out")]
        self.assertEqual(self.cycle(failed, T0 + timedelta(hours=1)).resolved, [])
        fixed = result_with(checks={(f.group, f.target)})
        plan = self.cycle(fixed, T0 + timedelta(hours=2))
        self.assertEqual([r["id"] for r in plan.resolved], [f.id])
        again = self.cycle(result_with(finding()), T0 + timedelta(hours=3))  # regression
        self.assertEqual([x.id for x in again.new], [f.id])

    def test_agent_suppression_is_announced_once(self):
        f = finding(severity=Severity.LOW, status="false_positive")
        result = result_with(f)
        result.suppressed_major = [f.id]
        self.assertEqual([x.id for x in self.cycle(result, T0).suppressed], [f.id])
        result.suppressed_major = [f.id]
        self.assertEqual(self.cycle(result, T0 + timedelta(hours=1)).suppressed, [])

    def test_corrupt_state_is_set_aside(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("{not json", encoding="utf-8")
        state = State.load(self.path)
        self.assertEqual(state.records, {})
        self.assertIn("unreadable", state.notes[0])
        self.assertTrue(any(p.name.startswith("state.json.corrupt-") for p in self.path.parent.iterdir()))


class EmailTest(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.repo = self.folder / "repo"
        self.repo.mkdir()

    def config(self, port):
        return load_config(write_config(self.folder, repos=[self.repo], smtp_port=port))

    def test_content_is_escaped_and_redacted(self):
        secret = "ghp_" + hexs(36)
        f = finding(
            title="<script>alert(1)</script> exposed",
            evidence=f"token {secret}".replace(secret, "ghp_...[redacted 40 chars]"),
            remediation="Block /.git in the web server.",
        )
        result = result_with(f)
        state = State(self.folder / "s.json")
        plan = state.plan(result, Severity.HIGH, timedelta(days=7), T0)
        msg = build_email(self.config(25), result, plan, self.folder / "report.html", T0)
        self.assertEqual(msg["Subject"], "[Sentinel] Test shop: 1 critical security finding(s) need attention")
        html = msg.get_body(preferencelist=("html",)).get_content()
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn(secret, msg.as_string())
        self.assertIn("Fix:", msg.get_body(preferencelist=("plain",)).get_content())

    def test_delivery_with_login(self):
        with smtp_server() as smtp:
            cfg = self.config(smtp.port)
            msg = build_email(cfg, result_with(finding()), State(self.folder / "s").plan(result_with(finding()), Severity.HIGH, timedelta(days=7), T0), None, T0)
            env = {"SENTINEL_TEST_SMTP_USER": "alerts@shop.example", "SENTINEL_TEST_SMTP_PASSWORD": "app-password"}
            with mock.patch.dict(os.environ, env):
                send_email(msg, cfg.notify.email, timeout=5)
        self.assertEqual(len(smtp.box.messages), 1)
        self.assertEqual(smtp.box.auth, [[b"", b"alerts@shop.example", b"app-password"]])
        received = email.message_from_bytes(smtp.box.messages[0]["data"], policy=policy.default)
        self.assertTrue(received["Subject"].startswith("[Sentinel] Test shop"))

    def test_rejected_recipient_raises(self):
        with smtp_server(reject_rcpt=True) as smtp:
            cfg = self.config(smtp.port)
            msg = build_email(cfg, result_with(finding()), State(self.folder / "s").plan(result_with(finding()), Severity.HIGH, timedelta(days=7), T0), None, T0)
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SENTINEL_TEST_SMTP_USER", None)
                with self.assertRaises(NotifyError):
                    send_email(msg, cfg.notify.email, timeout=5)

    def test_unreachable_server_raises(self):
        with smtp_server() as smtp:
            port = smtp.port
        cfg = self.config(port)  # server is now closed
        with self.assertRaises(NotifyError):
            send_email(build_email(cfg, result_with(), State(self.folder / "s").plan(result_with(), Severity.HIGH, timedelta(days=7), T0), None, T0), cfg.notify.email, timeout=3)


if __name__ == "__main__":
    unittest.main()
