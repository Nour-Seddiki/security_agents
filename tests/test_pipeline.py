import email
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from email import policy
from pathlib import Path

from sentinel.cli import main
from sentinel.config import ConfigError, load_config
from sentinel.demo import LocalSite, build_sample_repo, make_vulnerable_handler
from sentinel.pipeline import EXIT_MAJOR_FINDINGS, EXIT_NOTIFY_FAILED, RunOptions, run_scan

from .helpers import FakeClient, final_message, identity, osv_server, smtp_server, write_config

T0 = datetime(2026, 9, 1, 2, 0, tzinfo=timezone.utc)
QUIET = lambda _line: None  # noqa: E731

DJANGO = {
    "id": "GHSA-demo-django",
    "summary": "SQL injection in QuerySet.order_by",
    "aliases": ["CVE-2021-35042"],
    "database_specific": {"severity": "CRITICAL"},
    "affected": [{"package": {"ecosystem": "PyPI", "name": "django"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.2.0"}, {"fixed": "3.2.5"}]}]}],
}


class PipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = LocalSite(make_vulnerable_handler()).__enter__()
        cls.osv = osv_server({("django", "3.2.0"): ["GHSA-demo-django"]}, {"GHSA-demo-django": DJANGO}).__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.site.__exit__(None, None, None)
        cls.osv.__exit__(None, None, None)

    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="sentinel-pipe-"))
        self.repo = build_sample_repo(self.folder / "repo", use_git=False)

    def config(self, smtp_port=None, **kwargs):
        path = write_config(
            self.folder,
            urls=[self.site.url],
            repos=[self.repo],
            osv_api=f"http://127.0.0.1:{self.osv.port}",
            smtp_port=smtp_port,
            **kwargs,
        )
        return load_config(path)

    def test_dry_run_saves_the_alert_and_leaves_state_alone(self):
        config = self.config(smtp_port=9)
        outcome = run_scan(config, RunOptions(dry_run=True), now=T0, say=QUIET)
        self.assertEqual(outcome.exit_code, EXIT_MAJOR_FINDINGS)
        self.assertIn("dry run", outcome.email_status)
        self.assertFalse(config.state_file.exists())
        self.assertEqual(len(list(config.outbox_dir.glob("*.eml"))), 1)
        report = json.loads(outcome.reports["json"].read_text(encoding="utf-8"))
        checks = {c["group"]: c["state"] for c in report["checks"]}
        self.assertEqual(checks["deps.osv"], "ok")
        titles = [f["title"] for f in report["findings"]]
        self.assertTrue(any("django 3.2.0" in t for t in titles))
        self.assertTrue(any("Git repository exposed" in t for t in titles))
        self.assertIn("<html", outcome.reports["html"].read_text(encoding="utf-8"))
        # the whole report is free of the sample repository's secrets
        payments = (self.repo / "app/payments.py").read_text(encoding="utf-8").split('"')[1]
        self.assertNotIn(payments, outcome.reports["json"].read_text(encoding="utf-8"))

    def test_alerts_once_reminds_later_and_reports_fixes(self):
        with smtp_server() as smtp:
            config = self.config(smtp_port=smtp.port)
            options = RunOptions(use_agent=False)
            first = run_scan(config, options, now=T0, say=QUIET)
            self.assertEqual(len(smtp.box.messages), 1, first.email_status)
            self.assertTrue(first.plan.new)

            second = run_scan(config, options, now=T0 + timedelta(hours=6), say=QUIET)
            self.assertEqual(len(smtp.box.messages), 1, "nothing new: no second email")
            self.assertEqual(second.email_status, "nothing new to report")

            (self.repo / "app/payments.py").write_text("import os\nSTRIPE_API_KEY = os.environ['STRIPE_API_KEY']\n", encoding="utf-8")
            third = run_scan(config, options, now=T0 + timedelta(days=8), say=QUIET)
            self.assertEqual(len(smtp.box.messages), 2)
            message = email.message_from_bytes(smtp.box.messages[1]["data"], policy=policy.default)
            self.assertIn("reminder", message["Subject"])
            self.assertTrue(any("Stripe" in r["title"] for r in third.plan.resolved))
            body = message.get_body(preferencelist=("plain",)).get_content()
            self.assertIn("FIXED SINCE THE LAST ALERT", body)

    def test_failed_delivery_is_retried_next_run(self):
        with smtp_server() as dead:
            dead_port = dead.port
        config = self.config(smtp_port=dead_port)
        outcome = run_scan(config, RunOptions(use_agent=False), now=T0, say=QUIET)
        self.assertEqual(outcome.exit_code, EXIT_NOTIFY_FAILED)
        self.assertIn("FAILED", outcome.email_status)
        with smtp_server() as smtp:
            config = self.config(smtp_port=smtp.port)
            retry = run_scan(config, RunOptions(use_agent=False), now=T0 + timedelta(hours=1), say=QUIET)
            self.assertEqual(len(smtp.box.messages), 1)
            self.assertTrue(retry.plan.new)

    def test_agent_dismissal_is_flagged_to_the_admin(self):
        with smtp_server() as smtp:
            config = self.config(smtp_port=smtp.port)
            # The agent dismisses the exposed .git finding; the admin must still hear about
            # it. Finding ids only exist after scanning, so the fake runner looks the id up
            # through the agent's own list_findings tool.
            client = FakeClient([])
            outcome_holder = {}

            def tool_runner(**kwargs):
                client.calls.append(kwargs)
                tools = {fn.__name__: fn for fn in kwargs["tools"]}
                listing = tools["list_findings"]("critical", "web")
                git_id = next(line.split("]")[0][1:] for line in listing.splitlines() if "Git repository" in line)
                outcome_holder["git_id"] = git_id
                report = {
                    "summary": "The .git exposure is a decoy directory.",
                    "verdicts": [{"finding_ids": [git_id], "status": "false_positive", "severity": "info", "rationale": "decoy", "remediation": ""}],
                    "new_findings": [],
                    "risk_chains": [],
                }
                return iter([final_message(report)])

            client.beta.messages.tool_runner = tool_runner
            outcome = run_scan(config, RunOptions(), client=client, wrap_tool=identity, now=T0, say=QUIET)
            self.assertTrue(outcome.result.agent.ok, outcome.result.agent.error)
            self.assertEqual([f.id for f in outcome.plan.suppressed], [outcome_holder["git_id"]])
            message = email.message_from_bytes(smtp.box.messages[0]["data"], policy=policy.default)
            body = message.get_body(preferencelist=("plain",)).get_content()
            self.assertIn("DOWNGRADED OR DISMISSED BY AI TRIAGE", body)
            self.assertIn("decoy", body)
            self.assertTrue((outcome.run_dir / "agent_transcript.md").is_file())


class ConfigAndCliTest(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="sentinel-cfg-"))
        (self.folder / "repo").mkdir()

    def test_unknown_keys_and_bad_values_are_errors(self):
        path = write_config(self.folder, repos=[self.folder / "repo"], extra="\n[agent]\nefort = \"high\"\n")
        with self.assertRaisesRegex(ConfigError, "efort"):
            load_config(path)  # typo'd key
        path.write_text('[platform]\nname = "x"\n[notify]\nmin_severty = "high"\n[code]\nrepos = ["repo"]\n', encoding="utf-8")
        with self.assertRaisesRegex(ConfigError, "min_severty"):
            load_config(path)
        path.write_text('[platform]\nname = "x"\n[web]\nurls = ["ftp://x"]\n', encoding="utf-8")
        with self.assertRaisesRegex(ConfigError, "http"):
            load_config(path)
        with self.assertRaisesRegex(ConfigError, "not found"):
            load_config(self.folder / "missing.toml")

    def test_scan_refuses_without_authorization(self):
        path = write_config(self.folder, repos=[self.folder / "repo"], authorized=False)
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["scan", "-c", str(path), "--dry-run"])
        self.assertEqual(code, 2)
        self.assertIn("Refusing to scan", out.getvalue())
        self.assertFalse((self.folder / "reports").exists())

    def test_doctor(self):
        path = write_config(self.folder, repos=[self.folder / "repo"], smtp_port=2525)
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["doctor", "-c", str(path)])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("authorized: yes", text)
        self.assertIn("SENTINEL_TEST_SMTP_PASSWORD", text)


if __name__ == "__main__":
    unittest.main()
