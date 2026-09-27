import email
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from email import policy
from pathlib import Path

from sentinel.checks.code import sync_checkout
from sentinel.cli import main
from sentinel.config import ConfigError, load_config
from sentinel.demo import LocalSite, build_sample_repo, make_vulnerable_handler
from sentinel.pipeline import EXIT_MAJOR_FINDINGS, EXIT_NOTIFY_FAILED, RunOptions, run_scan

from .helpers import FakeClient, final_message, hexs, identity, osv_server, smtp_server, write_config

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

    def test_urls_are_normalized_and_fragments_dropped(self):
        path = write_config(
            self.folder,
            urls=["https://App.example.com/#/signin", "https://app.example.com", "https://app.example.com/login?x=1"],
        )
        config = load_config(path)
        self.assertEqual(config.web.urls, ["https://app.example.com/", "https://app.example.com/login?x=1"])
        self.assertTrue(any("#/signin" in note for note in config.notes))

    def test_git_urls_become_checkouts(self):
        checkouts = self.folder / "checkouts"
        path = write_config(self.folder, urls=["https://app.example.com/"])
        remote_repos = (
            "[code]\n"
            "repos = [' https://github.com/Owner/Shop-App/tree/main/src', 'git@gitlab.com:group/api.git']\n"
            f"checkout_dir = '{checkouts.as_posix()}'"
        )
        text = path.read_text(encoding="utf-8").replace("[code]\nrepos = []", remote_repos)
        path.write_text(text, encoding="utf-8")
        config = load_config(path)
        self.assertEqual(
            sorted(config.code.remotes.values()),
            ["git@gitlab.com:group/api.git", "https://github.com/Owner/Shop-App"],  # browser URL trimmed to the repo
        )
        self.assertEqual(
            sorted(p.relative_to(checkouts.resolve()).as_posix() for p in config.code.repos),
            ["github.com/Owner/Shop-App", "gitlab.com/group/api"],
        )
        path.write_text(text.replace("https://github.com/Owner", "https://user:token@github.com/Owner"), encoding="utf-8")
        with self.assertRaisesRegex(ConfigError, "credentials"):
            load_config(path)

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


@unittest.skipUnless(shutil.which("git"), "git not installed")
class RemoteRepoTest(unittest.TestCase):
    def git(self, *args, cwd):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args], cwd=cwd, check=True, capture_output=True)

    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="sentinel-remote-"))
        self.source = self.folder / "source"
        self.source.mkdir()
        self.git("init", "-q", cwd=self.source)
        (self.source / "app.py").write_text("print('v1')\n", encoding="utf-8")
        self.git("add", "-A", cwd=self.source)
        self.git("commit", "-q", "-m", "v1", cwd=self.source)

    def test_clone_then_update(self):
        dest = self.folder / "checkouts" / "source"
        self.assertEqual(sync_checkout(str(self.source), dest), "cloned")
        self.assertTrue((dest / "app.py").is_file())
        (self.source / "keys.py").write_text(f'TOKEN = "ghp_{hexs(36)}"\n', encoding="utf-8")
        self.git("add", "-A", cwd=self.source)
        self.git("commit", "-q", "-m", "v2", cwd=self.source)
        self.assertEqual(sync_checkout(str(self.source), dest), "updated")
        self.assertTrue((dest / "keys.py").is_file())

    def remote_config(self, dest, url):
        config = load_config(write_config(self.folder, urls=["https://app.example.com/"]))
        config.code.repos = [dest]
        config.code.remotes = {dest: url}
        return config

    def test_unreachable_remote_fails_the_code_checks(self):
        dest = (self.folder / "checkouts" / "missing").resolve()
        config = self.remote_config(dest, str(self.folder / "does-not-exist"))
        outcome = run_scan(config, RunOptions(dry_run=True, parts=("code",)), now=T0, say=QUIET)
        states = {c.group: (c.state, c.detail) for c in outcome.result.checks}
        self.assertEqual(states["code.secrets"][0], "error")
        self.assertIn("could not fetch", states["code.secrets"][1])

    def test_scan_clones_and_scans_the_remote(self):
        (self.source / "keys.py").write_text(f'TOKEN = "ghp_{hexs(36)}"\n', encoding="utf-8")
        self.git("add", "-A", cwd=self.source)
        self.git("commit", "-q", "-m", "v2", cwd=self.source)
        dest = (self.folder / "checkouts" / "source").resolve()
        config = self.remote_config(dest, str(self.source))
        outcome = run_scan(config, RunOptions(dry_run=True, parts=("code",)), now=T0, say=QUIET)
        self.assertIn("code.secrets.github_token", {f.check_id for f in outcome.result.findings})
        self.assertTrue((dest / ".git").exists())


if __name__ == "__main__":
    unittest.main()
