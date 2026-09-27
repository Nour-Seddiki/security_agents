import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinel.agent_cli import _brief, build_workspace, child_env, run_claude_code_agent
from sentinel.checks.code import list_repo_files, scan_secrets
from sentinel.config import ConfigError, load_config
from sentinel.models import ScanResult, Severity
from sentinel.pipeline import RunOptions, run_scan
from sentinel.scope import Scope
from sentinel.triage import baseline_triage

from .helpers import hexs, make_repo, write_config

FAKE_CLI = [sys.executable, str(Path(__file__).with_name("fake_claude.py"))]
QUIET = lambda _line: None  # noqa: E731


class ChildEnvTest(unittest.TestCase):
    def test_session_and_api_variables_are_dropped(self):
        env = child_env(
            {
                "PATH": "p",
                "CLAUDECODE": "1",
                "CLAUDE_CODE_SESSION_ID": "s",
                "CLAUDE_CODE_ENTRYPOINT": "desktop",
                "ANTHROPIC_API_KEY": "k",
                "ANTHROPIC_BASE_URL": "u",
                "CLAUDE_CODE_OAUTH_TOKEN": "t",
                "CLAUDE_CONFIG_DIR": "c",
            }
        )
        self.assertEqual(env, {"PATH": "p", "CLAUDE_CODE_OAUTH_TOKEN": "t", "CLAUDE_CONFIG_DIR": "c"})

    def test_progress_shows_workspace_relative_paths(self):
        ws = r"C:\Temp\sentinel-agent-x"
        self.assertEqual(_brief({"file_path": ws + r"\repos\shop\app.py"}, ws), "file_path=repos/shop/app.py")
        self.assertEqual(_brief({"path": ws, "pattern": "PIL|Image"}, ws), "path=., pattern=PIL|Image")


class ClaudeCodeAgentTest(unittest.TestCase):
    def setUp(self):
        self.token = "ghp_" + hexs(36)
        self.root = make_repo(
            {
                "app/admin.js": 'row.innerHTML = `<img src="${u.avatar_url}">`;\n',
                "app/config.py": f'GITHUB_TOKEN = "{self.token}"\n',
            }
        )
        self.folder = Path(tempfile.mkdtemp(prefix="sentinel-cc-"))
        path = write_config(self.folder, repos=[self.root], extra='\n[agent]\nbackend = "claude-code"\ntimeout_s = 60\n')
        self.config = load_config(path)
        self.scope = Scope.from_config(self.config)
        self.label = next(iter(self.scope.repos))
        self.repos = {self.label: list_repo_files(self.label, self.root)}
        self.result = ScanResult("Test shop", "now", findings=scan_secrets(self.repos[self.label]))
        baseline_triage(self.result)
        self.transcript = self.folder / "agent_transcript.md"

    def run_agent(self, mode="ok", **env):
        with mock.patch.dict(os.environ, {"FAKE_CLAUDE_MODE": mode, "FAKE_CLAUDE_SECRET": self.token, **env}):
            return run_claude_code_agent(
                self.result, scope=self.scope, repos=self.repos, osv=None, config=self.config,
                command=FAKE_CLI, transcript_path=self.transcript, say=QUIET,
            )

    def test_verdicts_and_new_findings_are_merged(self):
        token_finding = self.result.findings[0]
        # Variables of an enclosing Claude Code session must not reach the CLI.
        outcome = self.run_agent(CLAUDECODE="1", CLAUDE_CODE_SESSION_ID="x", ANTHROPIC_API_KEY="sk-test")
        self.assertTrue(outcome.ok, outcome.error)
        self.assertEqual((outcome.turns, outcome.tool_calls), (3, 1))
        self.assertEqual(outcome.summary, "Fake analyst summary.")
        self.assertEqual(token_finding.status, "confirmed")
        added = [f for f in self.result.findings if f.source == "agent"]
        self.assertEqual(len(added), 1)
        self.assertEqual((added[0].target, added[0].location), (self.label, "app/admin.js:1"))
        self.assertTrue(any("usage limits" in note for note in outcome.notes))
        text = self.transcript.read_text(encoding="utf-8")
        self.assertIn("### Read(", text)
        self.assertNotIn(self.token, text)

    def test_cli_error_leaves_scanner_results_alone(self):
        before = [(f.id, f.severity, f.status) for f in self.result.findings]
        outcome = self.run_agent("error")
        self.assertFalse(outcome.ok)
        self.assertIn("usage limit reached", outcome.error)
        self.assertEqual([(f.id, f.severity, f.status) for f in self.result.findings], before)

    def test_crash_reports_stderr(self):
        outcome = self.run_agent("crash")
        self.assertFalse(outcome.ok)
        self.assertIn("boom", outcome.error)

    def test_timeout(self):
        self.config.agent.timeout_s = 3
        outcome = self.run_agent("sleep")
        self.assertIn("did not finish", outcome.error)

    def test_missing_cli(self):
        self.config.agent.claude_code_path = str(self.folder / "missing" / "claude.exe")
        outcome = run_claude_code_agent(
            self.result, scope=self.scope, repos=self.repos, osv=None, config=self.config, say=QUIET
        )
        self.assertIn("not found", outcome.error)

    def test_workspace_is_redacted(self):
        ws = Path(tempfile.mkdtemp())
        stats = build_workspace(ws, self.result, self.repos, osv=None)
        self.assertEqual(stats["files"], 2)
        copied = (ws / "repos" / self.label / "app" / "config.py").read_text(encoding="utf-8")
        self.assertNotIn(self.token, copied)
        self.assertIn("ghp_...[redacted", copied)
        self.assertIn(f"repos/{self.label}/app/config.py:1", (ws / "FINDINGS.md").read_text(encoding="utf-8"))

    def test_backend_setting_is_validated(self):
        path = write_config(self.folder, repos=[self.root], extra='\n[agent]\nbackend = "chatgpt"\n')
        with self.assertRaisesRegex(ConfigError, "backend"):
            load_config(path)

    def test_pipeline_uses_the_claude_code_backend(self):
        with mock.patch.dict(os.environ, {"FAKE_CLAUDE_SECRET": self.token}):
            outcome = run_scan(self.config, RunOptions(parts=("code",)), agent_command=FAKE_CLI, say=QUIET)
        agent = outcome.result.agent
        self.assertTrue(agent.ok, agent.error)
        self.assertEqual(agent.model, "claude-code")
        self.assertTrue((outcome.run_dir / "agent_transcript.md").is_file())
        self.assertIn(Severity.HIGH, {f.severity for f in outcome.result.findings if f.source == "agent"})


if __name__ == "__main__":
    unittest.main()
