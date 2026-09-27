import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from sentinel.agent import (
    REPORT_SCHEMA,
    AgentSession,
    apply_report,
    build_tools,
    parse_report,
    run_agent,
)
from sentinel.checks.code import list_repo_files, scan_secrets
from sentinel.config import load_config
from sentinel.demo import LocalSite, make_vulnerable_handler
from sentinel.llm import FALLBACK_BETA
from sentinel.models import AgentOutcome, Finding, ScanResult, Severity
from sentinel.net import HttpClient
from sentinel.scope import Scope

from .helpers import FakeClient, final_message, hexs, identity, make_repo, tool_message, write_config


class AgentTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = LocalSite(make_vulnerable_handler()).__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.site.__exit__(None, None, None)

    def setUp(self):
        self.token = "ghp_" + hexs(36)
        self.root = make_repo(
            {
                "app/config.py": f'GITHUB_TOKEN = "{self.token}"\nDEBUG = True\n',
                "app/views.py": "def index():\n    return 'ok'\n",
            }
        )
        self.scope = Scope([self.site.url], repos=[self.root])
        self.label = next(iter(self.scope.repos))
        self.files = {self.label: list_repo_files(self.label, self.root)}
        self.result = ScanResult("Shop", "now", findings=scan_secrets(self.files[self.label]))
        self.session = AgentSession(self.result, self.scope, HttpClient(self.scope, delay_s=0, max_requests=5), self.files, None)
        self.tools = {fn.__name__: fn for fn in build_tools(self.session)}


class ToolTest(AgentTestBase):
    def test_file_tools_redact_and_stay_in_scope(self):
        out = self.tools["read_file"](self.label, "app/config.py")
        self.assertNotIn(self.token, out)
        self.assertIn("ghp_...[redacted", out)
        self.assertIn("ERROR", self.tools["read_file"](self.label, "../outside.py"))
        self.assertIn("ERROR", self.tools["read_file"]("other-repo", "app/config.py"))
        self.assertIn("ERROR", self.tools["read_file"](self.label, "app/missing.py"))
        self.assertIn("lines 1-2", self.tools["read_file"](self.label, "app/config.py:2"))  # finding locations work

    def test_search_runs_over_redacted_text(self):
        middle = self.token[10:30]
        self.assertTrue(self.tools["search_code"](self.label, middle).startswith("0 match"))
        hit = self.tools["search_code"](self.label, r"GITHUB_\w+", "*.py")
        self.assertIn("app/config.py:1", hit)
        self.assertNotIn(self.token, hit)
        self.assertIn("nested quantifiers", self.tools["search_code"](self.label, r"(a+)+$"))

    def test_http_tool_scope_budget_and_cookie_values(self):
        out = self.tools["http_get"](self.site.url)
        self.assertIn("-> 200", out)
        self.assertIn("sessionid=<value hidden>", out)
        self.assertIn("ERROR", self.tools["http_get"]("http://example.com/"))
        for _ in range(6):
            last = self.tools["http_get"](self.site.url)
        self.assertIn("ERROR: request budget of 5 is spent", last)

    def test_run_web_check_adds_findings(self):
        before = len(self.result.findings)
        out = self.tools["run_web_check"]("cors", self.site.url + "api/admin/users")
        self.assertIn("CORS allows any origin with credentials", out)
        self.assertEqual(len(self.result.findings), before + 1)
        self.assertEqual(self.result.checks[-1].group, "web.cors")

    def test_finding_tools(self):
        fid = self.result.findings[0].id
        self.assertIn(fid, self.tools["list_findings"]("critical"))
        self.assertIn("scanner remediation", self.tools["get_finding"](f"[{fid}]"))
        self.assertIn("ERROR", self.tools["get_finding"]("nope"))


class SchemaTest(unittest.TestCase):
    def test_every_object_is_closed_and_fully_required(self):
        def walk(node):
            if isinstance(node, dict):
                if node.get("type") == "object":
                    self.assertIs(node.get("additionalProperties"), False)
                    self.assertEqual(set(node["required"]), set(node["properties"]))
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(REPORT_SCHEMA)


class ReportMergeTest(unittest.TestCase):
    def test_parse_tolerates_prose_and_drops_junk(self):
        text = 'Here you go:\n{"summary": "ok", "verdicts": [{"finding_ids": ["abc"], "status": "confirmed", "severity": "high", "rationale": "r", "remediation": ""}, {"finding_ids": ["x"], "status": "maybe", "severity": "high"}], "new_findings": [], "risk_chains": []}'
        report = parse_report(text)
        self.assertEqual(len(report["verdicts"]), 1)
        with self.assertRaises(ValueError):
            parse_report("no json here")

    def test_apply_marks_suppressed_majors(self):
        major = Finding("web.exposure.git", "Git exposed", Severity.CRITICAL, "web", "https://s")
        minor = Finding("web.headers.csp_missing", "No CSP", Severity.MEDIUM, "web", "https://s")
        result = ScanResult("Shop", "now", findings=[major, minor])
        report = {
            "summary": "Summary.",
            "verdicts": [
                {"finding_ids": [major.id], "status": "false_positive", "severity": Severity.INFO, "rationale": "static decoy file", "remediation": ""},
                {"finding_ids": [minor.id, "unknown-id"], "status": "confirmed", "severity": Severity.HIGH, "rationale": "login page", "remediation": "Add a CSP."},
            ],
            "new_findings": [
                {"title": "Unauthenticated admin API", "severity": Severity.CRITICAL, "category": "web", "target": "https://s", "location": "https://s/api/admin/users", "evidence": f"token ghp_{hexs(36)}", "description": "d", "remediation": "r"}
            ],
            "risk_chains": ["a + b"],
        }
        outcome = AgentOutcome(ran=True)
        apply_report(result, report, Severity.HIGH, outcome)
        self.assertEqual(result.suppressed_major, [major.id])
        self.assertEqual(major.original_severity, Severity.CRITICAL)
        self.assertEqual(minor.severity, Severity.HIGH)
        self.assertEqual(minor.remediation, "Add a CSP.")
        self.assertEqual(outcome.verdicts_applied, 2)
        self.assertEqual(outcome.new_findings, 1)
        self.assertTrue(any("unknown-id" in n for n in outcome.notes))
        added = result.findings[-1]
        self.assertEqual((added.source, added.status), ("agent", "confirmed"))
        self.assertIn("[redacted", added.evidence)


class RunAgentTest(AgentTestBase):
    def config(self):
        folder = Path(tempfile.mkdtemp())
        return load_config(write_config(folder, urls=[self.site.url], repos=[self.root]))

    def report_for(self, fid, status="confirmed", severity="critical"):
        return {
            "summary": "One committed GitHub token.",
            "verdicts": [{"finding_ids": [fid], "status": status, "severity": severity, "rationale": "real token format in app code", "remediation": "Revoke it."}],
            "new_findings": [],
            "risk_chains": [],
        }

    def test_tool_loop_and_verdicts(self):
        fid = self.result.findings[0].id
        client = FakeClient([
            tool_message(("get_finding", {"finding_id": fid}), ("read_file", {"repo": self.label, "path": "app/config.py"})),
            final_message(self.report_for(fid)),
        ])
        transcript = Path(tempfile.mkdtemp()) / "t.md"
        outcome = run_agent(self.result, scope=self.scope, repos=self.files, osv=None, config=self.config(), client=client, wrap_tool=identity, transcript_path=transcript, say=lambda _l: None)
        self.assertTrue(outcome.ok, outcome.error)
        self.assertEqual((outcome.turns, outcome.tool_calls, outcome.verdicts_applied), (2, 2, 1))
        self.assertEqual(self.result.by_id()[fid].status, "confirmed")
        self.assertEqual([name for name, _args, _out in client.tool_log], ["get_finding", "read_file"])
        request = client.calls[0]
        self.assertEqual(request["model"], "claude-opus-5")
        self.assertEqual(request["thinking"], {"type": "adaptive"})
        self.assertEqual(request["output_config"]["format"]["type"], "json_schema")
        self.assertEqual(request["betas"], [FALLBACK_BETA])
        self.assertEqual(request["fallbacks"], "default")
        text = transcript.read_text(encoding="utf-8")
        self.assertIn("read_file", text)
        self.assertNotIn(self.token, text)

    def test_refusal_leaves_scanner_results_untouched(self):
        fid = self.result.findings[0].id
        before = self.result.by_id()[fid].severity
        client = FakeClient([final_message("", stop_reason="refusal", stop_details=SimpleNamespace(category="cyber"))])
        outcome = run_agent(self.result, scope=self.scope, repos=self.files, osv=None, config=self.config(), client=client, wrap_tool=identity, say=lambda _l: None)
        self.assertFalse(outcome.ok)
        self.assertIn("cyber", outcome.error)
        self.assertEqual(self.result.by_id()[fid].severity, before)
        self.assertEqual(self.result.by_id()[fid].status, "open")

    def test_max_tokens_stops_before_running_the_tool(self):
        client = FakeClient([tool_message(("list_findings", {}), stop_reason="max_tokens")])
        outcome = run_agent(self.result, scope=self.scope, repos=self.files, osv=None, config=self.config(), client=client, wrap_tool=identity, say=lambda _l: None)
        self.assertIn("max_tokens", outcome.error)
        self.assertEqual(client.tool_log, [])

    def test_unsupported_fallbacks_are_dropped_and_retried(self):
        fid = self.result.findings[0].id
        client = FakeClient([final_message(self.report_for(fid))], fail_first=TypeError("tool_runner() got an unexpected keyword argument 'fallbacks'"))
        outcome = run_agent(self.result, scope=self.scope, repos=self.files, osv=None, config=self.config(), client=client, wrap_tool=identity, say=lambda _l: None)
        self.assertTrue(outcome.ok, outcome.error)
        self.assertNotIn("fallbacks", client.calls[1])
        self.assertTrue(any("dropped fallbacks" in n for n in outcome.notes))

    def test_garbage_output_is_an_error_not_a_crash(self):
        client = FakeClient([final_message("I could not finish.")])
        outcome = run_agent(self.result, scope=self.scope, repos=self.files, osv=None, config=self.config(), client=client, wrap_tool=identity, say=lambda _l: None)
        self.assertFalse(outcome.ok)
        self.assertIn("not JSON", outcome.error)


if __name__ == "__main__":
    unittest.main()
