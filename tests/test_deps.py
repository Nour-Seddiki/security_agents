import json
import unittest

from sentinel.checks import CheckIncomplete, CheckSkipped
from sentinel.checks.deps import (
    OsvClient,
    Package,
    cvss3_base_score,
    osv_severity,
    parse_package_lock,
    parse_pipfile_lock,
    parse_requirements,
    parse_toml_lock,
    recommended_fix,
    scan_dependencies,
    version_key,
)
from sentinel.models import Severity

from .helpers import osv_server, repo_files


def advisory(vid, name, fixed, severity=None, aliases=(), vector=None, withdrawn=None, ecosystem="PyPI"):
    data = {
        "id": vid,
        "summary": f"{name} issue {vid}",
        "details": "Longer description.",
        "aliases": list(aliases),
        "affected": [{"package": {"ecosystem": ecosystem, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, *({"fixed": f} for f in fixed)]}]}],
    }
    if severity:
        data["database_specific"] = {"severity": severity}
    if vector:
        data["severity"] = [{"type": "CVSS_V3", "score": vector}]
    if withdrawn:
        data["withdrawn"] = withdrawn
    return data


class ParserTest(unittest.TestCase):
    def test_requirements(self):
        text = (
            "# comment\n"
            "Django==3.2.0  # pinned\n"
            "requests[socks]==2.19.0 ; python_version >= '3.8'\n"
            "PyYAML===5.3 \\\n"
            "    --hash=sha256:abc\n"
            "flask>=2.0\n"
            "numpy\n"
            "-r other.txt\n"
            "git+https://github.com/x/y.git\n"
        )
        pinned, loose = parse_requirements(text)
        self.assertEqual(pinned, [("django", "3.2.0"), ("requests", "2.19.0"), ("pyyaml", "5.3")])
        self.assertEqual(loose, ["flask", "numpy"])

    def test_toml_locks_skip_the_project_itself(self):
        text = '[[package]]\nname = "Django"\nversion = "4.2.1"\n\n[[package]]\nname = "myapp"\nversion = "0.1.0"\nsource = { editable = "." }\n'
        self.assertEqual(parse_toml_lock(text), [("django", "4.2.1")])

    def test_package_lock_v3_and_v1(self):
        v3 = {"lockfileVersion": 3, "packages": {"": {"name": "app"}, "node_modules/lodash": {"version": "4.17.20"}, "node_modules/@scope/pkg": {"version": "1.0.0"}, "node_modules/a/node_modules/b": {"version": "2.0.0"}, "node_modules/local": {"link": True}}}
        self.assertEqual(sorted(parse_package_lock(json.dumps(v3))), [("@scope/pkg", "1.0.0"), ("b", "2.0.0"), ("lodash", "4.17.20")])
        v1 = {"lockfileVersion": 1, "dependencies": {"x": {"version": "1.0.0", "dependencies": {"y": {"version": "2.0.0"}}}, "z": {"version": "file:../z"}}}
        self.assertEqual(sorted(parse_package_lock(json.dumps(v1))), [("x", "1.0.0"), ("y", "2.0.0")])

    def test_pipfile_lock(self):
        text = json.dumps({"default": {"Flask": {"version": "==2.0.1"}}, "develop": {"pytest": {"version": "==7.0.0"}}})
        self.assertEqual(parse_pipfile_lock(text), [("flask", "2.0.1"), ("pytest", "7.0.0")])


class SeverityTest(unittest.TestCase):
    def test_cvss31_reference_scores(self):
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 7.8)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)
        self.assertIsNone(cvss3_base_score("not a vector"))

    def test_osv_severity_sources(self):
        self.assertEqual(osv_severity({"database_specific": {"severity": "MODERATE"}})[0], Severity.MEDIUM)
        self.assertEqual(osv_severity({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}), (Severity.CRITICAL, "CVSS 9.8"))
        self.assertEqual(osv_severity({})[0], Severity.MEDIUM)

    def test_versions(self):
        self.assertLess(version_key("1.0.0rc1"), version_key("1.0.0"))
        self.assertLess(version_key("2.9.9"), version_key("2.10.0"))
        self.assertEqual(recommended_fix("3.2.0", ["2.2.28", "3.2.19", "4.0.1"]), "3.2.19")
        self.assertIsNone(recommended_fix("5.0", ["4.0.1"]))


class OsvScanTest(unittest.TestCase):
    def setUp(self):
        self.files = repo_files({"requirements.txt": "django==3.2.0\npyyaml==5.3\nflask\n", "web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.20"}}})})

    def test_findings_are_deduplicated_across_aliases(self):
        vulns = {("django", "3.2.0"): ["PYSEC-2021-1", "GHSA-aaaa", "GHSA-old"], ("pyyaml", "5.3"): ["GHSA-yaml"], ("lodash", "4.17.20"): ["GHSA-lodash"]}
        details = {
            "GHSA-aaaa": advisory("GHSA-aaaa", "django", ["3.2.19", "4.0.1"], "HIGH", aliases=["CVE-2021-1"]),
            "PYSEC-2021-1": advisory("PYSEC-2021-1", "django", ["3.2.19"], aliases=["CVE-2021-1", "GHSA-aaaa"]),
            "GHSA-old": advisory("GHSA-old", "django", ["3.2.1"], "LOW", withdrawn="2022-01-01T00:00:00Z"),
            "GHSA-yaml": advisory("GHSA-yaml", "PyYAML", ["5.4"], vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "GHSA-lodash": advisory("GHSA-lodash", "lodash", ["4.17.21"], "HIGH", ecosystem="npm"),
        }
        with osv_server(vulns, details) as osv:
            client = OsvClient(f"http://127.0.0.1:{osv.port}", timeout_s=5)
            findings = scan_dependencies(self.files, client)
        vulnerable = {f.evidence.split(";")[0].split(" ")[0]: f for f in findings if f.check_id == "deps.osv.vulnerable"}
        self.assertEqual(set(vulnerable), {"GHSA-aaaa", "GHSA-yaml", "GHSA-lodash"})
        self.assertEqual(vulnerable["GHSA-aaaa"].severity, Severity.HIGH)
        self.assertIn("to 3.2.19 or later", vulnerable["GHSA-aaaa"].remediation)
        self.assertEqual(vulnerable["GHSA-yaml"].severity, Severity.CRITICAL)
        self.assertIn("lodash@4.17.20", vulnerable["GHSA-lodash"].location)
        unpinned = [f for f in findings if f.check_id == "deps.osv.unpinned"]
        self.assertEqual(len(unpinned), 1)
        self.assertIn("flask", unpinned[0].evidence)

    def test_lookup_failures_keep_what_was_found(self):
        vulns = {("django", "3.2.0"): ["GHSA-aaaa"]}
        with osv_server(vulns, {}, fail_details=True) as osv:
            client = OsvClient(f"http://127.0.0.1:{osv.port}", timeout_s=5)
            client.retry_delay_s = 0
            with self.assertRaises(CheckIncomplete) as ctx:
                scan_dependencies(self.files, client)
        bare = [f for f in ctx.exception.findings if f.check_id == "deps.osv.vulnerable"]
        self.assertEqual(len(bare), 1)
        self.assertEqual(bare[0].confidence, "tentative")

    def test_pagination(self):
        vulns = {("django", "3.2.0"): ["GHSA-aaaa"]}
        details = {"GHSA-aaaa": advisory("GHSA-aaaa", "django", ["3.2.19"], "HIGH"), "GHSA-bbbb": advisory("GHSA-bbbb", "django", ["3.2.5"], "LOW")}
        with osv_server(vulns, details, pages={("django", "3.2.0"): ["GHSA-bbbb"]}) as osv:
            found = OsvClient(f"http://127.0.0.1:{osv.port}", timeout_s=5).query([Package("PyPI", "django", "3.2.0", "requirements.txt")])
        self.assertEqual(list(found.values()), [["GHSA-aaaa", "GHSA-bbbb"]])

    def test_no_manifests_is_skipped(self):
        with self.assertRaises(CheckSkipped):
            scan_dependencies(repo_files({"app.py": "x = 1\n"}), OsvClient("http://127.0.0.1:9"))


if __name__ == "__main__":
    unittest.main()
