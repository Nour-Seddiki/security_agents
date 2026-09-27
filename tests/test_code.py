import json
import shutil
import subprocess
import unittest

from sentinel.checks.code import (
    analyze_javascript,
    analyze_python,
    find_secrets,
    list_repo_files,
    scan_config,
    scan_python,
    scan_secrets,
)
from sentinel.models import ScanResult, Severity
from sentinel.redact import is_placeholder, mask, redact
from sentinel.triage import baseline_triage

from .helpers import hexs, make_repo, repo_files


AWS_DOCS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documented example, split so scanners stay quiet


def upper16() -> str:
    return "".join("ABCDEF0123456789"[int(c, 16)] for c in hexs(16))


def pem(kind: str = "RSA ") -> tuple[str, str]:
    """PEM armour built at run time, so this file never contains a key header itself."""
    return f"-----BEGIN {kind}" + "PRIVATE KEY-----", f"-----END {kind}" + "PRIVATE KEY-----"


class RedactTest(unittest.TestCase):
    def test_every_rule_value_is_masked(self):
        values = {
            "aws": "AKIA" + upper16(),
            "gh": "ghp_" + hexs(36),
            "stripe": "sk_live_" + hexs(24),
            "anthropic": "sk-ant-api03-" + hexs(40),
            "google": "AIza" + hexs(35),
        }
        text = "\n".join(f'{k}_value = "{v}"' for k, v in values.items())
        cleaned = redact(text)
        for value in values.values():
            self.assertNotIn(value, cleaned)
            self.assertIn(value[:4], cleaned)  # still recognisable

    def test_pem_env_and_auth_header(self):
        body = hexs(64)
        begin, end = pem()
        text = (
            f"{begin}\n{body}\n{body}\n{end}\n"
            f"DB_PASSWORD={hexs(20)}\n"
            f'headers = {{"Authorization": "Bearer {hexs(40)}"}}\n'
        )
        cleaned = redact(text)
        self.assertNotIn(body, cleaned)
        self.assertIn("[private key redacted]", cleaned)
        self.assertNotIn(text.split("DB_PASSWORD=")[1][:20], cleaned)
        self.assertNotIn(text.split("Bearer ")[1][:40], cleaned)

    def test_idempotent_and_placeholders(self):
        text = f'token = "ghp_{hexs(36)}"\npassword = "changeme"\nurl = "postgres://postgres:postgres@localhost/db"'
        once = redact(text)
        self.assertEqual(once, redact(once))
        self.assertIn('password = "changeme"', once)  # placeholders are left readable
        self.assertTrue(is_placeholder("${API_KEY}"))
        self.assertTrue(is_placeholder("your-api-key-here"))
        self.assertTrue(is_placeholder(AWS_DOCS_EXAMPLE_KEY))
        self.assertFalse(is_placeholder(hexs(24)))

    def test_fallback_defaults_are_masked_even_when_they_look_like_placeholders(self):
        default = "dev-" + "insecure-secret-change-me"
        cleaned = redact(f'secret_key = os.getenv("SECRET_KEY", "{default}")')
        self.assertNotIn(default, cleaned)
        self.assertIn("[redacted 29 chars]", cleaned)
        self.assertIn('password = "changeme"', redact('password = "changeme"'))  # ordinary placeholders stay

    def test_mask(self):
        self.assertEqual(mask("short"), "[redacted]")
        self.assertTrue(mask("sk_live_" + "a1" * 12).startswith("sk_l...[redacted 32 chars]"))


class SecretScanTest(unittest.TestCase):
    def test_detects_and_never_echoes_values(self):
        aws, gh, stripe, pw = "AKIA" + upper16(), "ghp_" + hexs(36), "sk_live_" + hexs(24), hexs(14)
        begin, end = pem("OPENSSH ")
        key_material = hexs(70)
        text = (
            f'AWS_ACCESS_KEY_ID = "{aws}"\n'
            f'client = Github("{gh}")\n'
            f'STRIPE_KEY = "{stripe}"\n'
            f'DATABASE_URL = "postgres://app:{pw}@db.internal/app"\n'
            f"{begin}\n{key_material}\n{end}\n"
        )
        findings = find_secrets("repo", "app/config.py", text)
        rules = {f.check_id for f in findings}
        self.assertEqual(
            rules,
            {
                "code.secrets.aws_access_key",
                "code.secrets.github_token",
                "code.secrets.stripe_key",
                "code.secrets.url_credentials",
                "code.secrets.private_key",
            },
        )
        dumped = json.dumps([f.to_dict() for f in findings])
        for value in (aws, gh, stripe, pw, key_material):
            self.assertNotIn(value, dumped)
        self.assertEqual({f.location for f in findings if "aws" in f.check_id}, {"app/config.py:1"})

    def test_private_keys_need_key_material(self):
        begin, end = pem("")
        material = hexs(64)
        self.assertEqual(find_secrets("repo", "docs/keys.md", f"Paste it like:\n{begin}\n...your key...\n{end}\n"), [])
        embedded = '{"type": "service_account", "private_key": "' + begin + "\\n" + material + "\\n" + end + '\\n"}\n'
        findings = find_secrets("repo", "deploy/sa.json", embedded)
        self.assertEqual([f.check_id for f in findings], ["code.secrets.private_key"])
        self.assertNotIn(material, findings[0].evidence)

    def test_templates_are_not_literal_secrets(self):
        text = 'API_KEY = "sk_{env}_{name}"\ndb_password = "%(DB_PASSWORD)s"\n'
        self.assertEqual(find_secrets("repo", "a.py", text), [])

    def test_secret_settings_with_hardcoded_fallbacks(self):
        text = (
            'secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")\n'
            'algorithm = os.getenv("ALGORITHM", "HS256")\n'
            'password = os.environ.get("DB_PASSWORD", "")\n'
        )
        findings = find_secrets("repo", "app/config.py", text)
        self.assertEqual([f.check_id for f in findings], ["code.secrets.secret_fallback"])
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("fail at startup", findings[0].remediation)
        self.assertNotIn("dev-secret-change-me", findings[0].evidence)
        js = find_secrets("repo", "server.js", 'const secret = process.env.JWT_SECRET || "changeme123";\n')
        self.assertEqual([f.check_id for f in js], ["code.secrets.secret_fallback_js"])

    def test_overlapping_rules_report_once(self):
        findings = find_secrets("repo", "settings.py", f'SECRET_KEY = "{hexs(40)}"\n')
        self.assertEqual([f.check_id for f in findings], ["code.secrets.framework_secret_key"])

    def test_placeholders_and_plain_words_are_ignored(self):
        text = (
            'password = "changeme"\n'
            'api_key = "${API_KEY}"\n'
            'API_KEY = "your-api-key-here"\n'
            f'aws = "{AWS_DOCS_EXAMPLE_KEY}"\n'
            'password_reset_url = "/accounts/reset/"\n'
            'token = os.environ["TOKEN"]\n'
        )
        self.assertEqual(find_secrets("repo", "a.py", text), [])

    def test_generic_secret_needs_entropy(self):
        findings = find_secrets("repo", "a.py", 'db_password = "Tr0ub4dor&3xyz"\n')
        self.assertEqual([f.check_id for f in findings], ["code.secrets.generic_secret"])
        self.assertEqual(findings[0].confidence, "tentative")

    def test_ids_are_stable_when_lines_move(self):
        secret = f'TOKEN = "ghp_{hexs(36)}"\n'
        first = find_secrets("repo", "a.py", secret)[0]
        moved = find_secrets("repo", "a.py", "\n\n# comment\n" + secret)[0]
        self.assertEqual(first.id, moved.id)
        self.assertNotEqual(first.location, moved.location)

    def test_operator_scripts_lower_code_patterns_but_not_secrets(self):
        files = repo_files(
            {
                "backend/scripts/migrate.py": 'conn.execute(text(f"ALTER TABLE users ADD COLUMN {name} TEXT"))\n',
                "backend/scripts/deploy.py": f'TOKEN = "ghp_{hexs(36)}"\n',
                "backend/app/api.py": 'conn.execute(text(f"SELECT * FROM t WHERE id = {user_id}"))\n',
            }
        )
        result = ScanResult("t", "now", findings=scan_python(files) + scan_secrets(files))
        baseline_triage(result)
        by_path = {f.location.split(":")[0]: f for f in result.findings}
        self.assertEqual(by_path["backend/scripts/migrate.py"].severity, Severity.MEDIUM)
        self.assertIn("operator script", by_path["backend/scripts/migrate.py"].triage_note)
        self.assertEqual(by_path["backend/app/api.py"].severity, Severity.HIGH)
        self.assertEqual(by_path["backend/scripts/deploy.py"].severity, Severity.CRITICAL)

    def test_test_paths_are_lowered_one_level(self):
        files = repo_files({"tests/test_api.py": f'TOKEN = "ghp_{hexs(36)}"\n', "app/api.py": f'TOKEN = "ghp_{hexs(36)}"\n'})
        result = ScanResult("t", "now", findings=scan_secrets(files))
        baseline_triage(result)
        by_path = {f.location.split(":")[0]: f for f in result.findings}
        self.assertEqual(by_path["app/api.py"].severity, Severity.CRITICAL)
        self.assertEqual(by_path["tests/test_api.py"].severity, Severity.HIGH)
        self.assertEqual(by_path["tests/test_api.py"].original_severity, Severity.CRITICAL)
        self.assertEqual(by_path["tests/test_api.py"].confidence, "tentative")


PY_BAD = """\
import os, pickle, subprocess, ssl, tempfile
import jwt, requests, yaml
from flask import render_template_string
from django.utils.safestring import mark_safe

def bad(cursor, user, host, blob, text, token, key, tpl, html):
    eval(user)
    subprocess.run(f"ping {host}", shell=True)
    os.system("ls " + host)
    cursor.execute(f"SELECT * FROM users WHERE name = '{user}'")
    cursor.execute("DELETE FROM t WHERE id = %s" % user)
    cursor.execute("UPDATE t SET a = {}".format(user))
    pickle.loads(blob)
    yaml.load(text)
    requests.get("https://x", verify=False)
    jwt.decode(token, options={"verify_signature": False})
    jwt.decode(token, key, algorithms=["none"])
    render_template_string(tpl)
    mark_safe(html)
    tempfile.mktemp()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False

if __name__ == "__main__":
    app.run(debug=True)
"""

PY_FINE = """\
import subprocess, yaml, requests

def fine(cursor, user, text):
    eval("1 + 1")
    subprocess.run(["ls", "-l"])
    subprocess.run("ls -l", shell=True)
    cursor.execute("SELECT * FROM users WHERE name = %s", (user,))
    cursor.execute(f"not sql {user}")
    yaml.load(text, Loader=yaml.SafeLoader)
    requests.get("https://x")
"""


class PythonRulesTest(unittest.TestCase):
    def test_rules_fire_on_bad_code(self):
        findings = {f.check_id.rsplit(".", 1)[1]: f for f in analyze_python("repo", "app/views.py", PY_BAD)}
        expected = {
            "eval", "shell_injection", "sql_injection", "pickle", "yaml_load", "tls_verify_off",
            "jwt_no_verify", "template_injection", "mark_safe", "mktemp", "debug_server",
        }
        self.assertEqual(set(findings), expected)
        # one finding per rule per file, listing every line
        sql = findings["sql_injection"]
        self.assertTrue(sql.title.endswith("(3 places)"))  # f-string, % and .format
        self.assertEqual(sql.location, "app/views.py:10")
        self.assertIn("also lines 11, 12", sql.evidence)
        self.assertEqual(findings["shell_injection"].title, "Shell command built from variables (2 places)")

    def test_safe_code_is_quiet(self):
        self.assertEqual(analyze_python("repo", "app/views.py", PY_FINE), [])

    def test_ids_survive_new_occurrences(self):
        one = analyze_python("repo", "a.py", "import pickle\npickle.loads(b)\n")[0]
        two = analyze_python("repo", "a.py", "import pickle\npickle.loads(a)\npickle.loads(b)\n")[0]
        self.assertEqual(one.id, two.id)

    def test_debug_setting_only_in_settings_modules(self):
        self.assertEqual(
            [f.check_id for f in analyze_python("repo", "proj/settings.py", "DEBUG = True\n")],
            ["code.python.debug_setting"],
        )
        self.assertEqual(analyze_python("repo", "proj/views.py", "DEBUG = True\n"), [])

    def test_syntax_errors_are_skipped(self):
        self.assertEqual(analyze_python("repo", "py2.py", "print 'hello'\n"), [])


class JavaScriptRulesTest(unittest.TestCase):
    def test_rules(self):
        js = (
            "const { exec } = require('child_process');\n"
            "exec(`convert ${file} out.png`);\n"
            "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);\n"
            "https.request({ rejectUnauthorized: false });\n"
            "el.innerHTML = userInput;\n"
            "el.innerHTML = '';\n"
            "eval(code);\n"
            "jwt.verify(t, k, { algorithms: ['HS256', 'none'] });\n"
        )
        rules = sorted(f.check_id.rsplit(".", 1)[1] for f in analyze_javascript("repo", "src/app.js", js))
        self.assertEqual(rules, ["command_injection", "dom_xss", "eval", "jwt_none", "sql_injection", "tls_verify_off"])

    def test_regex_exec_is_not_command_injection(self):
        self.assertEqual(analyze_javascript("repo", "a.js", "const m = /a+/.exec(s + t);\n"), [])

    def test_strings_inside_inline_handlers(self):
        js = (
            "row = `<button onclick=\"handleBanUser(${u.id}, '${escapeHtml(name)}')\">Ban</button>`;\n"
            'ok = `<button onclick="handleBanUser(${u.id})">Ban</button>`;\n'
        )
        findings = analyze_javascript("repo", "admin.js", js)
        self.assertEqual([(f.check_id, f.location) for f in findings], [("code.js.inline_handler_string", "admin.js:1")])
        self.assertIn("escapeHtml() does not protect", findings[0].description)

    def test_static_markup_is_not_dom_xss(self):
        js = (
            "tbody.innerHTML = '<tr><td colspan=\"5\"><div class=\"table-empty\">No users found</div></td></tr>';\n"
            'grid.innerHTML = "<div class=\'empty\'>none</div>"; // placeholder\n'
            "box.innerHTML = `<svg fill=\"none\">\n  <path d=\"M4 6h16\"/>\n</svg>`;\n"
            "if (x) { el.innerHTML = ''; return; }\n"
            "row.innerHTML = `<td>${user.name}</td>`;\n"
        )
        findings = analyze_javascript("repo", "admin.js", js)
        self.assertEqual([f.location for f in findings], ["admin.js:7"], [f.evidence for f in findings])


class ConfigRulesTest(unittest.TestCase):
    def test_docker_compose_django_nginx(self):
        files = repo_files(
            {
                "Dockerfile": f"FROM python:3.12\nENV API_KEY={hexs(20)}\nENV DB_PASSWORD=${{DB_PASSWORD}}\n",
                "docker-compose.yml": 'services:\n  db:\n    privileged: true\n    ports:\n      - "5432:5432"\n      - "127.0.0.1:6379:6379"\n',
                "proj/settings.py": "ALLOWED_HOSTS = ['*']\nCORS_ALLOW_ALL_ORIGINS = True\nSESSION_COOKIE_SECURE = False\n",
                "deploy/nginx.conf": "server {\n  autoindex on;\n}\n",
            }
        )
        rules = sorted(f.check_id.rsplit(".", 1)[1] for f in scan_config(files))
        self.assertEqual(
            rules,
            [
                "compose_db_port", "compose_privileged", "cors_allow_all", "django_allowed_hosts",
                "docker_root", "docker_secret", "insecure_cookie", "nginx_autoindex",
            ],
        )

    def test_dockerfile_with_user_is_fine(self):
        files = repo_files({"Dockerfile": "FROM python:3.12\nRUN useradd app\nUSER app\n"})
        self.assertEqual(scan_config(files), [])


@unittest.skipUnless(shutil.which("git"), "git not installed")
class GitListingTest(unittest.TestCase):
    def test_ignored_files_are_skipped_and_env_is_flagged(self):
        root = make_repo(
            {
                ".gitignore": ".env\nbuild/\n",
                ".env": f"DB_PASSWORD={hexs(16)}\n",
                ".env.production": f"DB_PASSWORD={hexs(16)}\n",
                ".env.example": "DB_PASSWORD=changeme\n",
                "build/out.js": "eval(x)\n",
                "node_modules/lib/index.js": "eval(x)\n",
                "app.py": "print('hi')\n",
            }
        )
        subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
        files = list_repo_files("repo", root)
        self.assertEqual(files.mode, "git")
        self.assertEqual(sorted(files.files), [".env.example", ".env.production", ".gitignore", "app.py"])
        env = [f for f in scan_config(files) if f.check_id == "code.config.env_file"]
        self.assertEqual([f.location for f in env], [".env.production"])
        self.assertEqual(env[0].severity, Severity.HIGH)


class WalkListingTest(unittest.TestCase):
    def test_vendor_dirs_and_binaries_skipped(self):
        files = repo_files(
            {
                "node_modules/x/index.js": "eval(x)\n",
                ".venv/lib/a.py": "eval(x)\n",
                "src/app.py": "x = 1\n",
                "model.pt": "binary-ish\n",
                ".env": f"DB_PASSWORD={hexs(16)}\n",
            }
        )
        self.assertEqual(files.mode, "walk")
        self.assertEqual(sorted(files.files), [".env", "src/app.py"])
        env = [f for f in scan_config(files) if f.check_id == "code.config.env_file"]
        self.assertEqual(env[0].severity, Severity.MEDIUM)  # outside git: "not ignored" rather than "committed"


if __name__ == "__main__":
    unittest.main()
