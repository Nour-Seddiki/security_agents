"""A deliberately vulnerable local web app and sample repository, for trying Sentinel
without pointing it at anything real. The site binds to 127.0.0.1 on a random port and
the repository lives in a folder you choose. The fake secrets are generated at run time,
so none of them appear in this source file.
"""

from __future__ import annotations

import json
import secrets
import shutil
import string
import subprocess
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

DJANGO_404 = (
    "<!doctype html><html><head><title>Page not found at /</title></head><body>"
    "<h1>Page not found <span>(404)</span></h1>"
    "<p>You're seeing this error because you have <code>DEBUG = True</code> in your Django "
    "settings file. Change that to <code>False</code>, and Django will display a standard 404 page.</p>"
    "</body></html>"
)


def _hex(n: int) -> str:
    return secrets.token_hex((n + 1) // 2)[:n]


def _upper(n: int) -> str:
    alphabet = string.ascii_uppercase[:6] + string.digits  # A-F and digits: never spells a placeholder word
    return "".join(secrets.choice(alphabet) for _ in range(n))


class _Handler(BaseHTTPRequestHandler):
    server_version = "Sentinel-test"
    sys_version = ""

    def log_message(self, format, *args):  # noqa: A002 - silence the default stderr log
        pass

    def send(self, status: int, body: bytes | str, ctype: str, headers: list[tuple[str, str]] = ()) -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)


def make_vulnerable_handler() -> type[BaseHTTPRequestHandler]:
    env_file = f"APP_ENV=production\nDB_PASSWORD={_hex(18)}\nSTRIPE_SECRET_KEY={_hex(24)}\nJWT_SECRET={_hex(32)}\n"
    session = _hex(32)
    users = [{"id": 1, "email": "owner@demo-shop.example", "role": "admin"}, {"id": 2, "email": "ops@demo-shop.example", "role": "admin"}]
    openapi = {
        "openapi": "3.0.0",
        "info": {"title": "Demo shop API", "version": "1.0"},
        "paths": {"/api/products": {"get": {}}, "/api/admin/users": {"get": {"summary": "List admin users"}}},
    }

    class VulnerableSite(_Handler):
        server_version = "Apache/2.4.29 (Ubuntu)"

        def do_GET(self):  # noqa: N802
            path = urlsplit(self.path).path
            origin = self.headers.get("Origin")
            cors = [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")] if origin else []
            if path == "/":
                page = "<!doctype html><html><head><title>Demo shop</title></head><body><h1>Demo shop</h1><a href='/login'>Log in</a></body></html>"
                self.send(200, page, "text/html; charset=utf-8", [("Set-Cookie", f"sessionid={session}; Path=/"), ("X-Powered-By", "PHP/7.2.1"), *cors])
            elif path == "/.git/HEAD":
                self.send(200, "ref: refs/heads/main\n", "text/plain")
            elif path == "/.git/config":
                self.send(200, '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://git.demo-shop.example/shop.git\n', "text/plain")
            elif path == "/.env":
                self.send(200, env_file, "text/plain")
            elif path == "/openapi.json":
                self.send(200, json.dumps(openapi), "application/json", cors)
            elif path == "/api/admin/users":
                self.send(200, json.dumps(users), "application/json", cors)
            else:
                self.send(404, DJANGO_404, "text/html; charset=utf-8")

    return VulnerableSite


class HardenedSite(_Handler):
    """The same pages with the protections in place: nothing for the web checks to report
    (apart from being plain HTTP on localhost, which is info-level)."""

    SECURITY_HEADERS = [
        ("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'self'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ]

    def do_GET(self):  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/":
            page = "<!doctype html><html><head><title>Shop</title></head><body>ok</body></html>"
            cookie = ("Set-Cookie", "sessionid=x; Path=/; HttpOnly; Secure; SameSite=Lax")
            self.send(200, page, "text/html; charset=utf-8", [*self.SECURITY_HEADERS, cookie])
        elif path == "/.well-known/security.txt":
            self.send(200, "Contact: mailto:security@shop.example\nExpires: 2030-01-01T00:00:00Z\n", "text/plain")
        else:
            self.send(404, "not found", "text/plain", self.SECURITY_HEADERS)


class SpaSite(_Handler):
    """A single-page app that answers 200 with index.html for every path."""

    def do_GET(self):  # noqa: N802
        page = "<!doctype html><html><head><title>App</title></head><body><div id=root></div></body></html>"
        self.send(200, page, "text/html; charset=utf-8", HardenedSite.SECURITY_HEADERS)


class LocalSite:
    """Run a handler on 127.0.0.1 with a free port for the duration of a with-block."""

    def __init__(self, handler: type[BaseHTTPRequestHandler]) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/"

    def __enter__(self) -> "LocalSite":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()


def sample_repo_files() -> dict[str, str]:
    return {
        "app/settings.py": textwrap.dedent(
            f"""\
            DEBUG = True
            SECRET_KEY = "{_hex(40)}"
            ALLOWED_HOSTS = ["*"]
            DATABASE_URL = "postgres://shop:{_hex(14)}@db.internal:5432/shop"
            """
        ),
        "app/views.py": textwrap.dedent(
            """\
            import pickle
            import subprocess

            import yaml
            from flask import Flask, render_template_string, request

            app = Flask(__name__)


            def search(db):
                term = request.args.get("q", "")
                return db.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")


            def ping(host):
                return subprocess.check_output(f"ping -c 1 {host}", shell=True)


            def restore(blob):
                return pickle.loads(blob)


            def load_config(text):
                return yaml.load(text)


            @app.route("/hello")
            def hello():
                return render_template_string(request.args.get("tpl", "hi"))


            if __name__ == "__main__":
                app.run(debug=True)
            """
        ),
        "app/payments.py": f'STRIPE_API_KEY = "sk_live_{_hex(24)}"\n',
        "deploy/aws.py": f'AWS_ACCESS_KEY_ID = "AKIA{_upper(16)}"\n',
        "tests/test_api.py": f'GITHUB_TOKEN = "ghp_{_hex(36)}"\n\n\ndef test_placeholder():\n    assert True\n',
        "static/app.js": "const q = decodeURIComponent(location.hash.slice(1));\ndocument.getElementById('out').innerHTML = q;\n",
        "requirements.txt": "django==3.2.0\npyyaml==5.3\nrequests==2.19.0\nflask\n",
        "Dockerfile": f"FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\nENV API_KEY={_hex(20)}\nCMD [\"python\", \"-m\", \"app.views\"]\n",
        "docker-compose.yml": 'services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n',
        ".env": f"DB_PASSWORD={_hex(16)}\n",
        "README.md": "# Demo shop\n\nA deliberately insecure sample for Sentinel's demo.\n",
    }


def build_sample_repo(root: Path, use_git: bool = True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in sample_repo_files().items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    git = shutil.which("git")
    if use_git and git and not (root / ".git").exists():
        subprocess.run([git, "init", "-q", str(root)], capture_output=True, timeout=60, check=False)
    return root


def write_demo_config(folder: Path, site_url: str, repo: Path, *, osv_api: str = "https://api.osv.dev") -> Path:
    path = folder / "sentinel-demo.toml"
    path.write_text(
        textwrap.dedent(
            f"""\
            # Generated by `python -m sentinel demo`. Everything here is local and disposable.
            [platform]
            name = "Demo shop"
            authorized = true

            [web]
            urls = ["{site_url}"]
            request_delay_ms = 0

            [code]
            repos = ['{repo.as_posix()}']

            [deps]
            osv_api = "{osv_api}"

            [agent]
            max_turns = 30

            [notify]
            min_severity = "high"

            [notify.email]
            to = ["admin@demo-shop.example"]
            from = "sentinel@demo-shop.example"
            smtp_host = "localhost"
            smtp_port = 25
            security = "none"

            [output]
            reports_dir = "reports"
            state_file = "state/sentinel-state.json"
            outbox_dir = "outbox"
            """
        ),
        encoding="utf-8",
    )
    return path
