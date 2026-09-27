"""Test fixtures: a fake OSV API, a fake SMTP server, a fake Claude client, temp repos.

Everything runs on 127.0.0.1 with free ports; nothing touches the network.
"""

from __future__ import annotations

import base64
import json
import secrets
import socketserver
import tempfile
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote

from sentinel.checks.code import RepoFiles, list_repo_files


def hexs(n: int) -> str:
    return secrets.token_hex((n + 1) // 2)[:n]


# --------------------------------------------------------------------------- servers


class Server:
    def __init__(self, server) -> None:
        self.server = server
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()


def osv_server(vulns: dict[tuple[str, str], list[str]], details: dict[str, dict], *, fail_details: bool = False, pages: dict | None = None) -> Server:
    """Fake https://api.osv.dev: querybatch, query (pagination) and vulns/{id}."""
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _json(self, status: int, payload) -> None:
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(self.path)
            if self.path == "/v1/querybatch":
                rows = []
                for query in body["queries"]:
                    key = (query["package"]["name"], query["version"])
                    row = {"vulns": [{"id": i, "modified": "2026-01-01T00:00:00Z"} for i in vulns.get(key, [])]} if key in vulns else {}
                    if pages and key in pages:
                        row["next_page_token"] = "page-2"
                    rows.append(row)
                self._json(200, {"results": rows})
            elif self.path == "/v1/query":
                key = (body["package"]["name"], body["version"])
                self._json(200, {"vulns": [{"id": i} for i in (pages or {}).get(key, [])]})
            else:
                self._json(404, {})

        def do_GET(self):  # noqa: N802
            requests.append(self.path)
            vid = unquote(self.path.rsplit("/", 1)[-1])
            if fail_details:
                self._json(500, {"message": "boom"})
            elif vid in details:
                self._json(200, details[vid])
            else:
                self._json(404, {"message": "not found"})

    server = Server(ThreadingHTTPServer(("127.0.0.1", 0), Handler))
    server.requests = requests
    return server


class _SmtpHandler(socketserver.StreamRequestHandler):
    def reply(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode())

    def handle(self) -> None:
        box = self.server.box
        self.reply("220 fake.smtp ESMTP")
        data_mode, lines, rcpts = False, [], []
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            if data_mode:
                if raw in (b".\r\n", b".\n"):
                    box.messages.append({"rcpts": list(rcpts), "data": b"".join(lines)})
                    data_mode, lines, rcpts = False, [], []
                    self.reply("250 queued")
                else:
                    lines.append(raw[1:] if raw.startswith(b"..") else raw)
                continue
            cmd = raw.decode(errors="replace").strip()
            upper = cmd.upper()
            if upper.startswith("EHLO"):
                self.wfile.write(b"250-fake.smtp\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
            elif upper.startswith("HELO"):
                self.reply("250 fake.smtp")
            elif upper.startswith("AUTH PLAIN"):
                parts = cmd.split()
                token = parts[2] if len(parts) > 2 else self.rfile.readline().decode().strip()
                box.auth.append(base64.b64decode(token).split(b"\0"))
                self.reply("235 accepted")
            elif upper.startswith("MAIL FROM"):
                self.reply("250 ok")
            elif upper.startswith("RCPT TO"):
                if box.reject_rcpt:
                    self.reply("550 no such user")
                else:
                    rcpts.append(cmd.split(":", 1)[1].strip())
                    self.reply("250 ok")
            elif upper == "DATA":
                data_mode = True
                self.reply("354 go ahead")
            elif upper in ("RSET", "NOOP"):
                self.reply("250 ok")
            elif upper == "QUIT":
                self.reply("221 bye")
                return
            else:
                self.reply("502 not implemented")


def smtp_server(reject_rcpt: bool = False) -> Server:
    class _Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = _Server(("127.0.0.1", 0), _SmtpHandler)
    server.box = SimpleNamespace(messages=[], auth=[], reject_rcpt=reject_rcpt)
    wrapped = Server(server)
    wrapped.box = server.box
    return wrapped


# --------------------------------------------------------------------------- repos and configs


def make_repo(files: dict[str, str], root: Path | None = None) -> Path:
    root = root or Path(tempfile.mkdtemp(prefix="sentinel-test-"))
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content), encoding="utf-8")
    return root


def repo_files(files: dict[str, str], label: str = "repo") -> RepoFiles:
    root = make_repo(files)
    return list_repo_files(label, root)


def write_config(folder: Path, *, urls=(), repos=(), osv_api="http://127.0.0.1:9", smtp_port=None, extra: str = "", authorized=True, deps=True) -> Path:
    url_list = ", ".join(f'"{u}"' for u in urls)
    repo_list = ", ".join(f"'{Path(r).as_posix()}'" for r in repos)
    email = ""
    if smtp_port is not None:
        email = textwrap.dedent(
            f"""
            [notify.email]
            to = ["admin@shop.example"]
            from = "sentinel@shop.example"
            smtp_host = "127.0.0.1"
            smtp_port = {smtp_port}
            security = "none"
            username_env = "SENTINEL_TEST_SMTP_USER"
            password_env = "SENTINEL_TEST_SMTP_PASSWORD"
            """
        )
    text = textwrap.dedent(
        f"""
        [platform]
        name = "Test shop"
        authorized = {"true" if authorized else "false"}

        [web]
        urls = [{url_list}]
        request_delay_ms = 0
        timeout_s = 5

        [code]
        repos = [{repo_list}]

        [deps]
        enabled = {"true" if deps else "false"}
        osv_api = "{osv_api}"
        timeout_s = 5

        [notify]
        min_severity = "high"
        remind_after_days = 7
        """
    ) + email + textwrap.dedent(
        """
        [output]
        reports_dir = "reports"
        state_file = "state/state.json"
        outbox_dir = "outbox"
        """
    ) + extra
    path = folder / "sentinel.toml"
    path.write_text(text, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- fake Claude


def usage(inp: int = 100, out: int = 50):
    return SimpleNamespace(input_tokens=inp, output_tokens=out, cache_read_input_tokens=0, cache_creation_input_tokens=0)


def tool_message(*calls: tuple[str, dict], stop_reason: str = "tool_use"):
    blocks = [SimpleNamespace(type="tool_use", id=f"toolu_{n}", name=name, input=args) for n, (name, args) in enumerate(calls)]
    return SimpleNamespace(content=blocks, stop_reason=stop_reason, stop_details=None, usage=usage())


def final_message(report: dict | str, stop_reason: str = "end_turn", stop_details=None):
    text = report if isinstance(report, str) else json.dumps(report)
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)], stop_reason=stop_reason, stop_details=stop_details, usage=usage())


class FakeRunner:
    """Mimics the SDK tool runner: yields each assistant message, then runs its tool calls."""

    def __init__(self, tools: dict, script: list, log: list) -> None:
        self.tools, self.script, self.log = tools, script, log

    def __iter__(self):
        for message in self.script:
            yield message
            for block in message.content:
                if block.type == "tool_use":
                    self.log.append((block.name, block.input, self.tools[block.name](**block.input)))


class FakeClient:
    def __init__(self, script: list, fail_first: Exception | None = None) -> None:
        self.calls: list[dict] = []
        self.tool_log: list = []
        self.script = script
        self.fail_first = fail_first
        self.beta = SimpleNamespace(messages=SimpleNamespace(tool_runner=self._tool_runner))

    def _tool_runner(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail_first is not None and len(self.calls) == 1:
            raise self.fail_first
        return FakeRunner({fn.__name__: fn for fn in kwargs["tools"]}, self.script, self.tool_log)


def identity(fn):
    return fn
