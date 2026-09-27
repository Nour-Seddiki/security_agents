"""sentinel.toml: what to scan, how hard, and whom to tell.

Validation is strict on purpose: an unknown key is an error, not a silent default,
because a typo in a security tool's config ("min_severty") should never quietly change
what gets reported.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .models import Severity
from .scope import ScopeError, origin_of

EFFORTS = ("low", "medium", "high", "xhigh", "max")
AGENT_BACKENDS = ("api", "claude-code")
SMTP_SECURITY = ("starttls", "ssl", "none")
REMOTE_REPO = re.compile(r"^(?:https?://|ssh://|git@[\w.-]+:)", re.I)
WEB_GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")


class ConfigError(ValueError):
    """The configuration file is missing, malformed or unsafe to act on."""


@dataclass
class WebConfig:
    urls: list[str] = field(default_factory=list)
    extra_hosts: list[str] = field(default_factory=list)
    max_requests: int = 300
    request_delay_ms: int = 150
    timeout_s: float = 10.0
    user_agent: str = "Sentinel/0.1 (authorized security self-assessment)"


@dataclass
class CodeConfig:
    repos: list[Path] = field(default_factory=list)  # local folders (remote ones: their checkout)
    exclude: list[str] = field(default_factory=list)
    max_file_kb: int = 1024
    remotes: dict[Path, str] = field(default_factory=dict)  # checkout folder -> git URL


@dataclass
class DepsConfig:
    enabled: bool = True
    osv_api: str = "https://api.osv.dev"
    timeout_s: float = 30.0
    max_advisory_lookups: int = 200


@dataclass
class AgentConfig:
    enabled: bool = True
    backend: str = "api"  # "api" (Anthropic API key) or "claude-code" (the claude CLI and your Claude login)
    model: str = "claude-opus-5"
    effort: str = "high"
    thinking: bool = True
    max_tokens: int = 16000
    max_turns: int = 30
    max_http_requests: int = 40
    claude_code_path: str = ""  # default: `claude` on PATH
    claude_code_model: str = ""  # e.g. "opus" or "sonnet"; default: the CLI's own default
    timeout_s: float = 1800.0  # claude-code backend: the whole analysis


@dataclass
class EmailConfig:
    to: list[str]
    sender: str
    smtp_host: str
    smtp_port: int = 587
    security: str = "starttls"
    username_env: str = "SENTINEL_SMTP_USER"
    password_env: str = "SENTINEL_SMTP_PASSWORD"
    subject_prefix: str = "[Sentinel]"


@dataclass
class NotifyConfig:
    min_severity: Severity = Severity.HIGH
    remind_after_days: float = 7.0
    email: EmailConfig | None = None


@dataclass
class Config:
    path: Path
    platform: str
    authorized: bool
    web: WebConfig
    code: CodeConfig
    deps: DepsConfig
    agent: AgentConfig
    notify: NotifyConfig
    reports_dir: Path
    state_file: Path
    outbox_dir: Path
    notes: list[str] = field(default_factory=list)  # adjustments made while loading


class _Table:
    """Typed access to one TOML table that remembers which keys were read."""

    def __init__(self, data, where: str) -> None:
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError(f"[{where}] must be a table")
        self.data = data
        self.where = where
        self.seen: set[str] = set()

    def _get(self, key: str, default, required: bool):
        self.seen.add(key)
        if key not in self.data:
            if required:
                raise ConfigError(f"[{self.where}] {key} is required")
            return default
        return self.data[key]

    def _fail(self, key: str, what: str):
        raise ConfigError(f"[{self.where}] {key} must be {what}")

    def str(self, key: str, default: str = "", required: bool = False) -> str:
        value = self._get(key, default, required)
        if not isinstance(value, str):
            self._fail(key, "a string")
        return value.strip()

    def bool(self, key: str, default: bool) -> bool:
        value = self._get(key, default, False)
        if not isinstance(value, bool):
            self._fail(key, "true or false")
        return value

    def int(self, key: str, default: int, lo: int | None = None, hi: int | None = None) -> int:
        value = self._get(key, default, False)
        if isinstance(value, bool) or not isinstance(value, int):
            self._fail(key, "an integer")
        if (lo is not None and value < lo) or (hi is not None and value > hi):
            self._fail(key, f"between {lo} and {hi}")
        return value

    def float(self, key: str, default: float, lo: float | None = None) -> float:
        value = self._get(key, default, False)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            self._fail(key, "a number")
        if lo is not None and value < lo:
            self._fail(key, f"at least {lo}")
        return float(value)

    def str_list(self, key: str, required: bool = False) -> list[str]:
        value = self._get(key, [], required)
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            self._fail(key, "a list of strings")
        return [v.strip() for v in value if v.strip()]

    def table(self, key: str):
        self.seen.add(key)
        return self.data.get(key)

    def done(self) -> None:
        extra = sorted(set(self.data) - self.seen)
        if extra:
            raise ConfigError(f"[{self.where}] unknown key(s): {', '.join(extra)}")


def _normalize_url(url: str, where: str, notes: list[str]) -> str:
    """Validate a URL and put it in canonical form. A #fragment (hash routing such as
    /#/signin) never reaches the server, so it is dropped rather than rejected."""
    try:
        origin_of(url)
    except ScopeError as exc:
        raise ConfigError(f"[{where}] {exc}") from None
    parts = urlsplit(url)
    if parts.fragment:
        notes.append(f"{url}: dropped '#{parts.fragment}' - the part after # is handled in the browser and never sent to the server")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def default_checkout_dir() -> Path:
    """Remote repositories are cloned here: outside the project (and outside OneDrive)."""
    base = os.environ.get("LOCALAPPDATA")
    return (Path(base) if base else Path.home() / ".cache") / "sentinel" / "repos"


def remote_repo(entry: str, checkout_dir: Path) -> tuple[str, Path]:
    """(clone URL, local checkout folder) for a git URL from [code] repos."""
    if entry.lower().startswith("git@"):
        host, _, path = entry[4:].partition(":")
    else:
        parts = urlsplit(entry)
        if parts.username or parts.password:
            raise ConfigError(
                "[code] don't put credentials in a repository URL; git's credential manager "
                "(or an SSH key) handles private repositories"
            )
        host, path = parts.hostname or "", parts.path
    segments = [s for s in path.strip("/").split("/") if s]
    if not host or not segments:
        raise ConfigError(f"[code] not a repository URL: {entry}")
    segments[-1] = segments[-1].removesuffix(".git")
    url = entry
    if host.lower() in WEB_GIT_HOSTS and not entry.lower().startswith("git@"):
        if len(segments) < 2:
            raise ConfigError(f"[code] expected {host}/<owner>/<repo>: {entry}")
        segments = segments[:2]  # drop /tree/main/... from a copied browser URL
        url = f"https://{host.lower()}/{segments[0]}/{segments[1]}"
    safe = [re.sub(r"[^\w.-]", "_", s) for s in [host.lower(), *segments]]
    return url, checkout_dir.joinpath(*safe).resolve()


def _email(data, where: str) -> EmailConfig | None:
    if data is None:
        return None
    t = _Table(data, where)
    to = t.str_list("to", required=True)
    sender = t.str("from", required=True)
    for address in [*to, sender]:
        if "@" not in address:
            raise ConfigError(f"[{where}] {address!r} is not an email address")
    cfg = EmailConfig(
        to=to,
        sender=sender,
        smtp_host=t.str("smtp_host", required=True),
        smtp_port=t.int("smtp_port", 587, 1, 65535),
        security=t.str("security", "starttls").lower(),
        username_env=t.str("username_env", "SENTINEL_SMTP_USER"),
        password_env=t.str("password_env", "SENTINEL_SMTP_PASSWORD"),
        subject_prefix=t.str("subject_prefix", "[Sentinel]"),
    )
    t.done()
    if not to:
        raise ConfigError(f"[{where}] to must list at least one address")
    if cfg.security not in SMTP_SECURITY:
        raise ConfigError(f"[{where}] security must be one of {', '.join(SMTP_SECURITY)}")
    return cfg


def load_config(path: str | Path) -> Config:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(
            f"config file not found: {path}\n"
            "  copy sentinel.example.toml to sentinel.toml and edit it"
        )
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from None
    base = path.resolve().parent
    root = _Table(data, "top level")
    notes: list[str] = []

    t = _Table(root.table("platform"), "platform")
    platform = t.str("name", required=True)
    authorized = t.bool("authorized", False)
    t.done()

    t = _Table(root.table("web"), "web")
    urls: list[str] = []
    for raw in t.str_list("urls"):
        url = _normalize_url(raw, "web", notes)
        if url not in urls:  # "https://x" and "https://x/" are the same page
            urls.append(url)
    web = WebConfig(
        urls=urls,
        extra_hosts=t.str_list("extra_hosts"),
        max_requests=t.int("max_requests", 300, 1, 100_000),
        request_delay_ms=t.int("request_delay_ms", 150, 0, 60_000),
        timeout_s=t.float("timeout_s", 10.0, 0.5),
        user_agent=t.str("user_agent", WebConfig.user_agent) or WebConfig.user_agent,
    )
    t.done()

    t = _Table(root.table("code"), "code")
    checkout_value = t.str("checkout_dir", "")
    checkout_dir = Path(checkout_value) if checkout_value else default_checkout_dir()
    if not checkout_dir.is_absolute():
        checkout_dir = base / checkout_dir
    repos: list[Path] = []
    remotes: dict[Path, str] = {}
    for entry in t.str_list("repos"):
        if REMOTE_REPO.match(entry):
            url, repo = remote_repo(entry, checkout_dir)
            remotes[repo] = url
        else:
            repo = Path(entry)
            repo = (repo if repo.is_absolute() else (base / repo)).resolve()
            if not repo.is_dir():
                raise ConfigError(
                    f"[code] repository not found: {repo}\n"
                    "  use a local folder, or a git URL such as https://github.com/<owner>/<repo>"
                )
        if repo not in repos:
            repos.append(repo)
    code = CodeConfig(
        repos=repos,
        exclude=t.str_list("exclude"),
        max_file_kb=t.int("max_file_kb", 1024, 1, 1_000_000),
        remotes=remotes,
    )
    t.done()

    t = _Table(root.table("deps"), "deps")
    deps = DepsConfig(
        enabled=t.bool("enabled", True),
        osv_api=t.str("osv_api", "https://api.osv.dev").rstrip("/"),
        timeout_s=t.float("timeout_s", 30.0, 1.0),
        max_advisory_lookups=t.int("max_advisory_lookups", 200, 0, 10_000),
    )
    t.done()
    if not deps.osv_api.startswith(("https://", "http://")):
        raise ConfigError("[deps] osv_api must be an http(s) URL")

    t = _Table(root.table("agent"), "agent")
    agent = AgentConfig(
        enabled=t.bool("enabled", True),
        backend=t.str("backend", "api").lower(),
        model=t.str("model", "claude-opus-5") or "claude-opus-5",
        effort=t.str("effort", "high").lower(),
        thinking=t.bool("thinking", True),
        max_tokens=t.int("max_tokens", 16000, 1024, 21000),
        max_turns=t.int("max_turns", 30, 1, 200),
        max_http_requests=t.int("max_http_requests", 40, 0, 1000),
        claude_code_path=t.str("claude_code_path", ""),
        claude_code_model=t.str("claude_code_model", ""),
        timeout_s=t.float("timeout_s", 1800.0, 30.0),
    )
    t.done()
    if agent.effort not in EFFORTS:
        raise ConfigError(f"[agent] effort must be one of {', '.join(EFFORTS)}")
    if agent.backend not in AGENT_BACKENDS:
        raise ConfigError(f"[agent] backend must be one of {', '.join(AGENT_BACKENDS)}")

    t = _Table(root.table("notify"), "notify")
    try:
        min_severity = Severity.parse(t.str("min_severity", "high"))
    except ValueError as exc:
        raise ConfigError(f"[notify] {exc}") from None
    notify = NotifyConfig(
        min_severity=min_severity,
        remind_after_days=t.float("remind_after_days", 7.0, 0.0),
        email=_email(t.table("email"), "notify.email"),
    )
    t.done()

    t = _Table(root.table("output"), "output")

    def _path(key: str, default: str) -> Path:
        value = Path(t.str(key, default) or default)
        return value if value.is_absolute() else base / value

    reports_dir = _path("reports_dir", "reports")
    state_file = _path("state_file", "state/sentinel-state.json")
    outbox_dir = _path("outbox_dir", "outbox")
    t.done()
    root.done()

    if not web.urls and not code.repos:
        raise ConfigError("nothing to scan: set [web] urls and/or [code] repos")

    return Config(
        path=path.resolve(),
        platform=platform,
        authorized=authorized,
        web=web,
        code=code,
        deps=deps,
        agent=agent,
        notify=notify,
        reports_dir=reports_dir,
        state_file=state_file,
        outbox_dir=outbox_dir,
        notes=notes,
    )
