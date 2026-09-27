"""sentinel.toml: what to scan, how hard, and whom to tell.

Validation is strict on purpose: an unknown key is an error, not a silent default,
because a typo in a security tool's config ("min_severty") should never quietly change
what gets reported.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .models import Severity
from .scope import ScopeError, origin_of

EFFORTS = ("low", "medium", "high", "xhigh", "max")
SMTP_SECURITY = ("starttls", "ssl", "none")


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
    repos: list[Path] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    max_file_kb: int = 1024


@dataclass
class DepsConfig:
    enabled: bool = True
    osv_api: str = "https://api.osv.dev"
    timeout_s: float = 30.0
    max_advisory_lookups: int = 200


@dataclass
class AgentConfig:
    enabled: bool = True
    model: str = "claude-opus-5"
    effort: str = "high"
    thinking: bool = True
    max_tokens: int = 16000
    max_turns: int = 30
    max_http_requests: int = 40


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


def _check_url(url: str, where: str) -> str:
    try:
        origin_of(url)
    except ScopeError as exc:
        raise ConfigError(f"[{where}] {exc}") from None
    if urlsplit(url).fragment:
        raise ConfigError(f"[{where}] URLs must not contain a #fragment: {url}")
    return url


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

    t = _Table(root.table("platform"), "platform")
    platform = t.str("name", required=True)
    authorized = t.bool("authorized", False)
    t.done()

    t = _Table(root.table("web"), "web")
    web = WebConfig(
        urls=[_check_url(u, "web") for u in t.str_list("urls")],
        extra_hosts=t.str_list("extra_hosts"),
        max_requests=t.int("max_requests", 300, 1, 100_000),
        request_delay_ms=t.int("request_delay_ms", 150, 0, 60_000),
        timeout_s=t.float("timeout_s", 10.0, 0.5),
        user_agent=t.str("user_agent", WebConfig.user_agent) or WebConfig.user_agent,
    )
    t.done()

    t = _Table(root.table("code"), "code")
    repos = []
    for entry in t.str_list("repos"):
        repo = Path(entry)
        repo = repo if repo.is_absolute() else (base / repo)
        repo = repo.resolve()
        if not repo.is_dir():
            raise ConfigError(f"[code] repository not found: {repo}")
        repos.append(repo)
    code = CodeConfig(
        repos=repos,
        exclude=t.str_list("exclude"),
        max_file_kb=t.int("max_file_kb", 1024, 1, 1_000_000),
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
        model=t.str("model", "claude-opus-5") or "claude-opus-5",
        effort=t.str("effort", "high").lower(),
        thinking=t.bool("thinking", True),
        max_tokens=t.int("max_tokens", 16000, 1024, 21000),
        max_turns=t.int("max_turns", 30, 1, 200),
        max_http_requests=t.int("max_http_requests", 40, 0, 1000),
    )
    t.done()
    if agent.effort not in EFFORTS:
        raise ConfigError(f"[agent] effort must be one of {', '.join(EFFORTS)}")

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
    )
