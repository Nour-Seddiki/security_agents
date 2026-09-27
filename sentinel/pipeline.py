"""One scan, end to end:

    scanners -> rule triage -> agent triage -> alert plan -> email -> state -> reports

Every stage after the scanners is allowed to fail without losing the scan: the agent
falls back to scanner severities, a failed email is saved to the outbox and retried on
the next run, and reports are always written.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from .agent import run_agent
from .agent_cli import run_claude_code_agent
from .checks import run_check
from .checks.code import (
    RepoFiles,
    list_repo_files,
    scan_config,
    scan_javascript,
    scan_python,
    scan_secrets,
    sync_checkout,
)
from .checks.deps import OsvClient, scan_dependencies
from .checks.tls import check_tls_cert, check_tls_protocols
from .checks.web import check_cookies, check_cors, check_exposure, check_headers, check_security_txt, check_transport
from .config import Config
from .models import CheckRun, ScanResult
from .net import HttpClient
from .notify import NotifyError, build_email, send_email, write_outbox
from .report import ascii_safe, console_summary, write_reports
from .scope import Scope, origin_of
from .state import NotifyPlan, State
from .triage import baseline_triage

SCAN_PARTS = ("web", "code", "deps")

EXIT_CLEAN = 0
EXIT_MAJOR_FINDINGS = 1
EXIT_USAGE = 2
EXIT_NOTIFY_FAILED = 3


@dataclass
class RunOptions:
    dry_run: bool = False  # no API calls, no email sent (outbox instead), state untouched
    use_agent: bool = True
    send_email: bool = True
    parts: tuple[str, ...] = SCAN_PARTS


@dataclass
class RunOutcome:
    result: ScanResult
    plan: NotifyPlan
    run_dir: Path
    reports: dict[str, Path]
    email_status: str
    exit_code: int


def _run_dir(reports_dir: Path, now: datetime) -> Path:
    base = reports_dir / now.strftime("%Y%m%d-%H%M%S")
    path, n = base, 2
    while path.exists():
        path = base.with_name(f"{base.name}-{n}")
        n += 1
    path.mkdir(parents=True)
    return path


def scan_web(config: Config, http: HttpClient, result: ScanResult, say: Callable[[str], None]) -> None:
    seen = set()
    for url in config.web.urls:
        origin = origin_of(url)
        origin_url = str(origin)
        say(f"[web] {url}")
        try:
            root = http.get(url)
        except Exception as exc:  # noqa: BLE001 - recorded as failed checks
            for group in ("web.headers", "web.cookies"):
                result.checks.append(CheckRun(group, url, ok=False, detail=f"could not fetch the page: {exc}"))
        else:
            run_check(result, "web.headers", url, check_headers, root, url)
            run_check(result, "web.cookies", url, check_cookies, root, url)
        run_check(result, "web.cors", url, check_cors, http, url)
        if origin in seen:
            continue
        seen.add(origin)  # origin-level checks run once per origin
        run_check(result, "web.transport", origin_url, check_transport, http, url)
        if origin.scheme == "https":
            run_check(result, "tls.cert", origin_url, check_tls_cert, http, url)
            run_check(result, "tls.protocol", origin_url, check_tls_protocols, http, url)
        run_check(result, "web.exposure", origin_url, check_exposure, http, origin_url)
        run_check(result, "web.securitytxt", origin_url, check_security_txt, http, origin_url)


def _repo_files(config: Config, label: str, root: Path, repos: dict[str, RepoFiles], result: ScanResult, say) -> RepoFiles:
    if label in repos:
        return repos[label]
    url = config.code.remotes.get(root)
    if url:
        try:
            status = sync_checkout(url, root)
            say(f"[code] {label}: {status} from {url}")
        except OSError as exc:
            if not (root / ".git").exists():
                raise OSError(f"could not fetch {url}: {exc}") from exc
            result.notes.append(f"{label}: could not update from {url} ({exc}); scanned the previous checkout")
    repos[label] = list_repo_files(label, root, config.code.exclude, config.code.max_file_kb * 1024)
    return repos[label]


def scan_code(config: Config, scope: Scope, result: ScanResult, repos: dict[str, RepoFiles], say) -> None:
    for label, root in scope.repos.items():
        try:
            files = _repo_files(config, label, root, repos, result, say)
        except OSError as exc:
            for group in ("code.secrets", "code.python", "code.js", "code.config"):
                result.checks.append(CheckRun(group, label, ok=False, detail=str(exc)))
            continue
        say(f"[code] {label}: {len(files.files)} files ({files.mode} listing)")
        if files.skipped_large:
            result.notes.append(f"{label}: {files.skipped_large} file(s) over {config.code.max_file_kb} KB were not scanned")
        run_check(result, "code.secrets", label, scan_secrets, files)
        run_check(result, "code.python", label, scan_python, files)
        run_check(result, "code.js", label, scan_javascript, files)
        run_check(result, "code.config", label, scan_config, files)


def scan_deps(config: Config, scope: Scope, result: ScanResult, repos: dict[str, RepoFiles], osv: OsvClient, say) -> None:
    for label, root in scope.repos.items():
        try:
            files = _repo_files(config, label, root, repos, result, say)
        except OSError as exc:
            result.checks.append(CheckRun("deps.osv", label, ok=False, detail=str(exc)))
            continue
        say(f"[deps] {label}")
        run_check(result, "deps.osv", label, scan_dependencies, files, osv)


def run_scan(
    config: Config,
    options: RunOptions | None = None,
    *,
    client=None,
    wrap_tool: Callable | None = None,
    agent_command: list[str] | None = None,
    now: datetime | None = None,
    say: Callable[[str], None] = print,
) -> RunOutcome:
    options = options or RunOptions()
    say = (lambda line, _say=say: _say(ascii_safe(line)))
    clock = time.monotonic()
    now = now or datetime.now().astimezone()
    result = ScanResult(platform=config.platform, started_at=now.isoformat(timespec="seconds"))
    run_dir = _run_dir(config.reports_dir, now)
    scope = Scope.from_config(config)
    http = HttpClient(
        scope,
        max_requests=config.web.max_requests,
        delay_s=config.web.request_delay_ms / 1000,
        timeout_s=config.web.timeout_s,
        user_agent=config.web.user_agent,
    )
    osv = (
        OsvClient(config.deps.osv_api, config.deps.timeout_s, config.deps.max_advisory_lookups, config.web.user_agent)
        if config.deps.enabled
        else None
    )
    repos: dict[str, RepoFiles] = {}
    result.notes.extend(config.notes)

    say(f"Sentinel: scanning {config.platform}" + (" (dry run)" if options.dry_run else ""))
    if "web" in options.parts and config.web.urls:
        scan_web(config, http, result, say)
    if "code" in options.parts:
        scan_code(config, scope, result, repos, say)
    if "deps" in options.parts and osv is not None:
        scan_deps(config, scope, result, repos, osv, say)
    result.notes.extend(http.notes)
    if http.used:
        result.notes.append(f"scanners made {http.used} of {http.max_requests} allowed HTTP requests")
    baseline_triage(result)

    if not options.use_agent:
        result.agent.error = "disabled with --no-agent"
    elif options.dry_run:
        result.agent.error = "dry run: no API calls"
    elif not config.agent.enabled:
        result.agent.error = "disabled in the config"
    elif not result.findings:
        result.agent.error = "nothing to triage"
    elif config.agent.backend == "claude-code":
        say(f"[agent] triaging {len(result.findings)} findings with Claude Code (your Claude login)")
        run_claude_code_agent(
            result,
            scope=scope,
            repos=repos,
            osv=osv,
            config=config,
            command=agent_command,
            transcript_path=run_dir / "agent_transcript.md",
            say=say,
        )
        if not result.agent.ok:
            say(f"[agent] did not complete ({result.agent.error}); using scanner severities")
    else:
        say(f"[agent] triaging {len(result.findings)} findings with {config.agent.model}")
        run_agent(
            result,
            scope=scope,
            repos=repos,
            osv=osv,
            config=config,
            client=client,
            wrap_tool=wrap_tool,
            transcript_path=run_dir / "agent_transcript.md",
            skip_hosts=http.unresponsive,
            say=say,
        )
        if not result.agent.ok:
            say(f"[agent] did not complete ({result.agent.error}); using scanner severities")
    result.finished_at = datetime.now().astimezone().isoformat(timespec="seconds")

    state = State.load(config.state_file)
    result.notes.extend(state.notes)
    plan = state.plan(result, config.notify.min_severity, timedelta(days=config.notify.remind_after_days), now)

    email_status, emailed, email_failed = "nothing new to report", False, False
    if plan.should_send:
        if config.notify.email is None:
            email_status = "alerts pending, but no [notify.email] is configured - see the report"
        else:
            msg = build_email(config, result, plan, run_dir / "report.html", now)
            (run_dir / "alert.eml").write_bytes(msg.as_bytes())
            if options.dry_run or not options.send_email:
                path = write_outbox(msg, config.outbox_dir, now)
                why = "dry run" if options.dry_run else "--no-email"
                email_status = f"not sent ({why}); message saved to {path}"
            else:
                try:
                    send_email(msg, config.notify.email)
                    emailed = True
                    email_status = f"sent to {', '.join(config.notify.email.to)} ({len(plan.alerting)} alert(s))"
                except NotifyError as exc:
                    email_failed = True
                    path = write_outbox(msg, config.outbox_dir, now)
                    email_status = f"FAILED: {exc}; saved to {path}; the alerts will be retried next run"
                    result.notes.append(f"email delivery failed: {exc}")

    if not options.dry_run:
        state.commit(result, plan, now, emailed=emailed)
        state.save()
    reports = write_reports(result, plan, run_dir, config.notify.min_severity)

    for line in console_summary(result, config.notify.min_severity):
        say(line)
    say(f"Email:    {email_status}")
    say(f"Report:   {reports['html']}")
    say(f"Done in {time.monotonic() - clock:.1f}s")

    if email_failed:
        code = EXIT_NOTIFY_FAILED
    elif result.open_major(config.notify.min_severity):
        code = EXIT_MAJOR_FINDINGS
    else:
        code = EXIT_CLEAN
    return RunOutcome(result, plan, run_dir, reports, email_status, code)
