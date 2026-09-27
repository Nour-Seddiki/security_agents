"""Command line: scan, doctor, test-email, demo."""

from __future__ import annotations

import argparse
import os
import platform
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config
from .pipeline import EXIT_USAGE, SCAN_PARTS, RunOptions, run_scan
from .report import ascii_safe


def _say(line: str) -> None:
    print(ascii_safe(line), flush=True)


def _parts(value: str | None) -> tuple[str, ...]:
    if not value:
        return SCAN_PARTS
    parts = tuple(p.strip().lower() for p in value.split(",") if p.strip())
    unknown = [p for p in parts if p not in SCAN_PARTS]
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown part(s): {', '.join(unknown)} (choose from {', '.join(SCAN_PARTS)})")
    return parts


def cmd_scan(args) -> int:
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        _say(f"config error: {exc}")
        return EXIT_USAGE
    if not config.authorized:
        _say(
            "Refusing to scan: set `authorized = true` under [platform] in "
            f"{config.path.name} to confirm you own every target in it, or have written "
            "permission to test them."
        )
        return EXIT_USAGE
    options = RunOptions(
        dry_run=args.dry_run,
        use_agent=not args.no_agent,
        send_email=not args.no_email,
        parts=args.only,
    )
    return run_scan(config, options, say=_say).exit_code


def cmd_doctor(args) -> int:
    from .checks.tls import _legacy_context
    from .llm import credential_source
    from .scope import Scope

    _say(f"Sentinel {__version__}, Python {platform.python_version()} on {platform.system()} {platform.release()}")
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        _say(f"config: ERROR - {exc}")
        return EXIT_USAGE
    _say(f"config: {config.path} (valid)")
    _say(f"platform: {config.platform}")
    _say("authorized: " + ("yes" if config.authorized else "NO - scans are refused until [platform] authorized = true"))
    for line in Scope.from_config(config).describe():
        _say(f"  scope: {line}")
    for path, url in config.code.remotes.items():
        state = "checked out" if (path / ".git").exists() else "cloned on the first scan"
        _say(f"  remote: {url} ({state})")
    for note in config.notes:
        _say(f"  note: {note}")

    import shutil

    _say("git: " + ("found" if shutil.which("git") else "not found (repos are walked instead; .gitignore is not honoured)"))
    _say("legacy TLS probe: " + ("available" if _legacy_context() is not None else "unavailable in this OpenSSL build (check will be skipped)"))
    _say(f"dependency audit: {'on, via ' + config.deps.osv_api if config.deps.enabled else 'off'}")

    if not config.agent.enabled:
        _say("agent: disabled in config")
    elif config.agent.backend == "claude-code":
        import subprocess

        from .agent_cli import child_env, claude_status, find_claude

        exe = find_claude(config.agent.claude_code_path)
        if exe is None:
            _say("agent: Claude Code backend - the `claude` CLI was NOT FOUND (install Claude Code, or set [agent] claude_code_path)")
        else:
            try:
                version = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60, env=child_env()).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                version = "version unknown"
            model = config.agent.claude_code_model or "the CLI's default model"
            _say(f"agent: Claude Code backend - {exe} ({version or 'version unknown'}); {model}, effort {config.agent.effort}")
            ok, status = claude_status([exe])
            _say(f"agent login: {'ok' if ok else 'MISSING'} - {status}")
        if os.environ.get("ANTHROPIC_API_KEY"):
            _say("note: ANTHROPIC_API_KEY is ignored by this backend, so your Claude login is what gets used")
    else:
        try:
            import anthropic  # noqa: F401

            sdk = f"anthropic {anthropic.__version__} installed"
        except ImportError:
            sdk = "anthropic NOT installed (pip install -r requirements.txt) - scans will run without AI triage"
        ok, where = credential_source()
        _say(f"agent: API backend - {config.agent.model}, effort {config.agent.effort}; {sdk}")
        _say(f"agent credentials: {'found' if ok else 'MISSING'} - {where}")
        if os.environ.get("ANTHROPIC_BASE_URL"):
            _say("note: ANTHROPIC_BASE_URL is set, so API requests go to that endpoint")

    email = config.notify.email
    if email is None:
        _say("email: not configured - alerts will only appear in reports")
    else:
        user_set = bool(os.environ.get(email.username_env, "").strip())
        pass_set = bool(os.environ.get(email.password_env, ""))
        _say(f"email: {email.smtp_host}:{email.smtp_port} ({email.security}) -> {', '.join(email.to)}")
        _say(f"  {email.username_env}: {'set' if user_set else 'not set'}; {email.password_env}: {'set' if pass_set else 'not set'}")
        if user_set and email.security == "none":
            _say("  WARNING: credentials would be sent without encryption (security = \"none\")")
    _say(f"alerts: {config.notify.min_severity.label} and above; reminders every {config.notify.remind_after_days:g} days")
    return 0


def cmd_test_email(args) -> int:
    from .notify import NotifyError, build_test_email, send_email, write_outbox

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        _say(f"config error: {exc}")
        return EXIT_USAGE
    if config.notify.email is None:
        _say("no [notify.email] section in the config")
        return EXIT_USAGE
    now = datetime.now().astimezone()
    msg = build_test_email(config, now)
    if args.dry_run:
        _say(f"test message written to {write_outbox(msg, config.outbox_dir, now)}")
        return 0
    try:
        send_email(msg, config.notify.email)
    except NotifyError as exc:
        _say(f"FAILED: {exc}")
        return 3
    _say(f"test message sent to {', '.join(config.notify.email.to)}")
    return 0


def cmd_demo(args) -> int:
    from .demo import LocalSite, build_sample_repo, make_vulnerable_handler, write_demo_config

    out = Path(args.out) if args.out else Path(tempfile.gettempdir()) / "sentinel-demo"
    out.mkdir(parents=True, exist_ok=True)
    repo = build_sample_repo(out / "sample-repo")
    with LocalSite(make_vulnerable_handler()) as site:
        _say(f"Demo site running at {site.url} (deliberately vulnerable, local only)")
        config = load_config(write_demo_config(out, site.url, repo))
        options = RunOptions(dry_run=not args.agent, use_agent=True, send_email=False)
        outcome = run_scan(config, options, say=_say)
    _say("")
    _say(f"Demo folder: {out}")
    _say("The alert that would have been emailed is saved as alert.eml next to the report.")
    return outcome.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Agentic security checks for a web platform and its code, with email alerts for major findings.",
    )
    parser.add_argument("--version", action="version", version=f"sentinel {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run the scanners, AI triage and alerting")
    scan.add_argument("-c", "--config", default="sentinel.toml")
    scan.add_argument("--dry-run", action="store_true", help="no API calls; alert saved to the outbox, not sent; alert state untouched")
    scan.add_argument("--no-agent", action="store_true", help="skip AI triage (scanner severities are used)")
    scan.add_argument("--no-email", action="store_true", help="save the alert to the outbox instead of sending it")
    scan.add_argument("--only", type=_parts, default=SCAN_PARTS, help="comma-separated subset of: web,code,deps")
    scan.set_defaults(func=cmd_scan)

    doctor = sub.add_parser("doctor", help="validate the config and show what this environment supports")
    doctor.add_argument("-c", "--config", default="sentinel.toml")
    doctor.set_defaults(func=cmd_doctor)

    test = sub.add_parser("test-email", help="send a test alert to check the SMTP settings")
    test.add_argument("-c", "--config", default="sentinel.toml")
    test.add_argument("--dry-run", action="store_true", help="write the test message to the outbox instead")
    test.set_defaults(func=cmd_test_email)

    demo = sub.add_parser("demo", help="scan a deliberately vulnerable local site and sample repo")
    demo.add_argument("--out", help="folder for the demo files (default: <temp>/sentinel-demo)")
    demo.add_argument("--agent", action="store_true", help="include AI triage (makes live API calls)")
    demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _say("interrupted")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
