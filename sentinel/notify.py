"""Email alerts (SMTP, stdlib only).

SMTP credentials come from environment variables named in the config and are never
written anywhere. Bodies contain only redacted evidence.
"""

from __future__ import annotations

import os
import smtplib
import ssl
from collections import Counter
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

from .config import Config, EmailConfig
from .models import Finding, ScanResult, Severity
from .report import esc, finding_html, summary_text, where
from .state import NotifyPlan


class NotifyError(RuntimeError):
    """The alert could not be delivered."""


def subject_for(config: Config, plan: NotifyPlan) -> str:
    prefix = config.notify.email.subject_prefix if config.notify.email else "[Sentinel]"
    fresh = Counter(f.severity.label for f in plan.new + plan.escalated)
    if fresh:
        parts = ", ".join(f"{fresh[s.label]} {s.label}" for s in sorted(Severity, reverse=True) if fresh[s.label])
        return f"{prefix} {config.platform}: {parts} security finding(s) need attention"
    if plan.reminders:
        return f"{prefix} {config.platform}: reminder - {len(plan.reminders)} major finding(s) still open"
    return f"{prefix} {config.platform}: {len(plan.suppressed)} finding(s) downgraded by AI triage - please review"


def _text_finding(n: int, f: Finding) -> list[str]:
    lines = [f"{n}. [{f.severity.label.upper()}] {f.title}", f"   Where:    {where(f)}"]
    if f.evidence:
        lines.append(f"   Evidence: {f.evidence}")
    if f.triage_note:
        lines.append(f"   Triage:   {f.triage_note}")
    if f.remediation:
        lines.append(f"   Fix:      {f.remediation}")
    return lines


def _sections(plan: NotifyPlan) -> list[tuple[str, list[Finding]]]:
    return [
        ("New major findings", plan.new),
        ("Severity increased", plan.escalated),
        ("Still open (reminder)", plan.reminders),
        ("Downgraded or dismissed by AI triage - please double-check", plan.suppressed),
    ]


def build_email(config: Config, result: ScanResult, plan: NotifyPlan, report_path: Path | None, now: datetime) -> EmailMessage:
    email_cfg = config.notify.email
    min_sev = config.notify.min_severity
    summary = summary_text(result, min_sev)
    ok, errors, skipped = result.coverage()
    coverage = f"{ok} checks completed, {errors} failed, {skipped} skipped"

    text = [
        f"Sentinel security scan - {config.platform}",
        f"Finished {now:%Y-%m-%d %H:%M} ({coverage}).",
        "",
        summary,
        "",
    ]
    if result.agent.risk_chains:
        text += ["How findings combine:"] + [f" - {c}" for c in result.agent.risk_chains] + [""]
    html_parts = [
        "<div style=\"font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:760px;line-height:1.45\">",
        f"<h2 style=\"margin:0 0 4px\">Security scan: {esc(config.platform)}</h2>",
        f"<div style=\"color:#6b7280;font-size:13px\">Finished {now:%Y-%m-%d %H:%M} | {esc(coverage)}</div>",
        f"<p>{esc(summary)}</p>",
    ]
    if result.agent.risk_chains:
        html_parts.append("<p><b>How findings combine:</b></p><ul>")
        html_parts += [f"<li>{esc(c)}</li>" for c in result.agent.risk_chains]
        html_parts.append("</ul>")

    for title, findings in _sections(plan):
        if not findings:
            continue
        text.append(f"{title.upper()} ({len(findings)})")
        html_parts.append(f"<h3 style=\"margin-bottom:4px\">{esc(title)} ({len(findings)})</h3>")
        for n, f in enumerate(findings, 1):
            text += _text_finding(n, f) + [""]
            html_parts.append(finding_html(f))
    if plan.resolved:
        text.append(f"FIXED SINCE THE LAST ALERT ({len(plan.resolved)})")
        text += [f" - {r.get('title', r['id'])}" for r in plan.resolved] + [""]
        html_parts.append(f"<h3>Fixed since the last alert ({len(plan.resolved)})</h3><ul>")
        html_parts += [f"<li>{esc(r.get('title', r['id']))}</li>" for r in plan.resolved]
        html_parts.append("</ul>")
    failed = [c for c in result.checks if not c.ok and not c.skipped]
    if failed:
        text.append("CHECKS THAT FAILED (their areas were not assessed this run)")
        text += [f" - {c.group} @ {c.target}: {c.detail}" for c in failed[:15]] + [""]
        html_parts.append("<h3>Checks that failed</h3><ul>")
        html_parts += [f"<li>{esc(c.group)} @ {esc(c.target)}: {esc(c.detail)}</li>" for c in failed[:15]]
        html_parts.append("</ul>")
    if report_path is not None:
        text.append(f"Full report on the scanning host: {report_path}")
        html_parts.append(f"<p style=\"color:#6b7280;font-size:12px\">Full report on the scanning host: {esc(report_path)}</p>")
    text.append("Secrets are redacted in this message.")
    html_parts.append("<p style=\"color:#6b7280;font-size:12px\">Sent by Sentinel. Secrets are redacted in this message.</p></div>")

    msg = EmailMessage()
    msg["Subject"] = subject_for(config, plan)
    msg["From"] = email_cfg.sender if email_cfg else "sentinel@localhost"
    msg["To"] = ", ".join(email_cfg.to) if email_cfg else "admin@localhost"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="sentinel.local")
    msg["Auto-Submitted"] = "auto-generated"  # RFC 3834: no auto-replies
    msg["X-Sentinel-Platform"] = config.platform
    msg.set_content("\n".join(text))
    msg.add_alternative("\n".join(html_parts), subtype="html")
    return msg


def send_email(msg: EmailMessage, cfg: EmailConfig, timeout: float = 30.0) -> None:
    user = os.environ.get(cfg.username_env, "").strip()
    password = os.environ.get(cfg.password_env, "")
    if user and not password:
        raise NotifyError(f"{cfg.username_env} is set but {cfg.password_env} is not")
    context = ssl.create_default_context()
    try:
        if cfg.security == "ssl":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=timeout, context=context)
        else:
            smtp = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=timeout)
        with smtp:
            smtp.ehlo()
            if cfg.security == "starttls":
                smtp.starttls(context=context)
                smtp.ehlo()
            if user:
                smtp.login(user, password)
            refused = smtp.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        raise NotifyError(f"could not send via {cfg.smtp_host}:{cfg.smtp_port}: {exc}") from exc
    if refused:
        raise NotifyError(f"the server refused these recipients: {', '.join(refused)}")


def write_outbox(msg: EmailMessage, outbox_dir: Path, now: datetime) -> Path:
    outbox_dir.mkdir(parents=True, exist_ok=True)
    path = outbox_dir / f"sentinel-{now:%Y%m%d-%H%M%S}.eml"
    n = 2
    while path.exists():
        path = outbox_dir / f"sentinel-{now:%Y%m%d-%H%M%S}-{n}.eml"
        n += 1
    path.write_bytes(msg.as_bytes())
    return path


def build_test_email(config: Config, now: datetime) -> EmailMessage:
    cfg = config.notify.email
    msg = EmailMessage()
    msg["Subject"] = f"{cfg.subject_prefix} {config.platform}: test alert"
    msg["From"] = cfg.sender
    msg["To"] = ", ".join(cfg.to)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="sentinel.local")
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(
        f"This is a test message from Sentinel for {config.platform}, sent {now:%Y-%m-%d %H:%M}.\n"
        f"Alerts for findings at {config.notify.min_severity.label} severity or above will arrive "
        "from this address."
    )
    return msg
