"""Reports: report.json for machines, report.html for people, a console summary for the
terminal. Everything scanned sites or code could influence is HTML-escaped - a page
title or a code line is data, never markup."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .models import Finding, ScanResult, Severity
from .state import NotifyPlan

SEVERITY_COLORS = {
    "critical": "#b3261e",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#1d4ed8",
    "info": "#4b5563",
}


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def badge(finding_or_label) -> str:
    label = finding_or_label.severity.label if isinstance(finding_or_label, Finding) else str(finding_or_label)
    color = SEVERITY_COLORS.get(label, "#4b5563")
    return (
        f'<span style="display:inline-block;padding:1px 7px;border-radius:4px;font-size:12px;'
        f'font-weight:700;letter-spacing:.03em;color:#fff;background:{color}">{esc(label.upper())}</span>'
    )


def where(f: Finding) -> str:
    """Location with enough context to act on: repository findings get the repo label."""
    if not f.location:
        return f.target
    if f.category in ("web", "tls") or f.location.startswith(("http://", "https://")):
        return f.location
    return f"{f.target}: {f.location}"


def finding_html(f: Finding, *, compact: bool = False) -> str:
    meta = [f"id {f.id}", f.category, f"confidence: {f.confidence}"]
    if f.status != "open":
        meta.append(f"status: {f.status.replace('_', ' ')}")
    if f.source == "agent":
        meta.append("found by the AI analyst")
    if f.original_severity is not None and f.original_severity != f.severity:
        meta.append(f"originally {f.original_severity.label}")
    parts = [
        '<div style="border:1px solid #d1d5db;border-left:4px solid '
        f'{SEVERITY_COLORS.get(f.severity.label, "#4b5563")};border-radius:6px;padding:10px 12px;margin:10px 0">',
        f'<div style="font-weight:600;font-size:15px">{badge(f)} {esc(f.title)}</div>',
        f'<div style="color:#6b7280;font-size:12px;margin:2px 0 6px">{esc(" | ".join(meta))}</div>',
        f"<div><b>Where:</b> {esc(where(f))}</div>",
    ]
    if f.evidence:
        parts.append(
            '<div><b>Evidence:</b> <code style="font-size:12px;word-break:break-all">'
            f"{esc(f.evidence)}</code></div>"
        )
    if f.description and not compact:
        parts.append(f"<div><b>Why it matters:</b> {esc(f.description)}</div>")
    if f.triage_note:
        parts.append(f"<div><b>Triage:</b> {esc(f.triage_note)}</div>")
    if f.remediation:
        parts.append(f"<div><b>Fix:</b> {esc(f.remediation)}</div>")
    if f.references and not compact:
        links = " ".join(f'<a href="{esc(r)}">{esc(r)}</a>' for r in f.references[:4] if r.startswith("http"))
        if links:
            parts.append(f'<div style="font-size:12px"><b>References:</b> {links}</div>')
    parts.append("</div>")
    return "\n".join(parts)


def default_summary(result: ScanResult, min_severity: Severity) -> str:
    major = result.open_major(min_severity)
    counts = result.counts()
    ok, errors, skipped = result.coverage()
    if not major:
        text = f"No open findings at {min_severity.label} severity or above."
    else:
        by_sev = ", ".join(
            f"{sum(1 for f in major if f.severity == s)} {s.label}"
            for s in sorted(Severity, reverse=True)
            if any(f.severity == s for f in major)
        )
        top = "; ".join(f.title for f in major[:3])
        text = f"{len(major)} finding(s) need attention ({by_sev}). Most urgent: {top}."
    text += (
        f" {sum(counts.values())} open findings in total from {ok} completed checks"
        + (f"; {errors} check(s) failed and {skipped} were skipped, so coverage is incomplete." if errors or skipped else ".")
    )
    return text


def summary_text(result: ScanResult, min_severity: Severity) -> str:
    if result.agent.ok and result.agent.summary:
        return result.agent.summary
    return default_summary(result, min_severity)


def agent_status(result: ScanResult) -> str:
    agent = result.agent
    if not agent.ran:
        return "not run" + (f" ({agent.error})" if agent.error else "")
    if agent.ok:
        return (
            f"ok - {agent.model}, {agent.turns} turns, {agent.tool_calls} tool calls, "
            f"{agent.verdicts_applied} verdicts, {agent.new_findings} new findings"
        )
    return f"failed ({agent.error}); scanner severities were used as-is"


CSS = """
:root { --fg:#111827; --muted:#6b7280; --bg:#ffffff; --card:#f9fafb; --line:#e5e7eb; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e5e7eb; --muted:#9ca3af; --bg:#111827; --card:#1f2937; --line:#374151; }
  a { color:#93c5fd; }
}
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; color:var(--fg);
       background:var(--bg); max-width:980px; margin:24px auto; padding:0 16px; line-height:1.45; }
h1 { margin-bottom:4px; } h2 { margin-top:28px; border-bottom:1px solid var(--line); padding-bottom:4px; }
.muted { color:var(--muted); font-size:13px; }
.counts span { display:inline-block; margin:4px 8px 4px 0; }
table { border-collapse:collapse; width:100%; font-size:13px; }
td, th { border-bottom:1px solid var(--line); padding:4px 6px; text-align:left; vertical-align:top; }
details { background:var(--card); border:1px solid var(--line); border-radius:6px; padding:6px 10px; margin:8px 0; }
summary { cursor:pointer; font-weight:600; }
code { word-break:break-all; }
"""


def _when(stamp: str) -> str:
    return stamp[:16].replace("T", " ") if stamp else "?"


STATE_COLORS = {"ok": "inherit", "error": "#dc2626", "skipped": "#d97706"}


def render_html(result: ScanResult, plan: NotifyPlan | None, min_severity: Severity) -> str:
    ok, errors, skipped = result.coverage()
    counts = result.counts()
    open_findings = [f for f in result.findings if f.status != "false_positive"]
    major = [f for f in open_findings if f.severity >= min_severity]
    minor = [f for f in open_findings if f.severity < min_severity]
    dismissed = [f for f in result.findings if f.status == "false_positive"]
    new_ids = {f.id for f in plan.new} if plan else set()

    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>Sentinel report - {esc(result.platform)}</title><style>{CSS}</style></head><body>",
        f"<h1>Security scan: {esc(result.platform)}</h1>",
        f"<div class='muted'>{esc(_when(result.started_at))} to {esc(_when(result.finished_at))} | "
        f"{len(result.checks)} checks: {ok} ok, {errors} failed, {skipped} skipped | "
        f"AI triage: {esc(agent_status(result))}</div>",
        "<div class='counts'>"
        + "".join(f"<span>{badge(s.label)} {counts[s.label]}</span>" for s in sorted(Severity, reverse=True))
        + "</div>",
        "<h2>Summary</h2>",
        f"<p>{esc(summary_text(result, min_severity))}</p>",
    ]
    if result.agent.risk_chains:
        out.append("<h3>How findings combine</h3><ul>")
        out += [f"<li>{esc(chain)}</li>" for chain in result.agent.risk_chains]
        out.append("</ul>")

    out.append(f"<h2>Major findings ({min_severity.label} and above): {len(major)}</h2>")
    if not major:
        out.append("<p>None.</p>")
    for f in major:
        prefix = "<div class='muted'>NEW since the last alert</div>" if f.id in new_ids else ""
        out.append(prefix + finding_html(f))

    if plan and plan.resolved:
        out.append("<h2>Fixed since the last alert</h2><ul>")
        out += [f"<li>{esc(r.get('title', r['id']))} <span class='muted'>({esc(r.get('location', ''))})</span></li>" for r in plan.resolved]
        out.append("</ul>")

    out.append(f"<h2>Other findings: {len(minor)}</h2>")
    for sev in sorted(Severity, reverse=True):
        group = [f for f in minor if f.severity == sev]
        if group:
            out.append(f"<details><summary>{badge(sev.label)} {len(group)} finding(s)</summary>")
            out += [finding_html(f, compact=True) for f in group]
            out.append("</details>")

    if dismissed:
        out.append(f"<h2>Dismissed as false positives: {len(dismissed)}</h2><details><summary>show</summary>")
        out += [finding_html(f, compact=True) for f in dismissed]
        out.append("</details>")

    out.append("<h2>Coverage</h2><table><tr><th>check</th><th>target</th><th>result</th><th>findings</th><th>detail</th></tr>")
    for c in result.checks:
        color = STATE_COLORS.get(c.state, "inherit")
        out.append(
            f"<tr><td>{esc(c.group)}</td><td>{esc(c.target)}</td>"
            f"<td style='color:{color};font-weight:{600 if c.state != 'ok' else 400}'>{esc(c.state)}</td>"
            f"<td>{c.findings}</td><td>{esc(c.detail)}</td></tr>"
        )
    out.append("</table>")
    notes = result.notes + result.agent.notes
    if notes:
        out.append("<h2>Notes</h2><ul>")
        out += [f"<li>{esc(n)}</li>" for n in notes]
        out.append("</ul>")
    out.append("<p class='muted'>Generated by Sentinel. Secrets are redacted in this report.</p></body></html>")
    return "\n".join(out)


def write_reports(result: ScanResult, plan: NotifyPlan | None, run_dir: Path, min_severity: Severity) -> dict[str, Path]:
    run_dir.mkdir(parents=True, exist_ok=True)
    data = result.to_dict()
    data["notification"] = plan.to_dict() if plan else None
    json_path = run_dir / "report.json"
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    html_path = run_dir / "report.html"
    html_path.write_text(render_html(result, plan, min_severity), encoding="utf-8")
    return {"json": json_path, "html": html_path}


def ascii_safe(text: str) -> str:
    """Windows consoles may not be UTF-8; degrade instead of raising mid-run."""
    return text.encode("ascii", "replace").decode("ascii")


def console_summary(result: ScanResult, min_severity: Severity) -> list[str]:
    ok, errors, skipped = result.coverage()
    counts = result.counts()
    lines = [
        f"Checks:   {ok} ok, {errors} failed, {skipped} skipped",
        "Findings: " + ", ".join(f"{counts[s.label]} {s.label}" for s in sorted(Severity, reverse=True)),
        f"AI triage: {agent_status(result)}",
    ]
    major = result.open_major(min_severity)
    if major:
        lines.append(f"Major findings ({min_severity.label}+):")
        for f in major[:15]:
            lines.append(f"  [{f.severity.label.upper():8}] {f.title} - {where(f)}")
        if len(major) > 15:
            lines.append(f"  ... and {len(major) - 15} more (see the report)")
    failed = [c for c in result.checks if not c.ok and not c.skipped]
    for c in failed[:10]:
        lines.append(f"  check failed: {c.group} @ {c.target}: {c.detail}")
    return [ascii_safe(line) for line in lines]
