"""Claude Code backend for the analyst: runs the `claude` CLI headless with the person's own
Claude login (e.g. a Pro or Max subscription) instead of an API key.

Same contract as agent.run_agent: it fills result.agent, merges the verdicts, and never
raises - any failure leaves the scanners' severities in place.

Safety, enforced by the CLI flags and the workspace rather than by the prompt:
  --tools Read,Grep,Glob       the only tools that exist in the session
  --restricted                 file tools confined to the working folder; user, project
                               and local settings (hooks included) ignored
  --safe-mode                  no CLAUDE.md, skills, plugins or custom agents
  --strict-mcp-config          no MCP servers
  --permission-prompts none    anything that would ask for permission is denied
  --no-session-persistence     nothing saved to disk
The working folder is a temporary, *redacted* copy of the scanned files plus the findings,
so secrets never reach the model and nothing else on the machine is in reach. It is
deleted when the run ends.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Callable

from .agent import REPORT_SCHEMA, AgentReportError, analyst_prompt, apply_report, finding_line, parse_report
from .checks.code import RepoFiles
from .models import AgentOutcome, ScanResult, Severity
from .redact import redact
from .triage import dedupe_and_sort

TOOLS = "Read,Grep,Glob"
MAX_WORKSPACE_BYTES = 40 * 1024 * 1024

# Variables of a Claude Code session Sentinel may be launched from (the desktop app, an
# IDE), and API credentials that would make the CLI bill an API account instead of using
# the person's Claude login. Deliberate user settings such as CLAUDE_CODE_OAUTH_TOKEN
# (from `claude setup-token`, for scheduled runs) are kept.
DROP_VARS = {"CLAUDECODE", "CLAUDE_PID", "CLAUDE_AGENT_SDK_VERSION", "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"}
KEEP_CLAUDE_CODE_VARS = {
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_GIT_BASH_PATH",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
}

CLI_TOOLS = (
    "You can only read: Read, Grep and Glob over a redacted copy of the platform's "
    "repositories in your working folder (repos/<label>/...), plus FINDINGS.md, findings.json "
    "and advisories/. You cannot reach the live site - web and TLS findings come with the "
    "scanners' evidence only."
)
CLI_LOOK = (
    "Look at the actual evidence: read the code around a flagged line, trace where the values "
    "in a risky call come from, and check whether the vulnerable part of a dependency is "
    "actually used (advisories/ holds the advisory texts)."
)
CLI_SYSTEM_PROMPT = analyst_prompt(CLI_TOOLS, CLI_LOOK)


def child_env(environ: dict[str, str] | None = None) -> dict[str, str]:
    source = os.environ if environ is None else environ
    return {
        key: value
        for key, value in source.items()
        if key not in DROP_VARS
        and not (key.startswith(("CLAUDE_CODE_", "CLAUDE_PREVIEW_")) and key not in KEEP_CLAUDE_CODE_VARS)
    }


def find_claude(configured: str = "") -> str | None:
    if configured:
        path = Path(configured).expanduser()
        return str(path) if path.is_file() else shutil.which(configured)
    found = shutil.which("claude")
    if found:
        return found
    home = Path.home()
    for candidate in (home / ".local/bin/claude.exe", home / ".local/bin/claude", home / ".claude/local/claude"):
        if candidate.is_file():
            return str(candidate)
    return None


def claude_status(command: list[str]) -> tuple[bool, str]:
    """(logged_in, description) from `claude auth status`, for `sentinel doctor`."""
    try:
        proc = subprocess.run([*command, "auth", "status"], capture_output=True, text=True, timeout=60, env=child_env())
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"could not run it: {exc}"
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        text = (proc.stdout + proc.stderr).strip().splitlines()
        return proc.returncode == 0, text[0][:160] if text else f"exit status {proc.returncode}"
    if data.get("loggedIn"):
        return True, f"logged in (auth: {data.get('authMethod', 'unknown')})"
    return False, "not logged in - run `claude auth login`"


# --------------------------------------------------------------------------- workspace


def _repo_path(finding, repos: dict[str, RepoFiles]) -> str:
    if finding.target in repos and finding.location and not finding.location.startswith(("http://", "https://")):
        return f"repos/{finding.target}/{finding.location}"
    return finding.location or finding.target


def findings_markdown(result: ScanResult, repos: dict[str, RepoFiles]) -> str:
    lines = [
        f"# Findings to triage - {result.platform}",
        "",
        "Repository files are under repos/<label>/ with secrets redacted. Code locations below",
        "point into that folder. findings.json has the same data in machine-readable form.",
        "",
    ]
    important = [f for f in result.findings if f.severity >= Severity.MEDIUM]
    for f in important:
        lines += [
            f"## [{f.id}] {f.severity.label.upper()} - {f.title}",
            f"- category: {f.category} (check {f.check_id}, confidence {f.confidence})",
            f"- where: {_repo_path(f, repos)}",
            f"- evidence: {f.evidence}",
        ]
        if f.description:
            lines.append(f"- why it matters: {f.description}")
        if f.remediation:
            lines.append(f"- scanner's suggested fix: {f.remediation}")
        if f.triage_note:
            lines.append(f"- triage so far: {f.triage_note}")
        lines.append("")
    rest = [f for f in result.findings if f.severity < Severity.MEDIUM]
    if rest:
        lines += ["## Low and info findings", ""]
        lines += [f"- {finding_line(f)} | {_repo_path(f, repos)}" for f in rest]
    return "\n".join(lines) + "\n"


def build_workspace(ws: Path, result: ScanResult, repos: dict[str, RepoFiles], osv) -> dict[str, int]:
    stats = {"files": 0, "skipped": 0, "bytes": 0, "advisories": 0}
    for label, files in repos.items():
        for rel in files.files:
            text = files.read_text(rel)
            if text is None:
                continue
            data = redact(text)
            if stats["bytes"] + len(data) > MAX_WORKSPACE_BYTES:
                stats["skipped"] += 1
                continue
            dest = ws / "repos" / label / rel
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(data, encoding="utf-8")
            except OSError:  # e.g. a path too long for Windows
                stats["skipped"] += 1
                continue
            stats["files"] += 1
            stats["bytes"] += len(data)
    (ws / "findings.json").write_text(json.dumps([f.to_dict() for f in result.findings], indent=2), encoding="utf-8")
    (ws / "FINDINGS.md").write_text(findings_markdown(result, repos), encoding="utf-8")
    advisories = getattr(osv, "_cache", None) or {}
    if advisories:
        (ws / "advisories").mkdir(exist_ok=True)
        for vid, data in advisories.items():
            name = re.sub(r"[^A-Za-z0-9._-]", "_", vid)
            (ws / "advisories" / f"{name}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
            stats["advisories"] += 1
    git = shutil.which("git")
    if git:  # its own repository root, so the CLI never looks at an enclosing one
        subprocess.run([git, "init", "-q", str(ws)], capture_output=True, timeout=60, check=False)
    return stats


def build_prompt(result: ScanResult, scope, repos: dict[str, RepoFiles], config, stats: dict[str, int]) -> str:
    ok, errors, skipped = result.coverage()
    counts = result.counts()
    lines = [
        f"Platform: {config.platform}",
        "",
        "Your working folder holds:",
        "- FINDINGS.md: every finding, critical to info, with evidence. Read it first.",
        "- findings.json: the same data as JSON.",
        f"- repos/<label>/...: {stats['files']} scanned files, secrets redacted"
        + (f" ({stats['skipped']} left out for size)" if stats["skipped"] else "")
        + ".",
    ]
    if stats["advisories"]:
        lines.append(f"- advisories/: {stats['advisories']} vulnerability advisories for the flagged dependencies.")
    lines += ["", "In scope:"]
    lines += [f"- origin {o}" for o in sorted(str(o) for o in scope.origins)]
    lines += [f"- repository `{label}` -> repos/{label}/" for label in repos]
    lines += ["", f"Scanner coverage: {ok} checks completed, {errors} failed, {skipped} skipped."]
    lines += [f"- {c.group} @ {c.target}: {c.state}: {c.detail}" for c in result.checks if not c.ok][:20]
    lines += [
        "",
        "Findings: " + ", ".join(f"{counts[s.label]} {s.label}" for s in sorted(Severity, reverse=True)) + ".",
        f"The administrator is alerted about findings at {config.notify.min_severity.label} severity or above.",
        "In new_findings, give locations as <path inside the repository>:<line>, without the repos/<label>/ prefix,",
        "and use the repository label as the target.",
        "",
        "Triage and investigate, then return the report as your structured output.",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- the run


def remove_tree(path: Path) -> None:
    """Delete a folder even when Windows marks files read-only (git does)."""

    def make_writable(func, target, _exc) -> None:
        os.chmod(target, stat.S_IWRITE)
        func(target)

    try:
        try:
            shutil.rmtree(path, onexc=make_writable)
        except TypeError:  # Python < 3.12
            shutil.rmtree(path, onerror=make_writable)
    except OSError:
        pass  # a file still held open: leave it for the OS temp cleaner


def _relative(value: str, workspace: str) -> str:
    """Show workspace paths relative to it: repos/<label>/app.py, not C:\\...\\Temp\\..."""
    text = value.replace("\\", "/")
    base = workspace.replace("\\", "/").rstrip("/")
    if text.lower() == base.lower():
        return "."
    if text.lower().startswith(base.lower() + "/"):
        return text[len(base) + 1 :]
    return value


def _brief(args: dict, workspace: str = "") -> str:
    parts = []
    for key in ("file_path", "path", "pattern", "glob", "offset", "limit"):
        if key in args and args[key] not in (None, ""):
            value = _relative(str(args[key]), workspace) if workspace else str(args[key])
            parts.append(f"{key}={value[:80]}")
    return ", ".join(parts)


class _Stream:
    """Reads the CLI's stream-json events: logs tool calls, keeps the final result."""

    def __init__(self, outcome: AgentOutcome, transcript: list[str], say: Callable[[str], None], workspace: Path) -> None:
        self.outcome = outcome
        self.transcript = transcript
        self.say = say
        self.workspace = str(workspace)
        self.final: dict | None = None

    def _short(self, text: str) -> str:
        for prefix in (self.workspace + os.sep, self.workspace.replace("\\", "/") + "/"):
            text = text.replace(prefix, "")
        return text

    def feed(self, line: str) -> None:
        try:
            event = json.loads(line)
        except ValueError:
            return
        kind = event.get("type")
        content = (event.get("message") or {}).get("content")
        if kind == "assistant" and isinstance(content, list):
            for block in content:
                if block.get("type") == "tool_use" and block.get("name") != "StructuredOutput":
                    self.outcome.tool_calls += 1
                    shown = _brief(block.get("input") or {}, self.workspace)
                    self.transcript.append(f"### {block.get('name')}({shown})\n")
                    self.say(f"  agent: {block.get('name')} {shown}"[:160])
                elif block.get("type") == "text" and (block.get("text") or "").strip():
                    self.transcript.append(block["text"].strip()[:3000] + "\n")
        elif kind == "user" and isinstance(content, list):
            for block in content:
                if block.get("type") == "tool_result":
                    body = block.get("content")
                    if isinstance(body, list):
                        body = "\n".join(str(b.get("text", "")) for b in body if isinstance(b, dict))
                    self.transcript.append(f"```\n{self._short(str(body))[:1500]}\n```\n")
        elif kind == "result":
            self.final = event


def _run_cli(cmd: list[str], prompt: str, cwd: Path, timeout: float, stream: _Stream) -> tuple[int | None, str, bool]:
    """Run the CLI, feeding stream events as they arrive. Returns (exit code, stderr, timed_out)."""
    timed_out = threading.Event()
    stderr: list[str] = []
    with subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
        env=child_env(),
    ) as proc:

        def kill() -> None:
            timed_out.set()
            proc.kill()

        def feed_prompt() -> None:
            try:
                proc.stdin.write(prompt)
                proc.stdin.close()
            except OSError:  # the CLI exited before reading its input; its exit status tells why
                pass

        readers = [
            threading.Thread(target=lambda: stderr.append(proc.stderr.read()), daemon=True),
            threading.Thread(target=feed_prompt, daemon=True),
        ]
        timer = threading.Timer(timeout, kill)
        timer.start()
        for thread in readers:
            thread.start()
        try:
            for line in proc.stdout:
                stream.feed(line)
            proc.wait()
        finally:
            timer.cancel()
            for thread in readers:
                thread.join(5)
    return proc.returncode, "".join(stderr), timed_out.is_set()


def run_claude_code_agent(
    result: ScanResult,
    *,
    scope,
    repos: dict[str, RepoFiles],
    osv,
    config,
    command: list[str] | None = None,
    transcript_path: Path | None = None,
    say: Callable[[str], None] = print,
) -> AgentOutcome:
    agent_cfg = config.agent
    outcome = AgentOutcome(ran=True, model="claude-code" + (f" ({agent_cfg.claude_code_model})" if agent_cfg.claude_code_model else ""))
    result.agent = outcome
    transcript = ["# Sentinel agent transcript (Claude Code backend)\n"]

    if command is None:
        exe = find_claude(agent_cfg.claude_code_path)
        if exe is None:
            outcome.error = "the Claude Code CLI (`claude`) was not found; install it or set [agent] claude_code_path"
            return outcome
        command = [exe]

    ws = Path(tempfile.mkdtemp(prefix="sentinel-agent-"))
    try:
        stats = build_workspace(ws, result, repos, osv)
        prompt = build_prompt(result, scope, repos, config, stats)
        transcript.append(f"## Task\n\n```\n{prompt}\n```\n\n## Tool calls\n")
        cmd = [
            *command, "-p",
            "--output-format", "stream-json", "--verbose",
            "--tools", TOOLS,
            "--restricted", "--safe-mode", "--strict-mcp-config",
            "--permission-prompts", "none",
            "--no-session-persistence",
            "--json-schema", json.dumps(REPORT_SCHEMA),
            "--append-system-prompt", CLI_SYSTEM_PROMPT,
            "--effort", agent_cfg.effort,
        ]
        if agent_cfg.claude_code_model:
            cmd += ["--model", agent_cfg.claude_code_model]
        say(f"[agent] Claude Code is reviewing {stats['files']} redacted files (read-only; up to {agent_cfg.timeout_s:.0f}s)")
        stream = _Stream(outcome, transcript, say, ws)
        try:
            code, stderr, timed_out = _run_cli(cmd, prompt, ws, agent_cfg.timeout_s, stream)
        except OSError as exc:
            outcome.error = f"could not start Claude Code: {exc}"
            return outcome

        final = stream.final
        if timed_out:
            outcome.error = f"Claude Code did not finish within {agent_cfg.timeout_s:.0f}s; raise [agent] timeout_s"
        elif final is None:
            tail = (stderr.strip().splitlines() or [f"exit status {code}"])[-1]
            outcome.error = f"Claude Code ended without a result: {tail[:300]}"
        elif final.get("is_error") or final.get("subtype") != "success":
            detail = str(final.get("result") or final.get("subtype") or "unknown error")
            outcome.error = f"Claude Code stopped ({final.get('subtype')}): {detail[:300]}"
        else:
            outcome.turns = int(final.get("num_turns") or 0)
            usage = final.get("usage") or {}
            outcome.usage = {
                key: int(usage.get(key) or 0)
                for key in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
            }
            data = final.get("structured_output")
            text = json.dumps(data) if isinstance(data, dict) else str(final.get("result") or "")
            report = parse_report(text)
            for item in report["new_findings"]:  # map workspace paths back to repository paths
                match = re.match(r"^repos/([^/]+)/(.+)$", item["location"].replace("\\", "/"))
                if match and match.group(1) in repos:
                    item["target"], item["location"] = match.group(1), match.group(2)
            apply_report(result, report, config.notify.min_severity, outcome)
            dedupe_and_sort(result)
            outcome.ok = True
            transcript.append(f"## Final report\n\n```json\n{json.dumps(data, indent=2)[:20000] if data else text[:20000]}\n```\n")
            cost = final.get("total_cost_usd")
            if isinstance(cost, (int, float)):
                outcome.notes.append(
                    f"Claude Code used about ${cost:.2f} of API-equivalent usage; on a Claude "
                    "subscription this counts toward your plan's usage limits rather than being billed"
                )
        denials = (final or {}).get("permission_denials") or []
        if denials:
            outcome.notes.append(f"Claude Code was refused {len(denials)} tool call(s) outside its read-only sandbox")
    except AgentReportError as exc:
        outcome.error = str(exc)
    except OSError as exc:
        outcome.error = f"could not prepare the agent's workspace: {exc}"
    finally:
        remove_tree(ws)
        if outcome.error:
            transcript.append(f"## Stopped\n\n{outcome.error}\n")
        if transcript_path is not None:
            transcript_path.parent.mkdir(parents=True, exist_ok=True)
            transcript_path.write_text("\n".join(transcript), encoding="utf-8")
    return outcome
