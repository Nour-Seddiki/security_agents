"""A stand-in for the `claude` CLI, used by the tests.

It refuses to run unless the lock-down flags are present and the parent session's
variables were stripped, checks that no raw secret made it into its workspace, and then
answers in stream-json the way the real CLI does. FAKE_CLAUDE_MODE picks the behaviour.
"""

import json
import os
import re
import sys
import time
from pathlib import Path

REQUIRED = [
    "-p", "--output-format", "stream-json", "--verbose", "--tools", "Read,Grep,Glob", "--restricted",
    "--safe-mode", "--strict-mcp-config", "--permission-prompts", "none", "--no-session-persistence",
    "--json-schema", "--append-system-prompt", "--effort",
]


def emit(event: dict) -> None:
    print(json.dumps(event), flush=True)


def fail(message: str) -> None:
    emit({"type": "result", "subtype": "error_during_execution", "is_error": True, "result": message})
    sys.exit(1)


def main() -> None:
    args = sys.argv[1:]
    if args[:2] == ["auth", "status"]:
        print(json.dumps({"loggedIn": True, "authMethod": "claude.ai"}))
        return
    if args == ["--version"]:
        print("9.9.9 (Claude Code, fake)")
        return
    mode = os.environ.get("FAKE_CLAUDE_MODE", "ok")
    missing = [flag for flag in REQUIRED if flag not in args]
    if missing:
        fail(f"missing flags: {missing}")
    for var in ("CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"):
        if var in os.environ:
            fail(f"{var} leaked into the CLI environment")
    prompt = sys.stdin.read()
    if "FINDINGS.md" not in prompt:
        fail("the prompt does not point at FINDINGS.md")
    secret = os.environ.get("FAKE_CLAUDE_SECRET")
    if secret:
        for path in Path.cwd().rglob("*"):
            if path.is_file() and ".git" not in path.parts and secret in path.read_text(encoding="utf-8", errors="ignore"):
                fail(f"raw secret found in workspace file {path.name}")
    if mode == "sleep":
        time.sleep(30)
    if mode == "error":
        fail("Claude AI usage limit reached")
    if mode == "crash":
        sys.stderr.write("boom: something broke\n")
        sys.exit(2)

    ids = re.findall(r"^## \[([0-9a-f]{12})\]", Path("FINDINGS.md").read_text(encoding="utf-8"), re.M)
    first = next((p for p in sorted(Path("repos").rglob("*")) if p.is_file()), None)
    label = first.parts[1] if first else "repo"
    emit({"type": "system", "subtype": "init", "cwd": str(Path.cwd())})
    emit({"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": str(first.resolve()) if first else "FINDINGS.md"}}
    ]}})
    emit({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t1", "content": "file contents"}]}})
    report = {
        "summary": "Fake analyst summary.",
        "verdicts": [
            {"finding_ids": ids[:1], "status": "confirmed", "severity": "critical", "rationale": "real token format", "remediation": "Revoke it."}
        ] if ids else [],
        "new_findings": [
            {
                "title": "Stored XSS through the avatar URL",
                "severity": "high",
                "category": "code",
                "target": label,
                "location": f"repos/{label}/app/admin.js:1",
                "evidence": "src=\"${u.avatar_url}\" is not escaped",
                "description": "An attacker-chosen avatar URL breaks out of the attribute.",
                "remediation": "Escape the URL.",
            }
        ],
        "risk_chains": [],
    }
    emit({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "t2", "name": "StructuredOutput", "input": report}]}})
    emit({
        "type": "result", "subtype": "success", "is_error": False, "num_turns": 3,
        "structured_output": report, "total_cost_usd": 0.12,
        "usage": {"input_tokens": 1000, "output_tokens": 200}, "permission_denials": [],
    })


main()
