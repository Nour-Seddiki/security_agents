# CLAUDE.md - sentinel

Agentic security checker: deterministic scanners (web, TLS, code, dependencies) ->
rule triage -> a Claude agent that triages/investigates with read-only scoped tools ->
alert plan -> SMTP email + HTML/JSON reports. README.md has the design and safety model.

## Commands

The project venv one level up is blocked by Windows Application Control. Use:

```bash
PY="C:/Users/seddi/AppData/Local/Programs/Python/Python314/python.exe"

$PY -m unittest discover -s tests -t .      # ~20s, all local (fake site/OSV/SMTP/Claude)
$PY -m sentinel demo --out <dir>            # vulnerable local site + sample repo, offline
$PY -m sentinel doctor -c sentinel.toml
$PY -m sentinel scan -c sentinel.toml --dry-run
$PY -m compileall -q sentinel tests
```

Set `PYTHONIOENCODING=utf-8` when redirecting output on Windows.

## Conventions

- **The core is stdlib-only.** `anthropic` is imported lazily (`llm.anthropic_module`), so
  scans, `--no-agent`, `--dry-run` and the tests run on a bare interpreter. Tests use
  `unittest`, not pytest, for the same reason.
- **Agent tools are plain typed functions** in `agent.build_tools`, wrapped with
  `beta_tool` at run time (schema from signature + docstring `Args:`). Keep annotations
  and `Args:` complete. Tests pass `wrap_tool=identity` and a `FakeClient`.
- **Request shape lives in `llm.request_kwargs`**: `claude-opus-5`, adaptive thinking,
  `output_config.effort`, top-level `cache_control`, `fallbacks="default"` + beta header.
  Features the SDK/account rejects are dropped via `Capabilities` and the run retried.
  Never add `budget_tokens` (rejected by this model).
- **Scope is enforced in code.** All HTTP goes through `net.HttpClient` (scope + budget +
  throttle, redirects re-checked); file tools only read files in `RepoFiles.files`.
  Never give the agent a tool that bypasses these.
- **Nothing unredacted leaves.** Findings carry `mask()`ed values; tool output goes
  through `redact()`; `search_code` searches redacted text (prevents regex probing).
- **Skipped/errored is not passed.** Checks run through `checks.run_check`; raise
  `CheckSkipped` when not applicable and `CheckIncomplete(detail, findings)` to keep
  partial results. "Fixed" requires the same (group, target) check to complete.
- **Finding ids must be stable across runs**: `fingerprint(check_id, target, key or
  location)`. Put anything that drifts (line numbers, random URLs) in `location` and a
  stable identity in `key`. Alert dedup depends on it.
- **Test fixtures never contain literal secrets**: build fake tokens at run time
  (`helpers.hexs`, `demo._hex`) so the repo itself stays clean for secret scanners.

## Gotchas

- `C:\Users\seddi` is itself a git repo with nothing tracked. `_git_files` therefore
  only uses git when the folder has its own `.git` or tracked files; otherwise it walks.
- Non-streaming requests: keep `max_tokens` <= ~21000 or the SDK demands streaming
  (config caps it at 21000).
- The Python tool runner does not resume `pause_turn`; we use no server tools, so it
  can't occur - revisit if server tools are ever added.
- `ANTHROPIC_BASE_URL` is set inside Claude Code sessions and the SDK honours it.
- Dry runs never write the state file, so they can't mark anything as notified.
