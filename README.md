# Sentinel - agentic security checks for your platform

Sentinel scans a web platform **and** its source code, has a Claude agent triage and
investigate what it found, and emails the administrator about the **major**
vulnerabilities: once when they appear, again as a reminder while they stay open, and
with a note when they are fixed.

```
             sentinel.toml (scope + authorization)
                              |
       +----------------------+----------------------+
       |                      |                      |
   web scanners          code scanners         dependency audit
   headers, cookies,     secrets, risky        lock/requirements
   CORS, TLS, exposed    Python/JS patterns,   files -> OSV.dev
   files, debug pages    Docker/compose/config
       |                      |                      |
       +------------ findings (evidence, redacted) --+
                              |
                  rule triage (dedupe, test paths)
                              |
               Claude agent (read-only, scoped tools)
         confirm / dismiss / re-rate, investigate leads,
         link findings into risk chains -> JSON verdict
                              |
          alert plan: new / escalated / reminder /
          dismissed-by-AI / fixed   <- state file
                              |
              email (SMTP)  +  report.html / report.json
```

## Contents

- [Why it is built this way](#why-it-is-built-this-way)
- [Safety model](#safety-model)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Email alerts](#email-alerts)
- [Running on a schedule](#running-on-a-schedule)
- [What it checks](#what-it-checks)
- [Example output](#example-output)
- [Limitations](#limitations)
- [Development](#development)

## Why it is built this way

- **Scanners guarantee coverage; the agent adds judgement.** Every check runs on every
  scan, whatever the model does. The agent then triages (is this real? how bad, *here*?),
  follows leads the scanners can't (an API spec listing an unauthenticated admin
  endpoint, a committed secret whose file is also served over HTTP), and explains how
  findings combine.
- **The agent is additive, never a single point of failure.** No SDK, no credentials, a
  refusal, a timeout or unusable output: the scan still reports and alerts using the
  scanners' own severities.
- **The AI cannot bury a finding.** If the agent dismisses or downgrades something the
  scanners rated major, the admin is told once, with the agent's reasoning, so a person
  makes the final call.
- **Silence is never a clean bill of health.** Every check is recorded as ok, failed or
  skipped. A finding is only reported *fixed* when the check that produced it completed
  against the same target again; a failed check proves nothing.

## Safety model

Sentinel is for assessing systems **you own or are authorized to test**.

- **Authorization gate.** `scan` refuses to run until `[platform] authorized = true`.
- **Scope is enforced in code, not in the prompt.** Every HTTP request - by a scanner or
  by the agent - is checked against the configured origins (redirects included) and
  counted against a budget. File access is limited to committed/committable files inside
  the configured repositories, and path traversal is rejected.
- **Read-only.** GET requests only: no payloads, no form submissions, no brute force. The
  CORS check sends a single `Origin` header on a reserved `.example` domain.
- **Secrets never leave unredacted.** Findings carry masked values
  (`ghp_...[redacted 40 chars]`), the agent only ever sees redacted files and responses,
  and its code search runs over redacted text so a secret can't be recovered by probing
  with regexes.
- **Scanned content is untrusted data.** Page bodies and code shown to the agent are marked
  as untrusted, and the agent is told to ignore instructions inside them. All report and
  email HTML is escaped.
- **Auditable.** Every tool call the agent makes is logged to `agent_transcript.md` in the
  run folder.

## Quick start

Requires Python 3.11+. The scanners, alerts and tests use only the standard library.

```bash
git clone https://github.com/Nour-Seddiki/security_agents.git
cd security_agents
python -m sentinel demo                  # deliberately vulnerable local site + sample repo; offline, no email
python -m unittest discover -s tests -t .
```

The demo prints where it wrote the HTML report and the alert email (`alert.eml`, which
opens in any mail client).

For your own platform:

```bash
cp sentinel.example.toml sentinel.toml   # edit urls, repos, email; set authorized = true
python -m sentinel doctor                # validate the config, show what's available
python -m sentinel scan --dry-run        # full scan; the alert is saved to outbox/, not sent
python -m sentinel test-email            # check SMTP delivery
python -m sentinel scan                  # the real thing
python -m sentinel send-alert            # re-send the latest saved alert without re-scanning
```

### Turning on the AI analyst

Pick one backend under `[agent]`:

| | `backend = "claude-code"` | `backend = "api"` |
|---|---|---|
| Needs | Claude Code CLI logged in with your Claude account (`claude auth login`) | `pip install -r requirements.txt` + `ANTHROPIC_API_KEY` |
| Billing | your Pro/Max plan's usage limits | pay-as-you-go API credits |
| Agent's tools | Read / Grep / Glob over a redacted copy of the code | files + in-scope GET requests + advisory lookups |

With `claude-code`, Sentinel runs `claude -p` headless in a temporary folder that holds a
redacted copy of the scanned files, the findings and the advisories - nothing else. The
session is locked down with `--tools Read,Grep,Glob --restricted --safe-mode
--strict-mcp-config --permission-prompts none --no-session-persistence`, returns the same
JSON verdict (`--json-schema`), and the folder is deleted afterwards. `ANTHROPIC_API_KEY`
is removed from its environment so your plan, not API credits, is used. For scheduled
runs, `claude setup-token` creates a long-lived login in `CLAUDE_CODE_OAUTH_TOKEN`.

`python -m sentinel doctor` shows which backend is active and whether it can log in.
`--no-agent` scans without the analyst.

## Configuration

Everything lives in `sentinel.toml` - see [`sentinel.example.toml`](sentinel.example.toml)
for every option with comments. Validation is strict: an unknown key is an error, because
a typo in a security tool's config should never silently change what gets reported.

| Section | What it controls |
|---|---|
| `[platform]` | name, and the `authorized` confirmation |
| `[web]` | URLs to assess, extra hosts redirects may reach, request budget, delay, timeout |
| `[code]` | source to scan - local folders and/or git URLs (shallow-cloned and refreshed each run) - exclusions, max file size |
| `[deps]` | OSV.dev dependency audit (package names and versions only are sent) |
| `[agent]` | backend (`api` or `claude-code`), model, effort, turn/HTTP budgets, timeout |
| `[notify]` | what counts as major (`min_severity`, default `high`), reminder interval |
| `[notify.email]` | recipients, sender, SMTP server; credentials come from environment variables |
| `[output]` | where reports, alert state and the outbox go |

Command-line options: `--dry-run` (no API calls, nothing sent, state untouched),
`--no-agent`, `--no-email` (save the alert to the outbox), `--only web,code,deps`.

## Email alerts

SMTP credentials are read from environment variables named in the config
(`SENTINEL_SMTP_USER` / `SENTINEL_SMTP_PASSWORD` by default), never from the file. For
Gmail, create an app password (Google Account -> Security -> App passwords), then:

```bash
export SENTINEL_SMTP_USER="you@gmail.com"                 # PowerShell: setx SENTINEL_SMTP_USER "you@gmail.com"
export SENTINEL_SMTP_PASSWORD="your-16-char-app-password"
```

with `smtp_host = "smtp.gmail.com"`, `smtp_port = 587`, `security = "starttls"`, and
`from` set to that same Gmail address (Gmail only sends as the account you log in with).
If a scan ran with `--no-email` or before the login was set up, `sentinel send-alert`
sends its saved alert afterwards.

An alert contains, per finding: severity, where, redacted evidence, why it matters and
how to fix it - plus the AI summary, how findings combine, anything the AI dismissed,
what was fixed since the last alert, and which checks failed (so gaps in coverage are
visible).

## Running on a schedule

Alert state is remembered between runs, so a nightly scan only emails when something is
new, got worse, is still open after `remind_after_days`, or was dismissed by the AI.

Windows Task Scheduler, daily at 02:00:

```powershell
schtasks /Create /SC DAILY /ST 02:00 /TN "Sentinel scan" /TR "cmd /c cd /d C:\path\to\security_agents && python -m sentinel scan"
```

cron:

```
0 2 * * * cd /opt/security_agents && python3 -m sentinel scan >> sentinel.log 2>&1
```

Exit codes: `0` no open major findings, `1` major findings open, `2` config or usage
error, `3` the alert could not be sent (it is saved to `outbox/` and retried next run).

## What it checks

| Area | Checks |
|---|---|
| Transport/TLS | plain-HTTP site, HTTP->HTTPS redirect, untrusted certificate, expiry (30/14 days), TLS 1.0/1.1 still accepted |
| Headers | HSTS (missing/short), CSP (missing/unsafe script sources), clickjacking, nosniff, Referrer-Policy, version disclosure (`Server`, `X-Powered-By`, ...) |
| Cookies | Secure / HttpOnly / SameSite on session-like cookies |
| CORS | arbitrary origin reflected, with or without credentials |
| Exposure | `.git`, `.env*`, `.aws/credentials`, `.htpasswd`, SVN/Hg metadata, SQL dumps, SQLite files, backup archives, config backups, `server-status`, `phpinfo`, Spring actuators and heap dumps, Go pprof, directory listings, framework debug pages (Django, Werkzeug, Laravel, Rails, ASP.NET, raw stack traces) - with soft-404 detection so single-page apps don't cause false alarms |
| Secrets | private keys (with key material, including JSON-embedded), AWS, GitHub, GitLab, Anthropic, OpenAI, Stripe, Slack, SendGrid and Google keys, passwords in connection URLs, framework `SECRET_KEY`, JWTs, generic `password = "..."` (entropy-filtered; placeholders and templates ignored) |
| Python (AST) | `eval`/`exec`, shell injection, SQL built with f-strings/`%`/`.format`, pickle/marshal, unsafe `yaml.load`, TLS verification off, JWT without verification, `render_template_string`, `mark_safe`, `debug=True`, `DEBUG = True` in settings, `mktemp` |
| JavaScript/TypeScript | `eval`/`new Function`, `child_process.exec` with templates, SQL template literals, `rejectUnauthorized: false`, JWT `none`, DOM XSS sinks |
| Config | `.env` committed or not ignored, Dockerfile running as root or baking in secrets, privileged containers, Docker socket mounts, databases published on all interfaces, Django `ALLOWED_HOSTS=['*']`, CORS allow-all, insecure cookies, nginx `autoindex on` |
| Dependencies | exact versions from `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `package-lock.json` checked against OSV.dev (GHSA/PYSEC/CVE), with the nearest fixed version |

Severity: **critical** directly exploitable now (exposed secrets or source, RCE, auth
bypass); **high** serious and likely exploitable; **medium** weakens defenses; **low**
hygiene; **info** no direct risk. "Major" means `min_severity` and above.

## Example output

`python -m sentinel demo` against the bundled vulnerable site and sample repository:

```
Sentinel: scanning Demo shop (dry run)
[web] http://127.0.0.1:53514/
[code] sample-repo: 11 files (git listing)
[deps] sample-repo
...
AI triage: not run (dry run: no API calls)
Major findings (high+):
  [CRITICAL] AWS access key ID in deploy/aws.py - sample-repo: deploy/aws.py:1
  [CRITICAL] Stripe live secret key in app/payments.py - sample-repo: app/payments.py:1
  [CRITICAL] Environment file exposed over HTTP - http://127.0.0.1:53514/.env
  [CRITICAL] Git repository exposed over HTTP - http://127.0.0.1:53514/.git/HEAD
  [HIGH    ] SQL query built with string formatting - sample-repo: app/views.py:12
  [HIGH    ] Shell command built from variables - sample-repo: app/views.py:16
  [HIGH    ] Template rendered from a non-literal string - sample-repo: app/views.py:29
  [HIGH    ] Environment file .env is committed or not git-ignored - sample-repo: .env
  [HIGH    ] Secret baked into the image (API_KEY) - sample-repo: Dockerfile:4
  [HIGH    ] GitHub token in tests/test_api.py - sample-repo: tests/test_api.py:1
  [HIGH    ] Hardcoded framework SECRET_KEY in app/settings.py - sample-repo: app/settings.py:2
  [HIGH    ] Password embedded in a connection URL in app/settings.py - sample-repo: app/settings.py:4
  [HIGH    ] CORS allows any origin with credentials - http://127.0.0.1:53514/
  [HIGH    ] Django debug mode is on - http://127.0.0.1:53514/<any missing page>
Email:    not sent (dry run); message saved to .../outbox/sentinel-20260927-142218.eml
```

(The sample repository also pins old Django, PyYAML and requests releases, which the
dependency audit reports when OSV.dev is reachable. The GitHub token sits in `tests/`,
so rule triage lowered it from critical to high.)

An entry in the alert email:

```
1. [CRITICAL] Environment file exposed over HTTP
   Where:    http://127.0.0.1:53514/.env
   Evidence: file defines 4 variables: APP_ENV, DB_PASSWORD, STRIPE_SECRET_KEY, JWT_SECRET; values not shown
   Fix:      Remove the file from the web root (or deny dotfiles in the web server), then rotate
             every credential it contained - assume they are already known.
```

## Troubleshooting

- **"stopped responding ... the remaining requests to it were skipped".** CDNs and
  firewalls (Netlify, Cloudflare, AWS WAF) often block a client that asks for `/.env`,
  `/.git/HEAD` and similar paths. After three failed requests in a row Sentinel leaves
  the host alone for the rest of the run, marks the affected checks as failed (never as
  passed), and reports how far it got, e.g. *"checked 18 of 27 paths (0 exposed)"*. For
  full coverage, allow-list the scanning machine's IP in the CDN/firewall or raise
  `[web] request_delay_ms`. The block is temporary, but while it lasts the site may not
  load from that network in a browser either.
- **URLs with `#/route`.** Hash routes are handled in the browser; Sentinel drops the `#`
  part and notes it (`doctor` shows the note).
- **Private repositories.** Git URLs are cloned with prompts disabled, so a scheduled run
  fails fast instead of hanging. Log in once with git's credential manager or use an SSH
  URL (`git@github.com:owner/repo.git`).
- **Many similar findings.** Code patterns are reported once per rule per file (with every
  line listed) and dependencies once per package version (with the one upgrade that fixes
  every advisory), so the alert reads like a to-do list rather than a log.

## Limitations

- It checks *hygiene and misconfiguration*, with an AI analyst on top; it is not a
  penetration test. There is no authenticated crawling, injection testing or
  business-logic review.
- Secrets are looked for in the current tree, not in git history.
- Code rules are pattern-based and marked `tentative`; the agent reading the code is what
  turns them into confirmed findings or dismissals.
- The dependency audit needs pinned versions (unpinned ones are listed as info).

## Development

```bash
python -m unittest discover -s tests -t .    # ~20 s; everything local
```

The tests run against a local vulnerable site, a fake OSV API, a fake SMTP server and a
fake Claude client, so they need no network, no credentials and no extra packages.
Fixture secrets are generated at run time, so the repository itself stays clean for
secret scanners.

Adding a check: write a function that returns `list[Finding]` (raise `CheckSkipped` when
it doesn't apply, `CheckIncomplete(detail, findings)` to keep partial results), call it
through `run_check(result, "<family>.<check>", target, fn, ...)` in `pipeline.py`, and
give each finding a stable `key` so alert deduplication works across runs.

```
sentinel/
  cli.py        scan | doctor | test-email | demo
  pipeline.py   one run: scanners -> triage -> agent -> alert plan -> email -> state -> reports
  config.py     strict TOML loading            scope.py   allowed origins and repositories
  net.py        scoped, budgeted HTTP client   redact.py  secret rules and redaction
  checks/       web.py  tls.py  code.py  deps.py  (+ run_check bookkeeping)
  triage.py     rule-based triage              agent.py   Claude analyst (SDK tool runner)
  agent_cli.py  Claude analyst via the Claude Code CLI (your Claude login)
  llm.py        request shape, credentials     state.py   alert memory
  report.py     HTML / JSON / console          notify.py  SMTP email
  demo.py       deliberately vulnerable local site + sample repo
tests/          unittest suite
```
