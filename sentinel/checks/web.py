"""Web checks. Every request is a plain GET through the scoped, budgeted client: nothing
is submitted, no attack payloads are sent, and response bodies are read only far enough
to recognise what they are.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Callable

from ..models import Finding, Severity
from ..net import REDIRECT_CODES, FetchError, HttpClient, Response
from ..redact import redact
from ..scope import origin_of
from . import CheckIncomplete, CheckSkipped

OWASP_HEADERS = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
OWASP_COOKIES = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies"
OWASP_CORS = "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing"

# RFC 2606 reserves .example, so this origin can never belong to anyone.
PROBE_ORIGIN = "https://sentinel-cors-probe.example"
SESSION_COOKIE = re.compile(r"(?i)sess|sid$|^sid|token|auth|jwt|login|remember|identity")
CSRF_COOKIE = re.compile(r"(?i)csrf|xsrf")


# --------------------------------------------------------------------------- helpers


def parse_csp(header: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in header.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def parse_set_cookie(header: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        if key.strip():
            attrs[key.strip().lower()] = value.strip()
    return name, attrs


@dataclass(frozen=True)
class DebugSignature:
    rule: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    description: str
    remediation: str


DEBUG_SIGNATURES: tuple[DebugSignature, ...] = (
    DebugSignature(
        "werkzeug",
        "Werkzeug interactive debugger exposed",
        Severity.CRITICAL,
        re.compile(r"Werkzeug Debugger|The debugger caught an exception in your WSGI application"),
        "The Werkzeug debugger runs arbitrary Python from the browser; anyone who gets past "
        "(or brute-forces) its PIN has remote code execution on the server.",
        "Never run Flask/Werkzeug with debug=True in production; serve the app with "
        "gunicorn/uwsgi and debug off.",
    ),
    DebugSignature(
        "django",
        "Django debug mode is on",
        Severity.HIGH,
        re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>"),
        "Django's debug pages disclose settings, URL patterns, SQL, source code and "
        "environment details to anyone who triggers an error.",
        "Set DEBUG = False in production settings (read it from the environment) and "
        "configure ALLOWED_HOSTS.",
    ),
    DebugSignature(
        "laravel",
        "Laravel/Whoops debug page exposed",
        Severity.HIGH,
        re.compile(r"Whoops! There was an error|Ignition\s*\|\s*Laravel"),
        "Framework debug pages disclose source, environment variables and credentials.",
        "Set APP_DEBUG=false in the production environment.",
    ),
    DebugSignature(
        "rails",
        "Rails development error page exposed",
        Severity.HIGH,
        re.compile(r"Action Controller: Exception caught"),
        "Rails development error pages disclose source, parameters and environment.",
        "Run with RAILS_ENV=production and config.consider_all_requests_local = false.",
    ),
    DebugSignature(
        "aspnet",
        "ASP.NET detailed error page exposed",
        Severity.MEDIUM,
        re.compile(r"Server Error in '/' Application|<b>\s*Stack Trace:\s*</b>"),
        "Detailed error pages disclose stack traces, paths and framework versions.",
        'Use customErrors mode="RemoteOnly" or app.UseExceptionHandler in production.',
    ),
    DebugSignature(
        "stacktrace",
        "Stack trace exposed in an error page",
        Severity.MEDIUM,
        re.compile(
            r"Traceback \(most recent call last\)|\bat Layer\.handle \[as handle_request\]"
            r"|at [\w.$]+\([\w./\\-]+\.(?:java|js|ts):\d+(?::\d+)?\)"
        ),
        "Stack traces reveal code paths, library versions and file locations that help an "
        "attacker target the application.",
        "Return generic error pages in production and log the details server-side.",
    ),
)


def debug_signatures(body: str) -> list[tuple[DebugSignature, str]]:
    found = []
    for sig in DEBUG_SIGNATURES:
        match = sig.pattern.search(body)
        if match:
            found.append((sig, match.group(0)[:80]))
    if len(found) > 1:  # a framework debug page also contains a raw trace: report it once
        found = [(s, m) for s, m in found if s.rule != "stacktrace"]
    return found


# --------------------------------------------------------------------------- headers


def check_headers(resp: Response, target: str) -> list[Finding]:
    if resp.offscope_redirect:
        raise CheckSkipped(
            f"{target} redirects out of scope to {resp.offscope_redirect}; add that host "
            "to [web] extra_hosts to assess the page it lands on"
        )
    out: list[Finding] = []
    where = resp.url

    def add(rule: str, title: str, severity: Severity, evidence: str, description: str, remediation: str) -> None:
        out.append(
            Finding(
                check_id=f"web.headers.{rule}",
                title=title,
                severity=severity,
                category="web",
                target=target,
                location=where,
                evidence=evidence,
                description=description,
                remediation=remediation,
                references=[OWASP_HEADERS],
                key=rule,
                confidence="certain",
            )
        )

    https = where.lower().startswith("https://")
    html = resp.is_html
    csp_header = resp.header("content-security-policy")
    csp = parse_csp(csp_header) if csp_header else {}

    if https:
        hsts = resp.header("strict-transport-security")
        if not hsts:
            add(
                "hsts_missing",
                "HSTS is not enabled",
                Severity.MEDIUM,
                f"no Strict-Transport-Security header on {where}",
                "Without HSTS a network attacker can strip TLS on a user's first visit or "
                "on any http:// link, and read or change the traffic.",
                "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on "
                "HTTPS responses; add `preload` once every subdomain serves HTTPS.",
            )
        else:
            match = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            if (int(match.group(1)) if match else 0) < 15_552_000:
                add(
                    "hsts_short",
                    "HSTS max-age is too short",
                    Severity.LOW,
                    f"Strict-Transport-Security: {hsts[:200]}",
                    "A short max-age lets browsers forget the policy quickly and reopens the "
                    "downgrade window.",
                    "Raise max-age to at least 15552000 (180 days); 31536000 (1 year) is standard.",
                )

    if html:
        if not csp_header:
            add(
                "csp_missing",
                "Content-Security-Policy is missing",
                Severity.MEDIUM,
                f"no Content-Security-Policy header on {where}",
                "Without a CSP, any HTML-injection bug becomes full cross-site scripting.",
                "Add a Content-Security-Policy, e.g. `default-src 'self'; object-src 'none'; "
                "base-uri 'self'; frame-ancestors 'self'`, and allow inline scripts only "
                "through nonces or hashes.",
            )
        else:
            scripts = csp.get("script-src", csp.get("default-src"))
            if scripts is None:
                add(
                    "csp_weak",
                    "CSP does not restrict scripts",
                    Severity.LOW,
                    f"Content-Security-Policy: {csp_header[:200]}",
                    "The policy has neither script-src nor default-src, so scripts from any "
                    "origin are allowed.",
                    "Add `script-src 'self'` (plus nonces/hashes for inline scripts) or a default-src.",
                )
            else:
                strict = any(
                    t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'"
                    for t in scripts
                )
                weak = [
                    t
                    for t in scripts
                    if t in ("'unsafe-eval'", "*", "data:", "http:", "https:")
                    or (t == "'unsafe-inline'" and not strict)
                ]
                if weak:
                    add(
                        "csp_weak",
                        "CSP allows unsafe script sources",
                        Severity.LOW,
                        f"script sources include {' '.join(weak)}",
                        "These sources let injected markup run script, which defeats most of "
                        "the protection a CSP gives.",
                        "Remove 'unsafe-inline', 'unsafe-eval' and wildcard sources; use nonces "
                        "or hashes for the inline scripts you need.",
                    )
        if not resp.header("x-frame-options") and "frame-ancestors" not in csp:
            add(
                "clickjacking",
                "No clickjacking protection",
                Severity.MEDIUM,
                "neither X-Frame-Options nor CSP frame-ancestors is set",
                "Any site can load these pages in an invisible frame and trick users into "
                "clicking buttons on them (clickjacking).",
                "Send `Content-Security-Policy: frame-ancestors 'self'` (or `X-Frame-Options: DENY`).",
            )
        if not resp.header("referrer-policy"):
            add(
                "referrer_policy_missing",
                "Referrer-Policy is not set",
                Severity.INFO,
                "no Referrer-Policy header",
                "Browsers default to strict-origin-when-cross-origin, so this is hygiene only.",
                "Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter) explicitly.",
            )

    if (resp.header("x-content-type-options") or "").strip().lower() != "nosniff":
        add(
            "nosniff_missing",
            "X-Content-Type-Options: nosniff is missing",
            Severity.LOW,
            "X-Content-Type-Options is not 'nosniff'",
            "Browsers may MIME-sniff responses, which can turn an uploaded file into script.",
            "Send `X-Content-Type-Options: nosniff` on every response.",
        )

    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        value = resp.header(name)
        if value and re.search(r"\d+\.\d+", value):
            add(
                f"version_{name.replace('-', '_')}",
                f"Software version disclosed in the {name} header",
                Severity.LOW,
                f"{name}: {value[:120]}",
                "Exact versions let attackers look up known vulnerabilities for your stack "
                "without probing.",
                f"Remove or genericize `{name}` (nginx `server_tokens off;`, Apache "
                "`ServerTokens Prod`, Express `app.disable('x-powered-by')`).",
            )

    body = resp.text(limit=200_000)
    if html and re.search(r"<title>\s*Index of /", body, re.I):
        add(
            "directory_listing",
            "Directory listing is enabled",
            Severity.MEDIUM,
            f"{where} returns an auto-generated 'Index of /' page",
            "Directory listings expose every file in the folder, including backups and "
            "files that were never meant to be linked.",
            "Disable auto-indexing (nginx `autoindex off;`, Apache `Options -Indexes`).",
        )
    for sig, marker in debug_signatures(body):
        add(f"debug_{sig.rule}", sig.title, sig.severity, f"page contains '{marker}'", sig.description, sig.remediation)
    return out


# --------------------------------------------------------------------------- cookies


def check_cookies(resp: Response, target: str) -> list[Finding]:
    if resp.offscope_redirect:
        raise CheckSkipped(f"{target} redirects out of scope to {resp.offscope_redirect}")
    out: list[Finding] = []
    https = resp.url.lower().startswith("https://")
    seen: set[str] = set()
    for raw in resp.header_values("set-cookie"):
        name, attrs = parse_set_cookie(raw)
        if not name or name in seen:
            continue
        seen.add(name)
        sensitive = bool(SESSION_COOKIE.search(name)) and not CSRF_COOKIE.search(name)
        missing = []
        if https and "secure" not in attrs:
            missing.append("Secure")
        if sensitive and "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if not missing:
            continue
        severity = Severity.MEDIUM if sensitive and {"Secure", "HttpOnly"} & set(missing) else Severity.LOW
        shown = "; ".join(f"{k}={v}" if v else k for k, v in attrs.items())
        out.append(
            Finding(
                check_id="web.cookies.flags",
                title=f"Cookie '{name}' is missing {', '.join(missing)}",
                severity=severity,
                category="web",
                target=target,
                location=resp.url,
                evidence=f"Set-Cookie: {name}=<value hidden>" + (f"; {shown}" if shown else ""),
                description=(
                    "Without Secure the cookie is also sent over plain HTTP; without HttpOnly "
                    "any XSS can steal it; without SameSite it rides along on cross-site "
                    "requests (CSRF)."
                ),
                remediation=(
                    f"Set `{name}` with `Secure; HttpOnly; SameSite=Lax` (or Strict), e.g. "
                    "Django SESSION_COOKIE_SECURE/HTTPONLY, Express cookie options, "
                    "Flask SESSION_COOKIE_SECURE."
                ),
                references=[OWASP_COOKIES],
                key=name,
                confidence="certain",
            )
        )
    return out


# --------------------------------------------------------------------------- CORS


def check_cors(http: HttpClient, url: str) -> list[Finding]:
    resp = http.get(url, headers={"Origin": PROBE_ORIGIN})
    allow = (resp.header("access-control-allow-origin") or "").strip()
    creds = (resp.header("access-control-allow-credentials") or "").strip().lower() == "true"
    if allow == PROBE_ORIGIN:
        evidence = f"Origin: {PROBE_ORIGIN} -> Access-Control-Allow-Origin: {allow}"
        if creds:
            evidence += "; Access-Control-Allow-Credentials: true"
        return [
            Finding(
                check_id="web.cors.reflected",
                title="CORS allows any origin with credentials" if creds else "CORS reflects any origin",
                severity=Severity.HIGH if creds else Severity.MEDIUM,
                category="web",
                target=url,
                location=resp.url,
                evidence=evidence,
                description=(
                    "Any website can make authenticated requests here from a visitor's "
                    "browser and read the responses - account data, API tokens, CSRF tokens."
                    if creds
                    else "Any website can read this endpoint's responses from a visitor's "
                    "browser; that matters if the responses contain non-public data."
                ),
                remediation=(
                    "Check the Origin header against an explicit allow-list of your own "
                    "front-end origins; never echo it back unconditionally."
                ),
                references=[OWASP_CORS],
                key="reflected",
                confidence="certain",
            )
        ]
    if allow == "*" and creds:
        return [
            Finding(
                check_id="web.cors.wildcard_credentials",
                title="CORS wildcard combined with credentials",
                severity=Severity.LOW,
                category="web",
                target=url,
                location=resp.url,
                evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                description="Browsers refuse this combination, but it shows the CORS policy "
                "is not deliberate and may be loosened into a real hole.",
                remediation="Use an explicit origin allow-list, or drop the credentials flag.",
                references=[OWASP_CORS],
                key="wildcard_credentials",
            )
        ]
    return []


# --------------------------------------------------------------------------- transport


def check_transport(http: HttpClient, url: str) -> list[Finding]:
    origin = origin_of(url)
    target = str(origin)
    if origin.scheme == "http":
        local = origin.is_loopback
        return [
            Finding(
                check_id="web.transport.plain_http",
                title="Site is served over plain HTTP" + (" (local target)" if local else ""),
                severity=Severity.INFO if local else Severity.HIGH,
                category="web",
                target=target,
                location=url,
                evidence=f"{url} is configured as an http:// URL",
                description="Passwords, session cookies and page content travel unencrypted "
                "and can be read or modified by anyone on the network path.",
                remediation="Serve the site over HTTPS (a free Let's Encrypt certificate works) "
                "and redirect every HTTP request to HTTPS.",
                key="plain_http",
                confidence="certain",
            )
        ]
    if origin.port != 443:
        raise CheckSkipped("HTTPS on a non-standard port: no plain-HTTP counterpart to test")
    plain = f"http://{origin.host}/"
    try:
        resp = http.get(plain, follow_redirects=False, max_body=16_384)
    except FetchError as exc:
        if "refused" in str(exc) or "timed out" in str(exc):
            return []  # nothing listens on port 80, so nothing is served in the clear
        raise
    location = resp.header("location") or ""
    if resp.status in REDIRECT_CODES:
        if location.lower().startswith("https://"):
            return []
        detail = f"GET {plain} -> {resp.status} Location: {location[:200]}"
        title = "HTTP redirects somewhere other than HTTPS"
    elif resp.status < 400:
        detail = f"GET {plain} -> {resp.status}, content served over plain HTTP"
        title = "HTTP version of the site does not redirect to HTTPS"
    else:
        return []
    return [
        Finding(
            check_id="web.transport.no_https_redirect",
            title=title,
            severity=Severity.MEDIUM,
            category="web",
            target=target,
            location=plain,
            evidence=detail,
            description="Users who type the bare domain or follow an http:// link use an "
            "unencrypted connection that can be intercepted.",
            remediation="Answer every plain-HTTP request with a 301 redirect to the https:// "
            "URL, and enable HSTS.",
            key="no_https_redirect",
            confidence="certain",
        )
    ]


# --------------------------------------------------------------------------- exposed files


def _starts(prefix: bytes) -> Callable[[bytes], bool]:
    return lambda body: body.startswith(prefix)


def _contains(*needles: bytes) -> Callable[[bytes], bool]:
    return lambda body: any(n in body for n in needles)


def _regex(pattern: bytes) -> Callable[[bytes], bool]:
    rx = re.compile(pattern)
    return lambda body: bool(rx.search(body))


def _not_html(test: Callable[[bytes], bool]) -> Callable[[bytes], bool]:
    def check(body: bytes) -> bool:
        head = body[:2048].lower()
        return b"<html" not in head and b"<!doctype" not in head and test(body)

    return check


_ENV_LINE = re.compile(rb"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", re.M)


def _env_like(body: bytes) -> bool:
    head = body[:2048].lower()
    if b"<html" in head or b"<!doctype" in head:
        return False
    lines = [
        ln for ln in body[:65536].splitlines() if ln.strip() and not ln.strip().startswith(b"#")
    ]
    assignments = [ln for ln in lines if _ENV_LINE.match(ln)]
    return bool(assignments) and len(assignments) * 2 >= len(lines)


def _env_keys(body: bytes) -> str:
    keys = [m.group(1).decode("ascii", "replace") for m in _ENV_LINE.finditer(body[:65536])]
    more = f" (+{len(keys) - 12} more)" if len(keys) > 12 else ""
    return f"file defines {len(keys)} variables: {', '.join(keys[:12])}{more}; values not shown"


def _first_line(body: bytes) -> str:
    line = body[:300].split(b"\n", 1)[0].decode("utf-8", "replace").strip()
    return f"begins with: {line[:120]}"


def _git_remote(body: bytes) -> str:
    text = body[:8192].decode("utf-8", "replace")
    urls = re.findall(r"(?m)^\s*url\s*=\s*(\S+)", text)
    return "git config" + (f"; remote url: {redact(urls[0])}" if urls else "")


def _sql_tables(body: bytes) -> str:
    names = re.findall(rb"(?i)CREATE TABLE\s+(?:IF NOT EXISTS\s+)?[`\"]?([\w.]+)", body[:65536])
    tables = ", ".join(n.decode("utf-8", "replace") for n in names[:8])
    return "SQL dump" + (f" with tables: {tables}" if tables else "")


def _describe_binary(kind: str) -> Callable[[bytes], str]:
    return lambda body: f"{kind} ({len(body)} bytes read)"


@dataclass(frozen=True)
class Probe:
    path: str
    rule: str
    title: str
    severity: Severity
    matches: Callable[[bytes], bool]
    describe: Callable[[bytes], str]
    description: str
    remediation: str


_GIT_WHY = (
    "Anyone can download the source code and its full history - including every secret "
    "ever committed - with off-the-shelf tools."
)
_GIT_FIX = (
    "Block access to /.git (nginx: `location ~ /\\.git { deny all; }`) and deploy build "
    "artifacts rather than a working copy. Rotate any secret that was ever in the repo."
)
_ENV_WHY = "Environment files normally hold database passwords, API keys and signing secrets."
_ENV_FIX = (
    "Remove the file from the web root (or deny dotfiles in the web server), then rotate "
    "every credential it contained - assume they are already known."
)
_DUMP_WHY = "A downloadable database or backup exposes user data and password hashes directly."
_DUMP_FIX = "Delete the file from the web root, keep backups outside it, and review access logs for downloads."

PROBES: tuple[Probe, ...] = (
    Probe("/.git/HEAD", "git", "Git repository exposed over HTTP", Severity.CRITICAL,
          _not_html(_regex(rb"^(?:ref: refs/|[0-9a-f]{40}\s*$)")), _first_line, _GIT_WHY, _GIT_FIX),
    Probe("/.git/config", "git", "Git repository exposed over HTTP", Severity.CRITICAL,
          _not_html(_contains(b"[core]")), _git_remote, _GIT_WHY, _GIT_FIX),
    Probe("/.env", "env", "Environment file exposed over HTTP", Severity.CRITICAL,
          _env_like, _env_keys, _ENV_WHY, _ENV_FIX),
    Probe("/.env.production", "env", "Environment file exposed over HTTP", Severity.CRITICAL,
          _env_like, _env_keys, _ENV_WHY, _ENV_FIX),
    Probe("/.env.local", "env", "Environment file exposed over HTTP", Severity.CRITICAL,
          _env_like, _env_keys, _ENV_WHY, _ENV_FIX),
    Probe("/.env.bak", "env", "Environment file exposed over HTTP", Severity.CRITICAL,
          _env_like, _env_keys, _ENV_WHY, _ENV_FIX),
    Probe("/.aws/credentials", "aws_credentials", "AWS credentials file exposed", Severity.CRITICAL,
          _not_html(_contains(b"aws_access_key_id")), lambda b: "AWS shared credentials file (values not shown)",
          "Cloud credentials give direct access to your AWS account.",
          "Remove the file from the web root and deactivate the keys in IAM immediately."),
    Probe("/.htpasswd", "htpasswd", "Password file (.htpasswd) exposed", Severity.HIGH,
          _not_html(_regex(rb"(?m)^[^:\s]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|\$[156]\$)")),
          lambda b: "htpasswd file with password hashes (not shown)",
          "Password hashes can be cracked offline.",
          "Move .htpasswd outside the web root and change the affected passwords."),
    Probe("/.svn/wc.db", "svn", "Subversion metadata exposed", Severity.HIGH,
          _starts(b"SQLite format 3"), _describe_binary("SVN working-copy database"),
          "SVN metadata lets anyone reconstruct the source code.", "Block access to /.svn and deploy exports, not working copies."),
    Probe("/.hg/requires", "hg", "Mercurial repository exposed", Severity.HIGH,
          _not_html(_regex(rb"^(?:revlogv1|store|fncache|dotencode|generaldelta)")), _first_line,
          "Mercurial metadata lets anyone reconstruct the source code.", "Block access to /.hg and deploy exports, not working copies."),
    Probe("/.DS_Store", "ds_store", "macOS .DS_Store file exposed", Severity.LOW,
          _starts(b"\x00\x00\x00\x01Bud1"), _describe_binary(".DS_Store listing"),
          ".DS_Store files list the names of files in the directory, revealing unlinked content.",
          "Delete .DS_Store files from the deployment and deny dotfiles in the web server."),
    Probe("/server-status", "apache_status", "Apache server-status page exposed", Severity.MEDIUM,
          _contains(b"Apache Server Status"), lambda b: "Apache mod_status page",
          "server-status shows live requests (URLs, client IPs) and internal server details.",
          "Restrict /server-status to localhost or an admin network (`Require local`)."),
    Probe("/phpinfo.php", "phpinfo", "phpinfo() page exposed", Severity.MEDIUM,
          _contains(b"phpinfo()", b"PHP Version"), lambda b: "phpinfo() output",
          "phpinfo() discloses configuration, paths, environment variables and loaded modules.",
          "Delete phpinfo pages from production."),
    Probe("/info.php", "phpinfo", "phpinfo() page exposed", Severity.MEDIUM,
          _contains(b"phpinfo()", b"PHP Version"), lambda b: "phpinfo() output",
          "phpinfo() discloses configuration, paths, environment variables and loaded modules.",
          "Delete phpinfo pages from production."),
    Probe("/wp-config.php.bak", "config_backup", "Backup of a config file is downloadable", Severity.CRITICAL,
          _contains(b"DB_PASSWORD", b"<?php"), lambda b: "PHP configuration source (contents not shown)",
          "Config backups are served as plain text, disclosing database credentials and keys.",
          "Delete editor/backup copies from the web root and rotate the credentials they contain."),
    Probe("/config.php.bak", "config_backup", "Backup of a config file is downloadable", Severity.CRITICAL,
          _contains(b"<?php"), lambda b: "PHP source (contents not shown)",
          "Config backups are served as plain text, disclosing database credentials and keys.",
          "Delete editor/backup copies from the web root and rotate the credentials they contain."),
    Probe("/backup.sql", "sql_dump", "Database dump is downloadable", Severity.CRITICAL,
          _not_html(_regex(rb"(?i)CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump")),
          _sql_tables, _DUMP_WHY, _DUMP_FIX),
    Probe("/dump.sql", "sql_dump", "Database dump is downloadable", Severity.CRITICAL,
          _not_html(_regex(rb"(?i)CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump")),
          _sql_tables, _DUMP_WHY, _DUMP_FIX),
    Probe("/db.sqlite3", "sqlite", "SQLite database is downloadable", Severity.CRITICAL,
          _starts(b"SQLite format 3"), _describe_binary("SQLite database"), _DUMP_WHY, _DUMP_FIX),
    Probe("/database.sqlite", "sqlite", "SQLite database is downloadable", Severity.CRITICAL,
          _starts(b"SQLite format 3"), _describe_binary("SQLite database"), _DUMP_WHY, _DUMP_FIX),
    Probe("/backup.zip", "archive", "Backup archive is downloadable", Severity.HIGH,
          _starts(b"PK\x03\x04"), _describe_binary("zip archive"), _DUMP_WHY, _DUMP_FIX),
    Probe("/backup.tar.gz", "archive", "Backup archive is downloadable", Severity.HIGH,
          _starts(b"\x1f\x8b"), _describe_binary("gzip archive"), _DUMP_WHY, _DUMP_FIX),
    Probe("/actuator/env", "spring_actuator", "Spring Boot actuator /env is public", Severity.HIGH,
          _contains(b"propertySources", b"activeProfiles"), lambda b: "actuator environment dump",
          "The actuator env endpoint lists configuration properties, often including credentials.",
          "Expose only health/info actuators publicly (management.endpoints.web.exposure.include)."),
    Probe("/actuator/heapdump", "spring_heapdump", "Spring Boot heap dump is downloadable", Severity.CRITICAL,
          _starts(b"JAVA PROFILE"), _describe_binary("JVM heap dump"),
          "A heap dump contains everything in memory: sessions, tokens, passwords, keys.",
          "Disable the heapdump actuator in production and restrict all actuators to admins."),
    Probe("/debug/pprof/", "go_pprof", "Go pprof debug endpoints are public", Severity.MEDIUM,
          _contains(b"Types of profiles available"), lambda b: "pprof index page",
          "Profiling endpoints leak internals and can be used to exhaust server resources.",
          "Serve net/http/pprof only on an internal port."),
    Probe("/openapi.json", "api_spec", "API description is public", Severity.INFO,
          _not_html(_regex(rb'"(?:openapi|swagger)"\s*:')), lambda b: "OpenAPI/Swagger document",
          "Not a vulnerability by itself, but it maps every endpoint for an attacker - make "
          "sure each listed endpoint enforces authentication.",
          "Publish the spec only if intended; otherwise require authentication for it."),
    Probe("/swagger.json", "api_spec", "API description is public", Severity.INFO,
          _not_html(_regex(rb'"(?:openapi|swagger)"\s*:')), lambda b: "OpenAPI/Swagger document",
          "Not a vulnerability by itself, but it maps every endpoint for an attacker - make "
          "sure each listed endpoint enforces authentication.",
          "Publish the spec only if intended; otherwise require authentication for it."),
)


def check_exposure(http: HttpClient, origin_url: str) -> list[Finding]:
    """Look for well-known sensitive files at the origin root. A hit needs HTTP 200, a
    body that differs from the site's own 404 page, and content that matches the file
    type - so single-page apps that answer 200 to everything don't raise false alarms."""
    base = origin_url.rstrip("/")
    out: list[Finding] = []
    baseline = http.get(f"{base}/sentinel-{secrets.token_hex(6)}-missing", follow_redirects=False, max_body=65_536)
    soft_404 = baseline.status == 200
    baseline_hash = hashlib.sha256(baseline.body).digest()
    for sig, marker in debug_signatures(baseline.text()):
        out.append(
            Finding(
                check_id=f"web.exposure.debug_{sig.rule}",
                title=sig.title,
                severity=sig.severity,
                category="web",
                target=origin_url,
                location=f"{base}/<any missing page>",
                evidence=f"the error page for a missing URL contains '{marker}'",
                description=sig.description,
                remediation=sig.remediation,
                key=f"debug_{sig.rule}",
                confidence="certain",
            )
        )

    # One finding per kind of exposure (/.git/HEAD and /.git/config are one problem).
    hits: dict[str, list[tuple[Probe, str, str]]] = {}

    def collect() -> list[Finding]:
        found = list(out)
        for rule, matches in hits.items():
            probe, url, evidence = matches[0]
            also = [u for _p, u, _e in matches[1:]]
            found.append(
                Finding(
                    check_id=f"web.exposure.{rule}",
                    title=probe.title,
                    severity=max(p.severity for p, _u, _e in matches),
                    category="web",
                    target=origin_url,
                    location=url,
                    evidence=evidence + (f"; also exposed: {', '.join(also)}" if also else ""),
                    description=probe.description,
                    remediation=probe.remediation,
                    key=rule,
                    confidence="certain",
                )
            )
        return found

    failures: list[str] = []
    checked: list[str] = []

    def progress() -> str:
        exposed = sum(len(m) for m in hits.values())
        return f"checked {len(checked)} of {len(PROBES)} paths ({exposed} exposed) before stopping"

    for probe in PROBES:
        url = base + probe.path
        try:
            resp = http.get(url, follow_redirects=False, max_body=65_536)
        except FetchError as exc:
            failures.append(str(exc))
            if len(failures) > 3:
                raise CheckIncomplete(f"{progress()}; {len(failures)} requests failed, last: {exc}", collect()) from exc
            continue
        except Exception as exc:  # budget spent or scope problem: keep what we have
            raise CheckIncomplete(f"{progress()}: {exc}", collect()) from exc
        checked.append(probe.path)
        if resp.status != 200 or not resp.body:
            continue
        if soft_404 and hashlib.sha256(resp.body).digest() == baseline_hash:
            continue
        if probe.matches(resp.body):
            hits.setdefault(probe.rule, []).append((probe, url, redact(probe.describe(resp.body))))
    if failures:
        raise CheckIncomplete(f"{progress()}; {len(failures)} request(s) failed, last: {failures[-1]}", collect())
    return collect()


def check_security_txt(http: HttpClient, origin_url: str) -> list[Finding]:
    url = origin_url.rstrip("/") + "/.well-known/security.txt"
    resp = http.get(url, max_body=32_768)
    if resp.status == 200 and not resp.is_html and re.search(r"(?im)^contact:", resp.text()):
        return []
    return [
        Finding(
            check_id="web.securitytxt.missing",
            title="No security.txt",
            severity=Severity.INFO,
            category="web",
            target=origin_url,
            location=url,
            evidence=f"GET {url} -> {resp.status}",
            description="security.txt (RFC 9116) tells researchers how to report a "
            "vulnerability to you instead of disclosing it publicly.",
            remediation="Publish /.well-known/security.txt with at least Contact: and Expires: fields.",
            references=["https://securitytxt.org/"],
            key="missing",
        )
    ]
