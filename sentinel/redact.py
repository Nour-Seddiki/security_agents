"""Secret patterns: used both to find secrets in code and to redact them from everything
Sentinel writes or sends - reports, emails, and whatever the agent is shown.

A secret value never leaves this module unmasked: findings carry `mask(value)`, and the
agent's file and HTTP tools run their output through `redact()` first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Severity


@dataclass(frozen=True)
class SecretRule:
    name: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    group: int = 0  # the capture group holding the secret itself
    confidence: str = "firm"
    # A fallback default is the problem even when it reads like "change-me": it is what
    # runs whenever the environment variable is missing.
    flag_placeholders: bool = False
    description: str = ""  # overrides the generic "leaked credential" wording
    remediation: str = ""


_FALLBACK_WHY = (
    "If the environment variable is ever missing - a new host, a renamed setting, a typo - the "
    "application silently runs with this default, and anyone who has seen the code knows it: "
    "they can forge login tokens or sign sessions."
)
_FALLBACK_FIX = (
    "Remove the default and fail at startup when the variable is missing. Check that production "
    "sets it, and rotate it if the service may ever have run on the default."
)
_SECRET_NAME = r"\w*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|SIGNING_?KEY)\w*"


_NL = r"(?:\r?\n|\\n)"  # a real newline, or a literal \n inside a JSON/env string

SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "private_key",
        "Private key committed",
        Severity.CRITICAL,
        # The header alone (docs, tests, parsers) is not a key: require key material.
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[ \t]*"
            + _NL
            + r"(?:[\w-]+:[^\n\\]*"
            + _NL
            + r"|[ \t]*"
            + _NL
            + r"){0,4}[A-Za-z0-9+/=]{40,}"
        ),
    ),
    SecretRule(
        "aws_access_key",
        "AWS access key ID",
        Severity.CRITICAL,
        re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        1,
    ),
    SecretRule(
        "aws_secret_key",
        "AWS secret access key",
        Severity.CRITICAL,
        re.compile(
            r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        1,
    ),
    SecretRule(
        "github_token",
        "GitHub token",
        Severity.CRITICAL,
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"),
        1,
    ),
    SecretRule(
        "gitlab_token",
        "GitLab token",
        Severity.CRITICAL,
        re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})"),
        1,
    ),
    SecretRule(
        "anthropic_key",
        "Anthropic API key",
        Severity.CRITICAL,
        re.compile(r"\b(sk-ant-(?:api|admin|oat)\d{2}-[A-Za-z0-9_\-]{20,})"),
        1,
    ),
    SecretRule(
        "openai_key",
        "OpenAI API key",
        Severity.CRITICAL,
        re.compile(r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"),
        1,
    ),
    SecretRule(
        "stripe_key",
        "Stripe live secret key",
        Severity.CRITICAL,
        re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})"),
        1,
    ),
    SecretRule(
        "slack_token",
        "Slack token",
        Severity.HIGH,
        re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})"),
        1,
    ),
    SecretRule(
        "sendgrid_key",
        "SendGrid API key",
        Severity.HIGH,
        re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})"),
        1,
    ),
    SecretRule(
        "google_api_key",
        "Google API key",
        Severity.HIGH,
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"),
        1,
    ),
    SecretRule(
        "slack_webhook",
        "Slack incoming-webhook URL",
        Severity.MEDIUM,
        re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9_/]{20,})"),
        1,
    ),
    SecretRule(
        "url_credentials",
        "Password embedded in a connection URL",
        Severity.HIGH,
        re.compile(r"(?i)\b[a-z][a-z0-9+.\-]{1,20}://[^\s:@/'\"`<>]{1,64}:([^\s@/'\"`<>]{3,128})@[^\s'\"`<>]+"),
        1,
    ),
    SecretRule(
        "secret_fallback",
        "Secret setting falls back to a hardcoded default",
        Severity.HIGH,
        re.compile(
            r"""(?i)\b(?:getenv|environ\.get|env\.get)\(\s*["']""" + _SECRET_NAME + r"""["']\s*,\s*[rbuRBU]?["']([^"'\n]{4,})["']"""
        ),
        1,
        flag_placeholders=True,
        description=_FALLBACK_WHY,
        remediation=_FALLBACK_FIX,
    ),
    SecretRule(
        "secret_fallback_js",
        "Secret setting falls back to a hardcoded default",
        Severity.HIGH,
        re.compile(r"""(?i)\bprocess\.env\.""" + _SECRET_NAME + r"""\s*(?:\|\||\?\?)\s*["'`]([^"'`\n]{4,})["'`]"""),
        1,
        flag_placeholders=True,
        description=_FALLBACK_WHY,
        remediation=_FALLBACK_FIX,
    ),
    SecretRule(
        "framework_secret_key",
        "Hardcoded framework SECRET_KEY",
        Severity.HIGH,
        re.compile(
            r"""(?m)^\s*(?:app\.config\[["']SECRET_KEY["']\]|app\.secret_key|SECRET_KEY)\s*=\s*[rbuRBU]?["']([^"'\n]{12,})["']"""
        ),
        1,
    ),
    SecretRule(
        "jwt",
        "JSON Web Token",
        Severity.MEDIUM,
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
        1,
        "tentative",
    ),
    SecretRule(
        "generic_secret",
        "Hardcoded password or secret",
        Severity.MEDIUM,
        re.compile(
            r"""(?i)\b[\w-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)[\w-]*["']?\s*[:=]\s*[rbuRBU]?["']([^"'\s]{8,})["']"""
        ),
        1,
        "tentative",
    ),
)

# Redaction-only patterns: shapes that carry secrets but are too noisy to report on.
_PEM_BLOCK = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----)(.*?)(-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.S,
)
_ENV_ASSIGNMENT = re.compile(
    r"(?im)^(\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?)[A-Z0-9_]*\s*[=:]\s*)([^\s#]\S*)"
)
_AUTH_HEADER = re.compile(
    r"(?i)(\bauthorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic|token)\s+)([A-Za-z0-9._~+/=\-]{8,})"
)

_PLACEHOLDER = re.compile(
    r"""(?ix)^(?:
        x+ | \*+ | \.+ | -+ | _+ | 0+ | \#+ |
        <[^>]*> | \$\{[^}]*\} | \$[A-Z_][A-Z0-9_]* | \{\{[^}]*\}\} | \{[^}]*\} | %\([^)]*\)s | %s |
        (?:your|my|some|the|enter)[_\-]?.* |
        .*(?:example|sample|dummy|placeholder|changeme|change[_-]me|redacted|replace[_-]?me|fake|xxxx|todo|insert[_-]).* |
        password\d* | passw(?:or)?d | pass | secret | admin | root | test(?:ing)? | postgres | mysql |
        guest | user | default | none | null | true | false
    )$"""
)
_CODE_REFERENCE = re.compile(r"^(?:os\.environ|os\.getenv|process\.env|env\(|config\[|settings\.)", re.I)


def is_placeholder(value: str) -> bool:
    """True for template/example values nobody could log in with."""
    v = value.strip().strip("\"'")
    return not v or bool(_PLACEHOLDER.match(v)) or bool(_CODE_REFERENCE.match(v))


def looks_like_secret(value: str) -> bool:
    """Cheap entropy test for the generic rule: skips URLs, paths and plain words."""
    v = value.strip()
    if v.startswith(("/", "./", "http://", "https://")) or " " in v:
        return False
    if re.search(r"\{[^}]*\}|\$\{|%\(|%s", v):
        return False  # a template ("sk_{env}_key", "%(password)s"), not a literal
    classes = sum(
        (
            any(c.islower() for c in v),
            any(c.isupper() for c in v),
            any(c.isdigit() for c in v),
            any(not c.isalnum() for c in v),
        )
    )
    if re.fullmatch(r"[a-z_]+", v) or re.fullmatch(r"[A-Z_]+", v):
        return False  # identifiers such as "password_reset" or "API_KEY_NAME"
    return classes >= 2 or len(v) >= 20


def mask(value: str) -> str:
    """Enough to recognise which credential it is, never enough to use it."""
    v = value.strip()
    if len(v) >= 16:
        return f"{v[:4]}...[redacted {len(v)} chars]"
    return "[redacted]"


def _mask_group(match: re.Match[str], group: int, force: bool = False) -> str:
    value = match.group(group)
    if value is None or "[redacted" in value or (is_placeholder(value) and not force):
        return match.group(0)
    whole = match.group(0)
    start = match.start(group) - match.start(0)
    end = match.end(group) - match.start(0)
    return whole[:start] + mask(value) + whole[end:]


def redact(text: str) -> str:
    """Mask every secret-shaped value in `text`."""
    if not text:
        return text
    text = _PEM_BLOCK.sub(lambda m: f"{m.group(1)}\n[private key redacted]\n{m.group(3)}", text)
    for rule in SECRET_RULES:
        if rule.name == "private_key":
            continue
        # A fallback default is masked even when it reads like "change-me": it is the key
        # the service really uses whenever the variable is missing.
        text = rule.pattern.sub(lambda m, g=rule.group, f=rule.flag_placeholders: _mask_group(m, g, f), text)
    text = _ENV_ASSIGNMENT.sub(lambda m: _mask_group(m, 2), text)
    text = _AUTH_HEADER.sub(lambda m: _mask_group(m, 2), text)
    return text
