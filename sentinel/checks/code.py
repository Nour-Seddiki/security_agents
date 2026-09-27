"""Source checks: committed secrets, risky code patterns and insecure configuration.

Only files that are (or could be) committed are read. In a git repository that is
`git ls-files --cached --others --exclude-standard`, so ignored files - a local .env,
virtualenvs, build output - are skipped exactly as they would be on push. Outside git,
the tree is walked with the usual vendor/build directories pruned.
"""

from __future__ import annotations

import ast
import fnmatch
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding, Severity
from ..redact import SECRET_RULES, is_placeholder, looks_like_secret, mask, redact

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv", "env",
    "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".next", ".nuxt", ".svelte-kit", "site-packages", "vendor",
    ".idea", ".vscode", "coverage", ".terraform", ".gradle", "target",
}
BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svgz", ".pdf", ".zip", ".gz",
    ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".whl", ".egg", ".pyc", ".pyo", ".so",
    ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".class", ".jar", ".war", ".pt", ".pth",
    ".ckpt", ".safetensors", ".onnx", ".h5", ".npy", ".npz", ".pkl", ".parquet", ".feather",
    ".db", ".sqlite", ".sqlite3", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4",
    ".wav", ".ogg", ".mov", ".avi", ".webm", ".ipynb_checkpoints",
}
PY_SUFFIXES = {".py", ".pyw"}
JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"}
OWASP_SECRETS = "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"


# --------------------------------------------------------------------------- file listing


@dataclass
class RepoFiles:
    label: str
    root: Path
    files: list[str]  # posix paths relative to root
    mode: str  # "git" or "walk"
    skipped_large: int = 0
    _cache: dict[str, str | None] = field(default_factory=dict, repr=False)

    def read_text(self, rel: str) -> str | None:
        """Decoded file contents, or None for binary/unreadable files."""
        if rel in self._cache:
            return self._cache[rel]
        try:
            data = (self.root / rel).read_bytes()
        except OSError:
            text = None
        else:
            text = None if b"\x00" in data[:8192] else data.decode("utf-8", errors="replace")
        if len(self._cache) < 4000:
            self._cache[rel] = text
        return text

    def with_suffix(self, suffixes: set[str]) -> list[str]:
        return [f for f in self.files if Path(f).suffix.lower() in suffixes]


def _git_files(root: Path) -> list[str] | None:
    """Committed plus committable files, or None when `root` isn't really a git checkout.

    A folder counts as one if it has its own .git, or if the enclosing repository tracks
    files inside it (a monorepo sub-folder). A folder that merely sits somewhere under an
    unrelated repository - a home directory kept in git, say - is walked instead, so that
    repository's ignore rules don't decide what gets scanned.
    """
    git = shutil.which("git")
    if not git:
        return None
    # core.fsmonitor=false: never let repository config launch a helper process.
    base = [git, "-c", "core.fsmonitor=false", "-C", str(root)]

    def ls(*args: str) -> list[str] | None:
        proc = subprocess.run(base + ["ls-files", "-z", *args], capture_output=True, timeout=120)
        if proc.returncode != 0:
            return None
        return [p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p]

    try:
        inside = subprocess.run(base + ["rev-parse", "--is-inside-work-tree"], capture_output=True, text=True, timeout=30)
        if inside.returncode != 0 or inside.stdout.strip() != "true":
            return None
        tracked = ls("--cached")
        if tracked is None or (not tracked and not (root / ".git").exists()):
            return None
        others = ls("--others", "--exclude-standard")
    except (OSError, subprocess.SubprocessError):
        return None
    if others is None:
        return None
    return list(dict.fromkeys(tracked + others))


def sync_checkout(url: str, dest: Path, timeout: float = 300.0) -> str:
    """Shallow-clone `url` into `dest`, or bring an existing checkout up to date.

    Prompts are disabled so a scheduled run fails fast on a private repository without
    credentials, and Git LFS content is not downloaded.
    """
    git = shutil.which("git")
    if not git:
        raise OSError("git is not installed, so remote repositories can't be fetched")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}

    def run(*args: str) -> None:
        try:
            proc = subprocess.run(
                [git, "-c", "core.fsmonitor=false", *args], capture_output=True, text=True, timeout=timeout, env=env
            )
        except subprocess.TimeoutExpired as exc:
            raise OSError(f"git {args[0] if args[0] != '-C' else args[2]} timed out after {timeout:.0f}s") from exc
        if proc.returncode != 0:
            lines = [ln for ln in (proc.stderr or proc.stdout).strip().splitlines() if ln.strip()]
            raise OSError(lines[-1] if lines else f"git exited with status {proc.returncode}")

    if (dest / ".git").exists():
        run("-C", str(dest), "fetch", "--depth", "1", "--quiet", "origin", "HEAD")
        run("-C", str(dest), "reset", "--hard", "--quiet", "FETCH_HEAD")
        return "updated"
    if dest.exists() and any(dest.iterdir()):
        raise OSError(f"{dest} exists but is not a git checkout")
    dest.parent.mkdir(parents=True, exist_ok=True)
    run("clone", "--depth", "1", "--quiet", "--", url, str(dest))
    return "cloned"


def _walk_files(root: Path) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        for name in filenames:
            out.append(name if rel_dir == "." else f"{rel_dir}/{name}")
    return out


def list_repo_files(label: str, root: Path, exclude: list[str] | tuple = (), max_bytes: int = 1 << 20) -> RepoFiles:
    rels = _git_files(root)
    mode = "git"
    if rels is None:
        rels, mode = _walk_files(root), "walk"
    keep, skipped_large = [], 0
    real_root = root.resolve()
    for rel in rels:
        parts = rel.split("/")
        if any(p in SKIP_DIRS for p in parts[:-1]):
            continue
        if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(parts[-1], pat) or pat in parts[:-1] for pat in exclude):
            continue
        if Path(rel).suffix.lower() in BINARY_SUFFIXES:
            continue
        path = root / rel
        try:
            if not path.is_file():
                continue  # tracked but deleted from the working tree
            if real_root not in path.resolve().parents:
                continue  # a symlink out of the repository: never read what it points at
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_bytes:
            skipped_large += 1
            continue
        keep.append(rel)
    return RepoFiles(label, root, sorted(keep), mode, skipped_large)


def _line_of(text: str, pos: int) -> tuple[int, str]:
    lineno = text.count("\n", 0, pos) + 1
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return lineno, text[start : end if end != -1 else len(text)]


def _evidence(rel: str, lineno: int, line: str) -> str:
    return f"{rel}:{lineno}: {redact(line.strip())[:200]}"


# --------------------------------------------------------------------------- secrets


def find_secrets(label: str, rel: str, text: str) -> list[Finding]:
    candidates = []
    for rule in SECRET_RULES:
        for m in rule.pattern.finditer(text):
            value = m.group(rule.group)
            if rule.name != "private_key":
                if is_placeholder(value) and not (rule.flag_placeholders and value.strip()):
                    continue
                if rule.name == "generic_secret" and not looks_like_secret(value):
                    continue
            candidates.append((rule, m.start(rule.group), m.end(rule.group), value))
    # The same value can match several rules (SECRET_KEY = ... is also "generic"):
    # keep the most specific (most severe) match for each span.
    candidates.sort(key=lambda c: (-c[0].severity, c[1]))
    kept: list[tuple] = []
    for cand in candidates:
        if not any(cand[1] < k[2] and k[1] < cand[2] for k in kept):
            kept.append(cand)
    kept.sort(key=lambda c: c[1])

    out, seen = [], {}
    for rule, start, _end, value in kept:
        lineno, line = _line_of(text, start)
        n = seen.get(rule.name, 0)
        seen[rule.name] = n + 1
        evidence = _evidence(rel, lineno, line)
        if rule.name != "private_key" and value in evidence:  # belt and braces: never echo the value
            evidence = evidence.replace(value, mask(value))
        out.append(
            Finding(
                check_id=f"code.secrets.{rule.name}",
                title=f"{rule.title} in {rel}",
                severity=rule.severity,
                category="secrets",
                target=label,
                location=f"{rel}:{lineno}",
                evidence=evidence,
                description=rule.description
                or "Anyone who can read this repository - or any clone, fork, CI log "
                "or backup of it, and its whole git history - can use this credential.",
                remediation=rule.remediation
                or "Revoke or rotate the credential now, load it from the environment or "
                "a secret manager instead, and purge it from git history (git filter-repo) if "
                "the repository was ever shared.",
                references=[OWASP_SECRETS],
                key=f"{rel}:{rule.name}:{n}",
                confidence=rule.confidence,
            )
        )
    return out


def scan_secrets(repo: RepoFiles) -> list[Finding]:
    out = []
    for rel in repo.files:
        text = repo.read_text(rel)
        if text:
            out.extend(find_secrets(repo.label, rel, text))
    return out


# --------------------------------------------------------------------------- Python


@dataclass(frozen=True)
class CodeRule:
    title: str
    severity: Severity
    description: str
    remediation: str


PY_RULES: dict[str, CodeRule] = {
    "eval": CodeRule(
        "eval()/exec() on a non-literal value", Severity.MEDIUM,
        "If any part of the argument can come from a user, this is arbitrary code execution.",
        "Avoid eval/exec: parse data with json or ast.literal_eval, or dispatch through an explicit mapping.",
    ),
    "shell_injection": CodeRule(
        "Shell command built from variables", Severity.HIGH,
        "A formatted string passed to a shell lets metacharacters in any interpolated value "
        "run extra commands (command injection).",
        "Call subprocess with an argument list and shell=False (the default); never interpolate input into a shell string.",
    ),
    "sql_injection": CodeRule(
        "SQL query built with string formatting", Severity.HIGH,
        "Interpolating values into SQL text allows SQL injection whenever a value is user-controlled.",
        "Use parameterized queries: cursor.execute('... WHERE id = %s', (value,)) or the ORM's query builder.",
    ),
    "pickle": CodeRule(
        "Unsafe deserialization (pickle/marshal)", Severity.MEDIUM,
        "Unpickling attacker-controlled bytes executes arbitrary code.",
        "Only unpickle data you produced and stored securely; use JSON (or a signed format) across trust boundaries.",
    ),
    "yaml_load": CodeRule(
        "yaml.load without SafeLoader", Severity.MEDIUM,
        "PyYAML's full loaders can construct arbitrary Python objects from a document.",
        "Use yaml.safe_load() or Loader=yaml.SafeLoader.",
    ),
    "tls_verify_off": CodeRule(
        "TLS certificate verification disabled", Severity.MEDIUM,
        "Connections made this way accept any certificate, so the traffic can be intercepted.",
        "Remove verify=False / CERT_NONE; for a private CA pass its bundle (verify='/path/ca.pem').",
    ),
    "jwt_no_verify": CodeRule(
        "JWT decoded without verifying the signature", Severity.HIGH,
        "Anyone can forge a token with arbitrary claims when signatures aren't checked.",
        "Always verify: jwt.decode(token, key, algorithms=['HS256' or 'RS256']) and never allow 'none'.",
    ),
    "debug_server": CodeRule(
        "Application started with debug=True", Severity.MEDIUM,
        "Framework debug servers expose interactive debuggers or detailed errors; the Werkzeug "
        "debugger allows code execution.",
        "Keep debug off outside local development: read it from an environment variable that defaults to False.",
    ),
    "debug_setting": CodeRule(
        "DEBUG = True in a settings module", Severity.MEDIUM,
        "If this settings module is used in production, error pages disclose code, settings and environment.",
        "Set DEBUG from the environment and default it to False.",
    ),
    "template_injection": CodeRule(
        "Template rendered from a non-literal string", Severity.HIGH,
        "render_template_string with user-influenced template text allows server-side template "
        "injection, which usually means code execution.",
        "Render templates from files and pass user data as context variables, never as template source.",
    ),
    "mark_safe": CodeRule(
        "HTML marked safe from a non-literal value", Severity.LOW,
        "Marking dynamic content safe disables auto-escaping; with user input this is XSS.",
        "Escape user content (format_html, markupsafe.escape) instead of marking it safe.",
    ),
    "mktemp": CodeRule(
        "tempfile.mktemp() is race-prone", Severity.LOW,
        "Another process can create the file between name generation and use.",
        "Use tempfile.mkstemp() or NamedTemporaryFile().",
    ),
}

SQL_WORDS = re.compile(r"(?i)\b(select|insert|update|delete|create|drop|alter|where|values|into)\b")
SQL_SINKS = {"execute", "executemany", "executescript", "raw", "text", "read_sql", "read_sql_query", "extra"}
SHELL_FUNCS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput"}
PICKLE_MODULES = {"pickle", "cPickle", "_pickle", "dill", "marshal", "shelve"}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func) + "()")
    else:
        parts.append("?")
    return ".".join(reversed(parts))


def _const_str(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _dynamic_string(node: ast.AST) -> bool:
    """f-string with placeholders, %-formatting, .format() or concatenation."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _const_str(node.left)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return not (_const_str(node.left) and _const_str(node.right))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _const_str(node.func.value)
    return False


def _literal_text(node: ast.AST) -> str:
    if _const_str(node):
        value = node.value  # type: ignore[attr-defined]
        return value.decode("utf-8", "replace") if isinstance(value, bytes) else value
    if isinstance(node, ast.JoinedStr):
        return "".join(_literal_text(v) for v in node.values if isinstance(v, ast.Constant))
    if isinstance(node, ast.BinOp):
        return _literal_text(node.left) + " " + _literal_text(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return _literal_text(node.func.value)
    return ""


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[tuple[str, int]] = []

    def hit(self, rule: str, node: ast.AST) -> None:
        self.hits.append((rule, getattr(node, "lineno", 1)))

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        last = name.rsplit(".", 1)[-1]
        head = name.split(".", 1)[0]
        first = node.args[0] if node.args else None
        dynamic_first = first is not None and not _const_str(first)

        if name in ("eval", "exec") and dynamic_first:
            self.hit("eval", node)
        if _is_true(_kw(node, "shell")) and dynamic_first:
            self.hit("shell_injection", node)
        elif name in SHELL_FUNCS and dynamic_first:
            self.hit("shell_injection", node)
        if last in SQL_SINKS and first is not None and _dynamic_string(first) and SQL_WORDS.search(_literal_text(first)):
            self.hit("sql_injection", node)
        if head in PICKLE_MODULES and last in ("load", "loads", "Unpickler", "open"):
            self.hit("pickle", node)
        if name in ("yaml.load", "yaml.load_all"):
            loader = _kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            if loader is None or _dotted(loader).rsplit(".", 1)[-1] not in SAFE_YAML_LOADERS:
                self.hit("yaml_load", node)
        elif name in ("yaml.unsafe_load", "yaml.unsafe_load_all"):
            self.hit("yaml_load", node)
        if _is_false(_kw(node, "verify")):
            self.hit("jwt_no_verify" if "jwt" in name.lower() else "tls_verify_off", node)
        if last == "_create_unverified_context":
            self.hit("tls_verify_off", node)
        if "jwt" in name.lower() and last == "decode":
            options = _kw(node, "options")
            if isinstance(options, ast.Dict):
                for k, v in zip(options.keys, options.values):
                    if isinstance(k, ast.Constant) and k.value == "verify_signature" and _is_false(v):
                        self.hit("jwt_no_verify", node)
            algorithms = _kw(node, "algorithms")
            if isinstance(algorithms, (ast.List, ast.Tuple)) and any(
                isinstance(e, ast.Constant) and str(e.value).lower() == "none" for e in algorithms.elts
            ):
                self.hit("jwt_no_verify", node)
        if last == "run" and _is_true(_kw(node, "debug")):
            self.hit("debug_server", node)
        if last == "render_template_string" and dynamic_first:
            self.hit("template_injection", node)
        if last in ("mark_safe", "Markup") and dynamic_first:
            self.hit("mark_safe", node)
        if name == "tempfile.mktemp":
            self.hit("mktemp", node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                if target.attr == "verify_mode" and _dotted(node.value).endswith("CERT_NONE"):
                    self.hit("tls_verify_off", node)
                elif target.attr == "check_hostname" and _is_false(node.value):
                    self.hit("tls_verify_off", node)
        self.generic_visit(node)


def analyze_python(label: str, rel: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text, filename=rel)
    except (SyntaxError, ValueError):
        return []
    visitor = _PythonVisitor()
    visitor.visit(tree)
    if re.search(r"(^|/)(settings|config)[^/]*\.py$", rel, re.I):
        for stmt in tree.body:  # module level only
            if isinstance(stmt, ast.Assign) and _is_true(stmt.value) and any(
                isinstance(t, ast.Name) and t.id == "DEBUG" for t in stmt.targets
            ):
                visitor.hit("debug_setting", stmt)
    return _code_findings(label, rel, text, visitor.hits, "python", PY_RULES)


def _code_findings(label, rel, text, hits, family, rules) -> list[Finding]:
    """One finding per rule per file, listing every line: the file is the unit someone
    fixes, and 50 separate alerts for one pattern in one file help nobody."""
    lines = text.splitlines()
    by_rule: dict[str, list[int]] = {}
    for rule_name, lineno in hits:
        found = by_rule.setdefault(rule_name, [])
        if lineno not in found:
            found.append(lineno)
    out = []
    for rule_name, linenos in sorted(by_rule.items(), key=lambda item: min(item[1])):
        linenos.sort()
        rule = rules[rule_name]
        first = linenos[0]
        evidence = _evidence(rel, first, lines[first - 1] if 0 < first <= len(lines) else "")
        if len(linenos) > 1:
            shown = ", ".join(str(n) for n in linenos[1:15]) + (", ..." if len(linenos) > 15 else "")
            evidence += f"  (also lines {shown})"
        out.append(
            Finding(
                check_id=f"code.{family}.{rule_name}",
                title=rule.title + (f" ({len(linenos)} places)" if len(linenos) > 1 else ""),
                severity=rule.severity,
                category="code",
                target=label,
                location=f"{rel}:{first}",
                evidence=evidence,
                description=rule.description,
                remediation=rule.remediation,
                key=f"{rel}:{rule_name}",
                confidence="tentative",
            )
        )
    return out


def scan_python(repo: RepoFiles) -> list[Finding]:
    out = []
    for rel in repo.with_suffix(PY_SUFFIXES):
        text = repo.read_text(rel)
        if text:
            out.extend(analyze_python(repo.label, rel, text))
    return out


# --------------------------------------------------------------------------- JavaScript


@dataclass(frozen=True)
class RegexRule:
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    description: str
    remediation: str
    requires: re.Pattern[str] | None = None


JS_RULES: dict[str, RegexRule] = {
    "eval": RegexRule(
        "eval() or new Function() on dynamic input", Severity.MEDIUM,
        re.compile(r"(?<![\w.$])eval\s*\(\s*(?![\"'`][^\"'`]*[\"'`]\s*\))|\bnew\s+Function\s*\("),
        "If any part of the evaluated string can come from a user, this is code injection.",
        "Remove eval/new Function; use JSON.parse or an explicit lookup table.",
    ),
    "command_injection": RegexRule(
        "Shell command built from a template or concatenation", Severity.HIGH,
        re.compile(r"\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^,)\n]*\+)"),
        "child_process.exec runs a shell; interpolated values can inject extra commands.",
        "Use execFile/spawn with an argument array (no shell) and validate inputs.",
        requires=re.compile(r"child_process"),
    ),
    "sql_injection": RegexRule(
        "SQL built with a template literal", Severity.HIGH,
        re.compile(r"\.(?:query|execute|raw|unsafe)\s*\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{", re.I),
        "Interpolating values into SQL text allows SQL injection.",
        "Use parameterized queries (placeholders plus a values array) or the query builder.",
    ),
    "tls_verify_off": RegexRule(
        "TLS certificate verification disabled", Severity.MEDIUM,
        re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0"),
        "Connections made this way accept any certificate, so the traffic can be intercepted.",
        "Remove rejectUnauthorized:false; trust a private CA with the `ca` option instead.",
    ),
    "jwt_none": RegexRule(
        "JWT 'none' algorithm allowed", Severity.HIGH,
        re.compile(r"algorithms\s*:\s*\[[^\]]*[\"']none[\"']", re.I),
        "Allowing alg=none lets anyone forge tokens without a key.",
        "Pin the expected algorithm (e.g. algorithms: ['RS256']).",
    ),
    "inline_handler_string": RegexRule(
        "Value interpolated into a string inside an inline event handler", Severity.MEDIUM,
        re.compile(r"""\bon[a-z]+\s*=\s*(?:"[^"\n]*'\$\{|'[^'\n]*"\$\{)"""),
        "Browsers decode HTML entities in an attribute before running the handler, so escapeHtml() "
        "does not protect a value placed inside a JavaScript string in onclick=\"...\": the handler "
        "receives the raw text, and a value like x');alert(1);// - or HTML that the handler later "
        "writes into the page - runs as code when the element is clicked.",
        "Pass only numeric ids to inline handlers and look the rest up in JavaScript, or attach "
        "handlers with addEventListener and read values from data- attributes.",
    ),
    "dom_xss": RegexRule(
        "HTML sink fed with dynamic content", Severity.LOW,
        re.compile(
            # Skip assignments of a complete string literal (quotes inside are fine) or a
            # template with no ${...}: static markup can't carry user input.
            r"dangerouslySetInnerHTML"
            r"|\.(?:innerHTML|outerHTML)\s*=(?!=)"
            r"(?!\s*(?:'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"|`[^`$]*`)\s*(?:;|$|//|\}))"
            r"|document\.write\s*\(",
            re.M,
        ),
        "Writing unescaped strings into the DOM is cross-site scripting when they contain user input.",
        "Use textContent, or sanitize with a vetted library (DOMPurify) before inserting HTML.",
    ),
}


def analyze_javascript(label: str, rel: str, text: str) -> list[Finding]:
    hits = []
    for rule_name, rule in JS_RULES.items():
        if rule.requires is not None and not rule.requires.search(text):
            continue
        for m in rule.pattern.finditer(text):
            hits.append((rule_name, text.count("\n", 0, m.start()) + 1))
    return _code_findings(label, rel, text, hits, "js", JS_RULES)


def scan_javascript(repo: RepoFiles) -> list[Finding]:
    out = []
    for rel in repo.with_suffix(JS_SUFFIXES):
        if rel.endswith((".min.js", ".bundle.js")):
            continue
        text = repo.read_text(rel)
        if text:
            out.extend(analyze_javascript(repo.label, rel, text))
    return out


# --------------------------------------------------------------------------- configuration

ENV_FILE = re.compile(r"(^|/)\.env(\.[\w.-]+)?$")
ENV_TEMPLATE = re.compile(r"\.(example|sample|template|dist|defaults?|tpl)$", re.I)
DB_PORTS = "5432|3306|6379|27017|9200|11211|1433|1521|5984|9042"


def _config_finding(label, rel, rule, title, severity, evidence, description, remediation, lineno=None, n=0):
    location = f"{rel}:{lineno}" if lineno else rel
    return Finding(
        check_id=f"code.config.{rule}",
        title=title,
        severity=severity,
        category="config",
        target=label,
        location=location,
        evidence=evidence,
        description=description,
        remediation=remediation,
        key=f"{rel}:{rule}:{n}",
        confidence="firm",
    )


def _regex_config(label, rel, text, rule, pattern, title, severity, description, remediation) -> list[Finding]:
    out = []
    for n, m in enumerate(re.finditer(pattern, text)):
        lineno, line = _line_of(text, m.start())
        out.append(_config_finding(label, rel, rule, title, severity, _evidence(rel, lineno, line), description, remediation, lineno, n))
    return out


def _dockerfile(label: str, rel: str, text: str) -> list[Finding]:
    out = []
    if re.search(r"(?im)^\s*FROM\s", text) and not re.search(r"(?im)^\s*USER\s+(?!root\b|0\b)\S+", text):
        out.append(
            _config_finding(
                label, rel, "docker_root", "Container runs as root", Severity.LOW,
                f"{rel}: no USER instruction switches away from root",
                "A compromise of the application gives root inside the container, which makes "
                "container escapes and host damage much easier.",
                "Create an unprivileged user and add `USER app` before the CMD/ENTRYPOINT.",
            )
        )
    for n, m in enumerate(
        re.finditer(r"(?im)^\s*(?:ENV|ARG)\s+(\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)\w*)[= ]\s*(\S+)", text)
    ):
        value = m.group(2).strip("\"'")
        if is_placeholder(value) or value.startswith("$"):
            continue
        lineno, _line = _line_of(text, m.start())
        out.append(
            _config_finding(
                label, rel, "docker_secret", f"Secret baked into the image ({m.group(1)})", Severity.HIGH,
                f"{rel}:{lineno}: {m.group(1)}={mask(value)}",
                "Values set with ENV/ARG are stored in the image layers and visible to anyone "
                "who can pull the image (docker history).",
                "Pass secrets at runtime (environment, Docker/Kubernetes secrets, BuildKit --secret), not in the Dockerfile.",
                lineno, n,
            )
        )
    return out


def scan_config(repo: RepoFiles) -> list[Finding]:
    out: list[Finding] = []
    gitignore = repo.read_text(".gitignore") or ""
    for rel in repo.files:
        name = rel.rsplit("/", 1)[-1]
        lower = name.lower()

        if ENV_FILE.search(rel) and not ENV_TEMPLATE.search(rel):
            if repo.mode == "git":
                out.append(
                    _config_finding(
                        repo.label, rel, "env_file", f"Environment file {rel} is committed or not git-ignored",
                        Severity.HIGH, f"git lists {rel} as tracked or untracked-but-not-ignored",
                        "Environment files hold production credentials; once committed they live "
                        "in the history of every clone.",
                        "Add .env* (except templates) to .gitignore, `git rm --cached` the file, "
                        "and rotate anything it contained if it was ever committed.",
                    )
                )
            elif ".env" not in gitignore:
                out.append(
                    _config_finding(
                        repo.label, rel, "env_file", f"Environment file {rel} is not git-ignored",
                        Severity.MEDIUM, ".gitignore does not mention .env",
                        "A future `git add .` will commit the credentials in this file.",
                        "Add .env* (except templates) to .gitignore.",
                    )
                )

        text = None
        if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
            text = repo.read_text(rel)
            if text:
                out.extend(_dockerfile(repo.label, rel, text))
        elif re.match(r"(docker-)?compose[\w.-]*\.ya?ml$", lower):
            text = repo.read_text(rel) or ""
            out += _regex_config(
                repo.label, rel, text, "compose_privileged", r"(?m)^\s*privileged:\s*true\b",
                "Privileged container", Severity.HIGH,
                "A privileged container can take over the host.",
                "Remove privileged: true and grant only the specific capabilities needed (cap_add).",
            )
            out += _regex_config(
                repo.label, rel, text, "compose_docker_sock", r"/var/run/docker\.sock",
                "Docker socket mounted into a container", Severity.HIGH,
                "Access to the Docker socket is root on the host.",
                "Don't mount the Docker socket; if a tool needs it, use a restricted socket proxy.",
            )
            out += _regex_config(
                repo.label, rel, text, "compose_db_port",
                rf"(?m)^\s*-\s*[\"']?(?:0\.0\.0\.0:)?\d+:(?:{DB_PORTS})[\"']?\s*$",
                "Database port published on all interfaces", Severity.MEDIUM,
                "Publishing the port without a host IP binds it on every interface, so the "
                "database is reachable from the network - Docker also bypasses host firewalls.",
                "Bind to localhost (\"127.0.0.1:5432:5432\") or don't publish the port at all.",
            )
        elif lower.endswith(".py"):
            text = repo.read_text(rel) or ""
            if "ALLOWED_HOSTS" in text or "CORS_" in text or "COOKIE_SECURE" in text:
                out += _regex_config(
                    repo.label, rel, text, "django_allowed_hosts", r"(?m)^\s*ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']\s*\]",
                    "ALLOWED_HOSTS accepts any host", Severity.LOW,
                    "A wildcard ALLOWED_HOSTS enables Host-header attacks such as password-reset poisoning.",
                    "List the real hostnames in ALLOWED_HOSTS.",
                )
                out += _regex_config(
                    repo.label, rel, text, "cors_allow_all", r"(?m)^\s*CORS_(?:ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS)\s*=\s*True",
                    "CORS allows all origins", Severity.MEDIUM,
                    "Any website can read API responses from a visitor's browser.",
                    "Replace with CORS_ALLOWED_ORIGINS listing your front-end origins.",
                )
                out += _regex_config(
                    repo.label, rel, text, "insecure_cookie", r"(?m)^\s*(?:SESSION|CSRF)_COOKIE_SECURE\s*=\s*False",
                    "Session/CSRF cookie allowed over plain HTTP", Severity.LOW,
                    "The cookie is sent over unencrypted connections too.",
                    "Set SESSION_COOKIE_SECURE = True and CSRF_COOKIE_SECURE = True in production.",
                )
        elif lower.endswith(".conf") or lower.startswith("nginx"):
            text = repo.read_text(rel) or ""
            out += _regex_config(
                repo.label, rel, text, "nginx_autoindex", r"(?m)^\s*autoindex\s+on\s*;",
                "Directory listing enabled in nginx config", Severity.MEDIUM,
                "Directory listings expose every file in the folder.",
                "Set `autoindex off;`.",
            )
    return out
