"""Dependency audit: exact versions from lock and requirements files, checked against
the OSV.dev vulnerability database (PyPI and npm).

Only package names and versions leave the machine, never code. Unpinned requirements
cannot be matched to advisories precisely, so they are reported (as info) rather than
guessed at.
"""

from __future__ import annotations

import json
import math
import re
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass

from ..models import Finding, Severity
from ..net import FetchError
from . import CheckIncomplete, CheckSkipped
from .code import RepoFiles

PYPI = "PyPI"
NPM = "npm"


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str
    manifest: str

    @property
    def spec(self) -> str:
        return f"{self.name}@{self.version}" if self.ecosystem == NPM else f"{self.name}=={self.version}"


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# --------------------------------------------------------------------------- manifests

_REQ_PINNED = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)\s*(?:;.*)?$"
)
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def parse_requirements(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    pinned, loose = [], []
    for raw in text.splitlines():
        line = re.split(r"\s+#", raw, maxsplit=1)[0].strip().rstrip("\\").strip()
        if not line or line.startswith(("#", "-", "git+", "http:", "https:", "file:", ".", "/")):
            continue
        m = _REQ_PINNED.match(line)
        if m:
            pinned.append((normalize_pypi(m.group(1)), m.group(2)))
        elif (name := _REQ_NAME.match(line)) is not None:
            loose.append(normalize_pypi(name.group(1)))
    return pinned, loose


def parse_toml_lock(text: str) -> list[tuple[str, str]]:
    """poetry.lock and uv.lock both list [[package]] tables with name and version."""
    out = []
    for entry in tomllib.loads(text).get("package", []):
        source = entry.get("source")
        if isinstance(source, dict) and {"editable", "virtual", "directory", "path"} & set(source):
            continue  # the project itself or a local path dependency
        if entry.get("name") and entry.get("version"):
            out.append((normalize_pypi(entry["name"]), str(entry["version"])))
    return out


def parse_pipfile_lock(text: str) -> list[tuple[str, str]]:
    out = []
    data = json.loads(text)
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = str((info or {}).get("version", ""))
            if version.startswith("=="):
                out.append((normalize_pypi(name), version[2:]))
    return out


def parse_package_lock(text: str) -> list[tuple[str, str]]:
    data = json.loads(text)
    out = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 and 3
        for key, info in packages.items():
            if not key or "node_modules/" not in key or not isinstance(info, dict) or info.get("link"):
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[1]
            if info.get("version"):
                out.append((name, str(info["version"])))
        return out

    def walk(deps) -> None:  # lockfileVersion 1
        for name, info in (deps or {}).items():
            version = str((info or {}).get("version", ""))
            if version and not version.startswith(("file:", "git", "http", "link:")):
                out.append((name, version))
            walk((info or {}).get("dependencies"))

    walk(data.get("dependencies"))
    return out


def find_manifests(repo: RepoFiles) -> list[str]:
    out = []
    for rel in repo.files:
        name = rel.rsplit("/", 1)[-1].lower()
        in_req_dir = "/requirements/" in f"/{rel.lower()}" and name.endswith(".txt")
        if (name.startswith("requirements") and name.endswith(".txt")) or in_req_dir:
            out.append(rel)
        elif name in ("poetry.lock", "uv.lock", "pipfile.lock", "package-lock.json", "npm-shrinkwrap.json"):
            out.append(rel)
    return out


def collect_packages(repo: RepoFiles, manifests: list[str]) -> tuple[list[Package], dict[str, list[str]], list[str]]:
    """(unique packages, {manifest: unpinned names}, parse errors)"""
    seen: dict[tuple[str, str, str], Package] = {}
    loose: dict[str, list[str]] = {}
    errors: list[str] = []
    for rel in manifests:
        text = repo.read_text(rel)
        if text is None:
            continue
        name = rel.rsplit("/", 1)[-1].lower()
        try:
            if name.endswith(".txt"):
                pairs, unpinned = parse_requirements(text)
                if unpinned:
                    loose[rel] = unpinned
                ecosystem = PYPI
            elif name in ("poetry.lock", "uv.lock"):
                pairs, ecosystem = parse_toml_lock(text), PYPI
            elif name == "pipfile.lock":
                pairs, ecosystem = parse_pipfile_lock(text), PYPI
            else:
                pairs, ecosystem = parse_package_lock(text), NPM
        except (ValueError, tomllib.TOMLDecodeError, AttributeError, TypeError) as exc:
            errors.append(f"{rel}: {exc}")
            continue
        for pkg_name, version in pairs:
            key = (ecosystem, pkg_name, version)
            if key not in seen:
                seen[key] = Package(ecosystem, pkg_name, version, rel)
    return list(seen.values()), loose, errors


# --------------------------------------------------------------------------- severity

_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest one-decimal number >= value, robust to float error."""
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    try:
        parts = dict(p.split(":", 1) for p in vector.strip().split("/")[1:])
        scope = parts["S"]
        iss = 1 - (
            (1 - _CVSS3["CIA"][parts["C"]]) * (1 - _CVSS3["CIA"][parts["I"]]) * (1 - _CVSS3["CIA"][parts["A"]])
        )
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        exploitability = (
            8.22 * _CVSS3["AV"][parts["AV"]] * _CVSS3["AC"][parts["AC"]] * _PR[scope][parts["PR"]] * _CVSS3["UI"][parts["UI"]]
        )
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW if score > 0 else Severity.INFO


def osv_severity(vuln: dict) -> tuple[Severity, str]:
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str):
        try:
            return Severity.parse(label), "advisory rating"
        except ValueError:
            pass
    scores = [
        cvss3_base_score(entry.get("score", ""))
        for entry in vuln.get("severity") or []
        if entry.get("type") == "CVSS_V3"
    ]
    scores = [s for s in scores if s is not None]
    if scores:
        return severity_from_score(max(scores)), f"CVSS {max(scores):.1f}"
    for affected in vuln.get("affected") or []:
        for key in ("ecosystem_specific", "database_specific"):
            label = (affected.get(key) or {}).get("severity")
            if isinstance(label, str):
                try:
                    return Severity.parse(label), "advisory rating"
                except ValueError:
                    pass
    return Severity.MEDIUM, "no rating published (defaulted to medium)"


# --------------------------------------------------------------------------- versions


def version_key(version: str) -> tuple:
    """Loose ordering that works for PEP 440 and semver release numbers: numeric parts
    compare as numbers, and a pre-release sorts before its final release."""
    key = []
    for part in re.split(r"[.\-+]", version.lower()):
        m = re.match(r"(\d+)(.*)", part)
        if m:
            key.append((int(m.group(1)), 0 if m.group(2) else 1, m.group(2)))
        elif part:
            key.append((-1, 0, part))
    return tuple(key)


def fixed_versions(vuln: dict, pkg: Package) -> list[str]:
    out = []
    wanted = normalize_pypi(pkg.name) if pkg.ecosystem == PYPI else pkg.name
    for affected in vuln.get("affected") or []:
        info = affected.get("package") or {}
        name = info.get("name", "")
        name = normalize_pypi(name) if pkg.ecosystem == PYPI else name
        if info.get("ecosystem") != pkg.ecosystem or name != wanted:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    out.append(str(event["fixed"]))
    return sorted(set(out), key=version_key)


def recommended_fix(current: str, fixed: list[str]) -> str | None:
    newer = [v for v in fixed if version_key(v) > version_key(current)]
    return min(newer, key=version_key) if newer else None


# --------------------------------------------------------------------------- OSV client


class OsvClient:
    """Minimal client for https://api.osv.dev (querybatch + vulns)."""

    def __init__(self, base_url: str = "https://api.osv.dev", timeout_s: float = 30.0, max_lookups: int = 200, user_agent: str = "Sentinel") -> None:
        self.base = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.max_lookups = max_lookups
        self.user_agent = user_agent
        self.retry_delay_s = 1.0
        self.lookups = 0
        self._cache: dict[str, dict] = {}

    def _call(self, method: str, path: str, payload: dict | None = None) -> dict:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            self.base + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": self.user_agent},
        )
        for attempt in range(2):  # one retry for transient network errors, none for HTTP errors
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_s) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                exc.close()
                if exc.code < 500 or attempt:
                    raise FetchError(f"OSV {method} {path}: HTTP {exc.code}") from exc
            except (urllib.error.URLError, OSError) as exc:
                if attempt:
                    raise FetchError(f"OSV {method} {path}: {getattr(exc, 'reason', exc)}") from exc
            except ValueError as exc:
                raise FetchError(f"OSV {method} {path}: invalid JSON ({exc})") from exc
            time.sleep(self.retry_delay_s)
        raise FetchError(f"OSV {method} {path}: failed")  # pragma: no cover - loop always returns or raises

    def query(self, packages: list[Package]) -> dict[Package, list[str]]:
        found: dict[Package, list[str]] = {}
        for start in range(0, len(packages), 500):
            chunk = packages[start : start + 500]
            payload = {
                "queries": [
                    {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version} for p in chunk
                ]
            }
            rows = self._call("POST", "/v1/querybatch", payload).get("results") or []
            for pkg, row in zip(chunk, rows):
                ids = [v["id"] for v in (row or {}).get("vulns") or [] if "id" in v]
                token, pages = (row or {}).get("next_page_token"), 0
                while token and pages < 10:
                    more = self._call(
                        "POST",
                        "/v1/query",
                        {"package": {"name": pkg.name, "ecosystem": pkg.ecosystem}, "version": pkg.version, "page_token": token},
                    )
                    ids += [v["id"] for v in more.get("vulns") or [] if "id" in v]
                    token, pages = more.get("next_page_token"), pages + 1
                if ids:
                    found[pkg] = sorted(set(ids))
        return found

    def vuln(self, vuln_id: str) -> dict | None:
        """Advisory details, or None once the lookup budget is spent."""
        if vuln_id in self._cache:
            return self._cache[vuln_id]
        if self.lookups >= self.max_lookups:
            return None
        self.lookups += 1
        data = self._call("GET", "/v1/vulns/" + urllib.parse.quote(vuln_id, safe=""))
        self._cache[vuln_id] = data
        return data


# --------------------------------------------------------------------------- scan


def _summary(vuln: dict) -> str:
    summary = (vuln.get("summary") or "").strip()
    if not summary:
        summary = (vuln.get("details") or "").strip().split("\n", 1)[0][:140]
    return summary or vuln.get("id", "?")


def package_finding(label: str, pkg: Package, advisories: list[dict], unfetched: list[str]) -> Finding:
    """One finding per vulnerable package version: one upgrade usually fixes every
    advisory, so that is the unit an administrator acts on (and is alerted about)."""
    rated = []
    for vuln in advisories:
        severity, basis = osv_severity(vuln)
        rated.append((severity, vuln, basis, recommended_fix(pkg.version, fixed_versions(vuln, pkg))))
    rated.sort(key=lambda r: (-r[0], r[1].get("id", "")))
    ids = [r[1].get("id", "?") for r in rated] + list(unfetched)
    total = len(ids)
    references = [f"https://osv.dev/vulnerability/{i}" for i in ids[:5]]
    common = dict(
        check_id="deps.osv.vulnerable",
        category="dependency",
        target=label,
        location=f"{pkg.manifest}: {pkg.spec}",
        key=f"{pkg.ecosystem}:{pkg.name}:{pkg.version}",
    )

    if not rated:  # nothing could be looked up: report what OSV matched, unrated
        return Finding(
            title=f"{pkg.name} {pkg.version}: {total} known vulnerabilit{'y' if total == 1 else 'ies'}",
            severity=Severity.MEDIUM,
            evidence=", ".join(ids[:8]) + "; details not fetched (lookup budget spent or OSV unreachable)",
            description="OSV lists this version as affected. Severities were not looked up.",
            remediation=f"Check the advisories and upgrade {pkg.name}.",
            references=references,
            confidence="tentative",
            **common,
        )

    fixes = [r[3] for r in rated if r[3]]
    unfixed = sum(1 for r in rated if not r[3])
    target = max(fixes, key=version_key) if fixes else None
    if target and not unfixed and not unfetched:
        remediation = f"Upgrade {pkg.name} from {pkg.version} to {target} or later" + (
            f" - that release fixes all {total} advisories." if total > 1 else "."
        )
    elif target:
        remediation = (
            f"Upgrade {pkg.name} from {pkg.version} to {target} or later (fixes {len(fixes)} of {total}); "
            "check the other advisories for mitigations."
        )
    else:
        remediation = "No fixed release is listed; check the advisory for mitigations or replace the package."

    if total == 1:
        severity, vuln, basis, _fix = rated[0]
        cves = [a for a in vuln.get("aliases") or [] if a.startswith("CVE-")]
        return Finding(
            title=f"{pkg.name} {pkg.version}: {_summary(vuln)}"[:180],
            severity=severity,
            evidence=vuln.get("id", "?") + (f" ({', '.join(cves[:3])})" if cves else "") + f"; severity: {basis}",
            description=((vuln.get("details") or "").strip() or _summary(vuln))[:900],
            remediation=remediation,
            references=references + [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:2]],
            confidence="firm",
            **common,
        )

    counts = Counter(r[0].label for r in rated)
    breakdown = ", ".join(f"{counts[s.label]} {s.label}" for s in sorted(Severity, reverse=True) if counts[s.label])
    listed = [f"{r[1].get('id', '?')} ({r[0].label})" for r in rated] + [f"{i} (unrated)" for i in unfetched]
    lines = [f"- [{r[0].label}] {_summary(r[1])}" for r in rated[:6]]
    if total > 6:
        lines.append(f"- ... and {total - 6} more")
    return Finding(
        title=f"{pkg.name} {pkg.version}: {total} known vulnerabilities ({breakdown})",
        severity=rated[0][0],
        evidence=", ".join(listed[:8]) + (f", +{total - 8} more" if total > 8 else ""),
        description="\n".join(lines),
        remediation=remediation,
        references=references,
        confidence="firm",
        **common,
    )


def scan_dependencies(repo: RepoFiles, osv: OsvClient) -> list[Finding]:
    manifests = find_manifests(repo)
    if not manifests:
        raise CheckSkipped("no supported lock or requirements files (requirements*.txt, poetry.lock, uv.lock, Pipfile.lock, package-lock.json)")
    packages, loose, errors = collect_packages(repo, manifests)
    out: list[Finding] = []
    for manifest, names in loose.items():
        out.append(
            Finding(
                check_id="deps.osv.unpinned",
                title=f"{len(names)} unpinned requirement(s) in {manifest}",
                severity=Severity.INFO,
                category="dependency",
                target=repo.label,
                location=manifest,
                evidence=", ".join(names[:15]) + (" ..." if len(names) > 15 else ""),
                description="Without an exact version these packages can't be matched to "
                "advisories, and every install may pull a different release.",
                remediation="Pin exact versions with a lock file (pip-compile, uv lock, poetry lock).",
                key=manifest,
            )
        )
    for error in errors:
        out.append(
            Finding(
                check_id="deps.osv.unparsed",
                title="Dependency manifest could not be parsed",
                severity=Severity.INFO,
                category="dependency",
                target=repo.label,
                location=error.split(":", 1)[0],
                evidence=error[:200],
                description="Packages in this file were not audited.",
                remediation="Fix the file's syntax so it can be audited.",
                key=error.split(":", 1)[0],
            )
        )
    if not packages:
        return out

    failures: list[str] = []
    for pkg, ids in osv.query(packages).items():
        covered: set[str] = set()
        advisories: list[dict] = []
        unfetched: list[str] = []
        # GHSA advisories carry a severity rating: look those up first.
        for vid in sorted(ids, key=lambda i: (not i.startswith("GHSA-"), i)):
            if vid in covered:
                continue
            vuln = None
            if len(failures) < 3:  # after repeated failures, stop waiting on the network
                try:
                    vuln = osv.vuln(vid)
                except FetchError as exc:
                    failures.append(str(exc))
            if vuln is None:
                unfetched.append(vid)
                covered.add(vid)
                continue
            aliases = set(vuln.get("aliases") or [])
            duplicate = bool(aliases & covered)  # e.g. PYSEC-x and GHSA-y for one issue
            covered.update([vid, *aliases])
            if not (vuln.get("withdrawn") or duplicate):
                advisories.append(vuln)
        if advisories or unfetched:
            out.append(package_finding(repo.label, pkg, advisories, unfetched))
    if failures:
        raise CheckIncomplete(f"{len(failures)} advisory lookup(s) failed, so some severities are unknown; last: {failures[-1]}", out)
    return out
