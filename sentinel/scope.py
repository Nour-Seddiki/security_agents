"""The scan scope: which origins and repositories Sentinel may touch.

Every network request and every file read - by a scanner or by the agent - is checked
here. Only the config file widens the scope; nothing the model says can.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ScopeError(PermissionError):
    """A target outside the configured scope, or a malformed one."""


@dataclass(frozen=True)
class Origin:
    scheme: str
    host: str
    port: int

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        if DEFAULT_PORTS.get(self.scheme) == self.port:
            return f"{self.scheme}://{host}"
        return f"{self.scheme}://{host}:{self.port}"

    @property
    def is_loopback(self) -> bool:
        return self.host in LOOPBACK_HOSTS or self.host.endswith(".localhost")


def origin_of(url: str) -> Origin:
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError as exc:
        raise ScopeError(f"malformed URL {url!r}: {exc}") from None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise ScopeError(f"only http(s) URLs are allowed, got {url!r}")
    if parts.username is not None or parts.password is not None:
        raise ScopeError("URLs with embedded credentials are not allowed")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise ScopeError(f"URL has no host: {url!r}")
    return Origin(scheme, host, port or DEFAULT_PORTS[scheme])


class Scope:
    def __init__(self, urls=(), extra_hosts=(), repos=()) -> None:
        origins: set[Origin] = set()
        for url in urls:
            origin = origin_of(url)
            origins.add(origin)
            if origin.scheme == "https" and origin.port == 443:
                # The plain-HTTP twin, so the HTTP->HTTPS redirect can be checked.
                origins.add(Origin("http", origin.host, 80))
        for host in extra_hosts:
            name = host.strip().rstrip(".").lower()
            if name:
                origins.add(Origin("https", name, 443))
                origins.add(Origin("http", name, 80))
        self.origins: frozenset[Origin] = frozenset(origins)

        self.repos: dict[str, Path] = {}
        for path in repos:
            root = Path(path).resolve()
            label = root.name or str(root)
            n = 2
            while label in self.repos:
                label = f"{root.name}-{n}"
                n += 1
            self.repos[label] = root

    @classmethod
    def from_config(cls, config) -> "Scope":
        return cls(config.web.urls, config.web.extra_hosts, config.code.repos)

    def check_url(self, url: str) -> Origin:
        origin = origin_of(url)
        if origin not in self.origins:
            allowed = ", ".join(sorted(str(o) for o in self.origins)) or "none"
            raise ScopeError(f"{origin} is out of scope (allowed origins: {allowed})")
        return origin

    def allows(self, url: str) -> bool:
        try:
            self.check_url(url)
        except ScopeError:
            return False
        return True

    def repo_root(self, label: str) -> Path:
        root = self.repos.get(label)
        if root is None:
            known = ", ".join(self.repos) or "none"
            raise ScopeError(f"unknown repository {label!r} (known: {known})")
        return root

    def resolve_in_repo(self, label: str, rel: str) -> Path:
        root = self.repo_root(label)
        rel = (rel or "").strip().replace("\\", "/")
        if rel.startswith("/") or re.match(r"^[A-Za-z]:", rel):
            raise ScopeError("paths must be relative to the repository root")
        candidate = (root / rel).resolve()
        if candidate != root and root not in candidate.parents:
            raise ScopeError(f"{rel!r} escapes the repository root")
        return candidate

    def describe(self) -> list[str]:
        lines = [f"origin {o}" for o in sorted(self.origins, key=str)]
        lines += [f"repository {label} -> {root}" for label, root in self.repos.items()]
        return lines
