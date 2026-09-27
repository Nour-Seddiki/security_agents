"""A deliberately small HTTP client for scanning: scope-checked, budgeted, throttled.

Built on http.client so that nothing happens implicitly: redirects are followed only
when asked and only while they stay in scope, bodies are read up to a cap, and every
request (and every TLS handshake, via `admit`) counts against the run's budget.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .scope import Origin, Scope

REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class FetchError(OSError):
    """The request could not be completed (refused, timed out, TLS failure...)."""


class BudgetExceeded(RuntimeError):
    """This run's request budget is spent."""


@dataclass
class Response:
    url: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes = b""
    truncated: bool = False
    redirects: list[str] = field(default_factory=list)
    offscope_redirect: str = ""
    tls_verified: bool | None = None  # None for plain HTTP

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def header_values(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    def text(self, limit: int | None = None) -> str:
        body = self.body if limit is None else self.body[:limit]
        return body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        ctype = self.content_type
        if ctype:
            return ctype in ("text/html", "application/xhtml+xml")
        head = self.body[:512].lstrip().lower()
        return head.startswith((b"<!doctype html", b"<html"))


def unverified_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def describe_error(exc: BaseException) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"certificate verification failed: {exc.verify_message or exc}"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timed out"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, socket.gaierror):
        return "DNS lookup failed"
    if isinstance(exc, ssl.SSLError):
        return f"TLS error: {exc.reason or exc}"
    return f"{type(exc).__name__}: {exc}"


class HttpClient:
    def __init__(
        self,
        scope: Scope,
        *,
        max_requests: int = 300,
        delay_s: float = 0.15,
        timeout_s: float = 10.0,
        user_agent: str = "Sentinel",
        max_body: int = 512 * 1024,
    ) -> None:
        self.scope = scope
        self.max_requests = max_requests
        self.delay_s = delay_s
        self.timeout_s = timeout_s
        self.user_agent = user_agent
        self.max_body = max_body
        self.used = 0
        self.unverified_hosts: set[str] = set()
        self.unresponsive: set[str] = set()
        self.notes: list[str] = []
        self._last: dict[str, float] = {}
        self._failures: dict[str, int] = {}

    # After this many consecutive transport failures a host is left alone for the rest of
    # the run: typically a CDN/WAF has started dropping the scanner's traffic, and waiting
    # out a timeout per remaining probe helps no one.
    BREAKER_THRESHOLD = 3

    @property
    def remaining(self) -> int:
        return max(0, self.max_requests - self.used)

    def _failed(self, origin: Origin, exc: BaseException) -> None:
        count = self._failures.get(origin.host, 0) + 1
        self._failures[origin.host] = count
        if count >= self.BREAKER_THRESHOLD and origin.host not in self.unresponsive:
            self.unresponsive.add(origin.host)
            self.notes.append(
                f"{origin} stopped responding ({count} requests in a row failed, last: {describe_error(exc)}); "
                "the remaining requests to it were skipped. If the site works in a browser, a CDN or "
                "firewall (Netlify, Cloudflare, ...) is probably rate-limiting or blocking this machine "
                "after the sensitive-path probes: allow-list this IP or raise [web] request_delay_ms."
            )

    def admit(self, url: str) -> Origin:
        """Scope check, budget and politeness delay for one request or handshake."""
        origin = self.scope.check_url(url)
        if origin.host in self.unresponsive:
            raise FetchError(f"skipped {url}: {origin.host} stopped responding earlier in this run")
        if self.used >= self.max_requests:
            raise BudgetExceeded(f"request budget of {self.max_requests} is spent")
        self.used += 1
        last = self._last.get(origin.host)
        if last is not None and self.delay_s > 0:
            wait = self.delay_s - (time.monotonic() - last)
            if wait > 0:
                time.sleep(wait)
        self._last[origin.host] = time.monotonic()
        return origin

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        max_body: int | None = None,
    ) -> Response:
        chain: list[str] = []
        current = url
        while True:
            resp = self._once(method, current, headers or {}, max_body)
            location = resp.header("location")
            if not (follow_redirects and resp.status in REDIRECT_CODES and location):
                resp.redirects = chain
                return resp
            target = urljoin(current, location.strip())
            if not self.scope.allows(target):
                resp.redirects = chain
                resp.offscope_redirect = target
                return resp
            if len(chain) >= max_redirects:
                resp.redirects = chain
                return resp
            chain.append(current)
            current = target
            if resp.status == 303:
                method = "GET"

    def _once(self, method: str, url: str, headers: dict[str, str], max_body: int | None) -> Response:
        origin = self.admit(url)
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        send = {"User-Agent": self.user_agent, "Accept": "*/*", "Connection": "close"}
        send.update(headers)
        limit = self.max_body if max_body is None else max_body
        verified = None if origin.scheme == "http" else origin.host not in self.unverified_hosts
        try:
            resp = self._exchange(origin, method, path, send, limit, url, verified)
        except ssl.SSLCertVerificationError as exc:
            # The TLS check reports the certificate itself. Keep reading the site so
            # the other checks can still run: one retry, counted against the budget.
            self.unverified_hosts.add(origin.host)
            self.notes.append(
                f"{origin}: certificate failed verification ({exc.verify_message or exc}); "
                "continued without verification"
            )
            self.admit(url)
            try:
                resp = self._exchange(origin, method, path, send, limit, url, False)
            except (OSError, http.client.HTTPException) as retry_exc:
                self._failed(origin, retry_exc)
                raise FetchError(f"{method} {url}: {describe_error(retry_exc)}") from retry_exc
        except (OSError, http.client.HTTPException) as exc:
            self._failed(origin, exc)
            raise FetchError(f"{method} {url}: {describe_error(exc)}") from exc
        self._failures[origin.host] = 0
        return resp

    def _exchange(
        self,
        origin: Origin,
        method: str,
        path: str,
        headers: dict[str, str],
        limit: int,
        url: str,
        verified: bool | None,
    ) -> Response:
        if origin.scheme == "https":
            ctx = ssl.create_default_context() if verified else unverified_context()
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                origin.host, origin.port, timeout=self.timeout_s, context=ctx
            )
        else:
            conn = http.client.HTTPConnection(origin.host, origin.port, timeout=self.timeout_s)
        try:
            conn.request(method, path, headers=headers)
            resp = conn.getresponse()
            body = b"" if method == "HEAD" else resp.read(limit + 1)
            return Response(
                url=url,
                status=resp.status,
                reason=resp.reason or "",
                headers=resp.getheaders(),
                body=body[:limit],
                truncated=len(body) > limit,
                tls_verified=verified,
            )
        finally:
            conn.close()
