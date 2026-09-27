"""TLS checks: is the certificate trusted and not about to expire, and does the server
still accept TLS 1.0/1.1. One or two handshakes per origin, counted against the budget."""

from __future__ import annotations

import socket
import ssl
import time
import warnings

from ..models import Finding, Severity
from ..net import HttpClient
from ..scope import Origin, origin_of
from . import CheckSkipped

MOZILLA_TLS = "https://wiki.mozilla.org/Security/Server_Side_TLS"


def _handshake(origin: Origin, ctx: ssl.SSLContext, timeout: float) -> tuple[dict, str | None]:
    with socket.create_connection((origin.host, origin.port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=origin.host) as tls:
            return tls.getpeercert() or {}, tls.version()


def evaluate_expiry(cert: dict, origin: Origin, now: float | None = None) -> list[Finding]:
    not_after = cert.get("notAfter")
    if not not_after:
        return []
    days = (ssl.cert_time_to_seconds(not_after) - (time.time() if now is None else now)) / 86400
    if days > 30:
        return []
    return [
        Finding(
            check_id="tls.cert.expiring",
            title=f"TLS certificate expires in {max(0, int(days))} days",
            severity=Severity.HIGH if days <= 14 else Severity.MEDIUM,
            category="tls",
            target=str(origin),
            location=f"{origin.host}:{origin.port}",
            evidence=f"notAfter = {not_after}",
            description="When the certificate expires every visitor gets a full-page browser "
            "error and API clients stop connecting.",
            remediation="Renew the certificate now and automate renewal (e.g. certbot/ACME with "
            "a renewal timer and expiry monitoring).",
            references=[MOZILLA_TLS],
            key="expiring",
            confidence="certain",
        )
    ]


def check_tls_cert(http: HttpClient, url: str, now: float | None = None) -> list[Finding]:
    origin = origin_of(url)
    if origin.scheme != "https":
        raise CheckSkipped("not an HTTPS origin")
    http.admit(url)
    try:
        cert, _version = _handshake(origin, ssl.create_default_context(), http.timeout_s)
    except ssl.SSLCertVerificationError as exc:
        return [
            Finding(
                check_id="tls.cert.untrusted",
                title="TLS certificate is not trusted",
                severity=Severity.HIGH,
                category="tls",
                target=str(origin),
                location=f"{origin.host}:{origin.port}",
                evidence=f"verification failed: {exc.verify_message or exc}",
                description="Browsers show a full-page warning; users who click through are "
                "open to interception, and it trains them to ignore real attacks.",
                remediation="Install a certificate from a public CA that covers this hostname "
                "(e.g. Let's Encrypt), and serve the full intermediate chain.",
                references=[MOZILLA_TLS],
                key="untrusted",
                confidence="certain",
            )
        ]
    return evaluate_expiry(cert, origin, now)


def _legacy_context() -> ssl.SSLContext | None:
    """A client context that offers only TLS 1.0/1.1, or None if this Python/OpenSSL
    build cannot offer them at all."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    return ctx


LOCAL_LIMITATIONS = ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_SUITABLE_SIGNATURE_ALGORITHM")


def check_tls_protocols(http: HttpClient, url: str) -> list[Finding]:
    origin = origin_of(url)
    if origin.scheme != "https":
        raise CheckSkipped("not an HTTPS origin")
    ctx = _legacy_context()
    if ctx is None:
        raise CheckSkipped("this Python/OpenSSL build cannot offer TLS 1.0/1.1, so it cannot test for them")
    http.admit(url)
    try:
        _cert, version = _handshake(origin, ctx, http.timeout_s)
    except ssl.SSLError as exc:
        reason = str(getattr(exc, "reason", "") or exc).upper()
        if any(limit in reason for limit in LOCAL_LIMITATIONS):
            raise CheckSkipped(f"local TLS stack refused to offer TLS 1.0/1.1 ({reason})") from exc
        return []  # the server refused the legacy handshake: good
    except (OSError, socket.timeout):
        return []  # connection dropped during the legacy handshake: treated as refused
    return [
        Finding(
            check_id="tls.protocol.legacy",
            title=f"Server still accepts {version or 'TLS 1.0/1.1'}",
            severity=Severity.MEDIUM,
            category="tls",
            target=str(origin),
            location=f"{origin.host}:{origin.port}",
            evidence=f"a client offering only TLS 1.0/1.1 completed a handshake ({version})",
            description="TLS 1.0 and 1.1 are deprecated (RFC 8996) and weaken the connection "
            "for any client that negotiates them.",
            remediation="Allow only TLS 1.2 and 1.3 (e.g. nginx `ssl_protocols TLSv1.2 TLSv1.3;`).",
            references=[MOZILLA_TLS, "https://datatracker.ietf.org/doc/html/rfc8996"],
            key="legacy",
            confidence="certain",
        )
    ]
