import ssl
import unittest
from http.server import BaseHTTPRequestHandler

from sentinel.checks import run_check
from sentinel.checks.tls import evaluate_expiry
from sentinel.checks.web import (
    check_cookies,
    check_cors,
    check_exposure,
    check_headers,
    check_security_txt,
    check_transport,
    parse_csp,
)
from sentinel.demo import HardenedSite, LocalSite, SpaSite, make_vulnerable_handler
from sentinel.models import ScanResult, Severity
from sentinel.net import BudgetExceeded, FetchError, HttpClient
from sentinel.scope import Origin, Scope, ScopeError


def client(url: str, **kwargs) -> HttpClient:
    return HttpClient(Scope([url]), delay_s=0, timeout_s=5, **kwargs)


class ScopeTest(unittest.TestCase):
    def test_origins(self):
        scope = Scope(["https://shop.example.com/app"], extra_hosts=["www.shop.example.com"])
        self.assertTrue(scope.allows("https://shop.example.com/anything?x=1"))
        self.assertTrue(scope.allows("http://shop.example.com/"))  # plain-HTTP twin for the redirect check
        self.assertTrue(scope.allows("https://WWW.shop.example.com./"))
        self.assertFalse(scope.allows("https://shop.example.com:8443/"))
        self.assertFalse(scope.allows("https://evil.example.com/"))
        self.assertFalse(scope.allows("ftp://shop.example.com/"))
        with self.assertRaises(ScopeError):
            scope.check_url("https://user:pw@shop.example.com/")

    def test_repo_paths(self):
        import tempfile
        from pathlib import Path

        root = Path(tempfile.mkdtemp())
        scope = Scope(repos=[root])
        label = next(iter(scope.repos))
        self.assertEqual(scope.resolve_in_repo(label, "a/b.py"), (root / "a/b.py").resolve())
        for bad in ("../outside.txt", "/etc/passwd", "C:/Windows/win.ini", "a/../../x"):
            with self.assertRaises(ScopeError, msg=bad):
                scope.resolve_in_repo(label, bad)
        with self.assertRaises(ScopeError):
            scope.resolve_in_repo("nope", "a.py")


class VulnerableSiteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = LocalSite(make_vulnerable_handler()).__enter__()
        cls.url = cls.site.url

    @classmethod
    def tearDownClass(cls):
        cls.site.__exit__(None, None, None)

    def test_headers(self):
        resp = client(self.url).get(self.url)
        rules = {f.check_id for f in check_headers(resp, self.url)}
        for rule in ("csp_missing", "clickjacking", "nosniff_missing", "version_server", "version_x_powered_by", "referrer_policy_missing"):
            self.assertIn(f"web.headers.{rule}", rules)
        self.assertNotIn("web.headers.hsts_missing", rules)  # plain HTTP: HSTS does not apply

    def test_cookies(self):
        findings = check_cookies(client(self.url).get(self.url), self.url)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertIn("HttpOnly", findings[0].title)
        self.assertIn("<value hidden>", findings[0].evidence)

    def test_cors_reflection_with_credentials(self):
        findings = check_cors(client(self.url), self.url)
        self.assertEqual([f.check_id for f in findings], ["web.cors.reflected"])
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_exposure(self):
        findings = {f.check_id: f for f in check_exposure(client(self.url), self.url.rstrip("/"))}
        self.assertEqual(
            set(findings),
            {"web.exposure.git", "web.exposure.env", "web.exposure.debug_django", "web.exposure.api_spec"},
        )
        git = findings["web.exposure.git"]
        self.assertEqual(git.severity, Severity.CRITICAL)
        self.assertIn("also exposed", git.evidence)  # /.git/HEAD and /.git/config: one finding
        env = findings["web.exposure.env"]
        self.assertIn("DB_PASSWORD", env.evidence)
        self.assertNotIn("production", env.evidence)  # names only, never values
        self.assertEqual(findings["web.exposure.debug_django"].severity, Severity.HIGH)

    def test_budget_keeps_partial_findings(self):
        result = ScanResult("t", "now")
        http = client(self.url, max_requests=4)  # baseline + 3 probes
        run_check(result, "web.exposure", self.url, check_exposure, http, self.url.rstrip("/"))
        self.assertFalse(result.checks[0].ok)
        self.assertIn("checked 3 of", result.checks[0].detail)
        self.assertIn("exposed) before stopping", result.checks[0].detail)
        self.assertIn("web.exposure.git", {f.check_id for f in result.findings})
        with self.assertRaises(BudgetExceeded):
            http.get(self.url)

    def test_scope_is_enforced_by_the_client(self):
        with self.assertRaises(ScopeError):
            client(self.url).get("http://example.com/")

    def test_transport_on_loopback_is_info(self):
        findings = check_transport(client(self.url), self.url)
        self.assertEqual([(f.check_id, f.severity) for f in findings], [("web.transport.plain_http", Severity.INFO)])


class HardenedSiteTest(unittest.TestCase):
    def test_nothing_to_report(self):
        with LocalSite(HardenedSite) as site:
            http = client(site.url)
            resp = http.get(site.url)
            self.assertEqual(check_headers(resp, site.url), [])
            self.assertEqual(check_cookies(resp, site.url), [])
            self.assertEqual(check_cors(http, site.url), [])
            self.assertEqual(check_exposure(http, site.url.rstrip("/")), [])
            self.assertEqual(check_security_txt(http, site.url.rstrip("/")), [])


class SpaSiteTest(unittest.TestCase):
    def test_soft_404_does_not_create_exposure_findings(self):
        with LocalSite(SpaSite) as site:
            self.assertEqual(check_exposure(client(site.url), site.url.rstrip("/")), [])


class RedirectOffScopeTest(unittest.TestCase):
    def test_headers_check_is_skipped_not_passed(self):
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):  # noqa: N802
                self.send_response(302)
                self.send_header("Location", "https://elsewhere.example/")
                self.send_header("Content-Length", "0")
                self.end_headers()

        with LocalSite(Redirect) as site:
            resp = client(site.url).get(site.url)
            self.assertEqual(resp.offscope_redirect, "https://elsewhere.example/")
            result = ScanResult("t", "now")
            run_check(result, "web.headers", site.url, check_headers, resp, site.url)
            self.assertTrue(result.checks[0].skipped)
            self.assertIn("extra_hosts", result.checks[0].detail)


class UnresponsiveHostTest(unittest.TestCase):
    def test_host_is_skipped_after_repeated_failures(self):
        import socket
        import threading

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        stop = threading.Event()

        def drop_connections():  # accept, then hang up without answering - like a blocking CDN
            listener.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                    conn.close()
                except OSError:
                    continue

        worker = threading.Thread(target=drop_connections, daemon=True)
        worker.start()
        try:
            url = f"http://127.0.0.1:{port}/"
            http = client(url)
            for _ in range(HttpClient.BREAKER_THRESHOLD):
                with self.assertRaises(FetchError):
                    http.get(url)
            used = http.used
            with self.assertRaisesRegex(FetchError, "stopped responding"):
                http.get(url + ".env")
            self.assertEqual(http.used, used)  # skipped without spending budget or time
            self.assertIn("rate-limiting or blocking", http.notes[-1])
        finally:
            stop.set()
            worker.join(2)
            listener.close()


class HelpersTest(unittest.TestCase):
    def test_parse_csp(self):
        csp = parse_csp("default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline'; frame-ancestors 'none'")
        self.assertEqual(csp["script-src"], ["'self'", "'nonce-abc'", "'unsafe-inline'"])
        self.assertIn("frame-ancestors", csp)

    def test_certificate_expiry(self):
        origin = Origin("https", "shop.example.com", 443)
        now = ssl.cert_time_to_seconds("Jan  1 00:00:00 2030 GMT")
        soon = {"notAfter": "Jan 10 00:00:00 2030 GMT"}
        later = {"notAfter": "Jan 25 00:00:00 2030 GMT"}
        fine = {"notAfter": "Jun  1 00:00:00 2030 GMT"}
        self.assertEqual(evaluate_expiry(soon, origin, now)[0].severity, Severity.HIGH)
        self.assertEqual(evaluate_expiry(later, origin, now)[0].severity, Severity.MEDIUM)
        self.assertEqual(evaluate_expiry(fine, origin, now), [])
        # the id is stable while the title counts down, so medium -> high is an escalation
        self.assertEqual(evaluate_expiry(soon, origin, now)[0].id, evaluate_expiry(later, origin, now)[0].id)


if __name__ == "__main__":
    unittest.main()
