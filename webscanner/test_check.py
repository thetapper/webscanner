"""Tests for the webscanner check functions.

Run with:
    python -m unittest test_checks.py -v
"""
import unittest
from email.message import Message

from backend import (
    check_transport,
    check_cookies,
    cookies_enabled,
    has_httponly,
    has_secure,
)


def make_headers(cookie_strings):
    """Build a fake response-headers object that supports get_all(),
    the same way http.client's real response headers do.
    """
    headers = Message()
    for cookie in cookie_strings:
        headers["Set-Cookie"] = cookie
    return headers


# ---------------------------------------------------------------------------
# check_transport
# ---------------------------------------------------------------------------

class TestCheckTransport(unittest.TestCase):
    """check_transport() should pass only when the final URL is HTTPS."""

    def test_http_redirects_to_https(self):
        result = check_transport("http://example.com", "https://example.com")
        self.assertTrue(result["passed"])

    def test_https_stays_https(self):
        result = check_transport("https://example.com", "https://example.com")
        self.assertTrue(result["passed"])

    def test_http_never_upgrades(self):
        result = check_transport("http://example.com", "http://example.com")
        self.assertFalse(result["passed"])

    def test_https_downgrades_to_http(self):
        result = check_transport("https://example.com", "http://example.com")
        self.assertFalse(result["passed"])


# ---------------------------------------------------------------------------
# has_httponly / has_secure
# ---------------------------------------------------------------------------

class TestHasHttponly(unittest.TestCase):
    """has_httponly() should detect the HttpOnly flag, case-insensitively."""

    def test_present(self):
        self.assertTrue(has_httponly("sessionid=abc; HttpOnly; Secure"))

    def test_missing(self):
        self.assertFalse(has_httponly("sessionid=abc; Secure"))

    def test_case_insensitive(self):
        self.assertTrue(has_httponly("sessionid=abc; httponly"))


class TestHasSecure(unittest.TestCase):
    """has_secure() should detect the Secure flag."""

    def test_present(self):
        self.assertTrue(has_secure("sessionid=abc; Secure"))

    def test_missing(self):
        self.assertFalse(has_secure("sessionid=abc; HttpOnly"))


# ---------------------------------------------------------------------------
# cookies_enabled
# ---------------------------------------------------------------------------

class TestCookiesEnabled(unittest.TestCase):
    """cookies_enabled() should report whether any cookies were set."""

    def test_no_cookie_header(self):
        self.assertFalse(cookies_enabled({}))

    def test_cookie_header_present(self):
        self.assertTrue(cookies_enabled({"set-cookie": "sessionid=abc"}))


# ---------------------------------------------------------------------------
# check_cookies
# ---------------------------------------------------------------------------

class TestCheckCookies(unittest.TestCase):
    """check_cookies() should flag any cookie missing HttpOnly or Secure."""

    def test_no_cookies_set(self):
        headers = make_headers([])

        result = check_cookies(headers)

        self.assertTrue(result["passed"])
        self.assertIn("No cookies", result["details"])

    def test_all_cookies_safe(self):
        headers = make_headers([
            "sessionid=abc; HttpOnly; Secure",
            "csrftoken=xyz; HttpOnly; Secure",
        ])

        result = check_cookies(headers)

        self.assertTrue(result["passed"])

    def test_one_cookie_missing_httponly(self):
        headers = make_headers([
            "sessionid=abc; Secure",  # missing HttpOnly
        ])

        result = check_cookies(headers)

        self.assertFalse(result["passed"])
        self.assertIn("HttpOnly", result["details"])

    def test_one_of_several_cookies_unsafe(self):
        """Regression test: every cookie must be checked, not just the
        first one (an earlier version returned as soon as it found one
        bad cookie, silently skipping the rest)."""
        headers = make_headers([
            "sessionid=abc; HttpOnly; Secure",
            "tracking=xyz",  # missing both flags
        ])

        result = check_cookies(headers)

        self.assertFalse(result["passed"])
        self.assertIn("tracking", result["details"])

    def test_cookie_with_comma_in_expires_not_split(self):
        """Regression test: a cookie with a comma inside its Expires date
        must stay intact as ONE cookie, not get shredded by a naive
        comma-split (an earlier version used raw_headers.get('Set-Cookie')
        and split on ',', which broke on dates like 'Wed, 21 Oct ...')."""
        headers = make_headers([
            "sessionid=abc; HttpOnly; Secure; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
        ])

        result = check_cookies(headers)

        self.assertTrue(result["passed"])


if __name__ == "__main__":
    unittest.main()