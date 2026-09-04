"""Small HTTP backend for the webscanner project."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys
import socket
import ipaddress
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse

try:
    import certifi
except ImportError:
    certifi = None


HOST = "127.0.0.1"
PORT = 8000


def cookies_enabled(headers):
    """Check if the server sets cookies."""
    return bool(headers.get("set-cookie"))

def has_httponly(cookie_string):
    """Check if a cookie has the HttpOnly attribute."""
    return "httponly" in cookie_string.lower()

def has_secure(cookie_string):
    """Check if a cookie has the Secure attribute."""
    return "secure" in cookie_string.lower()

def check_cookies(raw_headers):
    """ Check if the server sets cookies and if HTTPOnly and Secure attributes are present."""
    cookie_jar = raw_headers.get_all("Set-Cookie") or []

    if not cookie_jar:
        return {
            "name" : "cookies",
            "passed" : True,
            "details" : "No cookies are set."
        }

    issue = []
    for cookie in cookie_jar:
        if not has_httponly(cookie):
            issue.append(f"missing HttpOnly: {cookie}")
        if not has_secure(cookie):
            issue.append(f"missing Secure: {cookie}")

    passed = len(issue) == 0
    details = "All cookies have HttpOnly and Secure attributes." if passed else "; ".join(issue)

    return {
        "name": "cookies",
        "passed": passed,
        "details": details,
    }


def check_transport(url, final_url):
    """Describe how the URL's transport security changed."""
    original_scheme = urlparse(url).scheme
    final_scheme = urlparse(final_url).scheme


    if original_scheme == "http" and final_scheme == "https":
            passed = True
            details = "The URL redirects from HTTP to HTTPS."
        
    elif original_scheme == "https" and final_scheme == "http":
            passed = False
            details = "The URL downgrades from HTTPS to HTTP."
    
    elif final_scheme == "http":
            passed = False
            details = "The URL uses HTTP and does not redirect to HTTPS."

    else:
            passed = True
            details = "The URL uses HTTPS and does not downgrade to HTTP."        

    return {
        "name": "http_enforcement",
        "passed": passed,
        "details": details,
    }

def is_safe_host(hostname):
    """Check if a hostname resolves to a safe IP address."""
    if not hostname:
        return False

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for _, _, _, _, sockaddr in addresses:
        ip_obj = ipaddress.ip_address(sockaddr[0])
        if not ip_obj.is_global:
            return False
    return bool(addresses)

def scan_url(url):
    """Fetch a URL and report a few common security configuration gaps."""
    parsed_url = urlparse(url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError("url must be a valid http or https URL")
    if not is_safe_host(parsed_url.hostname):
        raise ValueError("url must resolve to a public IP address")

    request = Request(url, headers={"User-Agent": "webscanner/1.0"})
    ssl_context = ssl.create_default_context(
        cafile=certifi.where() if certifi else None
    )
    try:
        with urlopen(request, timeout=10, context=ssl_context) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            status = response.status
            final_url = response.geturl()
    except HTTPError as error:
        headers = {key.lower(): value for key, value in error.headers.items()}
        status = error.code
        final_url = url
    except URLError as error:
        raise ConnectionError(f"could not reach URL: {error.reason}") from error

    recommended_headers = {
        "content-security-policy": "Helps limit executable content sources.",
        "strict-transport-security": "Requires HTTPS on future requests.",
        "x-content-type-options": "Prevents MIME-type sniffing.",
        "x-frame-options": "Helps prevent clickjacking.",
    }
    missing_headers = [
        {"name": name, "reason": reason}
        for name, reason in recommended_headers.items()
        if name not in headers
    ]

    return {
        "url": url,
        "final_url": final_url,
        "status": status,
        "missing_security_headers": missing_headers,
    }


class BackendHandler(BaseHTTPRequestHandler):
    """Handle health checks and URL scan requests."""

    def send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self.send_json(
                {
                    "service": "webscanner backend",
                    "status": "ok",
                    "endpoints": {
                        "health": "GET /health",
                        "scan": "POST /scan with JSON body {\"url\": \"https://example.com\"}",
                    },
                }
            )
            return
        if self.path == "/health":
            self.send_json({"status": "ok"})
            return
        self.send_json({"error": "not found"}, status=404)

    def do_POST(self):
        if self.path != "/scan":
            self.send_json({"error": "not found"}, status=404)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                raise ValueError("request body is required")
            payload = json.loads(self.rfile.read(content_length))
            if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
                raise ValueError('request body must contain a string "url"')
            result = scan_url(payload["url"])
        except (ValueError, KeyError, json.JSONDecodeError) as error:
            self.send_json({"error": str(error)}, status=400)
            return
        except ConnectionError as error:
            self.send_json({"error": str(error)}, status=502)
            return

        self.send_json(result)

    def log_message(self, format_string, *args):
        sys.stderr.write(f"{self.address_string()} - {format_string % args}\n")


def main():
    server = HTTPServer((HOST, PORT), BackendHandler)
    print(f"webscanner backend listening on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping backend")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
