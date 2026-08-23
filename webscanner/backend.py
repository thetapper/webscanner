"""Small HTTP backend for the webscanner project."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse


HOST = "127.0.0.1"
PORT = 8000


def scan_url(url):
    """Fetch a URL and report a few common security configuration gaps."""
    parsed_url = urlparse(url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError("url must be a valid http or https URL")

    request = Request(url, headers={"User-Agent": "webscanner/1.0"})
    try:
        with urlopen(request, timeout=10) as response:
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
            payload = json.loads(self.rfile.read(content_length))
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
