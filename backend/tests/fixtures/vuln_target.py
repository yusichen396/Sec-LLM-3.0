"""A deliberately vulnerable local target used by the detector integration tests.

Not a web framework: a ``http.server`` handler is enough, keeps the test offline and
lets each endpoint demonstrate exactly one signal the detectors must catch.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Tuple
from urllib.parse import parse_qs, urlsplit


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output clean
        return

    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 - stdlib naming
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        value = (query.get("q") or [""])[0]
        file_value = (query.get("file") or [""])[0]

        if parts.path == "/search":
            # 注入单引号 → 数据库报错特征；AND 1=2 → 页面变短
            if "'" in value:
                self._send(500, "You have an error in your SQL syntax near ''' at line 1")
            elif "1 AND 1=2" in value:
                self._send(200, "no results")
            else:
                self._send(200, "<html><body>" + "result item " * 120 + "</body></html>")
            return

        if parts.path == "/download":
            if "etc/passwd" in file_value.replace("%2f", "/").replace("%2F", "/"):
                self._send(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            else:
                self._send(200, "<html><body>file not found</body></html>")
            return

        if parts.path == "/openapi.json":
            spec = {
                "openapi": "3.0.0",
                "paths": {
                    "/users": {"get": {"parameters": [{"name": "id", "in": "query"}]}},
                    "/login": {"post": {}},
                },
            }
            self._send(200, json.dumps(spec), content_type="application/json")
            return

        self._send(404, "<html><body>not found</body></html>")


def start(port: int = 0) -> Tuple[ThreadingHTTPServer, str, threading.Thread]:
    """Start the target on an ephemeral port; returns (server, base_url, thread)."""
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}", thread


if __name__ == "__main__":
    srv, base, _ = start(8099)
    print(f"vulnerable fixture listening on {base}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
