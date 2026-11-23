#!/usr/bin/env python3
"""HTTP endpoint for the BSC Token-Safety Scout.

  GET  /health          -> {"status": "ok"}
  POST /scan            -> JSON report for {"address": "0x..."}
  GET  /scan?address=0x...  (convenience, same report)

Standard library only (http.server). Port from env PORT (default 8787),
binds 0.0.0.0.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import scout


class Handler(BaseHTTPRequestHandler):
    server_version = "TokenSafetyScout/1.0"

    def _send_json(self, code, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _clean_path(raw):
        # Serverless hosts (e.g. Vercel) may deliver the request with the
        # function path still attached ("/api/index.py/health"); strip any
        # such prefix so routing matches the public URL.
        path = urlparse(raw).path
        for prefix in ("/api/index.py", "/api"):
            if path == prefix:
                return "/"
            if path.startswith(prefix + "/"):
                return path[len(prefix):]
        return path

    def do_GET(self):
        parsed = urlparse(self.path)
        route = self._clean_path(self.path)
        if route in ("/", "/health"):
            self._send_json(200, {"status": "ok",
                                  "service": "bsc-token-safety-scout"})
            return
        if route == "/scan":
            address = (parse_qs(parsed.query).get("address") or [None])[0]
            self._scan(address)
            return
        self._send_json(404, {"error": "not found",
                              "routes": ["GET /health",
                                         "POST /scan {address}",
                                         "GET /scan?address=0x..."]})

    def do_POST(self):
        if self._clean_path(self.path) != "/scan":
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._send_json(400, {"error": "body must be JSON "
                                           "{\"address\": \"0x...\"}"})
            return
        self._scan(payload.get("address"))

    def _scan(self, address):
        if not address:
            self._send_json(400, {"error": "missing 'address'"})
            return
        try:
            report = scout.scan(address)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:  # never leak a stack trace to clients
            self._send_json(502, {"error": f"scan failed: {exc}"})
            return
        self._send_json(200, report)

    def log_message(self, fmt, *args):  # keep stdout clean
        pass


def main():
    port = int(os.environ.get("PORT", "8787"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"bsc-token-safety-scout listening on 0.0.0.0:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
