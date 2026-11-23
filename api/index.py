#!/usr/bin/env python3
"""Vercel serverless entrypoint for the BSC Token-Safety Scout.

Same behaviour as server.py, exposed as a WSGI app:

  GET  /health               -> {"status": "ok", ...}
  GET  /scan?address=0x...   -> JSON verdict report
  POST /scan {"address": "0x..."} -> JSON verdict report
  GET  /                     -> service info + routes

Standard library only. The scan logic lives in ../scout.py.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scout  # noqa: E402

_STATUS = {
    200: "200 OK",
    400: "400 Bad Request",
    404: "404 Not Found",
    405: "405 Method Not Allowed",
    502: "502 Bad Gateway",
}


def _respond(start_response, code, obj):
    body = json.dumps(obj, indent=2).encode()
    start_response(_STATUS[code], [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(body))),
        ("Access-Control-Allow-Origin", "*"),
    ])
    return [body]


def _scan(start_response, address):
    if not address:
        return _respond(start_response, 400, {"error": "missing 'address'"})
    try:
        report = scout.scan(address)
    except ValueError as exc:
        return _respond(start_response, 400, {"error": str(exc)})
    except Exception as exc:  # never leak a stack trace to clients
        return _respond(start_response, 502, {"error": f"scan failed: {exc}"})
    return _respond(start_response, 200, report)


def _clean_path(path):
    # Serverless rewrites may deliver the function path itself
    # ("/api/index.py/health"); strip it so routing matches the public URL.
    for prefix in ("/api/index.py", "/api"):
        if path == prefix:
            return "/"
        if path.startswith(prefix + "/"):
            return path[len(prefix):]
    return path


def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = _clean_path(environ.get("PATH_INFO", "/") or "/")

    if path in ("/", "/health"):
        if method != "GET":
            return _respond(start_response, 405, {"error": "GET only"})
        return _respond(start_response, 200, {
            "status": "ok",
            "service": "bsc-token-safety-scout",
            "routes": ["GET /health",
                       "POST /scan {\"address\": \"0x...\"}",
                       "GET /scan?address=0x..."],
        })

    if path == "/scan":
        if method == "GET":
            from urllib.parse import parse_qs
            qs = parse_qs(environ.get("QUERY_STRING", ""))
            address = (qs.get("address") or [None])[0]
            return _scan(start_response, address)
        if method == "POST":
            try:
                length = int(environ.get("CONTENT_LENGTH") or 0)
                payload = json.loads(
                    environ["wsgi.input"].read(length) or b"{}")
            except Exception:
                return _respond(start_response, 400, {
                    "error": "body must be JSON {\"address\": \"0x...\"}"})
            return _scan(start_response, payload.get("address"))
        return _respond(start_response, 405, {"error": "GET or POST only"})

    return _respond(start_response, 404, {"error": "not found"})
