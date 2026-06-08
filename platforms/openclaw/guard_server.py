"""Lightweight HTTP server exposing prompt-guard scan endpoints for OpenClaw.

Listens on localhost:9373 (configurable via --port).
All endpoints return HTTP 200; errors are returned as JSON {"error": "..."}.

Endpoints:
  POST /scan         — check_output()       → GuardResult as JSON
  POST /scan-pre     — check_pre_tool()     → GuardResult as JSON
  POST /scan-memory  — check_memory_write() → GuardResult as JSON
  GET  /health       — {"status": "ok"}
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

_MAX_BODY = 2 * 1024 * 1024  # 2 MB

# ---------------------------------------------------------------------------
# Make project importable when run directly (python3 guard_server.py)
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from promptguard.guard import (  # noqa: E402
    GuardResult,
    check_memory_write,
    check_output,
    check_pre_tool,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("guard_server")


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def _result_to_dict(r: GuardResult) -> dict:
    return {
        "risk_score": r.risk_score,
        "risk_band": r.risk_band,
        "block": r.block,
        "advisory": r.advisory,
        "signals": r.signals,
    }


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class GuardHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):  # silence default access log noise
        log.debug(fmt, *args)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > _MAX_BODY:
            self.send_response(413)
            self.end_headers()
            return None
        body = self.rfile.read(length) if length else b"{}"
        return json.loads(body)

    def _send_json(self, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            self._send_json({"status": "ok"})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):  # noqa: N802
        try:
            body = self._read_json()
        except Exception as exc:
            self._send_json({"error": "invalid JSON: %s" % exc})
            return
        if body is None:  # 413 already sent
            return

        path = urlparse(self.path).path.rstrip("/") or "/"

        try:
            if path == "/scan":
                tool_name = str(body.get("tool_name") or "")
                content = str(body.get("content") or "")
                label = str(body.get("label") or "")
                result = check_output(tool_name, content, label)
                self._send_json(_result_to_dict(result))

            elif path == "/scan-pre":
                tool_name = str(body.get("tool_name") or "")
                tool_input = body.get("tool_input") or {}
                if not isinstance(tool_input, dict):
                    tool_input = {}
                result = check_pre_tool(tool_name, tool_input)
                self._send_json(_result_to_dict(result))

            elif path == "/scan-memory":
                file_path = str(body.get("file_path") or "")
                content = str(body.get("content") or "")
                result = check_memory_write(file_path, content)
                self._send_json(_result_to_dict(result))

            else:
                self.send_response(404)
                self.end_headers()

        except Exception as exc:
            log.exception("handler error on %s", self.path)
            self._send_json({"error": str(exc)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="prompt-guard HTTP scan server")
    parser.add_argument("--port", type=int, default=9373, help="Port to listen on (default: 9373)")
    args = parser.parse_args()

    server = HTTPServer(("127.0.0.1", args.port), GuardHandler)
    log.info("prompt-guard server listening on localhost:%d", args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        log.info("server stopped")


if __name__ == "__main__":
    main()
