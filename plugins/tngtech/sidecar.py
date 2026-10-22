#!/usr/bin/env python3
"""Dummy sidecar: fetches the tngtech.com homepage for a sandboxed workload.

Runs OUTSIDE the sandbox, in the supervisor's job object. It is the only
process in this design that talks to the internet on the workload's behalf.

Protocol (plain HTTP/1.0 on 127.0.0.1:$SIDECAR_PORT):

    GET /status   -> {"ok": true}                  (health probe, no token)
    GET /         -> the upstream homepage, verbatim text/html

Every other request, and every request without the facade token, is refused.
The token arrives in `X-Facade-Token`; it is per session and lives only in this
process's environment, never in the sandbox.

This plugin carries no secret yet. It is the transport proof: if a sandboxed
`curl http://tngtech.sandbox.invalid/` returns the homepage, then plugin
discovery, sidecar spawn, the health gate and the facade relay all work, and a
credentialed plugin only has to add headers at the marked place below.
"""

from __future__ import annotations

import gzip
import hmac
import io
import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("SIDECAR_PORT", "0"))
TOKEN = os.environ.get("SIDECAR_FACADE_TOKEN", "")
MOUNT = os.environ.get("SIDECAR_MOUNT", "tngtech")
UPSTREAM = os.environ.get("SIDECAR_UPSTREAM", "https://www.tngtech.com/")

if not PORT:
    print("sidecar: SIDECAR_PORT not set", file=sys.stderr)
    raise SystemExit(2)


def fetch_homepage() -> tuple[int, str, bytes]:
    """Fetch the upstream page. Credentials would be attached here."""
    req = urllib.request.Request(
        UPSTREAM,
        headers={
            # --- credential injection point ---------------------------------
            # A credentialed plugin adds e.g.
            #   "Authorization": "Basic " + base64(user + ":" + token)
            # resolved from this process's environment, never from the request.
            # ----------------------------------------------------------------
            "User-Agent": f"sandbox-sidecar/{MOUNT} (dummy)",
            "Accept-Encoding": "identity",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read()
            ctype = r.headers.get("Content-Type", "text/html; charset=utf-8")
            if r.headers.get("Content-Encoding", "").lower() == "gzip":
                body = gzip.GzipFile(fileobj=io.BytesIO(body)).read()
            return r.status, ctype, body
    except urllib.error.HTTPError as e:
        return e.code, "text/plain; charset=utf-8", (e.read() or b"upstream error")
    except Exception as e:  # noqa: BLE001 - the sidecar reports, it does not crash
        return 502, "text/plain; charset=utf-8", f"sidecar upstream failure: {e}".encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = f"sandbox-sidecar-{MOUNT}"

    def log_message(self, fmt, *args):  # keep stdout/stderr for the supervisor
        print(f"sidecar[{MOUNT}]: " + (fmt % args), file=sys.stderr)

    def _deny(self, code: int, why: str) -> None:
        body = (why + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/status":
            body = json.dumps({"ok": True, "mount": MOUNT}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        supplied = self.headers.get("X-Facade-Token", "")
        # The token is per session and only proves "the supervisor sent this".
        # A caller that reaches the port directly cannot pass it.
        if not TOKEN or not hmac.compare_digest(supplied, TOKEN):
            self._deny(401, "facade token required")
            return

        if self.path not in ("/", ""):
            self._deny(404, "operation not declared by this plugin")
            return

        status, ctype, body = fetch_homepage()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Sidecar-Mount", MOUNT)
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"sidecar[{MOUNT}]: listening on 127.0.0.1:{PORT}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
