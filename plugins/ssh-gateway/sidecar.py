#!/usr/bin/env python3
"""ssh-gateway: run DECLARED ssh verbs on DECLARED hosts for a sandboxed workload.

Runs OUTSIDE the sandbox, in the supervisor's job object. The SSH keys this
sidecar uses live host-side (typically %USERPROFILE%\\.ssh) and never enter the
container: the workload asks the facade for a verb on a named host and receives
the bytes. Everything else about SSH - identity, known_hosts, the network dial -
stays on the host.

Protocol (plain HTTP/1.0 on 127.0.0.1:$SIDECAR_PORT):

    GET  /status  -> {"ok": true, "mount": ..., "hosts": N}   (health, no token)
    GET  /hosts   -> the declared hosts, WITHOUT identity paths
    POST /exec    -> run one verb on one host; body is JSON:
                     {"host": "srv1", "verb": "list",
                      "args": "optional remote argument string",
                      "stdin": "optional stdin payload"}
                     success: 200, body = the remote stdout (verbatim bytes)
                     ssh failure: 502, body = the remote stderr
                     unknown host / verb not declared for it: 403
                     malformed request: 400

Policy comes from the gateway file (SIDECAR_CFG_GATEWAY_FILE, env-expanded):

    {
      "hosts": {
        "srv1": {
          "target": "logreader@photo-server.de",
          "port": 22,
          "identity": "%USERPROFILE%\\.ssh\\logreader_ed25519",
          "commands": ["list", "stream", "journal", "version"]
        }
      }
    }

Invariants:

  * an undeclared host, or a verb not in that host's `commands`, is refused
    before any process is spawned (403);
  * a verb of "*" admits any verb, but never arbitrary shell syntax: the remote
    command is `verb` + `args`, and BOTH are checked against a strict charset
    (no quotes, no semicolons, no whitespace in the verb). The remote end is the
    real guard - keep its sshd ForceCommand;
  * `args`/`stdin` are size-capped; ssh output is capped at
    `max_output_mb` (default 256);
  * every request except /status requires the facade token;
  * `ssh` is spawned as an argv list - this sidecar never builds a shell line.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("SIDECAR_PORT", "0"))
TOKEN = os.environ.get("SIDECAR_FACADE_TOKEN", "")
MOUNT = os.environ.get("SIDECAR_MOUNT", "ssh")
GATEWAY_FILE = os.environ.get("SIDECAR_CFG_GATEWAY_FILE", "")

VERB_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
ARGS_RE = re.compile(r"^[A-Za-z0-9@._,:=/+\- ]{0,4000}$")
DEFAULT_MAX_OUTPUT_MB = 256
MAX_STDIN_BYTES = 4 * 1024 * 1024


def expand_env(path: str) -> str:
    """Expand %NAME% (Windows style) and $NAME / ${NAME} in one string."""
    out = re.sub(r"%([A-Za-z_][A-Za-z0-9_]*)%",
                 lambda m: os.environ.get(m.group(1), m.group(0)), path)
    return os.path.expandvars(out)


def load_gateway() -> dict:
    """Read the gateway file; a missing or broken file means NO hosts, not a crash."""
    if not GATEWAY_FILE:
        return {"hosts": {}}
    path = expand_env(GATEWAY_FILE)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"sidecar[{MOUNT}]: gateway file unusable: {exc}", file=sys.stderr)
        return {"hosts": {}}
    if not isinstance(data, dict) or not isinstance(data.get("hosts"), dict):
        print(f"sidecar[{MOUNT}]: gateway file has no 'hosts' object", file=sys.stderr)
        return {"hosts": {}}
    return data


GATEWAY = load_gateway()


def host_entry(name: str) -> dict | None:
    entry = GATEWAY["hosts"].get(name)
    return entry if isinstance(entry, dict) else None


def verb_allowed(entry: dict, verb: str) -> bool:
    commands = entry.get("commands", [])
    return isinstance(commands, list) and ("*" in commands or verb in commands)


def run_ssh(entry: dict, verb: str, args: str, stdin: bytes) -> tuple[int, bytes]:
    """Spawn ssh for one verb; return (http_status, body)."""
    target = entry["target"]
    port = int(entry.get("port", 22))
    cmd = [
        "ssh",
        "-T",
        "-p", str(port),
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={int(entry.get('connect_timeout', 15))}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "LogLevel=ERROR",
    ]
    identity = entry.get("identity")
    if identity:
        path = expand_env(identity)
        if not os.path.isfile(path):
            return 502, f"identity file not accessible: {path}".encode()
        cmd += ["-i", path, "-o", "IdentitiesOnly=yes"]
    known_hosts = entry.get("known_hosts")
    if known_hosts:
        cmd += ["-o", f"UserKnownHostsFile={expand_env(known_hosts)}"]
    cmd.append(target)

    remote = verb if not args else f"{verb} {args.strip()}"
    cmd.append(remote)

    cap = int(entry.get("max_output_mb", DEFAULT_MAX_OUTPUT_MB)) * 1024 * 1024
    try:
        proc = subprocess.run(
            cmd,
            input=stdin if stdin else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=int(entry.get("command_timeout", 300)),
        )
    except subprocess.TimeoutExpired:
        return 504, f"ssh timed out: {verb}".encode()
    except FileNotFoundError:
        return 502, b"the 'ssh' executable was not found on the host"
    except OSError as exc:
        return 502, f"ssh could not be spawned: {exc}".encode()

    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        return 502, f"ssh exit {proc.returncode}: {detail}".encode()[:8192]
    if len(proc.stdout) > cap:
        return 502, f"output exceeds max_output_mb ({cap // (1024 * 1024)} MB)".encode()
    return 200, proc.stdout


def token_ok(supplied: str) -> bool:
    return bool(TOKEN) and hmac.compare_digest(supplied, TOKEN)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = f"sandbox-sidecar-{MOUNT}"

    def log_message(self, fmt, *args):  # keep stdout/stderr for the supervisor
        print(f"sidecar[{MOUNT}]: " + (fmt % args), file=sys.stderr)

    def _reply(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Sidecar-Mount", MOUNT)
        self.end_headers()
        self.wfile.write(body)

    def _deny(self, code: int, why: str) -> None:
        self._reply(code, (why + "\n").encode())

    def _json(self, code: int, obj: dict) -> None:
        self._reply(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/status":
            self._json(200, {"ok": True, "mount": MOUNT, "hosts": len(GATEWAY["hosts"])})
            return

        supplied = self.headers.get("X-Facade-Token", "")
        # The token is per session and only proves "the supervisor sent this".
        # A caller that reaches the port directly cannot pass it.
        if not token_ok(supplied):
            self._deny(401, "facade token required")
            return

        if self.path == "/hosts":
            hosts = [
                {"name": name,
                 "target": entry.get("target"),
                 "commands": entry.get("commands", [])}
                for name, entry in sorted(GATEWAY["hosts"].items())
                if isinstance(entry, dict)
            ]
            self._json(200, {"hosts": hosts})
            return

        self._deny(404, "operation not declared by this plugin")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        supplied = self.headers.get("X-Facade-Token", "")
        if not token_ok(supplied):
            self._deny(401, "facade token required")
            return

        length = min(int(self.headers.get("Content-Length", "0") or 0), MAX_STDIN_BYTES + 65536)
        raw = self.rfile.read(length) if length else b""
        try:
            req = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._deny(400, "body must be JSON")
            return
        if not isinstance(req, dict):
            self._deny(400, "body must be a JSON object")
            return

        host = req.get("host")
        verb = req.get("verb", "")
        args = req.get("args", "")
        stdin_text = req.get("stdin", "")

        if not isinstance(host, str) or not host:
            self._deny(400, "'host' is required")
            return
        entry = host_entry(host)
        if entry is None or "target" not in entry:
            self._deny(403, f"host_not_declared: {host}")
            return
        if not isinstance(verb, str) or not VERB_RE.match(verb):
            self._deny(400, "verb must be 1-64 chars of [A-Za-z0-9_.:-]")
            return
        if not verb_allowed(entry, verb):
            self._deny(403, f"command_not_declared: {verb} on {host}")
            return
        if not isinstance(args, str) or not ARGS_RE.match(args):
            self._deny(400, "args exceed the allowed charset or length")
            return
        if not isinstance(stdin_text, str) or len(stdin_text.encode("utf-8")) > MAX_STDIN_BYTES:
            self._deny(400, f"stdin must be text of at most {MAX_STDIN_BYTES} bytes")
            return

        code, body = run_ssh(entry, verb, args, stdin_text.encode("utf-8"))
        ctype = "application/octet-stream" if code == 200 else "text/plain; charset=utf-8"
        self._reply(code, body, ctype)


def main() -> int:
    if not PORT:
        print("sidecar: SIDECAR_PORT not set", file=sys.stderr)
        return 2
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"sidecar[{MOUNT}]: listening on 127.0.0.1:{PORT}, "
          f"{len(GATEWAY['hosts'])} host(s) declared", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
