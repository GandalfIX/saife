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
          "target": "logs@example.invalid",
          "port": 22,
          "identity": "%USERPROFILE%\\.ssh\\id_ed25519",
          "commands": ["list", "stream", "journal", "version"]
        }
      }
    }

Invariants:

  * an undeclared host, or a verb not in that host's `commands`, is refused
    before any process is spawned (403); a host entry whose `target` starts with
    '-' or contains whitespace, or whose numeric fields are not integers, is
    dropped AT LOAD (a `target` is interpolated into the argv; a leading dash is
    an ssh option if a refactor ever moves it before the host);
  * a verb of "*" admits any verb, but never arbitrary shell syntax: the remote
    command is `verb` + `args`, and BOTH are checked against a strict charset
    that ends with `\Z` (no quotes, no semicolons, no newline, no whitespace in
    the verb; the verb may not begin with '-'). The remote end is the real
    guard - keep its sshd ForceCommand;
  * ssh is spawned as an argv list - this sidecar never builds a shell line -
    under an empty `-F` config with forwarding and local-command options off, so
    the user's ~/.ssh/config cannot govern the connection;
  * `max_output_mb` bounds MEMORY: stdout is read through a bounded reader and
    the child is killed at the cap, instead of buffering first and checking
    after; a spent `command_timeout` and a hung-up client both kill the child;
  * `/exec` holds one of a bounded number of slots (SIDECAR_CFG_MAX_CONCURRENT,
    default 4); over-cap calls are a named 503, never a queue;
  * every request except /status requires the facade token;
  * every /exec - refused or run - leaves one structured EXEC record on stderr
    (host, verb, args digest, stdin bytes, status, ssh exit, output bytes).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(os.environ.get("SIDECAR_PORT", "0"))
TOKEN = os.environ.get("SIDECAR_FACADE_TOKEN", "")
MOUNT = os.environ.get("SIDECAR_MOUNT", "ssh")
GATEWAY_FILE = os.environ.get("SIDECAR_CFG_GATEWAY_FILE", "")

# First character may not be '-': a verb is a remote command NAME, and one that
# reads like an ssh option ("-oProxyCommand=...") is a trap for any future
# refactor that reorders the argv. Dashes inside stay legal ("list-verbose").
#
# \Z, not `$`: `$` also matches BEFORE a trailing newline, so "list\n" passed
# the charset and a wildcard host would execute two remote commands.
VERB_RE = re.compile(r"^[A-Za-z0-9_.:][A-Za-z0-9_.:-]{0,63}\Z")
ARGS_RE = re.compile(r"^[A-Za-z0-9@._,:=/+\- ]{0,4000}\Z")
DEFAULT_MAX_OUTPUT_MB = 256
MAX_STDIN_BYTES = 4 * 1024 * 1024
READ_CHUNK = 64 * 1024

# The ssh config this sidecar runs under: an EMPTY file shipped next to it, so
# the user's ~/.ssh/config (ProxyCommand, ForwardAgent, LocalForward, Match
# blocks) cannot govern a connection the manifest is supposed to define.
SSH_CONFIG = Path(__file__).with_name("ssh_config")


def max_exec() -> int:
    """Concurrent /exec slots. The sidecar spawns `ssh` per call; unbounded
    slots let one workload exhaust the host and flood the remote sshd."""
    raw = os.environ.get("SIDECAR_CFG_MAX_CONCURRENT",
                         os.environ.get("SIDECAR_MAX_EXEC", "4"))
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return 4


EXEC_PERMITS = threading.BoundedSemaphore(max_exec())


def expand_env(path: str) -> str:
    """Expand %NAME% (Windows style) and $NAME / ${NAME} in one string."""
    out = re.sub(r"%([A-Za-z_][A-Za-z0-9_]*)%",
                 lambda m: os.environ.get(m.group(1), m.group(0)), path)
    return os.path.expandvars(out)


def validate_entry(name: str, entry: object) -> list[str]:
    """Problems that make a host entry unsafe to spawn ssh for.

    `target` is interpolated into the argv: a leading '-' is an ssh OPTION if a
    future refactor ever moves it before the host, and whitespace would split it
    into several arguments. Both are refused here, at load, not at spawn.
    """
    if not isinstance(entry, dict):
        return [f"host '{name}': entry must be an object"]
    problems: list[str] = []
    target = entry.get("target")
    if not isinstance(target, str) or not target:
        problems.append(f"host '{name}': target is required")
    elif target.lstrip().startswith("-"):
        problems.append(f"host '{name}': target may not begin with '-'")
    elif any(ch.isspace() for ch in target):
        problems.append(f"host '{name}': target may not contain whitespace")
    for key in ("port", "connect_timeout", "command_timeout", "max_output_mb"):
        value = entry.get(key)
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            problems.append(f"host '{name}': {key} must be an integer")
    commands = entry.get("commands")
    if not isinstance(commands, list) or not all(isinstance(c, str) for c in commands):
        problems.append(f"host '{name}': commands must be a list of strings")
    return problems


def load_gateway(path: str | None = None) -> dict:
    """Read the gateway file; a missing or broken file means NO hosts, not a crash."""
    if path is None:
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
    # An invalid entry is DROPPED, loudly: zero hosts beats a target that turns
    # into an ssh option, and beats a crash loop on a config typo.
    hosts: dict = {}
    for name, entry in data["hosts"].items():
        problems = validate_entry(str(name), entry)
        if problems:
            for problem in problems:
                print(f"sidecar[{MOUNT}]: refused config: {problem}", file=sys.stderr)
            continue
        hosts[str(name)] = entry
    return {"hosts": hosts}


GATEWAY = load_gateway()


def audit(fields: dict) -> None:
    """One structured line per /exec on stderr (the supervisor's sidecar log).

    The facade leaf records THAT a call crossed the boundary; this record is
    what answers WHICH host, which verb, how many stdin bytes, what ssh did.
    args travel as a digest: a reviewer needs to correlate, not to log content.
    """
    record: dict = {"op": "EXEC", "mount": MOUNT}
    record.update(fields)
    print("sidecar-audit: " + json.dumps(record, separators=(",", ":"), default=str),
          file=sys.stderr)


def peer_gone(sock) -> bool:
    """True when the HTTP client hung up (peek, never consume)."""
    try:
        ready, _, _ = select.select([sock], [], [], 0)
        if not ready:
            return False
        return sock.recv(1, socket.MSG_PEEK) == b""
    except (OSError, ValueError):
        return True


def host_entry(name: str) -> dict | None:
    entry = GATEWAY["hosts"].get(name)
    return entry if isinstance(entry, dict) else None


def verb_allowed(entry: dict, verb: str) -> bool:
    commands = entry.get("commands", [])
    return isinstance(commands, list) and ("*" in commands or verb in commands)


def run_ssh(entry: dict, verb: str, args: str, stdin: bytes,
            client=None) -> tuple[int, bytes, dict]:
    """Spawn ssh for one verb; return (http_status, body, meta).

    Request-derived values are re-validated HERE, not only in the HTTP handler.
    This function is the sink, and a sink must not trust its callers:

      * CodeQL flags the handler-only shape as py/command-line-injection
        (critical) - the taint path request -> `cmd` is real even when an
        upstream check exists;
      * a second call site (a new endpoint, a refactor) would otherwise skip
        every check the handler makes.

    These checks duplicate `do_POST` ON PURPOSE - do not delete them as
    redundant. A refusal returns before any process is spawned.

    The child is supervised, not waited on blindly: stdout is read through a
    bounded reader (the cap kills the child, so `max_output_mb` bounds the
    sidecar's MEMORY, not just the reply), and this thread kills the child on a
    spent budget or a hung-up client - an orphaned ssh would otherwise hold a
    window for `command_timeout` for a caller that is already gone.
    `client` is the handler's socket, or None in tests.
    """
    meta: dict = {"outcome": "ok", "exit": None, "output_bytes": 0}
    if not isinstance(verb, str) or not VERB_RE.match(verb):
        meta["outcome"] = "refused:verb"
        return (400, b"verb must be 1-64 chars of [A-Za-z0-9_.:] and may not begin with '-'",
                meta)
    if not isinstance(args, str) or not ARGS_RE.match(args):
        meta["outcome"] = "refused:args"
        return 400, b"args exceed the allowed charset or length", meta
    if not verb_allowed(entry, verb):
        meta["outcome"] = "refused:command_not_declared"
        return 403, f"command_not_declared: {verb}".encode(), meta

    target = entry.get("target")
    if not isinstance(target, str) or not target:
        meta["outcome"] = "refused:no_target"
        return 502, b"host entry has no target", meta
    port = int(entry.get("port", 22))
    cmd = [
        "ssh",
        "-F", str(SSH_CONFIG),
        "-T",
        "-p", str(port),
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={int(entry.get('connect_timeout', 15))}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ClearAllForwardings=yes",
        "-o", "ForwardAgent=no",
        "-o", "PermitLocalCommand=no",
        "-o", "LogLevel=ERROR",
    ]
    identity = entry.get("identity")
    if identity:
        path = expand_env(identity)
        if not os.path.isfile(path):
            meta["outcome"] = "refused:identity"
            return 502, f"identity file not accessible: {path}".encode(), meta
        cmd += ["-i", path, "-o", "IdentitiesOnly=yes"]
    known_hosts = entry.get("known_hosts")
    if known_hosts:
        cmd += ["-o", f"UserKnownHostsFile={expand_env(known_hosts)}"]
    cmd.append(target)

    remote = verb if not args else f"{verb} {args.strip()}"
    cmd.append(remote)

    cap = int(entry.get("max_output_mb", DEFAULT_MAX_OUTPUT_MB)) * 1024 * 1024
    budget = int(entry.get("command_timeout", 300))
    started = time.monotonic()
    err_file = tempfile.TemporaryFile()
    try:
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=err_file,
            )
        except FileNotFoundError:
            meta["outcome"] = "ssh_not_found"
            return 502, b"the 'ssh' executable was not found on the host", meta
        except OSError as exc:
            meta["outcome"] = "ssh_spawn_failed"
            return 502, f"ssh could not be spawned: {exc}".encode(), meta

        if stdin:
            def feed() -> None:
                try:
                    proc.stdin.write(stdin)
                    proc.stdin.flush()
                    proc.stdin.close()
                except (OSError, ValueError):
                    pass  # the child may be gone; the caller hears of it below

            threading.Thread(target=feed, daemon=True).start()

        out = bytearray()
        outcome = {"why": None}
        done = threading.Event()

        def reader() -> None:
            try:
                while True:
                    chunk = proc.stdout.read(READ_CHUNK)
                    if not chunk:
                        break
                    out.extend(chunk)
                    if len(out) > cap:
                        outcome["why"] = "output_cap"
                        proc.kill()
                        break
            finally:
                done.set()

        threading.Thread(target=reader, daemon=True).start()

        deadline = started + budget
        while not done.wait(0.05):
            if outcome["why"]:
                continue
            if client is not None and peer_gone(client):
                outcome["why"] = "client_gone"
                proc.kill()
            elif time.monotonic() >= deadline:
                outcome["why"] = "timeout"
                proc.kill()

        proc.wait(timeout=5)
        meta["duration_ms"] = int((time.monotonic() - started) * 1000)
        meta["output_bytes"] = len(out)
        why = outcome["why"]
        if why == "output_cap":
            meta["outcome"] = "output_cap"
            return (502,
                    f"output exceeds max_output_mb ({cap // (1024 * 1024)} MB); child killed"
                    .encode(), meta)
        if why == "timeout":
            meta["outcome"] = "timeout"
            return 504, f"ssh timed out: {verb}".encode(), meta
        if why == "client_gone":
            meta["outcome"] = "client_gone"
            return 502, b"caller disconnected; ssh killed", meta
        returncode = proc.returncode
        meta["exit"] = returncode
        if returncode != 0:
            meta["outcome"] = "ssh_failed"
            err_file.seek(0)
            detail = err_file.read(8192).decode("utf-8", "replace").strip()
            return 502, f"ssh exit {returncode}: {detail}".encode()[:8192], meta
        return 200, bytes(out), meta
    finally:
        err_file.close()


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
        args_digest = None
        if isinstance(args, str) and args:
            args_digest = hashlib.sha256(args.encode("utf-8")).hexdigest()[:16]
        base_audit = {
            "host": host if isinstance(host, str) else None,
            "verb": verb if isinstance(verb, str) else None,
            "args_len": len(args) if isinstance(args, str) else None,
            "args_sha256": args_digest,
        }

        def refuse(code: int, why: str, outcome: str) -> None:
            audit({**base_audit, "status": code, "outcome": outcome})
            self._deny(code, why)

        if not isinstance(host, str) or not host:
            refuse(400, "'host' is required", "refused:no_host")
            return
        entry = host_entry(host)
        if entry is None or "target" not in entry:
            refuse(403, f"host_not_declared: {host}", "refused:host_not_declared")
            return
        if not isinstance(verb, str) or not VERB_RE.match(verb):
            refuse(400, "verb must be 1-64 chars of [A-Za-z0-9_.:] and may not begin with '-'",
                   "refused:verb")
            return
        if not verb_allowed(entry, verb):
            refuse(403, f"command_not_declared: {verb} on {host}",
                   "refused:command_not_declared")
            return
        if not isinstance(args, str) or not ARGS_RE.match(args):
            refuse(400, "args exceed the allowed charset or length", "refused:args")
            return
        if not isinstance(stdin_text, str) or len(stdin_text.encode("utf-8")) > MAX_STDIN_BYTES:
            refuse(400, f"stdin must be text of at most {MAX_STDIN_BYTES} bytes", "refused:stdin")
            return

        # The slot is held across the WHOLE ssh invocation, kill paths included -
        # that resource bound is the point. Over-cap is a named refusal, not a queue.
        if not EXEC_PERMITS.acquire(blocking=False):
            refuse(503, "sidecar_busy: every exec slot is held; retry later", "busy")
            return
        stdin_bytes = stdin_text.encode("utf-8")
        try:
            code, body, meta = run_ssh(entry, verb, args, stdin_bytes, client=self.connection)
        finally:
            EXEC_PERMITS.release()
        audit({**base_audit, "stdin_bytes": len(stdin_bytes), "status": code, **meta})
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
