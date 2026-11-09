#!/usr/bin/env python3
"""Unit tests for the ssh-gateway sink (the part that spawns ssh).

Run from the repository root:

    python plugins/ssh-gateway/test_sidecar.py -v

These pin the property CodeQL's py/command-line-injection alert named: the
function that builds the ssh argv list must refuse raw request data on its own,
not only because the HTTP handler happened to validate it first. Every refusal
test asserts that **no process was spawned** - a refused request must cost zero
subprocesses, not one that fails later.

Stdlib only (unittest), so it runs on the same Python that runs the sidecar.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sidecar  # noqa: E402 - after sys.path setup

DECLARED = {"target": "logs@example.invalid", "commands": ["list", "version"]}
WILDCARD = {"target": "logs@example.invalid", "commands": ["*"]}


def no_spawn(test: unittest.TestCase):
    """Patch subprocess.run so a refused request fails if it spawns anything."""

    def boom(*_a, **_k):  # pragma: no cover - only reached on a regression
        test.fail("refused request spawned a process")

    return mock.patch.object(sidecar.subprocess, "run", boom)


class SinkRefusesRawValues(unittest.TestCase):
    """run_ssh is the sink: it must not trust its caller (CodeQL py/command-line-injection)."""

    def test_undeclared_verb_is_refused_without_spawning(self):
        with no_spawn(self):
            code, body, _meta = sidecar.run_ssh(DECLARED, "rm", "", b"")
        self.assertEqual(code, 403)
        self.assertIn(b"command_not_declared", body)

    def test_shell_syntax_verb_is_refused_without_spawning(self):
        with no_spawn(self):
            code, _, _meta = sidecar.run_ssh(WILDCARD, "list; id", "", b"")
        self.assertEqual(code, 400)

    def test_leading_dash_verb_is_refused_even_when_commands_is_wildcard(self):
        # "-oProxyCommand=x" reads like an ssh option. It cannot bite today (it
        # lands after the host, so ssh treats it as the remote command), but a
        # refactor that reorders argv would turn it into a local execution.
        with no_spawn(self):
            code, _, _meta = sidecar.run_ssh(WILDCARD, "-oProxyCommand=x", "", b"")
        self.assertEqual(code, 400)

    def test_bad_args_are_refused_without_spawning(self):
        with no_spawn(self):
            code, _, _meta = sidecar.run_ssh(DECLARED, "list", "a; b", b"")
        self.assertEqual(code, 400)

    def test_entry_without_target_is_refused_not_crashed(self):
        with no_spawn(self):
            code, _, _meta = sidecar.run_ssh({"commands": ["list"]}, "list", "", b"")
        self.assertEqual(code, 502)


class SinkBuildsAnArgvList(unittest.TestCase):
    """The positive path: a list, ssh first, the remote command LAST and whole."""

    def test_declared_verb_becomes_one_remote_command_element(self):
        FakeProc.mode = "ok"  # the class attribute leaks from HttpFixture tests
        with mock.patch.object(sidecar.subprocess, "Popen", FakeProc):
            code, body, meta = sidecar.run_ssh(DECLARED, "list", "all", b"payload")

        self.assertEqual(code, 200)
        self.assertEqual(body, b"ok")
        self.assertEqual(meta["output_bytes"], 2)
        proc = FakeProc.instances[-1]
        argv = proc.argv
        self.assertIsInstance(argv, list, "argv list, never a shell line")
        self.assertTrue(os.path.isabs(argv[0]), f"ssh is spawned by absolute path: {argv[0]}")
        self.assertEqual(argv[0], sidecar.SSH_BIN, "the binary is resolved once at startup")
        self.assertEqual(argv[-1], "list all", "verb + args is ONE element")
        target_at = argv.index(DECLARED["target"])
        self.assertEqual(target_at, len(argv) - 2, "the remote command follows the target")
        self.assertIn("-F", argv, "user ssh config must not govern the connection")
        for opt in ("ClearAllForwardings=yes", "ForwardAgent=no", "PermitLocalCommand=no"):
            self.assertIn(opt, argv)
        self.assertIsNotNone(proc.stdin, "stdin is piped so the sidecar feeds the child")


def no_popen(test: unittest.TestCase):
    """Patch Popen so a request that must be refused fails if it spawns anything."""

    def boom(*_a, **_k):  # pragma: no cover - only reached on a regression
        test.fail("refused request spawned a process")

    return mock.patch.object(sidecar.subprocess, "Popen", boom)


class HostKeysArePinned(unittest.TestCase):
    """M13 (docs/design/2026-11-09-security-review-verdicts.md, verdict: confirmed).

    `StrictHostKeyChecking=accept-new` with NO `UserKnownHostsFile` made the first
    contact with any host a TOFU decision, and ssh then appended that key to the
    user's real `%USERPROFILE%\\.ssh\\known_hosts` - a file this plugin does not
    own and every later session trusts. The fix: a plugin-local `known_hosts`,
    `StrictHostKeyChecking=yes`, and an unknown key is a named 502 rather than a
    hang or a silent accept.
    """

    def _run(self, entry=None):
        FakeProc.mode = "ok"
        with mock.patch.object(sidecar.subprocess, "Popen", FakeProc):
            code, body, meta = sidecar.run_ssh(entry or dict(DECLARED), "list", "", b"")
        return code, body, meta, FakeProc.instances[-1].argv

    def test_the_shipped_known_hosts_is_plugin_local_and_holds_no_keys(self):
        self.assertEqual(sidecar.KNOWN_HOSTS.name, "known_hosts")
        self.assertEqual(sidecar.KNOWN_HOSTS.parent, Path(sidecar.__file__).resolve().parent,
                         "the file must live beside the sidecar, never in ~/.ssh")
        self.assertTrue(sidecar.KNOWN_HOSTS.is_file(), "the plugin must ship the file")
        keys = [line for line in sidecar.KNOWN_HOSTS.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(keys, [], "the shipped file starts empty: nothing is trusted by default")

    def test_argv_pins_the_plugin_local_file_and_strict_checking(self):
        code, _body, _meta, argv = self._run()
        self.assertEqual(code, 200, "a declared verb with a pinned file proceeds")
        self.assertIn(f"UserKnownHostsFile={sidecar.KNOWN_HOSTS}", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertNotIn("StrictHostKeyChecking=accept-new", argv,
                         "accept-new is TOFU and writes into whatever file it is handed")

    def test_a_per_host_known_hosts_overrides_the_default(self):
        with tempfile.NamedTemporaryFile("w", suffix=".known_hosts", delete=False,
                                         encoding="utf-8") as fh:
            fh.write("pinned.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA\n")
            seeded = fh.name
        try:
            code, _body, _meta, argv = self._run(dict(DECLARED, known_hosts=seeded))
        finally:
            Path(seeded).unlink(missing_ok=True)
        self.assertEqual(code, 200)
        self.assertIn(f"UserKnownHostsFile={seeded}", argv)
        self.assertNotIn(f"UserKnownHostsFile={sidecar.KNOWN_HOSTS}", argv)

    def test_an_unknown_host_key_is_a_named_502(self):
        FakeProc.mode = "hostkey"
        with mock.patch.object(sidecar.subprocess, "Popen", FakeProc):
            code, body, meta = sidecar.run_ssh(dict(DECLARED), "list", "", b"")
        self.assertEqual(code, 502)
        self.assertEqual(meta["outcome"], "host_key_unknown")
        self.assertIn(b"host_key_unknown", body, "the refusal must name the reason")
        self.assertIn(b"Host key verification failed", body,
                      "the ssh error is surfaced, not swallowed")
        self.assertNotEqual(body, b"ok", "no ssh output is trusted for an unknown host key")


class SshBinaryIsResolvedAtStartup(unittest.TestCase):
    """L-M (docs/design/2026-11-09-security-review-verdicts.md, verdict: confirmed).

    `ssh` was spawned by BARE NAME from the plugin directory as the child's cwd,
    and CreateProcess searches the parent's cwd before System32/PATH - so a file
    dropped next to `sidecar.py` wins. The fix resolves ssh ONCE at startup
    (System32\\OpenSSH first, then PATH), refuses to start without it, and spawns
    by absolute path.
    """

    def _sysroot(self, with_ssh: bool) -> Path:
        root = Path(tempfile.mkdtemp(prefix="saife-sshroot-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        if with_ssh:
            exe = root / "System32" / "OpenSSH" / "ssh.exe"
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b"")
        return root

    def test_the_system_openssh_is_preferred(self):
        root = self._sysroot(with_ssh=True)
        resolved = sidecar.resolve_ssh_binary(str(root))
        self.assertEqual(resolved, str(root / "System32" / "OpenSSH" / "ssh.exe"))
        self.assertTrue(os.path.isabs(resolved))

    def test_a_host_without_the_system_openssh_falls_back_to_path(self):
        root = self._sysroot(with_ssh=False)
        with mock.patch.object(sidecar.shutil, "which", lambda _name: "C:/tools/ssh.exe"):
            self.assertEqual(sidecar.resolve_ssh_binary(str(root)), "C:/tools/ssh.exe")

    def test_nothing_resolves_to_none_rather_than_a_guess(self):
        root = self._sysroot(with_ssh=False)
        with mock.patch.object(sidecar.shutil, "which", lambda _name: None):
            self.assertIsNone(sidecar.resolve_ssh_binary(str(root)))

    def test_main_refuses_to_start_without_an_ssh_binary(self):
        err = io.StringIO()
        with mock.patch.object(sidecar, "SSH_BIN", None), contextlib.redirect_stderr(err):
            self.assertEqual(sidecar.main(), 2, "a sidecar that cannot spawn ssh must not serve")
        self.assertIn("ssh", err.getvalue())
        self.assertIn("ssh_executable_not_found", err.getvalue(),
                    "the refusal must be a NAMED startup error, not a generic one")

    def test_the_spawn_uses_the_resolved_absolute_binary(self):
        absolute = "C:/Windows/System32/OpenSSH/ssh.exe"
        FakeProc.mode = "ok"
        with mock.patch.object(sidecar, "SSH_BIN", absolute), \
                mock.patch.object(sidecar.subprocess, "Popen", FakeProc):
            code, _body, _meta = sidecar.run_ssh(dict(DECLARED), "list", "", b"")
        self.assertEqual(code, 200)
        argv = FakeProc.instances[-1].argv
        self.assertEqual(argv[0], absolute, "argv[0] is the resolved path, not a bare name")
        self.assertTrue(os.path.isabs(argv[0]), "an absolute path cannot be shadowed by cwd")

    def test_a_missing_binary_is_refused_at_the_sink(self):
        with mock.patch.object(sidecar, "SSH_BIN", None), no_popen(self):
            code, body, meta = sidecar.run_ssh(dict(DECLARED), "list", "", b"")
        self.assertEqual(code, 502)
        self.assertIn(b"ssh_not_found", body)
        self.assertEqual(meta["outcome"], "ssh_not_found")


class VerbCharset(unittest.TestCase):
    def test_verb_length_boundary(self):
        self.assertIsNotNone(sidecar.VERB_RE.match("a" * 64))
        self.assertIsNone(sidecar.VERB_RE.match("a" * 65))

    def test_verb_may_not_begin_with_a_dash(self):
        self.assertIsNone(sidecar.VERB_RE.match("-version"))
        self.assertIsNotNone(sidecar.VERB_RE.match("v-ersion"), "dashes inside stay legal")

    def test_args_may_begin_with_a_dash(self):
        # Flags are legitimate arguments to a declared verb; they ride AFTER the
        # target, where ssh cannot read them as its own options.
        self.assertIsNotNone(sidecar.ARGS_RE.match("--json -n 5"))




class NewlineNeverPassesTheCharset(unittest.TestCase):
    """`$` in a Python regex matches before a trailing newline, so `verb="list\n"`
    passed the charset check - on a wildcard host the remote shell then executes
    TWO commands (`list`, then the next line). `\Z` closes it; the guarantee the
    README states must actually hold."""

    def test_trailing_newline_verb_is_refused(self):
        with no_spawn(self):
            code, _, _meta = sidecar.run_ssh(WILDCARD, "list\n", "", b"")
        self.assertEqual(code, 400)

    def test_trailing_newline_args_are_refused(self):
        with no_spawn(self):
            code, _, _meta = sidecar.run_ssh(DECLARED, "list", "all\n", b"")
        self.assertEqual(code, 400)

    def test_carriage_return_is_refused_too(self):
        with no_spawn(self):
            code, _, _meta = sidecar.run_ssh(DECLARED, "list", "all\r", b"")
        self.assertEqual(code, 400)


class TargetIsValidatedAtLoad(unittest.TestCase):
    """`target` goes into the ssh argv. A leading '-' would be read as an ssh
    OPTION when a refactor ever moves it before the host, and whitespace would
    split it into several arguments - refuse both at load, not at spawn."""

    def _load(self, entry: dict) -> dict:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump({"hosts": {"srv1": entry}}, f)
            name = f.name
        try:
            return sidecar.load_gateway(name)
        finally:
            Path(name).unlink(missing_ok=True)

    def test_leading_dash_target_is_dropped(self):
        gw = self._load({"target": "-oProxyCommand=calc", "commands": ["list"]})
        self.assertEqual(gw["hosts"], {}, "a dash-target must not survive load")

    def test_whitespace_target_is_dropped(self):
        gw = self._load({"target": "logs@host extra", "commands": ["list"]})
        self.assertEqual(gw["hosts"], {})

    def test_non_integer_port_is_dropped(self):
        gw = self._load({"target": "logs@host", "port": "22x", "commands": ["list"]})
        self.assertEqual(gw["hosts"], {})

    def test_a_good_entry_survives(self):
        gw = self._load({"target": "logs@host", "port": 22, "commands": ["list"]})
        self.assertIn("srv1", gw["hosts"])


# ---- HTTP-level behaviour -------------------------------------------------
# A REAL ThreadingHTTPServer with subprocess.Popen replaced by a controllable
# fake: concurrency, output bounding, kill paths and the audit record are
# exercised through the same code the supervisor talks to.


class FakeStdout:
    def __init__(self, proc):
        self._proc = proc

    def read(self, n: int) -> bytes:
        mode = self._proc.mode
        if mode == "ok":
            if self._proc.payload:
                out, self._proc.payload = self._proc.payload[:n], self._proc.payload[n:]
                return out
            return b""
        if mode == "block":
            while not self._proc.killed:
                self._proc.killed_event.wait(0.02)
            return b""
        if mode == "flood":
            if self._proc.killed:
                return b""
            time.sleep(0.001)
            return b"x" * n
        return b""


class FakeProc:
    instances: "list[FakeProc]" = []
    mode = "ok"

    class _Stdin:
        def __init__(self):
            self.data = b""

        def write(self, b):
            self.data += b

        def close(self):
            pass

        def flush(self):
            pass

    def __init__(self, argv, stdin=None, stdout=None, stderr=None, **_kw):
        self.argv = list(argv)
        self.stdin = self._Stdin() if stdin is not None else None
        self.stderr = stderr
        self.stdout = FakeStdout(self)
        self.payload = b"ok"
        self.killed = False
        self.killed_event = threading.Event()
        self.returncode = 0
        self.stderr_text = b""
        if self.mode == "hostkey":
            # ssh with StrictHostKeyChecking=yes and no entry in the pinned
            # known_hosts: exits 255, says so on stderr, and produces NO stdout.
            self.returncode = 255
            self.stderr.write(b"Host key verification failed.\r\n")
            self.stderr.flush()
        FakeProc.instances.append(self)

    def kill(self):
        self.killed = True
        self.killed_event.set()
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


class HttpFixture:
    def __init__(self, hosts: dict, max_concurrent: int = 2, mode: str = "ok"):
        self._hosts = hosts
        self._max = max_concurrent
        self._mode = mode
        self.audit: "list[dict]" = []
        self.base = ""

    def __enter__(self):
        FakeProc.instances = []
        FakeProc.mode = self._mode
        self._patches = [
            mock.patch.object(sidecar, "TOKEN", "test-token"),
            mock.patch.object(sidecar, "GATEWAY", {"hosts": self._hosts}),
            mock.patch.object(sidecar, "EXEC_PERMITS", threading.BoundedSemaphore(self._max)),
            mock.patch.object(sidecar.subprocess, "Popen", FakeProc),
            mock.patch.object(sidecar, "audit",
                             lambda fields: self.audit.append({"op": "EXEC", "mount": "ssh", **fields})),
        ]
        for p in self._patches:
            p.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), sidecar.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        for p in reversed(self._patches):
            p.stop()
        FakeProc.mode = "ok"  # never leak a blocking/flooding fake into the next test

    def post(self, body: dict, timeout: float = 15):
        req = urllib.request.Request(
            self.base + "/exec", method="POST", data=json.dumps(body).encode(),
            headers={"X-Facade-Token": "test-token"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def post_and_hang_up(self, body: dict) -> None:
        s = socket.create_connection(("127.0.0.1", self.server.server_address[1]), timeout=5)
        payload = json.dumps(body).encode()
        s.sendall(f"POST /exec HTTP/1.0\r\nHost: ssh\r\nX-Facade-Token: test-token\r\n"
                  f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload)
        s.close()


GOOD = {"target": "logs@example.invalid", "commands": ["list"], "command_timeout": 2}


def status_code_of(resp: bytes) -> int:
    """The status line's code, failing loudly when the connection was dropped."""
    line = resp.split(b"\r\n", 1)[0] if resp else b""
    parts = line.split()
    assert parts and parts[0].startswith(b"HTTP/"), (
        f"no HTTP status line - the connection was dropped: {resp[:120]!r}")
    return int(parts[1])


def raw_post(fx: "HttpFixture", headers: str, body: bytes = b"", timeout: float = 5) -> bytes:
    """One raw request on a socket whose write side stays OPEN until the reply.

    That is the point of using a raw socket here: a handler that blocks reading
    a body it was never sent must fail this helper by timing out, instead of
    passing because the client closed and turned the read into EOF.
    """
    sock = socket.create_connection(("127.0.0.1", fx.server.server_address[1]), timeout=timeout)
    try:
        sock.sendall(headers.encode("ascii") + body)
        sock.settimeout(timeout)
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout as exc:
                raise AssertionError(
                    f"the sidecar did not answer within {timeout}s - it is waiting on a "
                    "body the client never offered to close"
                ) from exc
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        sock.close()



class ExecPath(unittest.TestCase):
    def test_success_replies_the_bytes_and_audits_the_call(self):
        with HttpFixture({"srv1": dict(GOOD)}) as fx:
            code, body = fx.post({"host": "srv1", "verb": "list", "args": "all", "stdin": "hi"})
            self.assertEqual((code, body), (200, b"ok"))
            self.assertTrue(fx.audit, "every /exec must leave an audit record")
            rec = fx.audit[-1]
            self.assertEqual(rec["op"], "EXEC")
            self.assertEqual(rec["host"], "srv1")
            self.assertEqual(rec["verb"], "list")
            self.assertEqual(rec["status"], 200)
            self.assertEqual(rec["output_bytes"], 2)
            self.assertEqual(rec["stdin_bytes"], 2)
            self.assertIn("args_sha256", rec, "args by digest, never verbatim")
            self.assertNotIn("all", json.dumps(rec), "the audit must not carry the raw args")

    def test_ssh_is_spawned_with_hardening_and_an_isolated_config(self):
        with HttpFixture({"srv1": dict(GOOD)}) as fx:
            self.assertEqual(fx.post({"host": "srv1", "verb": "list"})[0], 200)
            argv = FakeProc.instances[0].argv
            self.assertIn("-F", argv, "user ssh config must not govern the connection")
            for opt in ("ClearAllForwardings=yes", "ForwardAgent=no", "PermitLocalCommand=no"):
                self.assertIn(opt, argv)

    def test_exec_slots_are_bounded_and_busy_is_a_named_503(self):
        with HttpFixture({"srv1": dict(GOOD)}, max_concurrent=2, mode="block") as fx:
            results = []
            lock = threading.Lock()

            def call():
                r = fx.post({"host": "srv1", "verb": "list"}, timeout=20)
                with lock:
                    results.append(r[0])

            threads = [threading.Thread(target=call) for _ in range(4)]
            for th in threads:
                th.start()
            for th in threads:
                th.join(30)
            self.assertEqual(len(FakeProc.instances), 2, "only the permitted slots may spawn ssh")
            self.assertEqual(results.count(503), 2, f"exactly the over-cap calls refuse: {results}")
            self.assertEqual(results.count(504), 2, f"the two holders time out: {results}")

    def test_output_cap_kills_the_child_instead_of_buffering_it(self):
        entry = dict(GOOD, max_output_mb=1)
        with HttpFixture({"srv1": entry}, mode="flood") as fx:
            code, body = fx.post({"host": "srv1", "verb": "list"}, timeout=30)
            self.assertEqual(code, 502)
            self.assertIn(b"output exceeds max_output_mb", body)
            self.assertTrue(FakeProc.instances[0].killed, "the child must be killed at the cap")

    def test_timeout_kills_the_child(self):
        entry = dict(GOOD, command_timeout=1)
        with HttpFixture({"srv1": entry}, mode="block") as fx:
            started = time.monotonic()
            code, body = fx.post({"host": "srv1", "verb": "list"}, timeout=30)
            self.assertEqual(code, 504)
            self.assertLess(time.monotonic() - started, 10)
            self.assertTrue(FakeProc.instances[0].killed, "a timed-out ssh must not run on")

    def test_a_hung_up_client_kills_the_child(self):
        with HttpFixture({"srv1": dict(GOOD, command_timeout=60)}, mode="block") as fx:
            fx.post_and_hang_up({"host": "srv1", "verb": "list"})
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not (FakeProc.instances and FakeProc.instances[0].killed):
                time.sleep(0.02)
            self.assertTrue(FakeProc.instances, "the call must have reached the spawn")
            self.assertTrue(FakeProc.instances[0].killed,
                            "when the caller is gone the ssh child must be killed, not run to timeout")

    def test_refusals_are_audited_with_their_reason(self):
        with HttpFixture({"srv1": dict(GOOD)}) as fx:
            self.assertEqual(fx.post({"host": "srv1", "verb": "rm"})[0], 403)
            rec = fx.audit[-1]
            self.assertEqual(rec["status"], 403)
            self.assertIn("command_not_declared", rec["outcome"])


class MalformedFramingIsContained(unittest.TestCase):
    """M16 (docs/design/2026-11-09-security-review-verdicts.md).

    `do_POST` used to trust `int(self.headers.get("Content-Length"))`: a negative
    value reached `rfile.read(-1)` (read to EOF - the handler parked until the
    caller hung up) and a non-numeric one raised out of the handler (the
    connection was dropped with no reply). The hardening (`max(0, ...)`,
    `try/except ValueError -> 400`, reject `Transfer-Encoding`) landed on
    2026-11-09; these tests are its regression guard. They pin the CONTRACT: a
    malformed frame gets a bounded, named refusal and never spawns ssh or
    leaves an EXEC record.
    """

    def _post_raw(self, fx, extra_headers: str, body: bytes = b"") -> bytes:
        head = (
            "POST /exec HTTP/1.0\r\nHost: ssh\r\nX-Facade-Token: test-token\r\n"
            f"{extra_headers}\r\n"
        )
        return raw_post(fx, head, body)

    def _assert_contained(self, fx, resp: bytes) -> None:
        code = status_code_of(resp)
        self.assertGreaterEqual(code, 400, f"a malformed frame must be refused: {resp[:200]!r}")
        self.assertLess(code, 600, f"expected an HTTP error reply: {resp[:200]!r}")
        self.assertEqual(FakeProc.instances, [], "no ssh may be spawned for a malformed frame")
        self.assertEqual(fx.audit, [], "no EXEC record: the request never became a call")

    def test_negative_content_length_is_refused_not_read_to_eof(self):
        # The write side stays open (raw_post never closes it): today
        # `read(-1)` waits for an EOF that only arrives when the caller gives
        # up, so the reply must come from the reply path, not from EOF.
        with HttpFixture({"srv1": dict(GOOD)}) as fx:
            resp = self._post_raw(fx, "Content-Length: -1\r\n")
            self._assert_contained(fx, resp)

    def test_non_numeric_content_length_gets_a_clean_reply(self):
        # `int("abc")` raises out of the handler today: the client sees a
        # dropped connection instead of a status line.
        with HttpFixture({"srv1": dict(GOOD)}) as fx:
            resp = self._post_raw(fx, "Content-Length: abc\r\n")
            self._assert_contained(fx, resp)

    def test_chunked_transfer_encoding_is_rejected(self):
        # A valid JSON body in chunked framing must not be decoded: the sidecar
        # speaks Content-Length framing only, so the request is refused whole.
        payload = json.dumps({"host": "srv1", "verb": "list"}).encode()
        body = f"{len(payload):x}\r\n".encode("ascii") + payload + b"\r\n0\r\n\r\n"
        with HttpFixture({"srv1": dict(GOOD)}) as fx:
            resp = self._post_raw(fx, "Transfer-Encoding: chunked\r\n", body)
            self._assert_contained(fx, resp)
            # The refusal must NAME the framing it will not speak - a bare
            # "body must be JSON" (what an empty Content-Length produces) would
            # leave the operator guessing why a valid body was rejected.
            self.assertIn(b"transfer-encoding", resp.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
