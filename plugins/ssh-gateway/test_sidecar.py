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

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sidecar  # noqa: E402 - after sys.path setup

DECLARED = {"target": "logreader@example.invalid", "commands": ["list", "version"]}
WILDCARD = {"target": "logreader@example.invalid", "commands": ["*"]}


def no_spawn(test: unittest.TestCase):
    """Patch subprocess.run so a refused request fails if it spawns anything."""

    def boom(*_a, **_k):  # pragma: no cover - only reached on a regression
        test.fail("refused request spawned a process")

    return mock.patch.object(sidecar.subprocess, "run", boom)


class SinkRefusesRawValues(unittest.TestCase):
    """run_ssh is the sink: it must not trust its caller (CodeQL py/command-line-injection)."""

    def test_undeclared_verb_is_refused_without_spawning(self):
        with no_spawn(self):
            code, body = sidecar.run_ssh(DECLARED, "rm", "", b"")
        self.assertEqual(code, 403)
        self.assertIn(b"command_not_declared", body)

    def test_shell_syntax_verb_is_refused_without_spawning(self):
        with no_spawn(self):
            code, _ = sidecar.run_ssh(WILDCARD, "list; id", "", b"")
        self.assertEqual(code, 400)

    def test_leading_dash_verb_is_refused_even_when_commands_is_wildcard(self):
        # "-oProxyCommand=x" reads like an ssh option. It cannot bite today (it
        # lands after the host, so ssh treats it as the remote command), but a
        # refactor that reorders argv would turn it into a local execution.
        with no_spawn(self):
            code, _ = sidecar.run_ssh(WILDCARD, "-oProxyCommand=x", "", b"")
        self.assertEqual(code, 400)

    def test_bad_args_are_refused_without_spawning(self):
        with no_spawn(self):
            code, _ = sidecar.run_ssh(DECLARED, "list", "a; b", b"")
        self.assertEqual(code, 400)

    def test_entry_without_target_is_refused_not_crashed(self):
        with no_spawn(self):
            code, _ = sidecar.run_ssh({"commands": ["list"]}, "list", "", b"")
        self.assertEqual(code, 502)


class SinkBuildsAnArgvList(unittest.TestCase):
    """The positive path: a list, ssh first, the remote command LAST and whole."""

    def test_declared_verb_becomes_one_remote_command_element(self):
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"ok\n", stderr=b"")
        with mock.patch.object(sidecar.subprocess, "run", return_value=done) as run:
            code, body = sidecar.run_ssh(DECLARED, "list", "all", b"payload")

        self.assertEqual((code, body), (200, b"ok\n"))
        argv = run.call_args.args[0]
        self.assertIsInstance(argv, list, "argv list, never a shell line")
        self.assertEqual(argv[0], "ssh")
        self.assertIs(argv[-1].__class__, str)
        self.assertEqual(argv[-1], "list all", "verb + args is ONE element")
        target_at = argv.index(DECLARED["target"])
        self.assertEqual(target_at, len(argv) - 2, "the remote command follows the target")
        self.assertNotIn("shell", run.call_args.kwargs, "no shell= anywhere")
        self.assertEqual(run.call_args.kwargs["input"], b"payload")


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
