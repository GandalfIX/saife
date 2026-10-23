"""sandbox: CPython 0o700-mkdir interposition (auto-injected via PYTHONPATH).

Windows CPython 3.7-3.14 maps `os.mkdir(path, 0o700)` to a protected DACL
granting only SYSTEM, Administrators and OWNER RIGHTS. Inside a Windows
AppContainer none of those trustees can authorize the process — the token's
Administrators SID is USE_FOR_DENY_ONLY and the OWNER RIGHTS ACE never
grants an AppContainer token, no matter which SID is the owner. Directories
created that way therefore deny their own creator, which breaks
`tempfile.mkdtemp` and everything built on it (`venv`/`ensurepip`/`pip`
staging). CPython main (3.15+) no longer applies the special DACL on
desktop builds.

This shim rewrites mode 0o700 to 0o755 so CPython creates the directory
with the normal inheritable DACL instead. It does not weaken the sandbox:
isolation is enforced by AppContainer grants and the Low integrity label,
not by directory modes.

Two injection channels, because `venv` strips PYTHONPATH from its ensurepip
subprocess (Lib/venv/__init__.py:352), which would otherwise defeat the
shim exactly where pip is bootstrapped:

1. PYTHONPATH (primary): the sandbox prepends this directory to PYTHONPATH
   and site.py imports it as `sitecustomize` for every sandboxed python.

2. venv-root copy: this shim also interposes `venv.EnvBuilder.setup_python`
   to place a copy of itself into a venv's root before venv runs ensurepip.
   venv invokes the ensurepip subprocess with `cwd = env_dir`, and
   `python -m` puts the cwd at `sys.path[0]`, so the env-stripped
   subprocess still imports the copy. The copy persists in the venv after
   the run; it self-gates on the SAIFE_SESSION_SID marker the sandbox
   sets on every sandboxed process, so outside the sandbox it is inert.

`_sandbox_sitecustomize_done` on the sys module makes every execution
idempotent: whichever copy site.py imports first installs the
interpositions and runs the interpreter's own (shadowed) sitecustomize;
any further copy encountered via exec is a no-op, so mixed channels can
never loop.
"""

import os
import sys


def _sandbox_install():
    """Install the idempotent os.mkdir 0o700 -> 0o755 interposition."""
    _real_mkdir = os.mkdir
    if getattr(_real_mkdir, "_sandbox_pyshim", False):
        return

    def _sandbox_mkdir(path, mode=0o777, *, dir_fd=None):
        if mode == 0o700:
            mode = 0o755
        return _real_mkdir(path, mode, dir_fd=dir_fd)

    _sandbox_mkdir._sandbox_pyshim = _real_mkdir
    os.mkdir = _sandbox_mkdir


def _sandbox_venv_hook():
    """Seed the venv-root sitecustomize copy before venv bootstraps pip.

    `venv` copies the parent environment minus PYTHONHOME/PYTHONPATH into
    the ensurepip subprocess, so the PYTHONPATH channel is absent there.
    Placing a self-gated copy of this file at the venv root closes that
    gap (see the module docstring). An existing file is never overwritten.
    """
    try:
        import venv as _venv
    except Exception:
        return
    if getattr(_venv.EnvBuilder, "_sandbox_pyshim", False):
        return
    _orig = _venv.EnvBuilder.setup_python

    def _sandbox_setup_python(self, context):
        target = os.path.join(context.env_dir, "sitecustomize.py")
        if not os.path.exists(target):
            try:
                import shutil

                shutil.copy(__file__, target)
            except Exception:
                pass
        return _orig(self, context)

    _sandbox_setup_python._sandbox_pyshim = _orig
    _venv.EnvBuilder.setup_python = _sandbox_setup_python


if os.name == "nt" and not getattr(sys, "_sandbox_sitecustomize_done", False):
    sys._sandbox_sitecustomize_done = True
    # Active mode only inside the sandbox: the sandbox sets
    # SAIFE_SESSION_SID on every sandboxed process, and the var survives
    # venv's env sanitization (only PYTHONHOME/PYTHONPATH are stripped).
    # venv-root copies persist in user venvs and must stay inert outside.
    if os.environ.get("SAIFE_SESSION_SID"):
        _sandbox_install()
        _sandbox_venv_hook()

    # The sandbox prepends this directory to PYTHONPATH, so our
    # sitecustomize shadows any the interpreter would have loaded. Find and
    # run that one now so user site customization keeps working.
    try:
        _here = os.path.dirname(os.path.abspath(__file__))
        for _entry in sys.path:
            if not _entry or os.path.abspath(_entry) == _here:
                continue
            _cand = os.path.join(_entry, "sitecustomize.py")
            if os.path.isfile(_cand):
                with open(_cand, "rb") as _f:
                    exec(compile(_f.read(), _cand, "exec"))
                break
    except Exception:
        pass
