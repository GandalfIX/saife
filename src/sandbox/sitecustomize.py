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
"""

import os

if os.name == "nt":
    _real_mkdir = os.mkdir

    if not getattr(_real_mkdir, "_sandbox_pyshim", False):

        def _sandbox_mkdir(path, mode=0o777, *, dir_fd=None):
            if mode == 0o700:
                mode = 0o755
            return _real_mkdir(path, mode, dir_fd=dir_fd)

        _sandbox_mkdir._sandbox_pyshim = _real_mkdir
        os.mkdir = _sandbox_mkdir

    # The sandbox prepends this directory to PYTHONPATH, so our
    # sitecustomize shadows any the interpreter would have loaded. Find and
    # run that one now so user site customization keeps working.
    try:
        import sys

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
