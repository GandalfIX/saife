sandbox - distribution bundle
=============================

A supervisor that runs a Windows workload inside a container (AppContainer or the
MXC base-container) with a proxy-only network and an audited session chain.

Both executables are built with a STATIC C runtime: there is no VC++ redistributable
to install on the target machine.

Contents
--------
  sandbox.exe                         the supervisor (x64)
  mxc-launch.exe                      the wrapper launcher - MUST stay beside sandbox.exe
  profiles/demo.json                  portable example profile
  profiles/node.json                  Node.js / npm (cache, nvm trees, registry hosts)
  profiles/jvm.json                   JDK / Gradle / Maven (caches, Maven Central)
  profiles/opencode.json              the opencode TUI (state dirs, WinGet tree, provider)
  plugins/tngtech/plugin.json         example host-side sidecar plugin
  plugins/tngtech/sidecar.py          its implementation (Python 3, stdlib only)
  plugins/tngtech/agents/opencode/    the agent skill that teaches opencode to use it
  VERSION.txt                         build provenance
  SHA256SUMS.txt                      checksums of every file above


Requirements on the target machine
----------------------------------
  * Windows 11 24H2 (build 26100.x) or newer, x64.
      - The default backend (mxc) needs the in-box base-container / PSEC support.
      - `--backend appcontainer` also runs on Windows 10 1709+, but network sessions
        there require an elevated shell (loopback firewall exemption).
  * No administrator rights, no service, no installer for the mxc path.
  * Python 3 on PATH only if you use the bundled tngtech plugin.


Install (2 minutes)
-------------------
  1. Copy this whole folder somewhere permanent, e.g. C:\tools\sandbox\bin
     Keep sandbox.exe and mxc-launch.exe in the SAME directory.
  2. Copy the profiles you want:
         profiles\*.json  ->  %USERPROFILE%\.sandbox\profiles\
     (the folder is created on first use if it does not exist)
  3. Optional, plugins:
         plugins\tngtech  ->  %USERPROFILE%\.sandbox\plugins\tngtech
     A plugin runs OUTSIDE the sandbox, with your rights, and owns the network on
     the workload's behalf. Only install plugins you have read.
  4. Optional, for opencode: copy
         plugins\tngtech\agents\opencode\SKILL.md
     to  %USERPROFILE%\.config\opencode\skills\sidecar-tngtech\SKILL.md
     and check it with:  opencode debug skill


Verify the installation
-----------------------
  .\sandbox.exe setup --check-only
      Expect the Windows build number, "AppContainer + RuleSet: available",
      "Job Object: available", and "Audit (hash-chain + Ed25519): available".
      The audit key is generated automatically on first use.

  .\sandbox.exe run --allow-cwd --block-net -- cmd /c echo ok
      Expect: ok

  .\sandbox.exe run --allow-cwd --allow-domain api.anthropic.com --no-prompt -- ^
      curl.exe -sS -o NUL -w "connect=%{http_connect}\n" https://api.anthropic.com/
      Expect: connect=200  (the tunnel was admitted; a TLS failure after that is a
      host/CRL condition, not a policy decision)

  The last line of every run is the guardrail proof, e.g.
      [sandbox] mxc: guardrail 1 proof probes=1 accepted=1 tunnels=1 unauthenticated=0


Running something
-----------------
  .\sandbox.exe run --allow-cwd -- cmd /c dir
  .\sandbox.exe run --allow-cwd --allow-domain api.anthropic.com -- claude
  .\sandbox.exe run --profile opencode --allow-cwd -- opencode
  .\sandbox.exe run --profile node --allow-cwd -- cmd /c "npm install"
  .\sandbox.exe run --allow-cwd --block-net -- powershell -NoProfile -Command "Get-Date"

  Windows batch shims (npm, npx, gradle, mvn) need cmd /c "..." because the
  launcher does not apply PATHEXT.

  Gradle builds do not work under the mxc backend: its daemon coordinates over
  loopback, which the sandbox denies by design. Use --backend appcontainer
  (elevated) for those.


Plugins (sidecars)
------------------
  A plugin is reached from inside the sandbox ONLY at its mount name:

      .\sandbox.exe run --plugin tngtech --allow-cwd -- ^
          cmd /c "curl.exe -s http://tngtech.sandbox.invalid/"

  The workload never talks to the real host and never holds a credential: the
  sidecar (a process outside the sandbox) does that. Add --plugin-dir <path> to
  use plugins from a project directory; those are never auto-discovered, because
  a cloned repository must not be able to run host-side code by being built.

  The bundled plugin needs Python 3 and fetches https://www.tngtech.com/.


What NOT to copy from another machine
-------------------------------------
  * %LOCALAPPDATA%\sandbox\signing\ed25519-key
        DPAPI-encrypted for that user on that machine; it cannot be decrypted
        here, and copying it is pointless. A fresh key is generated on first use.
        Audit chains are per-host by design.
  * %LOCALAPPDATA%\sandbox\audit, dacl-restore, sidecar-logs
        runtime state of that machine's sessions.
  * %USERPROFILE%\.sandbox\learned\default.json
        that user's remembered allow/deny decisions. Shipping it would
        pre-approve hosts on someone else's machine.

  Profiles and plugins ARE portable, with one caveat: jvm.json names the JDK by
  absolute path, so adjust it for the target machine's JDK.


Uninstall
---------
  Delete this folder, %USERPROFILE%\.sandbox and %LOCALAPPDATA%\sandbox.
  Nothing is registered in the registry or installed as a service.


Troubleshooting
---------------
  "Error: Failed to change directory to <dir>" from opencode (or any git-aware
  tool) when started in a SUBDIRECTORY of a repository:
        The tool resolves its project from the git root, which is outside the
        granted workspace, and reports the directory you asked it to open rather
        than the one it could not reach. Either start it at the git root
        (git rev-parse --show-toplevel) or grant that root read-only:
            .\sandbox.exe run --profile opencode --allow-cwd --allow <repo-root>:read -- opencode

  "failed to start npm" (or npx, gradle, mvn, yarn, pnpm):
        Those are .cmd/.bat shims and the launcher does not apply PATHEXT.
        Use:  cmd /c "npm --version"

  "Could not connect to the Gradle daemon":
        Gradle coordinates over loopback, which this sandbox denies by design.
        Build with --backend appcontainer (elevated) instead.

  A run that ends with "INCOMPLETE: no committed root" in `audit verify`:
        the supervisor died mid-session; the leaves that exist are still valid.

  Every run prints a guardrail line, e.g.
        [sandbox] mxc: guardrail 1 proof probes=1 accepted=1 tunnels=0 unauthenticated=0
        probes=0 under --block-net is correct (there is no proxy to probe).
