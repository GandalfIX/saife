# Maintenance

One-off tools for a host that has drifted. Nothing here runs in a build, a test
or a release; each script says what it changes and refuses to run half-way.

## `Remove-StaleSaifeFirewallRules.ps1`

Removes Windows Firewall rules that point at a saife test binary which no longer
exists.

**Why the rules exist.** Before 0.6.1 the forward-path tests served their
stand-in origin on the host's own LAN address (`src/net/proxy/tests.rs`). Windows
Firewall asks once per executable *file*, so every rebuild - and every
`cargo-mutants` copy of the tree - produced a new `deps\saife-<hash>.exe` and a
new prompt when the suite ran. Answering "Allow" left an inbound rule behind per
file; on this project's dev host that had accumulated 132 rules, 48 of them
pointing at deleted binaries.

**The cause is fixed**: the fixtures now serve their origin on `127.0.0.1`, so a
fresh host never grows these rules. This script exists for hosts that already
have them.

```powershell
# dry run - reads only, works unelevated
pwsh -File maintenance/Remove-StaleSaifeFirewallRules.ps1 -WhatIf

# removal - needs an elevated PowerShell window
pwsh -File maintenance/Remove-StaleSaifeFirewallRules.ps1
```

Scope: only rules whose `Program` path contains `saife` **and** whose file is
missing. Live binaries keep their rules. The script prints the count it removed
and exits non-zero if any stale rule survived.

Run it in one integrated elevated session, not as a hidden child process: the
firewall policy store is reached over MTA COM, and the removal throws
`NotSpecified` from a spawned no-console worker.

## Why not a rule for the current binary

A firewall rule names one program path; there is no wildcard, so "allow the test
binary" cannot be said once. That is why the fix belongs in the fixture (bind
loopback) and not in a rule.
