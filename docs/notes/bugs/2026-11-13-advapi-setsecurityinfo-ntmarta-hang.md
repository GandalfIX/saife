# BUG: `saife run` hangs in advapi32's `SetSecurityInfo` (ntmarta inheritance recompute)

> **Status:** FIXED in code — `set_dacl_kernel` writes through
> `NtSetSecurityObject` (ntdll) and propagation repairs the kernel-stamped
> child protection from a pre-write snapshot.
> **Reported:** 2026-11-13
> **Severity:** Blocker — every session whose workspace sits under
> `%LOCALAPPDATA%\Temp` (the default `--allow-cwd` scratch case) hung
> before spawn.
> **Environment:** Windows build 26300 (Insider flight), the same host that
> shipped the 2026-08-04 sibling.

## Summary

`saife run` hung before the child existed, with grants applied and no further
diagnostics. A minidump of the hung supervisor showed thread 0 in
`ntmarta!AccGetInheritanceSource → NtClose`, reached through advapi32's
`SetSecurityInfo` from the grant-application path. The hang object is NOT
deterministic per source: the identical call on `C:\Users\<user>\AppData\Local`
and sibling directories returns instantly; the identity call on
`AppData\Local\Temp` never returns.

## Measured mechanism (isolated probes, no saife state involved)

1. **The hang is in advapi32, both flags.** `SetSecurityInfo` on Temp — by
   handle, UNPROTECTED and PROTECTED — hung past a 60 s timeout. The 2026-08-04
   note blamed Defender real-time scanning; the same class recurs on this
   flight with no load present.
2. **The same DACL through `ntdll!NtSetSecurityObject` on a kernel handle
   returns in 0.01 s on the object that hangs** (identity write, temp probe).
3. **A direct kernel write changes child semantics on this build:** after a
   parent DACL write carrying a NEW inheritable ACE, every descendant reads
   `SE_DACL_PROTECTED` (measured against a control snapshot taken before the
   write; an advapi write passed unchanged). The kernel does not recompute the
   children's inherited ACEs; it marks them protected instead, and woe to any
   caller that treats protection as "deliberately out of the grant" — the next
   propagation would skip the whole tree.
4. **The protected marker is per-object, not tree-rooted:** an identity write
   with no new inheritable ACE leaves children untouched; only ACE deltas
   stamp the descendants.

## The fix as shipped

- `set_dacl_kernel` builds an absolute security descriptor in-process
  (`InitializeSecurityDescriptor` + `SetSecurityDescriptorDacl`), stamps
  `SE_DACL_PROTECTED` for protected writes and `SE_DACL_AUTO_INHERIT_REQ |
  SE_DACL_AUTO_INHERITED` for normal writes, and applies the DACL through
  `NtSetSecurityObject`. No advapi path, no ntmarta, no hang.
- Because the kernel stamps descendants protected whenever the write deltas
  the inheritable ACEs, `propagate_grant` snapshots which descendants were
  protected BEFORE the write (bounded by the propagation cap) and skips only
  those: protection that pre-dates the write is an earlier deliberate decision
  (the `.sandbox` isolation tree); protection the kernel just stamped is
  repaired by the child's own propagated write, which re-arms the recompute
  request.
- Known residual: the `SE_DACL_AUTO_INHERITED` SD control bit is
  reference-monitor-managed and the kernel write path cannot set it; ACE-level
  inherited flags are preserved, effective access is unchanged, and the suite's
  protected-DACL tests (`M5`, `teardown`) pin both halves.

## Host findings (elevated pass, 2026-11-14)

- Build: Windows 10 Pro 26H2, `26300.9974` — an Insider flight, not a released
  servicing build.
- Filesystem filter stack (`fltmc filters`, highest altitudes first):
  `bindflt 409800`, `FsDepends 407000`, `UCPD 385250.5`, `WdFilter 328010`
  (Defender), `storqosflt`, `wcifs`, `gameflt`, `CldFlt`, `bfs` (BitLocker),
  `FileCrypt`, `luafv`, `UnionFS`, `npsvctrig`, `Wof`, `FileInfo`.
- Defender: real-time protection on, no exclusions, **tamper protection ON**.
  `Set-MpPreference -DisableRealtimeMonitoring $true` is silently ignored under
  tamper protection (`RealTimeProtectionEnabled` stays `True`), so a true
  Defender-off A/B cannot be run without disabling tamper protection itself —
  a machine-wide protection change nobody should make to take a measurement.
- A/B with the filter stack as found, session from a Temp workspace:
  unfixed base binary **hangs** (killed at the 60 s harness bound, twice);
  fixed binary completes in **0.3 s**.

## What remains open (host-level)

The stall owner is not yet named. Candidates, in order of likelihood: `WdFilter`
(Defender's scan on the object the inheritance walk touches), `UCPD` (26H2's
user-consent protection driver, new in this flight), or the flight's own
`ntmarta`/SRM changes. A minimal repro (identity DACL write through
`SetSecurityInfo` on `%LOCALAPPDATA%\Temp`, hang; the same write through
`NtSetSecurityObject`, 0.01 s) plus the minidump stack
(`ntmarta!AccGetInheritanceSource → NtClose`) is ready for a Microsoft report.

