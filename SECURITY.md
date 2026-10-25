# Security policy

SAIFE Sandbox is a containment tool: its job is to stop a workload from doing
things, and to leave a record of what it did. A bug that lets a session do more
than the profile allows is a **security bug**, not a defect.

## What counts as a security issue

In scope:

- **Containment escape** - a sandboxed process reads, writes, executes or
  connects somewhere the resolved profile does not allow, including through a
  child process, a launcher, or an inherited handle.
- **Policy widening** - a profile (or `extends` chain, or CLI flag) resolves to
  more access than it states, or a refused profile is silently accepted.
- **Network egress outside the policy** - a connection that reaches a host
  neither the profile nor an approved prompt allowed; a proxy/bypass path that
  skips the decision log.
- **Audit integrity** - a record that verifies when it should not, a session
  that leaves no root, a field that can be edited without invalidating the
  chain, or a way to make the audit claim something false.
- **Credential exposure** - a token or secret readable by the workload, or
  written into the audit, a log, or an error message.
- **Guardrail bypass** - a session that reports success while the workload had
  no egress (the "silent misconfiguration" class guardrail 1 exists to catch).

Out of scope: bugs in the agent you choose to run, malware you deliberately run
inside the sandbox (that is what the sandbox is for), missing features, and
anything that requires the ability to write to the audit directory or the
binary itself (that is administrator-equivalent).

## Reporting

Use GitHub's **private vulnerability reporting** on this repository
(Security -> Report a vulnerability). Do not open a public issue for a
containment escape.

Please include: the `saife --version` output, the resolved profile
(`saife profile show <name> --expanded`), the command you ran, the audit session
id if one was written, and the smallest reproduction you have.

We aim to acknowledge within 7 days and to ship a fix or a mitigation decision
within 90 days, and we will credit you in the release notes unless you ask
otherwise. There is no bug bounty.

## Supported versions

The newest published minor receives fixes. Pre-1.0, a fix may require a profile
or CLI change; when it does, the release notes say so under `Breaking` and the
error message names the new spelling.
