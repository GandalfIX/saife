# Windows-Native CLI Sandbox: Implementation Work Breakdown

## 0. Agent handoff

This is the authoritative implementation plan for coding agents working on the
Windows host. Before taking a ticket, read sections 0 through 6, the complete
ticket and its transitive dependencies, the target release definition, and all
referenced threat-model and open-question entries. Implement one independently
testable ticket per branch or pull request unless a ticket explicitly says
otherwise.

Workspace assumptions:

- `mxc/` is the pinned upstream checkout and source-level reference. Do not
  modify it unless a ticket is explicitly designated as an upstream MXC change.
- Create the product as a sibling directory, initially named
  `windows-agent-sandbox/`. Renaming it requires an ADR because scripts, CI, and
  packaging will depend on the path.
- Build and test natively from PowerShell on Windows. Do not use WSL for build,
  tests, scripts, or path conversion.
- The R&D host is Windows Experimental Future Platforms build `29671.1000`
  Enterprise. Runtime probes, not the build number, decide capability support.
- Record the MXC commit ID in every host-dependent result. Never test against an
  unrecorded moving `main` checkout.

Implementation defaults:

- Rust is the control-plane language for the CLI, profile compiler, backend
  adapter, process lifecycle, audit, diagnostics, and proxy.
- A small C++ shim is permitted only when a supported Windows or MXC ABI cannot
  be used safely from Rust. The shim may translate ABI types but must not make
  policy decisions.
- PowerShell is limited to host setup, build, test, signing, and packaging
  automation.
- Authored profiles use versioned TOML. Canonical compiled plans and structured
  diagnostics use JSON.
- Start with a Cargo workspace and committed `Cargo.lock`. Use WiX/MSI only
  after the portable R&D package is working.

The initial repository shape should be:

```text
windows-agent-sandbox/
  apps/
    sandboxctl/
    sandbox-host-proxy/       # implemented in R3
  crates/
    config/
    policy-model/
    policy-compiler/
    policy-analysis/
    capabilities/
    mxc-contract/
    mxc-adapter/
    launcher/
    lifecycle-owner/
    privileged-ipc/
    windows-isolation/
    storage-quota/
    conpty/
    credentials/
    provider-gateway/
    ocsf/
    audit/
    diagnostics/
    test-support/
  schemas/
  examples/profiles/
  tests/
  docs/adr/
  tools/powershell/
  packaging/
```

Dependency direction is toward stable product contracts: the policy model must
not depend on MXC, Windows bindings, CLI rendering, or audit storage. The MXC
adapter translates a compiled plan but cannot reinterpret profile intent. The
policy analyzer consumes the same normalized product model as the compiler and
runtime. Credential and provider-gateway crates cannot depend on MXC internals;
they receive generation-bound product contracts. The CLI cannot bypass the
compiler, modeled containment result, semantic report, or capability gate.

Before implementation begins, create and maintain these ADRs:

- Rust control plane and conditions for a C++ shim.
- MXC behind a product-owned adapter.
- Runtime capability gating and no DACL fallback.
- TOML profile format and monotonic trust-layer composition.
- Separation of process transport from ConPTY.
- Structured audit format and redaction rules.
- Insider builds as R&D evidence, not a production support commitment.
- MXC preview artifacts and the upstream security-boundary graduation gate.
- BaseContainer selection versus Hyper-V-isolated reference testing; no runtime
  fallback between them.
- Hostname enforcement through proxy policy, not DNS-derived static rules.
- Endpoint-bound credential brokerage with no generic TLS interception.
- OCSF-aligned security events and product extension policy.
- Typed launch generations and semantic backend-loss reporting.
- Privilege architecture and authenticated control-plane IPC.
- Versioned canonicalization and domain-separated policy hashes.
- Immutable release candidates, detached promotion evidence, and rollback
  protection.

Design influence from NVIDIA OpenShell:

- The plan adopts endpoint-bound opaque credential placeholders, provider-route
  policy, semantic-loss reports, typed lifecycle generations, revisioned
  effective policy, manual denial proposals, and OCSF-aligned events from the
  concepts documented in OpenShell at commit
  `6f00d5cacc9ce1b92e9514c466eb354aa0513c58`.
- OpenShell's native Windows work is still RFC-stage. This plan does not adopt
  its general `processcontainer`/AppContainer assumption, unique-port-only proxy
  identity, static configured-command network identity, generic TLS interception,
  or in-memory-only lifecycle registry.
- Linux-specific Landlock, seccomp, namespaces, cgroups, and OCI-image security
  claims do not transfer to Windows. Windows claims require independent
  BaseContainer/PSEC/WFP evidence.
- Reference:
  `https://github.com/NVIDIA/OpenShell/blob/main/rfc/0013-native-windows-mxc/README.md`.

Upstream maturity and alternative-boundary evidence:

- The pinned MXC README and support documents must be archived with every G0S
  decision. As of the plan revision that introduced G0S, public MXC `main`
  described the code as an early preview, acknowledged overly permissive
  generated policies, and stated that profiles must not be treated as security
  boundaries. Reference: `https://github.com/microsoft/mxc`.
- BaseContainer policy flow and version support are documented at
  `https://github.com/microsoft/mxc/blob/main/docs/process-container/guide.md`
  and
  `https://github.com/microsoft/mxc/blob/main/docs/process-container/os-version-support.md`.
- The Hyper-V oracle decision uses Microsoft's isolation comparison at
  `https://learn.microsoft.com/windows-server/containers/manage-containers/hyperv-container`.
  Hyper-V's separate kernel is a stronger reference boundary, not runtime
  fallback authority.
- Windows Sandbox is a disposable separate-kernel reference but is not selected
  because its desktop-oriented model and single-concurrent-instance constraint
  do not satisfy the product shape. Reference:
  `https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/`.

First Windows-host bring-up:

1. Install Git, Rust through `rustup`, the MSVC C++ build tools required by the
   pinned MXC Rust workspace, and PowerShell 7 (`pwsh`).
2. Check out the recorded MXC commit as `mxc/` and start PowerShell at the
   workspace parent.
3. Run the upstream suite without `-SkipBuild`; it builds debug and release
   `wxc-exec.exe`, `wxc-ui-probe.exe`, `plm.exe`, and
   `winhttp-proxy-shim.exe` in the locations expected by the tests:

```powershell
$MxcRoot = (Resolve-Path .\mxc).Path
pwsh "$MxcRoot\tests\scripts\run_processcontainer_all_tests.ps1" `
  -RequireTier base-container -SkipNetwork
```

4. The resulting release executor is normally
   `$MxcRoot\src\target\release\wxc-exec.exe`. Capture its probe separately:

```powershell
& "$MxcRoot\src\target\release\wxc-exec.exe" --version
& "$MxcRoot\src\target\release\wxc-exec.exe" --probe
```

`--probe` does not launch a workload, but current MXC performs stale DACL-state
recovery before reporting capabilities. Treat it as a security-state operation,
not a universally read-only command. The BaseContainer-only project must not run
`wxc-host-prep`: MXC documents that preparation as necessary for the T3
AppContainer+DACL path. A recommendation to run it indicates that the host is
not ready for this plan.

## 1. Scope and fixed decisions

This plan is for a new Windows-only CLI sandbox. Development and security
validation initially target Windows Experimental Future Platforms build
`29671.1000 Enterprise` on x64. The product must use MXC's BaseContainer/PSEC
execution path and fail closed. It must never run a workload through
AppContainer+BFS, AppContainer+DACL, an unsandboxed process, WSL, Hyper-V, or
another fallback backend. Hyper-V-isolated Windows containers are a separately
provisioned security reference and differential-test oracle, not a selectable
product backend in R1-R4.

Release posture is intentionally asymmetric:

- While the pinned upstream MXC release states that MXC profiles must not be
  treated as security boundaries, every artifact from this plan is an R&D or
  security-preview artifact. It must not make a production isolation claim.
- Independent testing may find defects and support preview evaluation, but it
  cannot override an explicit upstream security-boundary disclaimer.
- Production support requires Gate G0S. The first supported product scope after
  that gate is Windows Enterprise x64 only. ARM64 and other editions require
  separate qualification and release-manifest entries.

Initial users are CLI AI agents. The design must not hard-code agent-specific behavior into the execution core so later releases can run arbitrary console programs.

Fixed product invariants:

- Windows native only; no WSL dependency or execution path.
- MXC is the initial backend, behind a narrow internal backend interface.
- A request runs only if the host and request-scoped MXC probe select `base-container` and all required PSEC capabilities are present.
- The exact workload token, privileges, namespaces, inherited handles, process
  mitigations, IPC exposure, registry exposure, device exposure, and mandatory
  resource controls are independently attested; a backend tier name is not
  sufficient containment evidence.
- Probe failure, ambiguous probe output, unsupported policy, backend drift, setup failure, and teardown failure are errors, never reasons to weaken policy.
- Profiles explicitly grant workspace and toolchain directories. Workspace access is profile-controlled; toolchains are read-only by default.
- The default network posture is deny all.
- Network-enabled execution must not ship until direct traffic is WFP-blocked and the only permitted egress is to the product proxy.
- Brokered or indirect egress through host services and accessible IPC is part
  of the network boundary and must be denied or explicitly modeled.
- Hostname allow/deny decisions happen in the proxy. WFP supplies process/container-scoped route enforcement, not hostname classification.
- No compatibility mode silently drops a requested filesystem, process, UI, or network restriction.
- Every security-relevant decision produces a bounded, secret-safe audit event.
- The baseline security audit sink is mandatory, durable, protected from the
  workload, and has specified disk-full and failure behavior.
- Every launch attempt has an immutable generation identity. Workload code runs
  only after the exact effective policy, backend tier, proxy, credential broker,
  and resource controls required for that generation are attested.
- Backend translation produces a machine-readable semantic report. Any
  unsupported, unknown, or authority-broadening mapping blocks launch.
- Effective policy has a canonical revision and hash distinct from authored
  profile versions. Approvals and credentials bind to that revision.
- Real provider credentials never enter the sandbox. A network-enabled agent
  requiring credentials ships only with an endpoint-bound host broker that
  supports its exact client and provider protocol.
- A credential placeholder is generation-scoped authority available to any
  untrusted code that can read it. Endpoint binding prevents secret disclosure,
  not misuse within the approved route; operation, cost, rate, and request
  budgets remain mandatory.
- The attacker model includes arbitrary code inside the BaseContainer. An
  already-compromised unsandboxed process running as the same host user,
  administrator compromise, kernel compromise, and malicious endpoint-security
  software are outside the isolation guarantee. Same-user interference with
  protected product state remains a hardening and test requirement, not a
  claimed security boundary.

Explicitly out of initial scope:

- Linux, macOS, and WSL.
- GUI application compatibility.
- Persistent or state-aware sandboxes.
- Inbound networking.
- UDP/QUIC proxying, transparent arbitrary TCP proxying, generic TLS
  interception, and installation of a product root CA.
- AppContainer or DACL fallback.
- Learning mode that automatically broadens a profile.
- A general package manager or toolchain installer.
- Production isolation claims before G0S passes.
- Automatic fallback to the Hyper-V reference environment.

## 2. Release slices

| Release | Capability | Ship condition |
|---|---|---|
| R0 | Research and feasibility harness | D-01 through D-13 establish BaseContainer selection, supported integration/pre-resume control, Windows isolation domains, privilege ownership, hard-quota feasibility, and the Hyper-V oracle. Unknown MXC APIs remain blockers. Not a product release. |
| R1 | Offline security preview | Runs a direct console workload with profile-granted filesystem access, network denied, typed launch generations, attested Windows isolation domains, and enforceable process-count, memory, and storage ceilings. It has a minimal noninteractive CLI and remains preview-only unless G0S has passed. |
| R2 | Agent-ready CLI | Adds stable streaming/terminal behavior, complete user commands, supported toolchain recipes, diagnostics, installer/support lifecycle, and representative agent tests. Network remains denied. It is the first candidate for supported Windows Enterprise x64 release after G0S. |
| R3 | Governed HTTP/S and provider access | WFP permits only the identity-bound proxy endpoint; network rules are revisioned and manually approved; supported provider clients use endpoint-bound credentials without receiving real secrets. |
| R4 | Arbitrary console programs | Compatibility matrix is expanded without weakening R1-R3 security invariants. |

R1 and R2 may ship with deny-all networking. A cooperative `HTTP_PROXY`/`HTTPS_PROXY` implementation without WFP enforcement is not an intermediate network-enabled release.

The word "release" in this document means a versioned artifact and evidence
set. It does not imply production support while G0S is unsatisfied.

## 3. Proposed component boundaries

Names are descriptive, not prescribed implementation names.

| Component | Responsibility | Must not do |
|---|---|---|
| CLI | Parse commands, select profile, connect console streams, render errors | Construct ad hoc backend policy |
| Profile loader | Parse, validate, normalize, and version profiles | Touch MXC or start processes |
| Policy compiler | Convert validated profile plus invocation into an immutable execution plan | Probe the host or weaken unsupported settings |
| Backend adapter | Probe MXC, render a request plus semantic report, own typed generation transitions, launch, attest, wait, cancel, and report effective tier | Select any non-BaseContainer tier or classify a lossy mapping as exact |
| Lifecycle owner | Durably own generation jobs and security resources, journal state, reconcile crashes, and quarantine unknown state | Adopt resources by PID/port/name alone or outlive policy authorization |
| Privileged control plane | Perform only D-11-authorized privileged operations over authenticated generation-bound IPC | Trust project paths, ambient impersonation, or unauthenticated local callers |
| Windows isolation evidence | Query and attest token, namespace, handle, IPC, registry, service, device, UI, and mitigation domains | Treat the backend tier label as proof of those domains |
| Storage quota controller | Create, query, breach-handle, and recover hard generation storage quotas | Substitute polling for the mandatory R1 hard ceiling |
| Path security | Canonicalize grants and reject aliases, unsafe roots, overlaps, and reparse-point escapes | Infer grants from ambient user access |
| Network controller | Start/authorize proxy and supply endpoint/identity to the backend | Permit direct external traffic |
| Policy proxy | Resolve names; decide host, port, protocol, and inspectable operation; connect upstream; and audit decisions | Trust client-provided destination IP as hostname proof or claim visibility inside opaque TLS |
| Credential broker | Issue run-scoped placeholders and perform approved provider-specific requests with endpoint-bound host credentials | Expose real credentials, general host credential stores, or arbitrary request rewriting to the workload |
| Policy analyzer | Report backend semantic loss and modeled authority deltas between ceilings, approvals, and effective plans | Claim equivalence or formal verification outside explicitly modeled domains |
| Audit/diagnostics | Emit pinned OCSF events plus documented extensions, redaction, and support bundles | Log command secrets, environment values, URLs with queries, headers, payloads, or credentials by default |

The first MXC integration may use `wxc-exec.exe`, an MXC library, or an FFI surface. Ticket D-03 decides this after testing supported lifecycle, stream, cancellation, capability, and redistribution behavior. Do not choose an undocumented API by assumption.

## 4. Profile contract baseline

The profile format should be versioned from its first commit. The exact serialization is a design ticket, but the semantic baseline is:

- `version`: exact supported profile version.
- `workspace`: one required path and access mode, normally read-write.
- `toolchains`: zero or more paths, read-only unless an explicit future feature permits otherwise.
- `workingDirectory`: must resolve within an allowed directory.
- `environment`: allowlisted non-secret names and literal values or explicit
  inheritance; no inherit-all default. Provider credentials and values marked as
  secrets are not representable here and require a broker capability.
- `network.mode`: `deny` initially; later `proxy`.
- `network.rules`: host or permitted address class, port, protocol, and operation
  where the selected protocol adapter can observe it. HTTPS `CONNECT` exposes
  host and port, not HTTP methods or paths.
- `credentials`: references to approved provider routes and host credential
  identities; never secret material.
- `limits`: wall-clock timeout, bounded output, process count, committed memory,
  and any additional limit proven enforceable on the selected backend.
- `provenance`: trusted executable, toolchain, signer, hash-manifest, and loader
  expectations required by a recipe.
- `ui`: secure default policy for console workloads.
- `audit`: destination and verbosity within product policy.

Profile locations and trust layers:

| Layer | Initial location | Authority |
|---|---|---|
| Engine invariants | Compiled into signed product | Non-overridable denials and capability gates |
| Machine ceiling | `%ProgramData%\WindowsAgentSandbox\policy.toml` | Administrator-controlled maximum filesystem, network, credential issuer, executable, and resource authority |
| User profiles | `%LOCALAPPDATA%\WindowsAgentSandbox\profiles\*.toml` | Reusable grants within the machine ceiling |
| Project request | `<workspace>\.sandbox\request.toml` | May request or narrow capabilities; never grants them |
| Session options | CLI invocation | May narrow or select pre-approved grants; never bypasses ceilings |

The exact product directory name may change through an ADR, but the trust split
must not. Configuration inside the workspace is attacker-controlled. Merely
naming a reusable profile from a project request cannot activate it without a
matching user approval.

Security semantics:

- Omitted security fields choose secure defaults, not ambient host access.
- Unknown fields and unknown enum values are errors.
- Relative grant paths, device paths, alternate data streams, malformed UNC paths, and path traversal are errors.
- Environment-variable expansion is either forbidden in profiles or performed once before validation under documented rules.
- A command line is invocation data, not a profile permission.
- The executable and every required loader/toolchain path must be covered by grants.
- Read-write child grants under read-only parents need deterministic precedence and tests.
- Reparse points are resolved and checked both when the plan is created and as close to launch as the chosen Windows/MXC interfaces permit.
- Composition is monotonic: restrictions combine by union, while grants are
  bounded by the intersection of machine ceilings and explicit user approval.
- Shared writable caches are not grants in v1. Tool recipes receive
  project-scoped or session-scoped writable cache roots.
- Rules that depend on an unobservable operation are rejected, not approximated
  as host-only permission.
- Project and agent network proposals are inert review artifacts. Only an
  explicit user approval within the machine ceiling creates a future effective
  policy revision; proposals never modify a running generation in v1.
- Every effective plan records all source revisions, its canonical hash, the
  modeled domains used for containment checks, and domains that remain
  unsupported or inconclusive.

## 5. Phase and dependency graph

```text
P0 Discovery, support decision, and threat model
  -> P1 Product skeleton and contracts
       -> P1a Path normalization and containment foundations (S-01, S-02, F-07)
             -> P2 BaseContainer-only execution
                  -> P3 Mandatory Windows isolation-domain hardening
                   -> P4 Agent CLI usability
                       -> P5 WFP proxy-only networking
                            -> P6 Arbitrary-program readiness
  -> P7 CI, packaging, and security validation (incremental from P1 onward)
```

Critical ship gates:

- Gate G0: D-01 through D-13 have reproducible evidence from build 29671.1000,
  D-03/D-04 prove atomic BaseContainer selection and the pre-resume staging
  point, D-11 selects the privilege architecture, MXC redistribution is legally
  and operationally viable, and no unresolved critical discovery question is
  being filled by an assumed interface.
- Gate G0S: the exact pinned MXC/BaseContainer/PSEC release is supported by its
  publisher for use as a security boundary and no longer carries an applicable
  upstream warning that profiles must not be treated as security boundaries.
  Product security review must also approve the exact Windows servicing
  baseline. Local testing or risk acceptance cannot substitute for this gate.
- Gate G1: an unsupported or non-BaseContainer host cannot launch a workload,
  and token, namespace, handle, IPC, registry, service, device, UI, and process-
  mitigation evidence matches the signed required-controls manifest. Mandatory
  audit and the authenticated privileged control plane are ready before resume.
- Gate G2: filesystem, runtime-TOCTOU, resource-limit, hard storage-quota,
  trusted-loader, inherited-handle, crash-recovery, and process-tree cleanup
  negative tests pass, and offline direct/indirect network-denial tests pass.
- Gate G3: the exact immutable R1/R2 candidate package passes install, run,
  crash-recovery, upgrade, and uninstall tests on clean Windows Enterprise x64
  VMs with network denied.
- Gate G4: WFP bypass, proxy identity, policy revision, manual approval, and
  credential-broker suites pass before `network.mode=proxy` is enabled in a
  release build. Proxy self-hardening, indirect/brokered egress, BFE/filter
  failure, and host-network-configuration suites are included. No network-
  enabled agent recipe may inherit a real provider credential.
- Gate G5: security review signs the threat-model delta for each release slice.
  A passed G5 cannot convert a preview artifact into a production-supported
  artifact while G0S is unsatisfied.

## 6. Agent execution rules

Each ticket is intended for one coding agent and normally one pull request.
Tickets should be split until one independently testable unit can normally be
completed in roughly one to three focused engineering days. A heading that
still describes a larger epic must contain numbered subtickets before work is
assigned. Discovery tickets are timeboxed around one narrow question and
produce checked-in evidence and decisions, not speculative production code.

Every ticket must:

- list touched components before implementation;
- preserve fail-closed behavior;
- include automated tests or state why only a manual build-specific test is possible;
- add no fallback behavior unless a later approved ticket changes the fixed decisions;
- record commands and the exact Windows build used for host-dependent tests;
- avoid changing profile semantics outside the ticket;
- leave a short handoff note containing assumptions, test results, and unresolved risks.

Suggested labels: `discovery`, `contract`, `security`, `backend-mxc`, `filesystem`, `cli`, `network-wfp`, `proxy`, `test-infra`, `packaging`.

## 7. Phase 0: discovery and security baseline

### D-01: Capture the target-host baseline

**Depends on:** none

**Deliverables:** A checked-in host-baseline document and machine-readable sanitized report containing Windows edition/build, architecture, relevant optional features, MXC commit/version, `wxc-exec.exe` hash/version, elevation state, and probe output.

**Acceptance criteria:**

- Report identifies build `29671.1000 Enterprise` x64. ARM64 evidence is a
  separately labeled non-supporting experiment and cannot satisfy D-01.
- Collection launches no workload. It documents that `--probe` may perform MXC
  stale-DACL recovery before capability detection and records whether recovery
  occurred.
- Probe output is retained verbatim after review for secrets.
- A second run produces only expected timestamp or environment differences.

**Commands/tests:**

```powershell
$MxcRoot = (Resolve-Path .\mxc).Path
$WxcExec = "$MxcRoot\src\target\release\wxc-exec.exe"
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture
Get-Item $WxcExec | Select-Object -ExpandProperty VersionInfo
Get-FileHash $WxcExec -Algorithm SHA256
& $WxcExec --version
& $WxcExec --probe
```

### D-02: Verify BaseContainer/PSEC capability behavior on build 29671.1000

**Depends on:** D-01

**Deliverables:** Capability matrix for empty, filesystem, UI, deny-all-network,
and proxy requests; raw request-scoped probe evidence; source-verified mapping
from MXC's exposed capability booleans to required PSEC contract versions and
support bits.

**Acceptance criteria:**

- Empty and planned R1 requests resolve to `base-container`.
- Each required policy is probed as a complete request, not inferred from OS build number.
- Any policy that resolves to AppContainer or returns ambiguous capability data is marked blocked.
- Results distinguish symbol presence, PSEC environment creation support, and
  request compatibility where MXC exposes those distinctions. If the required
  distinction is not observable, enhanced diagnostics become an upstream
  blocker rather than an inferred result.

**Known MXC test entry points to evaluate:**

```powershell
& $WxcExec --probe --config .\candidate-config.json
pwsh "$MxcRoot\tests\scripts\run_processcontainer_probes_test.ps1" `
  -RequireTier base-container
```

### D-03: Select the supported MXC integration surface

**Depends on:** D-01, D-02

**Deliverables:** Architecture decision record comparing subprocess execution through `wxc-exec.exe`, available MXC SDK/library surfaces, and available FFI surfaces.

**Acceptance criteria:**

- Comparison covers API support status, redistribution, schema/version coupling, stdout/stderr streaming, stdin, cancellation, process-tree teardown, request-scoped probing, diagnostics, signing, and update strategy.
- A minimal spike proves probe, launch, output, exit code, timeout, and cancellation using only documented or source-verified interfaces.
- Investigation records whether the selected surface supports a created-but-not-
  running workload, pre-resume attestation, generation-correlated ownership,
  Job Object resource controls, and query-back of effective controls.
- The decision names the MXC version/commit boundary and upgrade policy.
- Any unavailable capability becomes a follow-up discovery blocker rather than an invented interface.
- This ticket and D-04 are stop-work gates for implementation beyond contracts
  and test infrastructure. If the selected supported surface cannot satisfy the
  created-not-running and pre-resume requirements, no product launch path may be
  implemented until an upstream mechanism is available.

### D-04: Establish BaseContainer-only enforcement options

**Depends on:** D-02, D-03

**Deliverables:** Decision record for preventing fallback, including whether MXC supports a force/require-tier input or whether the adapter must combine request-scoped preflight with post-launch effective-tier attestation.

**Acceptance criteria:**

- The selected mechanism is backed by source or runtime evidence.
- A deliberately PSEC-incompatible request fails before workload code executes.
- A test demonstrates that AppContainer+DACL availability does not make the product request succeed.
- A race analysis covers capability change between probe and launch. If MXC offers no atomic require-tier operation, this is raised as an upstream requirement or mitigated by effective-tier attestation before resume; it is not waved away.
- The launch sequence identifies and proves a staging point at which mandatory
  controls can be installed and attested before workload code executes. D-08
  and implementation tickets prove each specific control at that point.

### D-05: Filesystem semantics and aliasing investigation

**Depends on:** D-02

**Deliverables:** Test report for normal paths, case variants, UNC paths, subst drives, junctions, symlinks, mount points, 8.3 aliases, hard links, alternate data streams, deleted/recreated roots, and grants containing spaces.

**Acceptance criteria:**

- Tests cover read, write, create, delete, rename, enumerate, execute, and child-process access.
- Workspace read-write and toolchain read-only semantics are verified on BaseContainer.
- Every known alias that can escape a grant is either blocked by product validation or recorded as a release blocker.
- Results do not rely on the AppContainer+DACL path.

**Relevant existing MXC suite:**

```powershell
pwsh "$MxcRoot\tests\scripts\run_processcontainer_filesystem_matrix_test.ps1" `
  -RequireTier base-container
pwsh "$MxcRoot\tests\scripts\run_processcontainer_path_aliasing_test.ps1" `
  -RequireTier base-container
```

### D-06: Discover the enforceable proxy-only contract

**Depends on:** D-02, D-03

**Deliverables:** Build-specific report for MXC/PSEC WFP egress, loopback endpoint restrictions, proxy endpoint format, proxy peer identity, filter lifetime, IPv4/IPv6 behavior, DNS behavior, privilege requirements, and teardown.

**Acceptance criteria:**

- Report distinguishes documented MXC schema from OS/PSEC implementation behavior.
- Direct public, private, host-loopback, IPv4, and IPv6 paths are measured.
- It identifies whether a packaged proxy or AppContainer profile identity is required for the product threat model.
- It identifies how filter installation failure and proxy death affect an active workload.
- Unknown PSEC or WFP calls are listed as upstream questions; no API signatures are invented.

**Relevant existing MXC suites:**

```powershell
pwsh "$MxcRoot\tests\scripts\run_processcontainer_network_model3_test.ps1" `
  -RequireTier base-container
pwsh "$MxcRoot\tests\scripts\run_processcontainer_network_proxy_test.ps1" `
  -RequireTier base-container
pwsh "$MxcRoot\tests\scripts\run_processcontainer_network_rejections_test.ps1" `
  -RequireTier base-container
```

### D-07: Threat model and abuse-case catalog

**Depends on:** D-04, D-05, D-06, D-09, D-10, D-11, D-12

**Deliverables:** Threat model with trust boundaries, assets, attacker capabilities, misuse cases, mitigations, and explicit residual risks.

**Acceptance criteria:**

- Covers malicious command/profile input, path aliases, inherited handles, named objects, process injection, console/clipboard/UI, credentials/environment, proxy impersonation, DNS rebinding, IPv6, direct sockets, filter teardown, TOCTOU, log injection, and update tampering.
- Covers same-user host interference, credential replay, broker abuse, approval
  spoofing, stale policy revisions, generation confusion, resource exhaustion,
  executable replacement, DLL/plugin search paths, and crash-dump exposure.
- Separates risks accepted for AI agents from requirements before arbitrary-program support.
- Every high-severity threat maps to a ticket or blocks the relevant release.

### D-08: Discover enforceable resource controls

**Depends on:** D-02, D-03, D-04

**Deliverables:** Build-specific report for Job Object and MXC ownership,
nesting, breakaway prevention, active-process count, committed memory, handle
count, CPU, session-storage/disk, wall-clock, output, query-back, and breach
notification behavior.

**Acceptance criteria:**

- Results distinguish kernel-enforced controls, reliably measured product
  controls, and unsupported claims.
- Process-count and memory controls cover the complete descendant tree and can
  be installed before workload execution. If either cannot coexist with MXC's
  Job Object ownership, R1 is blocked.
- Handle and optional storage-accounting controls beyond the mandatory D-12
  hard session quota are advertised only when a supported mechanism is
  demonstrated; otherwise they remain explicitly unsupported. Failure to find
  the D-12 hard quota blocks R1.
- Limit breaches have deterministic process-tree and audit outcomes.
- CPU controls may remain an R4 follow-up if unavailable without weakening the
  R1 denial, filesystem, network, and cleanup boundaries.

### D-09: Discover Windows object namespace and IPC isolation

**Depends on:** D-02, D-04

**Deliverables:** Reproducible BaseContainer exposure matrix for Object Manager
namespaces, named pipes, mailslots, ALPC, RPC, COM/DCOM/WinRT, shared sections,
synchronization objects, host process handles, SCM, scheduled tasks, WMI, BITS,
authentication agents, and other same-user or service endpoints.

**Acceptance criteria:**

- Tests cover create, enumerate, open, connect, impersonate, duplicate, squat,
  collide, and cross-generation reuse where the object class supports them.
- Global, local, session, `BaseNamedObjects`, `RPC Control`, pipe, section,
  event, mutex, semaphore, symbolic-link, and job namespaces have explicit
  expected outcomes.
- Accessible host deputies are tested for indirect filesystem, credential,
  process, service, and network actions. Incidental endpoint DACL denial is not
  misreported as namespace isolation.
- Root, child, and grandchild processes are covered. Every unexplained
  high-impact host endpoint blocks R1 and maps to a mitigation ticket.

### D-10: Define the workload token and process-security contract

**Depends on:** D-02, D-04, D-09

**Deliverables:** Exact acceptable token, process/thread security, namespace,
desktop/window-station, and process-mitigation baseline for every supported
recipe class, plus a native query fixture.

**Acceptance criteria:**

- Evidence records user, owner, primary group, enabled and deny-only groups,
  restricted SIDs, AppContainer/BaseContainer identity, capabilities, integrity
  level, privileges, elevation, UIAccess, virtualization, mandatory policy,
  authentication/session IDs, default DACL, and impersonation properties.
- Dangerous privileges and capabilities are absent unless a separate reviewed
  requirement names them and proves why they cannot be removed.
- Process and thread DACLs prevent workload access to product, proxy, broker,
  credential, and unrelated host processes with duplicate-handle, VM-write,
  create-thread, token, or termination rights.
- Mandatory and recipe-dependent process mitigations are enumerated and can be
  queried before resume. Child processes cannot weaken mandatory controls.
- Unknown or additional authority is a launch blocker, not a warning.

### D-11: Select the privilege and lifecycle-owner architecture

**Depends on:** D-03, D-04, D-06, D-09, D-10

**Deliverables:** ADR deciding which operations run in the standard-user CLI,
MXC, a per-user broker, an elevated helper, or a Windows service, and which
component durably owns jobs, WFP state, proxies, credentials, and recovery.

**Acceptance criteria:**

- Every privileged operation and protected state transition has one named
  owner, minimum token/privileges, installation model, and authenticated IPC
  contract.
- Service or helper IPC verifies the caller's user, session, executable where
  trustworthy, request generation, plan hash, and authorization; it prevents
  pipe squatting, confused-deputy use, unsafe impersonation, and replay.
- The architecture guarantees workload termination and security-resource
  reconciliation after CLI death. "Where supported" is not an acceptable crash
  cleanup guarantee for an enabled release.
- Standard-user runtime and all elevation prompts are fixed before Q-04; a late
  packaging exception cannot redefine the trust boundary.

### D-12: Prove hard session-storage quota feasibility

**Depends on:** D-03, D-04, D-08, D-11

**Deliverables:** Decision and spike for a kernel-enforced, generation-bound
storage quota covering every product-created writable session/cache root used by
R1, including cleanup and crash recovery.

**Acceptance criteria:**

- The selected VHD, volume, filesystem quota, or equivalent mechanism enforces
  a byte ceiling without relying only on polling and post-facto termination.
- Quota setup and query-back occur before resume; setup failure blocks launch.
- Exhaustion cannot spill writes into host temp/profile locations, another
  generation, or an unbounded audit path.
- Sparse allocation, metadata growth, hard links, alternate streams, compression,
  concurrent writers, crash cleanup, and host-volume-low-space behavior are
  tested. If no supported hard mechanism exists, R1 is blocked.

### D-13: Establish the Hyper-V-isolated reference oracle

**Depends on:** D-07, D-09, D-10

**Deliverables:** ADR and non-product test spike comparing selected hostile
fixtures under BaseContainer and a Hyper-V-isolated Windows container.

**Acceptance criteria:**

- The ADR records security strength, host/image versioning, startup, concurrency,
  filesystem mapping, network, privilege, licensing, and operational tradeoffs.
- Differential tests cover token/namespace visibility, IPC, registry, services,
  devices, direct and indirect networking, host process access, and teardown.
- The oracle is provisioned separately and cannot be selected by a profile,
  environment variable, hidden flag, downgrade, or automatic fallback.
- Divergence does not prove a BaseContainer defect by itself, but unexplained
  broader authority blocks the relevant BaseContainer release claim.

## 8. Phase 1: product skeleton and contracts

### F-01: Bootstrap repository and Windows CI build

**Depends on:** D-03

**Deliverables:** Minimal repository structure, pinned toolchain/dependencies, deterministic debug/release builds, unit-test command, formatting/linting, and Windows CI workflow.

**Acceptance criteria:**

- A clean Windows checkout builds without WSL.
- CI publishes unsigned test artifacts with hashes.
- Dependency lock files are committed.
- Build metadata includes product version and source revision.

**Commands:** Start with `cargo build --workspace --locked`,
`cargo test --workspace --locked`, `cargo fmt --all -- --check`, and
`cargo clippy --workspace --all-targets --locked -- -D warnings`. Wrap these in
documented PowerShell entry points only when packaging or native-shim work needs
additional orchestration.

### F-02: Define CLI contract and exit-code taxonomy

**Depends on:** F-01

**Deliverables:** CLI specification for at least `run`, `validate`, `compile`,
`explain`, `doctor`, and `version`; exit-code table; stdout/stderr contract;
noninteractive behavior.

**Acceptance criteria:**

- `run --profile <path> -- <program> [args...]` preserves argument boundaries without shell re-parsing.
- Product errors and workload exit codes are unambiguous.
- The process exit-code contract reserves product outcomes and carries the exact
  workload exit value in the versioned result channel. It does not claim that a
  single raw process exit code can represent both namespaces without collision.
- JSON diagnostic output is versioned and separate from workload stdout.
- Unknown options and missing `--` fail before backend invocation.
- Help documents that PowerShell and `cmd.exe` perform their own outer parsing.

### F-03: Define versioned profile schema

**Depends on:** D-05, D-07, F-01

**Deliverables:** Profile schema, semantic specification, valid/invalid examples, and compatibility policy.

**Acceptance criteria:**

- Unknown properties are rejected.
- Secure defaults are explicit in tests.
- Workspace, toolchain, working-directory, environment, provenance, resource
  limits, credential references, UI, audit, rich network-rule, and network-deny
  semantics are represented.
- Proxy fields may be reserved but cannot enable networking before R3.
- A network operation constraint is valid only when its selected protocol
  adapter can observe and enforce that operation.
- Schema validation and semantic validation return stable error identifiers.

### F-04: Implement immutable execution-plan contract

**Depends on:** F-03

**Deliverables:** Internal plan model and profile-to-plan compiler interface,
with redacted debug rendering, source revision identities, canonical effective
policy revision/hash, required enforcement semantics, resource controls,
provenance requirements, and credential bindings.

**Acceptance criteria:**

- The backend receives only a fully validated plan.
- All paths are absolute, normalized, classified by access, and tied to validation evidence.
- Environment inheritance is explicit.
- The plan contains required backend capabilities and `requireBaseContainer=true` semantics even if the chosen MXC surface represents this differently.
- Per-launch generation identity is not reusable profile state; it is assigned
  when one execution attempt begins and binds the immutable plan to runtime
  resources.
- Canonicalization is a versioned product contract covering JSON encoding,
  Unicode normalization, Windows path representation/case, numeric encoding,
  set ordering, and schema/compiler/analyzer domain separation. Cross-language
  golden vectors produce identical hashes.
- Unit tests prove no permissive default appears when profile fields are omitted.

### F-05: Define structured errors and audit events

**Depends on:** F-02, F-04

**Deliverables:** Stable error categories and an event schema aligned to a
pinned OCSF version for validation, capability, configuration state, process
activity, credential use, network activity, detection findings, timeout,
cancellation, workload exit, and teardown. Product extensions are documented.

**Acceptance criteria:**

- Events include correlation ID, launch generation, policy generation/revision,
  profile identity/hash, backend semantic-report hash, effective backend/tier,
  product/MXC versions, timestamps, stable reason code, and outcome.
- Raw environment values, proxy credentials, file contents, and command output are absent by default.
- User-controlled strings cannot forge additional log records.
- Audit-write failure behavior is explicitly defined; security-audit modes fail closed if required by profile or product policy.
- Network or policy security findings emit both the applicable domain event and
  an OCSF `DetectionFinding`; event size, cardinality, and user-controlled text
  are bounded and schema-tested.

### F-05A: Implement durable security-audit storage

**Depends on:** F-05, D-11

**Deliverables:** Protected baseline audit sink with atomic record framing,
generation sequence numbers, retention/rotation budgets, recovery, and explicit
failure behavior. Diagnostics remain a separate best-effort channel.

**Acceptance criteria:**

- Workload and project-controlled configuration cannot redirect, truncate,
  clear, reorder, or forge the security sink.
- Each generation has monotonic sequence numbers, durable start/end or gap
  records, and an incomplete-run marker recoverable after a crash.
- Required pre-resume decisions are durable before workload execution;
  credential-use authorization is durable before upstream credentialed writes.
- Disk full, sink loss, clock rollback, duplicate/replayed records, rotation,
  retention expiry, and owner crash have deterministic fail-closed or teardown
  outcomes. Audit storage is charged to a bounded product quota and cannot fill
  the host volume without limit.
- Release evidence uses integrity-protected batches or a protected Windows Event
  Log channel with documented ACL and clearing semantics.

### F-06: Implement profile discovery, trust layers, and composition

**Depends on:** F-03, F-04

**Deliverables:** Deterministic loading and composition of engine invariants,
machine ceiling, approved user profile, optional project request, and session
narrowing.

**Acceptance criteria:**

- Workspace-controlled files cannot add a path, environment variable, network
  host, executable root, cache-sharing domain, credential, IPC endpoint, or UI
  capability.
- Machine and user files are loaded only from their documented protected roots;
  project-controlled includes, junctions, environment redirects, and search-path
  precedence cannot replace them.
- Unknown fields, composition cycles, missing approved profiles, and profile
  version mismatches fail before backend invocation.
- `sandboxctl explain` shows each effective grant or denial and its source layer.
- The canonical effective plan is deterministic and hashable.
- Persistent revisions are atomically published and rollback-detecting; an old
  but correctly signed approval or plan cannot replace newer effective state.
- Composition records every source and approval revision and computes a
  deterministic effective-policy revision. Changes affect later generations
  only in v1.
- Tests demonstrate that every attempted project-side privilege expansion is
  rejected while project-side narrowing succeeds.

### F-07: Implement modeled containment and policy-delta framework

**Depends on:** F-04, F-06, S-01, S-02

**Deliverables:** A versioned Windows-aware analyzer framework that compares a
candidate effective plan with its machine/user ceiling and reports modeled
authority additions and removals. It initially covers composed filesystem,
environment, executable-root, and declared limit semantics. Network, credential,
and enforced-resource tickets add their domain adapters using the same result
contract. This is not presented as formal verification of the complete sandbox.

**Acceptance criteria:**

- Containment returns exactly `within`, `exceeds`, `unsupported`, or
  `inconclusive`; only `within` can authorize an approval or launch.
- Results identify modeled and excluded domains, normalized input hashes,
  analyzer version, assumptions, and a concrete counterexample when available.
- Each enabled domain uses the same normalization semantics as its runtime
  compiler. A domain without an installed analyzer adapter returns `unsupported`
  and cannot authorize a grant or approval.
- Timeout, resource exhaustion, unresolved path identity, and unsupported policy
  shapes fail closed for authorization.
- An empty risk-finding delta is never described as proof of containment.
- Mutation and golden tests prove project/session narrowing and detect deliberate
  widening in every modeled domain.

## 9. Phase 2: BaseContainer-only execution

### B-01: Implement side-effect-minimal host doctor

**Depends on:** D-03, D-04, F-02, F-05

**Deliverables:** `doctor` checks for OS/build, architecture, MXC presence/version/hash policy, BaseContainer/PSEC availability, and required capabilities.

**Acceptance criteria:**

- `doctor` never launches user workload code.
- It reports build 29671.1000 as tested, but capability probes remain authoritative.
- Missing, malformed, or contradictory probe data returns not-ready.
- Human and JSON output identify remediation without suggesting fallback.

### B-02: Render deny-all MXC requests

**Depends on:** D-03, F-04

**Deliverables:** Deterministic adapter from execution plan to the chosen MXC
request format plus a versioned machine-readable semantic report.

**Acceptance criteria:**

- Request explicitly selects ProcessContainer and deny-all networking according to the verified MXC contract.
- Request includes only validated filesystem grants, working directory, environment, UI policy, command, and limits supported by MXC.
- Golden tests pin rendered policy while ignoring approved runtime-only values.
- Every source requirement has one disposition: `exact`, `delegated`,
  `backend_added_restriction`, `unsupported`, or `approximated`.
- Delegation names an enforcer and becomes valid only when that enforcer is
  ready and bound to the same launch generation.
- `unsupported`, `approximated`, unknown capability state, and unclassified
  mapper branches fail rendering. Backend-added restrictions remain visible.
- Reports record plan hash, request hash, mapper/schema/MXC versions, capability
  snapshot, Windows build, reason codes, and responsible enforcer.
- Every emitted MXC permission and request field traces back to an authorized
  plan requirement or an explicitly classified backend-added restriction.
  Unaccounted emitted authority blocks launch.

### B-03: Enforce request-scoped BaseContainer preflight

**Depends on:** B-01, B-02, D-04, F-06, F-07

**Deliverables:** Preflight that evaluates the exact rendered request and requires BaseContainer plus all plan capabilities.

**Acceptance criteria:**

- No launch occurs if tier is absent, unknown, or not exactly `base-container`.
- No launch occurs when a required capability is absent.
- Preflight checks the semantic report against the exact capability snapshot and
  audits its hash with the effective-policy revision.
- Tests inject malformed probe output, timeout, nonzero probe exit, and AppContainer tier.
- Probe diagnostics are bounded and redacted.

### B-04: Launch and attest effective tier

**Depends on:** B-03, F-06, F-07

**Deliverables:** Typed launch state machine with stdin/stdout/stderr plumbing,
exit-code capture, generation ownership, and the strongest effective-tier check
supported by D-04.

**Acceptance criteria:**

- `cmd.exe /d /s /c exit 0` and a direct executable smoke test complete successfully on BaseContainer.
- A nonzero workload exit is returned as workload outcome, not a sandbox setup error.
- The product records effective tier as `base-container` from trustworthy backend evidence.
- If tier cannot be attested at the required point, launch fails or R1 remains blocked.
- The minimum states are `Planned`, `Preflighted`, `ResourcesPrepared`,
  `CreatedNotRunning`, `Attested`, `Running`, `Terminating`, `Terminated`, and
  `CleanupFailed`.
- A unique typed launch-generation ID is assigned before resources are prepared.
  It binds plan hash, capability snapshot, tier evidence, MXC session, resource
  controls, proxy/broker identities, and policy generation.
- Only `Attested -> Running` may permit workload execution. If the selected MXC
  surface cannot provide this ordering, R1 remains blocked or requires an
  explicitly reviewed upstream mechanism.
- B-04 implements an extensible attestation barrier and transition guard.
  Initially it requires tier, composed-policy containment, and semantic-report
  evidence. Later control tickets register their own typed evidence with that
  barrier; a release manifest defines which evidence kinds are mandatory for
  that artifact. `Attested` means every evidence kind required by the current
  signed release manifest is installed, generation-bound, and confirmed.
- S-07 adds process/memory evidence, S-08 adds provenance evidence, S-09 adds
  offline deny-all evidence, S-10 through S-14 add token, handle, IPC/domain,
  hard-quota, and mitigation evidence, and the R3 network/broker tickets add
  WFP, proxy, policy, and credential-broker evidence. No ticket may bypass or
  special-case the common transition guard.

### B-05: Cancellation, timeout, and process-tree teardown

**Depends on:** B-04

**Deliverables:** Ctrl-C handling, wall-clock timeout, explicit cancellation, and deterministic teardown.

**Acceptance criteria:**

- Child and grandchild processes do not survive cancellation, timeout, CLI
  crash recovery, or normal completion.
- First interrupt requests graceful cancellation only if bounded; repeated interrupt forces teardown.
- Teardown timeout becomes a product error and audit event.
- Handle/process counts remain stable over a 1,000-run stress test.
- Teardown is generation-scoped and idempotent. Stale callbacks, handles, or
  cleanup requests from another generation are rejected.

### B-06: Backend conformance test double

**Depends on:** F-04, F-05

**Deliverables:** Test backend that scripts probe, launch, stream, cancellation, tier, and teardown outcomes without weakening production code paths.

**Acceptance criteria:**

- CLI and policy tests run on ordinary Windows CI without requiring build 29671.1000.
- Production packaging cannot select the test backend.
- Failure-injection tests cover every structured backend error.
- Tests cover invalid state transitions, stale generation IDs, semantic loss,
  policy revision mismatch, delayed completion, and session-ID reuse.

### B-07: Crash-consistent generation ownership and recovery

**Depends on:** B-04, B-05, D-11, F-05A

**Deliverables:** Durable, secret-free generation journal and lifecycle owner
for process jobs, MXC sessions, proxy/WFP resources, broker routes, one-shot
approvals, audit completion, quotas, and session roots.

**Acceptance criteria:**

- Workload processes cannot survive loss of the interactive CLI. Job handles
  are not inherited by workloads, kill-on-close or an equivalent supported
  lease is proven, and the durable owner cannot disappear while a workload can
  remain alive.
- Startup reconciliation identifies and terminates or quarantines every stale
  generation without adopting resources by reusable PID, port, or object name.
- Unknown prior state blocks new launches that could conflict with it.
- Forced termination and power-loss simulation at every state from
  `ResourcesPrepared` through `CleanupFailed` leave deterministic evidence and
  recover on next startup.
- Recovery covers process, filesystem/session root, quota, proxy, WFP, broker,
  credential placeholder, approval, and audit resources as one generation.

### B-08: Implement the privileged control-plane boundary

**Depends on:** D-11, B-06, F-04, F-05A

**Deliverables:** The selected service/helper/broker architecture and its
authenticated, versioned, generation-bound IPC protocol.

**Acceptance criteria:**

- Every request is authorized against caller identity, session, immutable plan
  hash, effective-policy revision, and launch generation before privileged work.
- IPC endpoints have explicit non-project-controlled names and ACLs; tests cover
  squatting, replay, confused-deputy requests, unsafe impersonation, malformed
  frames, client death, server restart, version skew, and cross-user attempts.
- Privileged components use service SIDs or reduced tokens, minimum privileges,
  restrictive process DACLs, explicit handle lists, and no ambient workspace
  access beyond the validated request.
- Production packaging cannot replace the implementation with an in-process or
  test-only bypass.

## 10. Phase 3: filesystem and process hardening

### S-01: Canonical path validator

**Depends on:** D-05, F-03

**Deliverables:** Windows path validation rules and implementation for workspace, toolchain, executable, and working-directory paths.

**Acceptance criteria:**

- Rejects relative, empty, device namespace, ADS, traversal, and unsupported network paths.
- Uses Windows-aware comparison and normalization rather than string-prefix containment.
- Detects reparse points and verifies resolved targets remain permitted.
- Unit tests include drive roots, UNC policy decision, spaces, non-ASCII paths, case variants, trailing separators, and long paths.

### S-02: Grant overlap and precedence validator

**Depends on:** S-01

**Deliverables:** Deterministic rules for duplicate, ancestor, descendant, read-only, and read-write grants.

**Acceptance criteria:**

- Conflicting grants are rejected unless the schema explicitly defines safe precedence.
- Toolchain roots cannot accidentally become writable through an ancestor workspace grant.
- Working directory and executable are proved to lie within suitable grants.
- Error messages identify profile locations without exposing unrelated filesystem contents.

### S-03: Object-identity and runtime TOCTOU controls

**Depends on:** S-01, S-02, B-04

**Deliverables:** Revalidation immediately before launch, stable root/object
identity where supported, post-resume mutation testing, and documented residual
race analysis.

**Acceptance criteria:**

- Replacing a validated root with a junction before launch is detected in a deterministic test harness.
- File identity or handle-based checks are used where supported and justified by D-05.
- Accepted filesystem types, path namespaces, reparse tags, case-sensitivity
  modes, and volume properties form a closed allowlist. Unknown forms fail.
- Grant-root handles or equivalent backend leases remain valid for the
  generation where needed to prevent root replacement.
- Post-resume tests race junction, mount-point, hard-link, rename, delete/recreate,
  volume-remount, and host-side mutations while the workload repeatedly opens
  targets. PSEC must authorize the resolved object on each open rather than only
  a setup-time pathname.
- Any race MXC/PSEC cannot close is a release-blocking risk decision, not silently accepted.

### S-04: Filesystem enforcement E2E matrix

**Depends on:** S-03

**Deliverables:** BaseContainer-only tests for workspace RW, toolchain RO, ungranted deny, and path alias attacks.

**Acceptance criteria:**

- Workspace create/read/update/delete succeeds.
- Toolchain read/execute succeeds and create/update/delete fails.
- Reads and writes outside grants fail.
- Junction, symlink, mount-point, subst, 8.3, hard-link, ADS, case, rename,
  deleted/recreated-root, unsupported-reparse-tag, Volume GUID, extended-path,
  and post-resume mutation cases have asserted outcomes.
- Test setup verifies effective tier before accepting a pass.

### S-05: Environment and credential isolation

**Depends on:** F-03, B-04, D-07

**Deliverables:** Environment builder with minimal defaults and explicit inheritance.

**Acceptance criteria:**

- Common secret variables and host proxy variables are not inherited.
- Provider credentials, values marked as secrets, cloud tokens, SSH secrets, and
  package-registry credentials cannot be explicitly inherited through reserved
  credential fields or known credential variable names. They require a broker
  capability or remain unavailable. Arbitrary literals cannot be reliably
  classified as secrets; environment values and argv are omitted from audit and
  support output by default, and profiles warn that arbitrary literals are not
  a secret transport.
- `PATH`, temp directories, home/profile variables, and tool cache locations have documented sandbox semantics.
- Environment keys are case-insensitively deduplicated as Windows requires.
- Tests prove inherited secrets are absent and allowed values survive exactly.

### S-06: Console and UI isolation baseline

**Depends on:** D-02, B-04

**Deliverables:** Secure UI/console policy for CLI agents and compatibility report.

**Acceptance criteria:**

- Clipboard, desktop/system control, global atoms/handles, injection, and Win32k policy are explicitly configured where supported.
- R1 uses an isolated noninteractive desktop/window station or a source- and
  runtime-proven PSEC equivalent. UIAccess, host input desktop, shell,
  accessibility/UI Automation control, global hooks, broadcast messages, and
  cross-generation console handles are denied.
- Bounded redirected input and output work for the R1 baseline. Interactive
  console/ConPTY behavior is deferred to C-03 and R2.
- A policy that requires an unsupported UI restriction fails before launch.
- Existing MXC BaseContainer UI suites pass or deviations are release blockers.

### S-07: Enforce launch resource ceilings

**Depends on:** D-08, F-04, B-04, B-05

**Deliverables:** Generation-bound enforcement for the resource controls proven
by D-08, including process count and committed memory for R1 plus any supported
handle controls for R2. Hard session storage is mandatory and owned separately
by D-12/S-13.

**Acceptance criteria:**

- Controls are installed and, where supported, queried back before the
  `Attested -> Running` transition.
- Child and grandchild processes cannot escape the controlling Job Object or
  obtain a less restrictive resource context.
- Process-count and memory breach tests terminate or contain the complete
  generation with stable workload and OCSF outcomes.
- Wall-clock and output limits retain bounded buffers and deterministic teardown.
- Handle controls are claimed only when D-08 proved a supported mechanism;
  unsupported handle controls remain visible in diagnostics. Storage quota
  cannot be marked unsupported because S-13 is an R1 blocker.

### S-08: Trusted executable and loader provenance

**Depends on:** F-03, S-02, B-04, D-07

**Deliverables:** Provenance validation for product/MXC binaries, selected
workload executables, trusted toolchains, and relevant native loader dependencies
using approved signatures, hashes, or versioned manifests.

**Acceptance criteria:**

- Provenance is revalidated as close to launch as the selected Windows APIs
  permit, and the evidence is bound to the launch generation.
- Tests cover user-writable adjacent DLLs, DLL/plugin search order, `PATH` and
  `PATHEXT` substitution, mixed-version installations, executable replacement,
  junction/symlink replacement, and writable compiler/plugin directories.
- A trusted executable in an untrusted loader environment is rejected rather
  than considered trusted by pathname alone.
- Toolchain recipes declare their trusted roots, mutable plugin/native-module
  locations, and expected spawned executables.

### S-09: Deny-all network E2E baseline

**Depends on:** B-04, B-05, D-06

**Deliverables:** Offline BaseContainer tests proving that the R1/R2 network
posture has no external or host-network path before any proxy is configured.

**Acceptance criteria:**

- Direct IPv4 and IPv6 TCP, UDP, QUIC, raw destination IP, system and direct
  DNS, DoH/DoT canaries, private LAN, metadata-style addresses, and host loopback
  fail from root, child, and grandchild processes.
- Inbound listeners cannot create an external or host-reachable channel beyond
  explicitly documented intra-sandbox loopback behavior.
- Every test proves effective tier `base-container`, the expected policy hash,
  and matching launch generation before accepting a denial result.
- Missing network prerequisites fail the assigned security-test runner rather
  than silently skipping the suite.

### S-10: Attest workload token and namespace evidence

**Depends on:** D-10, B-04

**Deliverables:** Generation-bound implementation of the D-10 token, process-
security, namespace, desktop, and mitigation query fixture integrated into the
common attestation barrier.

**Acceptance criteria:**

- Root, child, and grandchild evidence matches the signed required-controls
  manifest before and after representative process creation.
- Unknown SIDs, capabilities, enabled privileges, integrity changes, UIAccess,
  namespace changes, or weaker process/thread DACLs block launch or terminate
  the generation.
- Evidence is collected from trustworthy handles rather than workload-supplied
  PIDs or text, is bounded, and is hash-bound to the generation.

### S-11: Enforce the handle capability boundary

**Depends on:** D-10, B-04

**Deliverables:** Explicit launch handle allowlist and host-process handle
isolation for redirected pipes and supported ConPTY operation.

**Acceptance criteria:**

- Launch uses `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` or an equally strict supported
  mechanism. Global inheritable-handle behavior without an exact allowlist is
  forbidden.
- Only minimum-right generation-specific stdio/ConPTY handles cross the boundary.
  Job, token, process, thread, proxy, broker, credential, audit, WFP, registry,
  directory, and secret-bearing handles do not.
- Concurrent host handle creation cannot race inheritance. Root and descendants
  cannot reopen protected product processes with duplicate-handle, VM-write,
  create-thread, token, or termination rights.
- Created-not-running and stress tests compare actual inherited handles with the
  expected manifest and prove kill-on-close is not defeated by a leaked job
  handle.

### S-12: Enforce IPC, registry, service, and device isolation

**Depends on:** D-09, D-10, B-04, F-07

**Deliverables:** Runtime controls, semantic-report domains, analyzer adapters,
and negative tests for the R1 subset established by D-09.

**Acceptance criteria:**

- Named objects, pipes, ALPC/RPC/COM, host process access, registry views, SCM,
  scheduled tasks, WMI, BITS, authentication agents, and device classes have
  exact supported or denied outcomes.
- Both 32-bit and 64-bit registry views and per-user COM registration are tested.
- Host deputies cannot perform filesystem, network, credential, service, or
  process operations on behalf of the workload outside the effective plan.
- Every enabled domain produces generation-bound attestation evidence. Missing
  enforcement or analyzer support returns `unsupported` and blocks R1.

### S-13: Enforce hard session-storage quotas

**Depends on:** D-12, B-04, B-07, S-05

**Deliverables:** Generation-bound creation, query-back, breach handling, and
cleanup for the selected hard quota mechanism.

**Acceptance criteria:**

- Every R1 writable synthetic/session/cache root is inside the enforced quota
  before `Attested -> Running`; no fallback unbounded host path is present.
- Quota exhaustion has a deterministic workload result, bounded audit event,
  complete process-tree teardown, and crash-recoverable cleanup.
- Concurrent generations cannot consume, mount, relabel, or inherit one
  another's quota-backed storage.
- Sparse, compressed, ADS, hard-link, metadata, and host-low-space tests confirm
  the D-12 contract.

### S-14: Enforce recipe-specific process mitigations

**Depends on:** D-10, B-04

**Deliverables:** Mandatory minimum and recipe-specific creation-time mitigation
profiles covering DEP/ASLR, CFG/CET where available, strict handle checks,
extension points, image/font loading, dynamic code, child processes, and Win32k.

**Acceptance criteria:**

- Every mitigation is classified as mandatory, recipe-required exception, or
  unsupported with a stable reason; exceptions cannot be introduced by project
  configuration.
- Effective policies are queried before resume and included in S-10 evidence.
- Child processes cannot weaken mandatory inherited controls.
- JIT runtimes and native build tools have explicit compatibility tests rather
  than causing global mitigation relaxation.

## 11. Phase 4: agent CLI usability

### C-01: Correct Windows argument transport

**Depends on:** F-02, B-04

**Deliverables:** Argument transport implementation and quoting test corpus.

**Acceptance criteria:**

- Empty arguments, spaces, quotes, trailing backslashes, Unicode, and shell metacharacters arrive unchanged at a native argv probe.
- The product does not implicitly invoke `cmd.exe` or PowerShell.
- Shell execution requires the caller to explicitly select the shell.

### C-02: Streaming stdio and backpressure

**Depends on:** B-04, B-06

**Deliverables:** Binary-safe stdin/stdout/stderr streaming and bounded buffering.

**Acceptance criteria:**

- Streams preserve bytes and keep stdout separate from stderr.
- A slow consumer does not cause unbounded memory use.
- Closing stdin is delivered to the workload.
- At least 1 GiB generated output is handled under a documented memory ceiling or terminated by the configured output limit.

### C-03: Terminal mode and signal behavior

**Depends on:** B-05, C-02

**Deliverables:** Decision and implementation for redirected pipes versus interactive console/ConPTY behavior supported by MXC.

**Acceptance criteria:**

- Redirected CI usage is fully automated.
- Interactive behavior is either supported and tested or rejected with a clear error in R2.
- Ctrl-C ownership between host CLI and workload is deterministic.
- Terminal resize is tested if ConPTY is supported.
- Raw workload control sequences are treated as untrusted output. Product
  diagnostics and approvals use a separate trusted channel; tests cover OSC,
  clipboard, title, hyperlink, cursor, prompt-spoofing, and malformed escape
  sequences against each supported terminal mode.

### C-04: Deterministic offline workload harness

**Depends on:** S-04, S-05, C-01, C-02

**Deliverables:** Native test executables and local fixtures that exercise
arguments, environment, filesystem access, child processes, stdio, terminal
behavior, and attempted network access without requiring an actual AI provider.

**Acceptance criteria:**

- Every fixture is deterministic, offline, and safe to run repeatedly on a
  disposable test host.
- Probes emit machine-readable results and distinguish denied access from a
  fixture defect.
- Test invocation declares all workspace and executable grants rather than
  relying on ambient access.
- The harness can be reused by toolchain recipes and security regression tests.

### C-05: Diagnostics and support bundle

**Depends on:** B-01, F-05, C-04

**Deliverables:** Extensions to the B-01 `doctor`, per-run correlation IDs,
redacted support archive, and operator troubleshooting guide.

**Acceptance criteria:**

- Bundle includes versions, sanitized profile, probe result, event log, and hashes, but no workspace contents or secret values.
- Redaction has adversarial tests.
- Support instructions never recommend disabling BaseContainer-only checks.

### C-06: Toolchain recipe contract and synthetic user directories

**Depends on:** F-06, S-05, S-08, C-01

**Deliverables:** A recipe contract for trusted read-only tool roots,
project/session writable state, environment rewrites, executable discovery, and
network requirements. Create short per-run `USERPROFILE`, `APPDATA`,
`LOCALAPPDATA`, `TEMP`, and cache paths under a product-owned session root.

**Acceptance criteria:**

- Recipes compile into ordinary profile permissions; they cannot bypass the
  trust-layer compiler.
- Tool binaries and installations are read-only unless a recipe documents and
  tests a narrower writable requirement.
- Writable caches, configuration, temporary files, and build output are scoped
  to a project or session and are never shared writable across unrelated
  projects.
- The synthetic user directories do not expose the host user profile, agent
  credentials, package credentials, SSH configuration, or cloud configuration.
- Recipe behavior is visible in `validate`, `compile`, and `explain` output.
- Every recipe declares provenance and loader expectations rather than trusting
  an installation path alone.

### C-07: Python and pip recipe

**Depends on:** C-06, S-04

**Deliverables:** Profile examples and E2E tests for a trusted Python
installation, project `.venv`, pip, bytecode, temporary files, and an isolated
package cache.

**Acceptance criteria:**

- The trusted Python installation is read/execute-only.
- `PYTHONNOUSERSITE=1`; inherited `PYTHONPATH`, `PYTHONHOME`, and
  `PYTHONSTARTUP` are absent.
- `PIP_CONFIG_FILE`, `PIP_CACHE_DIR`, `PYTHONPYCACHEPREFIX`, and temporary paths
  point only to approved synthetic or project locations.
- Creating and using a project virtual environment works offline from a local
  fixture; reading or modifying the host Python user site fails.
- Native extension modules, interpreter DLL resolution, and spawned build tools
  satisfy the recipe's provenance and writable-search-path tests.
- Network package installation remains unavailable until R3 and then uses the
  enforced proxy.

### C-08: Java, Gradle, and Maven recipe

**Depends on:** C-06, S-04, C-03

**Deliverables:** Profile examples and E2E tests for a trusted JDK, Gradle
wrapper, Maven wrapper/client, isolated Gradle/Maven homes, temporary files, and
build output.

**Acceptance criteria:**

- The JDK and approved Gradle/Maven installations are read/execute-only.
- `JAVA_HOME` is explicit; inherited `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, and
  `JDK_JAVA_OPTIONS` are absent unless a trusted recipe sets them.
- `GRADLE_USER_HOME`, Maven local repository, Java temporary directory, and all
  wrapper state resolve to project-scoped or session-scoped writable paths.
- Gradle daemon behavior is tested inside the same sandbox job; cross-project
  daemon reuse is impossible. If dynamic localhost ports are not safely
  supported, the recipe enforces `--no-daemon` for the supported baseline.
- Offline fixture builds pass; attempts to modify the JDK or host `.gradle` and
  `.m2` directories fail.
- Dependency verification and wrapper distribution integrity expectations are
  documented before online downloads are enabled in R3.
- JNI/native libraries, Java agents, build plugins, annotation processors, and
  wrapper-launched executables are included in provenance tests.

### C-09: Node, npm, and native build-tool recipe

**Depends on:** C-06, S-04

**Deliverables:** Profile examples and E2E tests for trusted Node/npm, isolated
npm configuration/cache/global prefix, lifecycle scripts, and child compiler
processes.

**Acceptance criteria:**

- Node/npm installations are read/execute-only and host npm credentials are not
  visible.
- npm cache, user config, global config, and global prefix point to approved
  synthetic or project locations.
- The initial recipe either disables lifecycle scripts or explicitly documents
  that they execute as untrusted code inside the same sandbox.
- Offline `npm ci` and a native-child-process fixture pass without ambient host
  access.
- Native add-ons, `node-gyp`, lifecycle children, and executable lookup are
  included in provenance and loader tests.

### C-10: Representative AI-agent matrix

**Depends on:** C-04, C-07, C-08, C-09

**Deliverables:** Reproducible compatibility matrix for the selected CLI agents,
including runtime, configuration, terminal, filesystem, and network needs.

**Acceptance criteria:**

- At least one Node-based agent and one additional supported agent run against
  deterministic offline fixtures before R3.
- Agent configuration lives under the synthetic user root. Host agent
  credentials are not mounted wholesale.
- Offline testing records each provider's client protocol, configurable base
  URL, credential header, model selection, streaming behavior, and broker needs.
  A network-enabled agent cannot ship until its provider is supported by the
  credential-broker tickets below or it requires no credential.
- A workload incompatibility creates a recipe or capability issue, never a
  global policy relaxation.

### C-11A: Integrate the minimal R1 CLI

**Depends on:** F-02, F-05A, F-06, F-07, B-05, B-07, C-01

**Deliverables:** Preview implementations of `run`, `validate`, `doctor`, and
`version` for redirected, noninteractive execution using only product compiler,
analyzer, audit, and backend interfaces.

**Acceptance criteria:**

- No command constructs backend policy directly or bypasses composition,
  containment, semantic reporting, capability checks, mandatory audit, or the
  attestation barrier.
- R1 `run` uses bounded redirected streams from B-04. Interactive terminal mode,
  high-throughput streaming, `compile`, and `explain` remain disabled with
  stable preview errors until their R2 tickets are present.
- Product outcome uses the reserved product exit namespace and versioned result
  channel; workload exit values remain exact in that result.
- Production packaging cannot expose incomplete R2 commands through aliases,
  hidden flags, environment variables, or direct library calls.

### C-11: Integrate the complete user-facing CLI commands

**Depends on:** C-11A, C-02, C-03, C-05

**Deliverables:** Production implementations of `run`, `validate`, `compile`,
`explain`, `doctor`, and `version` using only the product compiler, analyzer, and
backend interfaces.

**Acceptance criteria:**

- No command constructs backend policy directly or bypasses profile composition,
  containment, semantic reporting, capability checks, or audit initialization.
- `run` preserves workload exit status while keeping product/setup errors
  unambiguous and binds Ctrl-C/cancellation to the correct launch generation.
- `compile` and `explain` redact secrets and placeholders and display source,
  effective-policy, containment, and semantic-report revisions.
- Machine-readable output is versioned and never shares workload stdout.

## 12. Phase 5: WFP-enforced proxy-only networking

This phase has three independent controls:

1. PSEC/WFP ensures the sandbox can reach only the approved proxy endpoint and cannot connect directly.
2. The proxy resolves destinations and decides host, port, protocol, and any
   operation visible without generic TLS interception.
3. The provider gateway resolves generation-scoped placeholders and applies real
   credentials only to approved provider-specific upstream requests.

No control substitutes for another. Proxy environment variables improve
compatibility but are not enforcement. Generic HTTPS `CONNECT` is opaque and
never supports credential injection in R3.

### N-01: Specify governed network policy semantics

**Depends on:** D-06, D-07, F-03

**Deliverables:** Versioned policy for destination host/address class, port,
protocol, inspectable operation, executable identity when trustworthy evidence
exists, credential binding, default decision, and audit behavior.

**Acceptance criteria:**

- Defines exact-name and subdomain matching, IDNA normalization, case, trailing dot, wildcard restrictions, ports, default decision, redirects, and audit behavior.
- IP literals are separately controlled and denied by default.
- DNS rebinding policy is defined: the proxy resolves and connects to the vetted result; it rejects forbidden address classes unless explicitly permitted.
- Private, loopback, link-local, multicast, unspecified, and metadata-style addresses are denied by default.
- Policy explains HTTP, HTTPS `CONNECT`, WebSocket, and unsupported protocols.
- The specification identifies observable dimensions per adapter. Plain HTTP may
  expose method and normalized authority; HTTPS `CONNECT` exposes destination
  host and port only. Generic TLS interception is not available in R3.
- Rules depending on an unobservable method, path, model, or other operation are
  rejected rather than reduced to host-only authority.
- Executable identity is enforceable only when derived from trustworthy
  backend/kernel evidence. The configured top-level command is not substituted
  for the process that initiated a connection.

### N-02: Implement policy decision engine

**Depends on:** N-01

**Deliverables:** Pure host/address/port/protocol/operation decision library
with table-driven tests.

**Acceptance criteria:**

- No network or filesystem access occurs in the decision function.
- Tests cover Unicode/IDNA confusables, suffix boundary errors, trailing dots, mixed case, IPv4 variants, IPv4-mapped IPv6, redirects, and DNS answer changes.
- Deny wins over allow where rules overlap.
- Decision output includes matched rule ID, effective-policy revision,
  dimensions actually inspected, unavailable dimensions, and a stable reason
  code.

### N-03: Implement minimal HTTP/S policy proxy

**Depends on:** N-02

**Deliverables:** Loopback-only proxy supporting required HTTP forwarding and HTTPS `CONNECT`, upstream DNS resolution, policy checks, limits, and audit events.

**Acceptance criteria:**

- Listener binds only the exact configured loopback address and ephemeral/assigned port.
- Proxy authenticates or is identity-bound strongly enough to prevent an unrelated local client from abusing it; exact mechanism follows D-06.
- Header sizes, connection counts, idle time, total lifetime, and audit fields are bounded.
- Proxy does not log authorization headers, URLs with queries, request bodies, or TLS payloads by default.
- Unsupported methods/protocols fail closed.
- Each listener and accepted connection is bound to one typed launch generation
  and policy generation. A unique port alone is not treated as sufficient
  caller authentication.
- The wire contract defines absolute/origin/authority forms, duplicate and
  conflicting authorities, userinfo, IPv6 zones, hop-by-hop and proxy headers,
  connection reuse, CNAME/address handling, request smuggling, and parser size
  budgets. `CONNECT` is described as an opaque host/port TCP tunnel, not proof
  of TLS or visibility into encrypted methods and paths.

### N-03A: Minimize and harden host proxy authority

**Depends on:** N-03, B-08, S-11, S-14

**Deliverables:** Reduced host process boundary for the proxy and provider
gateway plus explicit outbound resolver, TLS, credential, and host-proxy policy.

**Acceptance criteria:**

- Proxy/gateway processes have reduced tokens, restrictive process DACLs,
  explicit handles, resource jobs, no child-process authority, and no workspace,
  user-profile, credential-store, or unrelated registry access.
- Outbound behavior disables WPAD/PAC, ambient WinHTTP/WinINet proxy settings,
  default credentials, automatic NTLM/Kerberos/Negotiate, ambient cookies,
  credential UI, and automatic client-certificate selection unless a separately
  modeled machine policy explicitly enables one.
- Resolver, suffix-search, CNAME, redirect, connected-peer, TLS trust-store,
  hostname, protocol-version, and revocation semantics are fixed and tested.
- Crash dumps, debugging, ETW payloads, paging exposure, secret-buffer lifetime,
  and zeroization have explicit controls and adversarial tests.
- Compromise tests prove the proxy cannot read broader host state or open
  destinations outside its generation-bound upstream policy.

### N-04: Integrate PSEC/WFP proxy-only request

**Depends on:** D-06, N-03A, B-04, B-05, B-07

**Deliverables:** Network controller and MXC request rendering for the verified proxy-only PSEC contract.

**Acceptance criteria:**

- Product starts and verifies the proxy before workload launch.
- Exact request preflight still returns `base-container` and required network capabilities.
- WFP permits only the configured proxy endpoint for the sandbox.
- Proxy startup, identity, policy load, or WFP setup failure prevents workload launch.
- WFP filter identity/lifetime, proxy identity, policy revision, and listener
  readiness register typed generation evidence with the B-04 attestation
  barrier. No network-enabled path may resume through a separate guard.
- Proxy death causes workload network failure and bounded teardown; it never opens direct egress.
- WFP/filter ownership and cleanup are verified after normal exit, cancellation, CLI crash, and proxy crash.

### N-05: Inject proxy compatibility configuration

**Depends on:** N-04, S-05

**Deliverables:** Per-run proxy environment and any verified per-container WinHTTP configuration.

**Acceptance criteria:**

- `HTTP_PROXY`, `HTTPS_PROXY`, lowercase variants, and WinHTTP behavior match the chosen contract.
- `NO_PROXY` cannot create an enforcement bypass; direct connections remain WFP-blocked.
- Existing host proxy variables are removed unless product policy explicitly composes them.
- Proxy credentials, if later introduced, are not placed in command arguments or logs.

### N-06: Network bypass test suite

**Depends on:** N-03A, N-04, N-05

**Deliverables:** Automated BaseContainer-only adversarial network suite with local deterministic test servers and controlled external canaries where approved.

**Acceptance criteria:**

- Allowed HTTP and HTTPS hostnames succeed through the proxy.
- Denied hostname, suffix confusion, redirect to denied host, and forbidden DNS result fail.
- Direct IPv4/IPv6 TCP, raw destination IP, alternate port, private LAN, host loopback other than the proxy, and DNS-to-external-server fail.
- UDP and QUIC fail unless a future policy explicitly supports them.
- A client that deletes proxy environment variables still cannot connect directly.
- A second local process cannot impersonate the approved proxy under the selected identity model.
- The local-process impersonation case runs as the same host user but without
  possession of a generation capability; results are documented as hardening,
  not protection from an already-compromised same-user host process.
- Every accepted test run proves effective tier is `base-container`.
- Tests cover port/protocol mismatch, requested operation requiring unavailable
  inspection, stale policy generation, stale launch generation, and same-user
  attempts to reuse the listener.

### N-06A: Indirect and brokered egress test suite

**Depends on:** D-09, S-12, N-04, N-06

**Deliverables:** Adversarial tests for host services, IPC endpoints, kernel
redirectors, and local developer tools that could perform network activity on
behalf of the workload under a host identity.

**Acceptance criteria:**

- Tests cover BITS, WinINet/URL and COM brokers, SMB/WebDAV redirectors, WMI,
  scheduled tasks, browser automation, package services, authentication agents,
  and discovered Docker/WSL/SSH or developer-service endpoints where present.
- Each attempted deputy action has a positive-control fixture and trustworthy
  denial attribution; absence of a service is not accepted as enforcement.
- No accessible host deputy can reach an address, protocol, filesystem source,
  or credential outside the effective plan. Any necessary deputy receives a
  dedicated modeled contract and generation-bound authorization.
- G4 treats a brokered-host connection as a direct-egress bypass even when the
  socket is owned by an unsandboxed host process.

### N-07: Network operational hardening

**Depends on:** N-06

**Deliverables:** Rate limits, health checks, crash recovery, stale-filter detection, diagnostics, and upgrade behavior.

**Acceptance criteria:**

- Repeated runs leave no stale filters/listeners according to supported diagnostics.
- Host sleep/resume and network-interface changes do not broaden egress.
- Policy reload cannot affect an existing run unless explicitly designed and audited.
- A 24-hour stress run shows bounded handles, sockets, memory, and audit storage.

### N-08: Manual ceiling-bounded network proposals

**Depends on:** F-05A, F-06, F-07, B-04, N-01, N-02, N-03,
N-04, N-06

**Deliverables:** A host-side, network-only proposal and review workflow for
denied requests. No proposal directly modifies policy or invokes PSEC learning
mode.

**Acceptance criteria:**

- A proposal is created only when destination, port, protocol, policy revision,
  and launch generation have trustworthy provenance. Unattributed WFP denials
  remain findings rather than proposals.
- Proposals exclude queries, headers, payloads, command-line secrets, and
  credentials; they are bounded, deduplicated, and expire.
- Approval requires a review token covering proposal hash, the fully composed
  candidate plan/hash that would result, machine ceiling, capability snapshot,
  source revisions, and observed launch generation. Consumption atomically
  recomputes containment; any change invalidates the review.
- Approval creates a revisioned user-layer authorization within the machine
  ceiling and applies to a future launch only in v1.
- The UI offers deny, approve once for a future launch, approve with expiry, and
  explicit persistent promotion. There is no automatic approval.
- `approve once` is single-use and race-safe: exactly one matching future launch
  generation may consume it, and failed or concurrent consumption cannot widen
  another launch.
- `explain` shows proposal provenance, containment result, approval identity,
  expiry, credential implications, and resulting effective-policy revision.

### N-08A: Trusted approval channel and storage

**Depends on:** N-08, B-08, F-05A, C-11

**Deliverables:** Host-side approval command/UI, protected revisioned storage,
authenticated approver identity, revocation, and anti-spoofing behavior.

**Acceptance criteria:**

- Approval prompts never share a terminal region or input channel with
  untrusted workload output. OSC/ANSI output cannot forge product diagnostics or
  approval state.
- Approver user/session identity, proposal hash, resulting plan, expiry, and
  storage revision are authenticated and audited.
- Storage uses protected ACLs, atomic publication, rollback detection, explicit
  revocation, and crash-safe single-use consumption.
- Noninteractive sessions fail with a review-required result; they never infer
  consent from stdin, project files, environment variables, or agent output.

### N-09: Effective network-policy revisions

**Depends on:** F-06, F-07, N-07, N-08, N-08A

**Deliverables:** Immutable network-only policy generations bound to launch
generations, plus a design for later hot reload without enabling it in v1.

**Acceptance criteria:**

- Startup activates one complete validated network snapshot.
- Partial, invalid, unsupported, or inconclusive candidates fail closed and do
  not replace active state.
- Connections carry their policy generation; stale state cannot authorize a
  later launch. CB-06 composes this with credential and broker revisions.
- V1 policy changes affect future launches only. Any later hot-reload proposal
  must define connection revocation and atomic proxy/broker activation first.

### CB-D01: Discover supported provider clients and host credential storage

**Depends on:** C-10, D-06, N-03

**Deliverables:** Evidence for at least one Node-based agent and one additional
target client covering base-URL replacement, credential-header shape, streaming,
model selection, retries, compression, proxy behavior, Windows Credential
Manager/DPAPI behavior, and one-listener proxy/gateway dispatch.

**Acceptance criteria:**

- Clients complete a credential-free flow against a local fake provider through
  a configured base URL without hidden direct connections.
- BaseContainer cannot enumerate or resolve the selected host credential store.
- Same-user and sandbox attempts to obtain broker process handles, DPAPI blobs,
  Credential Manager entries, SSPI credentials, certificate private keys, Web
  Account Manager tokens, or secret-bearing dumps have explicit outcomes.
- Any uncertainty in proxy peer identity, PSEC/WFP routing, secret storage, or
  client behavior blocks dependent tickets.

### CB-01: Define credential and provider-route contracts

**Depends on:** CB-D01, N-01, F-06, F-07

**Deliverables:** Versioned schema for host credential metadata and trusted
provider routes fixing upstream HTTPS origin, allowed methods/paths/operations,
model constraints, authentication transform, expiry, and trust-layer ownership.

**Acceptance criteria:**

- Project requests cannot create or widen routes, credential issuers, operations,
  or model scope.
- Unknown transforms, wildcard origins, URL credentials, fragments, plain HTTP
  upstreams, and unsafe path forms are rejected.
- Credential authority is a subset of ordinary network policy.
- Initial transforms are limited to bearer authorization and explicitly named
  provider headers; query, cookie, arbitrary body, and arbitrary rewriting are
  unsupported.
- Each route defines method/operation/model/account scope plus request, token,
  concurrency, rate, and cost budgets. Possession of a placeholder authorizes
  use within that bounded route; it is not treated as proof of benign intent.

### CB-02: Implement Windows host secret storage

**Depends on:** CB-D01, CB-01

**Deliverables:** An ADR-selected Windows Credential Manager or current-user
DPAPI store supporting set, rotate, revoke, expiry, resolution, and metadata-only
listing.

**Acceptance criteria:**

- No plaintext secret appears in metadata, argv, environment, profile, compiled
  plan, diagnostics, crash text, or audit output.
- Storage updates are atomic; revoked and expired values cannot resolve.
- Product APIs never enumerate or import unrelated ambient host credentials.
- The BaseContainer workload cannot access the store through filesystem,
  registry, credential, or broker APIs.
- Store ACLs and broker process DACLs are part of the security boundary.
  Machine-wide DPAPI is rejected unless separately approved; secret-bearing
  processes cannot create ambient WER/local dumps or be opened for debug,
  VM-read/write, duplicate-handle, or thread-creation access by the workload.
- Plaintext lifetime is minimized and buffers are cleared on success,
  cancellation, parse failure, upstream failure, rotation, and teardown.

### CB-03: Issue generation-scoped opaque placeholders

**Depends on:** CB-01, CB-02, S-05, B-04

**Deliverables:** Random per-launch placeholder capabilities and an in-memory,
constant-time resolver bound to route, credential identity, permitted operation,
policy generation, launch generation, and expiry.

**Acceptance criteria:**

- Real secret bytes never enter the workload environment; only the exact client
  variables required by a trusted recipe receive placeholders.
- Placeholders are unique across runs and broker restarts. Cross-run, wrong-route,
  wrong-operation, expired, revoked, and stale-generation use fails closed.
- Placeholders are never accepted in URLs or query parameters and are redacted
  like secrets even though they are not upstream credentials.
- Descendant copying and same-generation replay remain possible authority uses
  and are constrained by CB-01 budgets; cross-generation or broader-route use
  remains impossible.

### CB-04: Implement purpose-built local provider gateway

**Depends on:** CB-03, N-03A

**Deliverables:** Reserved origin-form routes on the approved proxy listener,
fixed-origin upstream HTTPS, bounded request parsing, selected provider adapter,
credential injection, cancellation, and streaming response support.

**Acceptance criteria:**

- Caller cannot override upstream scheme, host, port, authorization header,
  credential header, route configuration, or forwarding headers.
- Wrong method/path/operation/model, malformed bounded input, redirects, and TLS
  certificate/hostname failures are rejected before credentialed forwarding.
- The fake HTTPS upstream receives the real credential while the workload sees
  only its placeholder.
- Generic HTTPS `CONNECT` remains opaque and never resolves placeholders.

### CB-05: Implement rotation, revocation, and broker lifecycle

**Depends on:** CB-02, CB-03, CB-04

**Deliverables:** Explicit rotation/revocation commands, atomic credential
revision publication, pre-upstream-write recheck, broker health, and teardown.

**Acceptance criteria:**

- Rotation changes the next eligible request atomically; revocation prevents
  every request not already sent upstream.
- Endpoint, operation, model, or credential-identity changes issue new
  placeholders and revoke old scope.
- Broker restart invalidates all run placeholders. Broker death never enables
  direct egress or stale-secret fallback.
- Concurrent requests cannot mix route metadata and credential values from
  different revisions.

### CB-06: Integrate broker with PSEC/WFP and agent recipes

**Depends on:** N-04, N-05, N-09, CB-04, CB-05

**Deliverables:** Provider base-URL and placeholder environment generation,
single-listener dispatch, startup ordering, generation binding, and selected
agent recipe integration.

**Acceptance criteria:**

- Proxy, route, broker, credential revision, and WFP policy are ready before the
  workload can run.
- Each control registers typed evidence with the B-04 common attestation barrier;
  integration tests prove removal of any evidence kind prevents resume.
- Network policy, provider route, credential revision, proxy, and broker are
  activated as one generation-bound snapshot; partial activation fails closed.
- Direct provider IPv4/IPv6, raw IP, alternate DNS, QUIC, deleted proxy variables,
  and ordinary `CONNECT` with a placeholder cannot bypass the broker.
- An unrelated same-user process without the generation-bound proxy/broker
  capability cannot use the listener. Theft from an already-compromised
  unsandboxed same-user process remains outside the isolation guarantee and is
  documented as residual risk.
- Unsupported clients receive a stable compatibility error and no credential or
  network fallback.

### CB-07: Credential-broker adversarial and compatibility suite

**Depends on:** CB-05, CB-06, N-06

**Deliverables:** Fake HTTPS providers, representative agent E2E tests, and
regressions for replay, route/model confusion, duplicate headers, path
normalization, oversized input, redirects, cancellation, and log injection.

**Acceptance criteria:**

- Selected agents complete one bounded streaming inference flow without real
  credential material entering the sandbox.
- Secrets, placeholders, headers, queries, and bodies are absent from default
  logs and support bundles.
- Every accepted run proves `base-container`, exact WFP proxy routing, matching
  policy/launch generation, and a clean semantic report.

## 13. Phase 6: arbitrary console-program readiness

### A-01: Compatibility taxonomy and test corpus

**Depends on:** N-06, N-06A, N-07, N-09, CB-07, Q-05A, and the
completed detached Q-07 promotion evidence for R3 (`Q-07[R3]`), not the R4
Q-07 instance

**Deliverables:** Program taxonomy covering native Win32, .NET, Node, Python, Java, Git, package clients, compilers, and programs that spawn trees or use named IPC.

**Acceptance criteria:**

- Each workload declares required grants, environment, UI, IPC, and network behavior.
- Incompatibility is categorized as missing grant, unsupported Windows/PSEC feature, proxy limitation, or product defect.
- No workload is made to pass by weakening global defaults.

### A-02: Additional CPU and arbitrary-program resource controls

**Depends on:** A-01, S-07

**Deliverables:** Additional controls required by arbitrary console programs,
including CPU-rate policy and controls not required or proven for R1/R2.

**Acceptance criteria:**

- Limits are advertised only when kernel/backend enforcement is demonstrated
  and compatible with the generation-bound controls established by S-07.
- Unsupported controls are omitted or clearly marked, never simulated as
  security boundaries.
- Limit breaches terminate the complete process tree and produce stable outcomes.

### A-03: Expanded IPC and named-object compatibility

**Depends on:** A-01, D-09, S-12

**Deliverables:** Expansion of the R1 security baseline for additional arbitrary-
program IPC and named-object compatibility without adding unexplained host
authority.

**Acceptance criteria:**

- The D-09/S-12 host attack-surface baseline remains mandatory and is rerun;
  this ticket covers only additional program classes and narrowly approved IPC.
- New access is modeled, least-authority, generation-bound, and regression-tested.
  High-risk unexpected access blocks R4 or receives an explicit mitigation ticket.
- The product does not claim arbitrary-program safety beyond tested controls.

### A-04: Organizational profile distribution and signing

**Depends on:** F-06, A-01

**Deliverables:** Optional organization-managed profile distribution, signing,
versioning, and revocation design if enterprise deployment requires it.

**Acceptance criteria:**

- Trust anchors and update authority reside outside project-writable locations.
- A modified, expired, revoked, or incorrectly scoped profile is rejected.
- Organization profiles remain bounded by engine invariants and produce the
  same inspectable, hashable effective plan as local profiles.
- If managed distribution is unnecessary, close the ticket with that decision
  rather than adding signing infrastructure.

## 14. Phase 7: CI, packaging, and assurance

### Q-01: Layered Windows test pipeline

**Depends on:** F-01, B-06

**Deliverables:** CI tiers for unit/contract tests, ordinary Windows integration tests, and dedicated build-29671.1000 BaseContainer E2E tests.

**Acceptance criteria:**

- Pull requests run non-host-specific tests without special OS assumptions.
- Host-specific jobs fail, not skip, when assigned a BaseContainer-capable runner.
- E2E results record OS build, MXC version/hash, effective tier, and test artifact hashes.
- Network tests run in isolated infrastructure with controlled destinations.
- R1/R2 qualification runs on Windows Enterprise x64. ARM64 and other editions
  may compile in ordinary CI but cannot appear in a supported release manifest
  until they have equivalent dedicated runtime and package lanes.
- CI is delivered as subtickets: build/unit after F-01, mock-backend integration
  after B-06, dedicated MXC runner provisioning after D-02, and release/soak
  lanes after the applicable controls exist.

### Q-02: BaseContainer release gate suite

**Depends on:** Q-03, F-06, F-07, F-05A, B-05, B-07, B-08, S-04,
S-05, S-06, S-07, S-08, S-09, S-10, S-11, S-12, S-13, S-14, C-11A

**Deliverables:** One release command that executes probes, semantic mapping,
typed lifecycle, offline execution, filesystem, resource, provenance/loader, UI,
teardown, and stress tests with `base-container` required.

**Acceptance criteria:**

- Any test resolving to AppContainer is a hard failure.
- No security test is silently skipped for missing prerequisites.
- Results are machine-readable and signed or integrity-protected in release CI.
- Any unsupported or approximated security requirement, unattested delegation,
  invalid generation transition, resource-control failure, or executable/loader
  provenance mismatch is a hard failure.
- The suite installs and tests the exact immutable candidate package and records
  package, required-controls manifest, executable, MXC, and configuration hashes.
- Crash injection, inherited-handle, token/namespace, IPC/registry/device,
  runtime-TOCTOU, hard-quota, and audit-durability suites are mandatory.

**MXC baseline to incorporate where applicable:**

```powershell
pwsh "$MxcRoot\tests\scripts\run_processcontainer_all_tests.ps1" `
  -SkipBuild -RequireTier base-container
```

### Q-03: Build immutable signed candidate packages

**Depends on:** F-01, B-04, B-08, S-08, and every implementation ticket in
the target release's section 16 row except Q-01 through Q-07. The build system
materializes this as a checked input list.

**Deliverables:** Immutable signed candidate installer/package, SBOM, dependency
notices, file manifest, required-controls manifest, upgrade/uninstall behavior,
and verification documentation. The candidate is complete before Q-02/Q-04 and
is never modified during promotion.

**Acceptance criteria:**

- Product and bundled MXC/proxy artifacts are signed and hash-verified before use.
- Installation paths are administrator-protected where trust depends on binary integrity.
- User-writable adjacent DLL/executable substitution tests fail.
- Upgrade is atomic or fails without leaving an executable mixed-version set.
- Uninstall removes product-owned state without deleting user workspaces.
- The required-controls manifest states enabled features and mandatory evidence
  kinds but does not claim that qualification has passed. It is signed or
  catalog-bound without embedding a circular hash of its containing artifact.
- Candidate bits include the same feature paths used during qualification; test
  flags or post-test binary replacement cannot activate a different path.
- Signer identity, timestamp, certificate expiry/revocation, release channel,
  update metadata, schema migration, downgrade prevention, interrupted-update
  recovery, and emergency revocation have explicit tests.

### Q-04: Clean-machine and least-privilege validation

**Depends on:** Q-02, Q-03

**Deliverables:** Automated install/run/uninstall tests on clean Windows
Enterprise x64 VMs for standard-user and administrator contexts.

**Acceptance criteria:**

- Normal sandbox runs follow the privilege/elevation architecture fixed by
  D-11. Q-04 cannot introduce a new elevation exception.
- Installation documents all privileged changes.
- Missing prerequisites cause actionable fail-closed errors.
- No global firewall, DACL, registry, or optional-feature mutation remains after uninstall except explicitly documented OS-owned state.

### Q-05: Core fuzzing and parser hardening

**Depends on:** F-03, F-04, F-07, S-01

**Deliverables:** Fuzz targets for profile parsing, path normalization,
containment/delta analysis, command/argument transport, and semantic-report
parsing.

**Acceptance criteria:**

- Seed corpus includes all regression cases.
- CI runs bounded fuzz smoke tests; scheduled jobs run longer campaigns.
- Crashes, hangs, excessive allocation, and acceptance of invalid security fields are failures.

### Q-05A: Network, proposal, and credential fuzzing

**Depends on:** N-02, N-03, N-08, CB-04

**Deliverables:** Fuzz targets for hostname/address policy, proposal/review
tokens, proxy requests, provider routes, operation/model parsing, and credential
placeholders.

**Acceptance criteria:**

- Seed corpora include every network and broker regression case.
- Parsers enforce documented size/depth/cardinality budgets and never emit
  secret-bearing diagnostics.
- Crashes, hangs, excessive allocation, ambiguous normalization, and fail-open
  parser outcomes are release failures.

### Q-06: Security review and release evidence

**Depends on:** D-07, Q-02, Q-04, and every target-release ticket listed in
section 16 except Q-06 and Q-07. Each release instantiates this dependency as a
checked machine-readable evidence list rather than the literal prose.

**Deliverables:** Review checklist, threat-model delta, test evidence, known limitations, and release sign-off.

**Acceptance criteria:**

- Reviewer can trace every profile permission to emitted MXC policy and runtime evidence.
- Negative tests demonstrate absence of fallback and direct network bypass.
- Experimental-build and MXC-preview limitations are prominent.
- Claims are limited to the exact signed product/MXC versions and tested Windows builds.

### Q-07: Release capability activation gates

**Depends on:** Q-06; for R3 also N-06, N-06A, N-07, N-08, N-08A,
N-09, CB-07, Q-05A

**Deliverables:** Verification of the candidate's signed required-controls
manifest, plus detached signed promotion evidence over immutable package and
test-evidence hashes. Promotion does not modify candidate bits.

**Acceptance criteria:**

- R1/R2 artifacts cannot enable proxy networking, network approvals, provider
  routes, or credential commands through hidden flags, profiles, environment
  variables, downgrade, or direct library calls.
- R3 candidate bits expose network mode only when their required-controls
  manifest enables it and requires WFP bypass, indirect-egress, proxy identity,
  policy revision, proposal, broker, fuzz, cleanup, and exact-tier evidence.
- Runtime verifies the signed required-controls manifest, product/MXC hashes,
  schema versions, and capability requirements before accepting an enabled
  feature. Distribution systems verify detached promotion evidence before
  publishing the unchanged candidate.
- Missing, invalid, stale, or mixed-version evidence disables the feature and
  fails closed; it never selects a compatibility path.
- G0S status is recorded separately from technical qualification. Promotion may
  label an artifact only as research/security preview while G0S is unsatisfied.

## 15. Parallelization map

After G0, independent agents can work in these lanes:

| Lane | Tickets | Merge coordination |
|---|---|---|
| Contracts | F-02, F-03, F-05 | Freeze error/profile version before backend golden tests |
| Backend | B-01 through B-06 | Own the MXC adapter boundary |
| Lifecycle/privilege | B-07, B-08 | Own crash recovery and privileged IPC selected by D-11 |
| Filesystem | S-01 through S-04 | Consume profile and plan contracts; do not edit backend selection |
| Windows boundary | S-10 through S-14 | Own token, handles, IPC/registry/device, quota, and mitigations |
| Runtime UX | C-01 through C-03 | Consume backend stream interface |
| Profile trust | F-06 | Own layer composition and `explain`; coordinate all schema changes |
| Policy analysis | F-07 and B-02 report contract | Own modeled domains, loss dispositions, and delta results |
| Resource controls | D-08, D-12, S-07, S-13 | Coordinate process/memory/handle controls and mandatory hard storage quota |
| Provenance | S-08 | Coordinate product signing, toolchain recipes, and loader tests |
| Toolchains | C-06 through C-09 | Split by recipe after the recipe contract is frozen |
| Agent compatibility | C-10 | Starts after required recipes and terminal mode are stable |
| Assurance | Q-01, Q-05 | Build test infrastructure early |
| Network policy | N-01, N-02, N-08, N-09 | Proposals depend on trust composition and modeled containment |
| Proxy | N-03 through N-07, N-03A, N-06A | Starts after N-02; includes host-process hardening and indirect egress |
| Credential broker | CB-D01, CB-01 through CB-07 | Split storage, contracts, gateway, and integration after discovery |
| Packaging | Q-03 design | Final integration waits for stable artifact layout |

Files or modules defining the profile schema, execution plan, backend interface, and audit schema should have explicit code ownership. Changes to those boundaries require coordination because most lanes depend on them.

## 16. Definition of done by release

The required ticket sets are normative; prose in a release definition cannot
silently add or waive a ticket. A change updates this table and the dependency
graph in the same review. Letter ranges include every numbered ticket and
explicitly named suffixed ticket in the range.
Q-02, Q-03, Q-04, Q-06, and Q-07 are instantiated per target release (for
example, `Q-07[R3]`). A later release may depend on detached promotion evidence
from an earlier instance without depending on its own not-yet-built candidate.

| Release | Required ticket evidence |
|---|---|
| R0 | D-01 through D-13 |
| R1 | R0; F-01 through F-07 including F-05A; B-01 through B-08; S-01 through S-14; C-01 and C-11A; Q-01, Q-02, Q-03, Q-04, Q-05, Q-06, Q-07 |
| R2 | R1; C-02 through C-11 including C-11A |
| R3 | R2; N-01 through N-09 including N-03A, N-06A, and N-08A; CB-D01 and CB-01 through CB-07; Q-05A |
| R4 | R3; A-01 through A-04 |

R0-R4 remain research/security-preview artifacts while G0S is unsatisfied. The
first eligible supported product is R2 on Windows Enterprise x64 after G0S and
all applicable gates pass. R1 intentionally remains a minimal preview even if
G0S later passes.

### R1 offline security preview

- G0, G1, G2, G3, and G5 pass for the R1 artifact.
- `run`, `validate`, `doctor`, and `version` support bounded redirected,
  noninteractive execution. `compile`, `explain`, interactive terminal mode,
  and R2 streaming features fail with stable unavailable errors.
- Exact-request probe and effective-tier evidence require BaseContainer.
- Semantic report contains no unsupported or approximated security requirement.
- Typed launch state and generation tests prove no workload runs before
  attestation and no stale resource can attach to another generation.
- Workspace RW, toolchain RO, ungranted deny, secure environment, UI baseline,
  process-count and memory limits, timeout, cancellation, and process-tree
  cleanup pass.
- Token/privilege, namespace, inherited-handle, IPC, registry, service, device,
  process-mitigation, crash-recovery, and hard storage-quota evidence pass.
- Networking is deny-all and direct plus host-deputy/indirect negative tests pass.
- The exact immutable signed candidate passes clean-machine package tests.
- Artifact labeling prominently states security preview and the current G0S
  status; it makes no production isolation claim while G0S is unsatisfied.

### R2 agent-ready CLI

- R1 remains green and G5 passes for the R2 delta.
- G0S passes before R2 is described or distributed as a supported production
  sandbox. Without G0S, an otherwise-qualified R2 remains a security preview.
- Supported scope is Windows Enterprise x64 only. Other architectures and
  editions are rejected by the support manifest even if capability probes pass.
- Argument, streaming, backpressure, terminal decision, support bundle, and representative agent tests pass.
- `run`, `validate`, `compile`, `explain`, `doctor`, and `version` are complete
  and stable under the versioned CLI/result contract.
- Offline use does not require an external service.
- Documentation gives minimal profiles for each supported toolchain.
- Python/pip and Java/Gradle/Maven recipes pass their offline E2E suites.
- Node/npm passes for the selected initial Node-based agent.
- Profile layering proves that workspace configuration cannot widen authority.
- Trusted toolchain, executable, DLL/plugin search-path, and native-module
  provenance tests pass.
- Any advertised handle limit passes its enforcement and breach tests;
  unsupported handle limits remain explicitly unclaimed. The R1 hard session-
  storage quota remains mandatory and green.

### R3 governed networking and provider access

- R2 remains green; G4 and G5 pass for the signed R3 artifact.
- Network policy, proposal, proxy, provider-route, and credential-broker parsers
  pass fuzzing and adversarial tests.
- WFP restricts sandbox egress to the exact proxy endpoint.
- Deleting proxy settings, using raw sockets, alternate DNS, IP literals, QUIC,
  redirects, local proxy impersonation, or an accessible host deputy does not
  bypass policy.
- Proxy and WFP lifecycle cleanup passes crash and stress tests.
- Manual approvals are machine-ceiling-bounded, revisioned, review-token-bound,
  and apply only to future launches in v1.
- Supported credentialed agents receive only generation-scoped placeholders;
  endpoint and operation checks occur before host credentials are used.
- Unsupported clients receive no credential fallback. Generic TLS interception
  and product CA installation remain absent.
- OCSF-aligned process, configuration, network, credential, lifecycle, and
  detection events validate against the pinned schema and contain no secrets.

### R4 arbitrary console programs

- R3 remains green and G5 passes for the R4 delta.
- Compatibility taxonomy and expanded IPC compatibility review are complete;
  the D-09/S-12 R1 boundary remains mandatory.
- Resource claims are backed by enforceable tests.
- Known unsupported program classes are documented without fallback.
- Security review approves the broader claim.

## 17. Open discovery questions

These are intentionally unanswered until the discovery tickets produce evidence:

- Which pinned MXC release first removes the applicable warning that profiles
  must not be treated as security boundaries, and what publisher support terms
  make G0S objectively pass?
- Which MXC integration surface is supported for redistribution and gives the required streaming and cancellation semantics?
- Does the selected MXC revision expose an atomic require-BaseContainer operation, or only request-scoped probe plus launch?
- Can effective tier be attested before the workload is resumed?
- Which PSEC contract version and support bits are active on build 29671.1000 for filesystem grants, UI controls, deny-all networking, WFP egress, ingress/loopback, and proxy configuration?
- What proxy peer identity forms are accepted and sufficiently strong on that build?
- Who owns WFP filter lifetime when the CLI or proxy crashes, and what supported diagnostics prove cleanup?
- Can all required filesystem roots be enforced without unresolved reparse-point or path-alias escapes?
- Which console/ConPTY behavior is supported through the selected MXC surface?
- Can MXC's Job Object ownership coexist with pre-resume process-count and
  memory controls, and which effective limits can be queried back?
- What exact token, restricted SID/capability, integrity, namespace, desktop,
  process-DACL, inherited-handle, and mitigation properties does BaseContainer
  produce for root and descendant processes?
- Which Object Manager, ALPC/RPC/COM, named-pipe, registry, SCM, scheduled-task,
  WMI, BITS, authentication-agent, and device endpoints remain reachable, and
  can any act as a filesystem, credential, process, service, or network deputy?
- Which component owns privileged setup and durable lifecycle state, and what
  supported authenticated IPC and crash-recovery mechanism enforces that
  ownership for standard-user launches?
- Which supported kernel-enforced storage mechanism can hard-limit every R1
  writable session/cache root, including metadata and crash recovery?
- Which handle and optional storage-accounting controls beyond the mandatory
  D-12/S-13 hard quota are genuinely enforceable rather than measured or
  advisory?
- Can every required executable and native loader dependency be identified and
  revalidated without unsafe pathname-only trust?
- Can the proxy peer be bound strongly enough that an unrelated same-user host
  process cannot use the approved listener or a captured placeholder?
- Can brokered traffic through accessible host services be attributed and
  blocked, including kernel redirectors and sockets created under a host process
  identity?
- Which target agents support a replaceable local provider base URL, bounded
  request parsing, streaming, and placeholder-style credentials on Windows?
- Is Windows Credential Manager or a current-user DPAPI store the narrower
  supported secret-storage boundary for the selected deployment model?
- Which network operations are observable without TLS interception, and which
  provider-specific adapters are required before claiming method/model scope?
- What denial evidence is sufficiently attributable to generate a manual
  proposal rather than only an audit finding?
- What are the MXC licensing, servicing, signing, and version-skew constraints for bundling versus external installation?
- What cumulative-update range, rollback policy, qualification cadence, and
  end-of-support rule applies to the first Windows Enterprise x64 supported
  baseline after G0S?

No implementation ticket may fill these gaps by calling guessed exports, constructing guessed PSEC FlatBuffers, or depending on an undocumented build number check.
