# ADR 0001: Windows Key Agent Service Boundary

## Status

Accepted on 2026-08-25.

This ADR selects an architecture; it does not claim that the selected Windows
composition has been implemented or proven. Release status remains `STOP-SHIP`.
The accepted Design Brief is
[`docs/designs/windows-key-agent-service.md`](../designs/windows-key-agent-service.md).

## Context

The current Key Agent prototype runs as a zero-capability LPAC under the same
Windows user as the Broker and other untrusted desktop processes. Repository
kernel evidence shows that this principal cannot receive a loader-compatible
process/thread policy that denies `WRITE_DAC` from birth. The later authenticated
R10 gate can harden a token default DACL, but it cannot retroactively protect
objects or high-authority handles created before that gate.

The current LPAC launch, Job, token, storage, and Approval exchange code remains
useful evidence and implementation material, but it is not production-reachable:
`COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` are `None`, the sealed
Approval terminal has no signing conversion, and the Key Agent has no runtime
signing protocol.

The required threat boundary includes same-user non-elevated malware and a
compromised Browser, Native Host, or Broker. Local Administrator, kernel,
hypervisor, firmware, and compromised Windows TCB remain out of scope.

## Decision

### Distinct restricted service principal

The Key Agent signing authority MUST move to an own-process Windows service with
the fixed service name `YourWalletKeyAgent`, the virtual account
`NT SERVICE\YourWalletKeyAgent`, and `SERVICE_SID_TYPE_RESTRICTED`.

The service MUST be headless in Session 0 and MUST NOT use
`SERVICE_INTERACTIVE_PROCESS`. LocalSystem, NetworkService, shared LocalService,
and a password-managed account are not accepted final identities. The final
service token MUST contain only privileges demonstrated necessary by Phase 1
kernel evidence. `SeTcbPrivilege`, `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`,
and `SeRestorePrivilege` are forbidden in the final policy.

The service alone MUST own decrypted key material, PCP/TPM private-key handles,
protected settings authority, durable nonce/signing/broadcast state, helper
creation, Approval authorization, and the private signing transition. Broker
data is untrusted input and cannot itself authorize signing.

### Service-owned user-session LPAC helpers

Approval and Secret Input MUST remain distinct, fixed, zero-capability LPAC
frontends in the enrolled user's interactive session. The service MUST derive an
exact primary user token from an already authenticated local client context,
verify its user/logon/session/elevation state, and create each helper directly
with `CreateProcessAsUserW` and `STARTUPINFOEXW`.

The service MUST retain the returned process/thread handles and the helper Job.
The Broker MUST NOT create, resume, debug, inject, or retain any process, thread,
token, Job, endpoint, or channel handle for a trusted helper. Broker-owned helper
creation followed by handle transfer is a forbidden downgrade.

### ncalrpc-first authenticated control plane

The first IPC design to prove MUST be authenticated local RPC over `ncalrpc`.
The service endpoint MUST be local-only, use an explicit security descriptor and
security callback, pin its final Windows authentication policy, and derive the
caller's token user, AppContainer state, session/logon identity, local PID, live
process object, image role, and one-shot epoch rather than trusting wire fields.

The service MUST bind Broker and helper calls to distinct roles. Secret Input or
Approval results MUST be accepted only from an exact helper process created and
still retained by the service. Endpoint-name secrecy, a current-user DACL, or a
numeric PID alone is not authentication.

Zero-capability LPAC-to-Session-0 `ncalrpc` behavior and exact mutual identity are
unverified until Phase 1. If this proof fails, implementation MUST stop for a new
ADR. It MUST NOT silently fall back to the current session-scoped
`\\.\pipe\LOCAL\...` primitive, a Broker-mediated secret channel, or an
unauthenticated named endpoint.

### No inherited helper handles

Every service-created helper MUST use `bInheritHandles = FALSE` and MUST NOT
receive `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, inherited stdio, inherited sockets,
or any other ambient handle capability.

After the exact child has been created suspended and authenticated, the service
MUST use its retained process handle to `DuplicateHandle` exactly the minimum
one-shot request and response handles into the child. Duplication MUST use
explicit minimum access, `bInheritHandle = FALSE`, and zero duplication options.
The Broker MUST never observe either endpoint or the returned child-table handle
values.

The child MUST verify that the candidates are distinct, non-pseudo,
non-inheritable, non-stdio, exact-type, exact-direction, and exact-access handles.
It MUST immediately replace them with fresh child-local least-authority
duplicates, close the launcher-known candidates, and bind the resulting channel
to the authenticated service epoch, child process identity, nonce, role, and
deadline before parsing a request.

### Exact R10/R11 child-owned bootstrap gate

The selected bootstrap is an x64 child-owned exact R10/R11 breakpoint gate. The
signed helper MUST contain one unique preflighted executable sequence that loads
independent fixed public markers into R10 and R11, executes `INT3`, and captures
the post-continue values into child-owned state before any call, allocation, TLS,
stdio, UI, or protocol operation.

The service MUST authenticate the exact mapped image, PID, primary TID,
first-chance exception, gate RVA and bytes, executable image page, allocation
base, RIP, both marker registers, token/session, creation security, Job, and
admitted debug-event history before duplicating either handle. It then MAY place
the two returned child-table values in R10 and R11 with `SetThreadContext` only
while the authenticated event stops the exact primary thread. Complete context
readback MUST show no unintended mutation. The child MUST capture and clear both
registers immediately.

The debug relationship MUST remain on one dedicated service OS thread. Detach,
creator-handle attenuation, UI resume, and channel use occur only after exact
handle adoption while an independent suspend count still holds the child.
Partial duplication, wrong context, an unexpected event/thread, failed
readback, timeout, or child rejection MUST terminate and reap the exact child and
close its Job.

A remote-memory bootstrap is not an automatic fallback under this ADR. It would
add VM authority and compiler/linker placement risks and therefore requires a
separate ADR and security review.

### No service network authority

The service MUST contain no DNS, chain RPC, HTTP, WebSocket, update, telemetry,
or broadcast adapter. Installation MUST apply and read back an outbound block
for the exact service identity/image. Release evidence MUST prove denial of TCP,
UDP, DNS, loopback, private addresses, remote named pipes, inherited sockets,
and machine-credential outbound access. UI helpers retain their independent
zero-network requirement. Broker remains the only networking process.

### Fail-closed lifecycle and release policy

Service start MUST verify the service token, restricted SID state, privilege
set, installed image/configuration, storage/PCP/anchor bindings, network block,
single-instance state, enrolled user state, and durable recovery state before
listening.

Lock, logoff, user switch, cancellation, deadline expiry, Broker/helper exit,
RPC disconnect, Job violation, SCM stop, service crash, and failed revalidation
MUST invalidate non-durable authority and terminate/reap every live helper. A
restart MUST enter recovery and MUST NOT continue or automatically re-sign an
unfinished request. Ambiguous durable results remain quarantined until an
authenticated recovery transition resolves them.

`COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` MUST remain `None` through
feasibility and integration. They may change only through the reviewed,
reproducible release-generation path after the complete signed-artifact,
installer, kernel, IPC, lifecycle, key-custody, network, and independent-review
evidence set passes.

## Consequences

- The wallet becomes an administrator-installed Windows application rather than
  a portable same-user process bundle.
- The service principal supplies the ownership separation that the current
  same-user LPAC cannot supply; Approval and Secret Input retain LPAC isolation
  for their narrow interactive roles.
- SCM configuration, service privileges, session-token derivation, service-only
  storage, firewall policy, session notifications, crash recovery, and hardware
  key custody enter the security TCB and release evidence.
- The current Key Agent process shell, inherited startup channel, and
  AppContainer persistent-storage authority are replaced. Existing domain,
  authorization, journal, vault, and signing types may be reused only where
  their invariants remain valid under service ownership.
- Service creation of a user-session LPAC, ncalrpc identity, post-create handle
  injection, and the R10/R11 gate are all conditional on Phase 1 kernel proof.
  Acceptance of this ADR is not evidence that Windows supports the combination.
- A Phase 1 failure keeps release disabled and requires an explicit design
  decision; it does not authorize a weaker implementation.

## Rejected alternatives

- **Continue hardening the same-user LPAC Key Agent:** rejected because a later
  gate cannot close the measured from-birth `WRITE_DAC` gap.
- **Broker-owned helper creation:** rejected because the attacker begins with
  creator-strength process/thread authority and transferable handles.
- **LocalSystem plus `WTSQueryUserToken`:** rejected as unnecessarily powerful
  and dependent on `SeTcbPrivilege`.
- **Interactive Session 0 service:** rejected; trusted UI belongs in a
  service-created interactive-session LPAC.
- **Inherited handles across Session 0 and the user session:** rejected by the
  cross-session inheritance contract and the `bInheritHandles = FALSE`
  invariant.
- **Current `\\.\pipe\LOCAL\...` as the trust boundary:** rejected because it is
  session-scoped and its current-logon DACL does not exclude same-user malware.
- **Command-line, environment, raw PID, or name-secret bootstrap:** rejected as
  forgeable, observable, transferable, or insufficiently object-bound.
- **Post-creation DACL repair:** rejected as birth security because authority may
  escape before repair.
- **Service networking for convenience:** rejected; all network activity stays
  in Broker.
- **Remote-memory bootstrap without a new ADR:** rejected because it introduces
  additional VM authority not accepted by this decision.

## Release blockers

Implementation status on 2026-08-26: the repository contains only no-secret
Phase 1 feasibility fixtures—an inert SCM host, bounded Status/Unavailable wire,
a checked-in x64 MIDL/SEH boundary, an authenticated local-RPC server, and a
dormant compile-only one-shot helper-creation seam. That
RPC surface exists only in the exact Windows debug build with the explicit
feature; default, production, non-Windows, and release paths remain silent and
fail closed as unavailable. There is no production RPC client and no proof of
an enrolled Broker, Broker role or image, helper role, or service mutual
identity. The admission predicate proves at most a local, medium-integrity,
interactive, non-AppContainer caller. It requires the SDK-defined `CallStatus`
cancellation/disconnection bit field to be zero (active), rejecting values 1,
2, and 3. `TokenHasRestrictions` is observed in the canonical one- or four-byte
form and must remain continuous between the impersonation and primary tokens;
a normal UAC-filtered desktop token is not rejected merely for having been
filtered. The runtime supplies a numeric client PID, not an atomic
origin-process capability; reopening and retaining a process handle does not
upgrade that observation into original-client proof.

The manager path now derives one non-inheritable move-only `TokenPrimary` while
the authenticated desktop caller is impersonated. It requests exactly
`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`, compares the duplicate
to both the effective impersonation identity and the caller process primary
token before revert, and revalidates the retained token and handle flags across
the epoch. The If3 callback independently authenticates but returns only a
data-free success marker, never a token or launch authority. This is a
same-host feasibility result, not enrolled-Broker or helper-launch proof.

A separate explicit debug fixture observes the current service process token
before `SERVICE_RUNNING`. It can enforce the fixed virtual-account user SID,
primary Session-0 restricted-token shape, documented normal-group facts, the
four documented restricted-SID identities, and the exact candidate privilege
presence set. The resulting proof remains typed `Unverified` for restricted-SID
attributes, privilege enablement/necessity, integrity, and SCM configuration;
the installed restricted-service positive probe is intentionally ignored until
an elevated disposable-VM harness exists.

The fixture retains its non-inheritable `TOKEN_QUERY` handle and canonical
baseline. A fresh, exclusive creation-token capability is issued only after a
no-impersonation check, a fresh current-process token open, same-kernel-object
comparison, zero handle-flag readback, and exact identity, token-ID, group,
restricted-SID, privilege, and privilege-catalog continuity. `TokenOwner` must
equal the fixed service SID, and `TokenPrimaryGroup` must occur exactly once in
`TokenGroups`. The capability can derive the paired process/thread creation
descriptors only from that service principal; it compares the copied owner/group
bytes to the sealed baseline and repeats full token revalidation after descriptor
construction. The authenticated desktop primary token is not an accepted owner.
The compile-only launch-attempt state now consumes that authority once and keeps
the paired descriptor owners and service-token proof live through created-object
readback.

The same compile-only feature contains a separate unnamed, non-nested,
one-process Job primitive. Its effective flags must equal
`KILL_ON_JOB_CLOSE | ACTIVE_PROCESS`, its active-process limit must equal one,
its creation attribute is lifetime-bound to the Job owner, and terminal cleanup
is bounded and Job-authoritative. This is not the existing two-process Key Agent
root Job.

The same feature also contains compile-only target-user launch inputs. The
manager-retained desktop token is never exposed as a raw or borrowed handle;
auth instead returns a must-use, same-thread impersonation lease whose explicit
finish and drop fallback each own exact-once revert, clean-thread proof, and
client revalidation. While that lease is held under the existing process-wide
profile mutex, fixed Approval or Secret Input profile creation, SID derivation,
SID equality, folder observation, and filesystem validation are individually
bookended by effective-token checks. `LOCALAPPDATA` is the exact
`GetAppContainerFolderPath` result (`...\Packages\<fixed-profile>\AC`), not its
parent, and the environment otherwise contains only verified `SystemRoot` and
`WINDIR`. Stable LPAC attributes carry the fixed SID, zero capabilities, and
the ALL APPLICATION PACKAGES opt-out.

A separate five-slot startup owner installs, in order, the Job list, the
existing helper mitigation policy, those two LPAC attributes, and the
restricted-child policy. It fixes `winsta0\default`, leaves every standard
handle null, and has no inherited-handle-list slot.

The dormant launch attempt owns the sole `CreateProcessAsUserW` call. It accepts
only the fixed application name, no command line, `bInheritHandles = FALSE`,
the paired non-inheritable service-owned process/thread security attributes,
and exactly `CREATE_SUSPENDED | DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW |
CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT`. Native success is
adopted immediately into move-only owners. Before any child code or debug event
can advance, readback proves the paired object descriptors, exact Job
membership/count, and both retained and freshly opened primary child tokens.
The token proof requires the fixed Approval or Secret Input profile SID, zero
capabilities, exact LPAC/AAP-opt-out membership, target session, and equality to
the authenticated desktop `TokenUser`, exactly one logon SID, and
`AuthenticationId`; no ordinary-AppContainer or unsupported-LPAC fallback is
accepted.

The create transition also consumes a move-only witness minted only on a fresh
debugger OS thread. This slice receives or continues no debug event, releases no
suspend count, performs no detach, and never calls
`DebugSetProcessKillOnExit(FALSE)`. On a post-create failure it requests
termination of the exact child first and then latches whole-Job termination.
The pending owner can be reaped only after the exact creator/debugger thread has
exited and joined; the matching join proof then permits bounded process wait and
exact-zero Job completion.

No RPC operation or executable consumes this creation seam, and that creation
slice adds no helper entrypoint, parent-side handle injection, or integrated
R10/R11 gate. Required
privilege enablement, exact interactive window-station/desktop DACL access,
child-token query access, the actual cross-session call, and the positive
installed-service/nonnested-Job matrix remain unproved.

A separate child-only Phase 1 feasibility leaf,
`key-agent-service-helper-bootstrap`, depends on `key-agent-service-wire` and
target-specific `windows` APIs. It does not depend on `platform-windows`, either
UI crate, or the service. No executable consumes it, and no default or release
path reaches register capture/adoption. Its secret-free canonical 72-byte
correlation ACK codec is always available but is neither authentication nor
authority. Register capture and adoption are
compiled only for Windows x86_64 with the explicit
`child-capture-feasibility-test-hook` feature and `debug_assertions`; the safe
API is dormant and MUST NOT run unless the authenticated parent debugger is
ready to own the breakpoint.

The child leaf contains one exact 34-byte naked sequence: `movabs` loads public
markers into R10 and R11, `INT3` stops at the gate, register-only stores through
RCX/RDX capture both values, 32-bit XORs clear both registers, and `RET` returns.
Adoption rejects zero, negative/invalid or pseudo, equal, standard-handle-
aliasing, nonzero-flag, non-`FILE_TYPE_PIPE`, and same-object candidates. It
creates fresh child-local duplicates with explicit desired access `0x00100001`
for the request
reader and `0x00100002` for the response writer, inheritance false, and options
zero; verifies candidate/duplicate object continuity; and checked-closes both
launcher-known candidates. The resulting safe state exposes no raw handle
getter and performs no I/O.

Every capture or adoption failure is process-terminal: the child calls
`std::process::abort()` and exposes no failure return. No UI code can continue;
the OS closes the child's entire handle table, and the parent MUST terminate and
reap the helper Job.

The source candidates' exact `GrantedAccess` and pipe direction remain
**UNVERIFIED**. Supported Win32 APIs cannot query that admission fact, and the
explicit-rights `DuplicateHandle` result may be stronger than the candidate.
`NtQueryObject` is test/change-prone evidence and is not permitted as runtime
admission. The leaf therefore does not satisfy the target exact-access/direction
requirement and does not integrate either UI, parent injection, ACK transport,
the independent second suspend, detach, or signed artifacts. Those steps and
their supported-kernel matrix remain Phase 1 **STOP-SHIP** blockers.

The fixed zero-padded 76-byte MIDL frame and its canonical decoder are the hard
message bound. RPC `MaxCalls = 8` and `MaxRpcSize = 76` are runtime hints, not
that bound. The server separately caps concurrent callback-authentication work
at eight permits and serializes manager dispatch. If failed startup rollback or
stop rundown retains RPC-referenced runtime state, the SCM host deliberately
omits `SERVICE_STOPPED`. During worker rundown, its progress reporter advances
the `SERVICE_STOP_PENDING` checkpoint every 500 ms with a 3-second wait hint and
aborts on a 15-second deadline, status-report failure, or reporter disconnect;
uncertain cleanup is never presented as a clean stop.

The ignored Windows same-process authenticated round-trip now passes on the
current interactive host, including manager-only primary-token duplication and
retained-token revalidation. It proves only this local debug composition, not
the claimed Windows-build matrix, installed service identity/configuration,
endpoint-squatting resistance, cross-session zero-capability LPAC behavior, or
a real production Broker client; those remain **STOP-SHIP**. This single-host
result does not satisfy the blockers below.

Phase 1 MUST first prove, with an inert no-secret service and real user-session
LPAC fixture on every initially claimed Windows 11 x64 build:

- restricted virtual-account token/privilege behavior;
- authenticated-client impersonation and exact primary-token derivation;
- Session-0 `CreateProcessAsUserW` composition with `STARTUPINFOEXW`,
  zero-capability LPAC, explicit process/thread security, mitigations, debug
  flags, interactive desktop access, and creation-time Job assignment;
- service ownership and exact from-birth DACL readback that denies the enrolled
  user without breaking loader/helper startup;
- cross-session zero-capability LPAC `ncalrpc` authentication and exact
  PID/token/session/service-role binding;
- `bInheritHandles = FALSE`, post-create `DuplicateHandle`, exact injected-handle
  type/access/flag validation, and no child/grandchild leakage;
- unique real-helper R10/R11 sequence, context mutation/readback, debugger-event
  provenance, suspend counts, detach, handle attenuation, and cleanup;
- lock/logoff/user-switch, timeout, crash, SCM stop/restart, and failure at every
  bootstrap edge;
- complete service/helper outbound-network denial.

Even after Phase 1, release remains blocked on the production installer and
immutable signed dependency graph, service-only storage, PCP/TPM non-exportable
key provisioning, rollback-resistant anchor, rotation/recovery, protected
settings, durable crash reconciliation, authenticated real Approval/Secret Input
E2E, canonical authorization-to-signature-to-broadcast binding, final Windows
negative matrix, Authenticode identities, offline release lineage/checkpoint,
independent review, and the final offline verifier.

No Phase 1 fixture or partial integration permits either compiled policy to
change from `None`.
