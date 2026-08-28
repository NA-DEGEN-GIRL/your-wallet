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

The pre-event create transition also consumes a move-only witness minted only on
a fresh debugger OS thread. That subtransition receives or continues no debug
event, releases no
suspend count, performs no detach, and never calls
`DebugSetProcessKillOnExit(FALSE)`. On a post-create failure it requests
termination of the exact child first and then latches whole-Job termination.
The pending owner can be reaped only after the exact creator/debugger thread has
exited and joined; the matching join proof then permits bounded process wait and
exact-zero Job completion.
This restriction is scoped to creation/pre-event cleanup; the later dormant
parent gate below owns the admitted debug-event sequence.

No RPC operation or executable consumes this creation seam. Required
privilege enablement, exact interactive window-station/desktop DACL access,
child-token query access, the actual cross-session call, and the positive
installed-service/nonnested-Job matrix remain unproved.

A separate Phase 1 helper-bootstrap crate exposes only its platform-neutral gate
byte specification and secret-free canonical 100-byte hello/72-byte ACK codecs
to the optional, default-feature-disabled `platform-windows` launch feature.
Those values are correlation evidence, not authentication or authority. Child
register capture, adoption, and completion compile only for Windows x86_64 with
the explicit `child-capture-feasibility-test-hook` feature and
`debug_assertions`. The child API remains unreachable from either UI, the
service executable, RPC, default, and release paths and MUST NOT run unless the
authenticated parent debugger is ready to own both breakpoints.

The child leaf contains one exact 34-byte capture sequence: `movabs` loads public
markers into R10 and R11, `INT3` stops at the gate, register-only stores through
RCX/RDX capture both values, 32-bit XORs clear both registers, and `RET` returns.
Adoption rejects zero, negative/invalid or pseudo, equal, standard-handle-
aliasing, nonzero-flag, non-`FILE_TYPE_PIPE`, and same-object candidates. It
creates fresh child-local duplicates with explicit desired access `0x00100001`
and `0x00100002`, inheritance false, and options zero; verifies object
continuity; and checked-closes both launcher-known candidates. A separate exact
28-byte adoption-complete sequence loads independent R10/R11 markers, executes
its sole `INT3`, clears both registers, and returns. Both sequences have their
only breakpoint at offset 20.

After adoption the child exact-reads and canonically decodes the 100-byte hello.
It binds the expected role that a future signed entrypoint must fix, current
child PID, distinct nonzero service PID, child creation `FILETIME`, strict-future
deadline no more than five seconds away, and the client PID of both child-owned
server handles to that service PID. It synchronously writes the exact 72-byte
ACK and immediately enters gate two. Every capture, adoption, framing, role,
identity, deadline, peer, write, or gate failure calls `std::process::abort()`
and exposes no failure return.

The dormant parent first performs a bounded read-only/reparse-point reopen of the
pinned helper with file identity checked before and after reading, and accepts
exactly one nonoverlapping copy of each complete gate only in initialized
executable nonwritable AMD64 PE32+ code. It requires canonical virtual/raw
section order, raw offsets equal to RVAs for every nonempty raw section in a
low-alignment image, and a final aligned section extent equal to `SizeOfImage`.
A fresh debugger thread
authenticates the create event, exact PID/primary TID, event aliases,
main-image identity and creation time, bounded system `ntdll` load, one system
breakpoint, and then the exact capture RVA/page/bytes/context/markers. It rejects
every extra process/thread/loader event and revalidates the client, service
descriptors, target LPAC token, context, and one-member Job before injection.

Only two `DuplicateHandle` calls are admitted, with target masks `0x00100001`
and `0x00100002`, inheritance false, and options zero. Remote results are opaque
child-table register words, never local handle owners. If only the first remote
duplicate was installed, local rollback cannot close it; every injection error
therefore MUST terminate and bounded-reap the exact child and Job.
`DUPLICATE_SAME_ACCESS`, inherited duplication, rights broadening, and a
recoverable production call site are forbidden.

The parent changes only R10/R11 with complete readback, writes the hello before
continuing capture, exact-reads/binds the ACK, then authenticates gate two. The
child's synchronous ACK-write-before-gate-two order and parent's ACK-read-before-
gate-two-authentication order are the race boundary. `PeekNamedPipe` is omitted
because it requires `GENERIC_READ`, wider than the request mask;
`FlushFileBuffers` is omitted because it requires `GENERIC_WRITE`, wider than
the response mask. Gate two installs an independent suspend count from prior
zero, continues the event, and revalidates liveness, attachment, Job, and no-
pending-event state. `DebugSetProcessKillOnExit(FALSE)` is the final fallible
debugger-thread operation; no `DebugActiveProcessStop`, `WriteProcessMemory`, or
`CreateRemoteThread` path exists.

After the debugger thread exits and joins, success requires debugger absence,
flags/ID/same-object reauthentication and checked close of retained create-event
aliases, exact Job count one, and a suspend probe 1 -> 2 -> 1. The measured host
kept those aliases valid and same-object after no-kill thread exit, but this is
host evidence only. Alias lifetime, thread-exit detach, loader order, context,
suspend, and cleanup behavior across every claimed kernel remain **STOP-SHIP**.

Rejected-event cleanup registers query-only, non-inheritable canonical anchors
with `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID)` or
`OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, TID)` and immediately uses
`CompareObjectHandles` before checked close. This rejects wrong IDs and
different objects but cannot authenticate a raw `DEBUG_EVENT` slot generation
or eliminate same-object ABA and the compare-to-close TOCTOU. Local rejected-
alias closure remains debug-only **STOP-SHIP** kernel-matrix evidence, not an
activation safety claim. The production design must instead isolate borrowed
raw event aliases in a dedicated debugger process and let process exit close its
handle table; the product process must not close those aliases individually.

The dormant feasibility implementation proves only the transport mechanics for
that eventual shape. `key-agent-debugger-wire` uses exact 80-byte bootstrap,
72-byte `READY_FROZEN`, and 56-byte decision frames with big-endian integers,
zeroed reserved fields, and CRC32C framing; CRC32C, the nonce, and private-pipe
PID topology are not authentication or authority. Secretless
`key-agent-debugger.exe` is silent and exits 78 outside its debug test hook. An
ignored current-host kernel test drives private platform typestate through a
suspended helper with exactly three inherited `HANDLE_LIST` entries, private
pipes, parent-to-helper `SYNCHRONIZE` sentinel installation, protocol-only
`READY_FROZEN`, test-only helper-to-parent `DUPLICATE_SAME_ACCESS` pull-back,
`COMMIT`, `ABORT`, EOF, timeout, malformed input, forced termination,
natural-exit/Drop cleanup, and process-exit handle-table cleanup. The exact same
creation installs one `PROC_THREAD_ATTRIBUTE_JOB_LIST` entry backed by an
unnamed, non-inheritable Job configured with `KILL_ON_JOB_CLOSE` only. It has
neither an active-process limit nor breakaway; the parent creates and retains
one Job handle, and pre-resume readback proves the policy, helper membership,
and current active count one. A Job-only path terminates and reaches exact-zero
accounting without consulting the process handle. A current-host path closes
the parent-retained handle before benign suspended-helper code can run and,
without an explicit termination API, proves that live helper becomes terminal.
`READY_FROZEN` does not assert OS suspension.

A dormant artifact-admission boundary now accepts an already verified, pinned
helper only in this order: the exact manifest-derived `KeyAgentDebugger` role,
opaque whole-release attestation, the dedicated debugger-manifest digest kept
distinct from the three generic helpers and the Broker, an absolute verified
path whose file is held without write/delete sharing, and complete
`FILE_ID_INFO` queried from that same held file handle without reopen or path
lookup. `PreflightDebuggerArtifact`, `PreparedReleaseDebuggerArtifact`, and the
linear `MappedReleaseDebuggerArtifact` proof are private,
move-only/non-cloneable, and redacted. Only the sibling transport inside the
private debugger umbrella may borrow the held path or consume prepared
admission; no external path, raw-handle, artifact, release-digest, or generic
launcher surface exists. Admission and preparation allocate no Job, pipe,
channel, thread, process, or debug resource.

The debug-only transport now consumes that prepared value before helper user
mode. The ordinary path accepts no application override and creates only the
held path with exactly `CREATE_SUSPENDED | CREATE_NO_WINDOW |
CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | DEBUG_PROCESS |
DEBUG_ONLY_THIS_PROCESS`, preserving the existing exact three-handle stdio list,
one Job-list entry, private pipes, sentinel, and 80/72/56-byte wire. Before the
returned process/thread slots are adopted, raw numeric values must be distinct
across the held artifact, Job, the exact three stdio pipe slots, and both native
outputs; ambiguity aborts. The creator thread then validates those handles and
the Job. Initial `ResumeThread` must report previous count one or fail-fast;
only that exact result establishes count zero before the bounded first
`CREATE_PROCESS_DEBUG_EVENT` with exact PID/TID, zero-flag borrowed aliases,
same-object process/thread comparisons, and a present, distinct, zero-flag
`hFile`. Before adopting the event file, the transport again requires raw
numeric distinctness across the held artifact, all three pipes, creator
process/thread, Job, and event process/thread/file slots. Exact-object
comparison binds only each event process/thread alias to its creator counterpart
and keeps `hFile` distinct from those aliases; the held artifact is instead
bound by full `FILE_ID_INFO` equality. Equality with the simultaneously held
prepared artifact consumes `PreparedReleaseDebuggerArtifact` into
`MappedReleaseDebuggerArtifact`; the event file is checked-closed before any
continuation, with ambiguous close fail-fast.

While that event still freezes the helper, `SuspendThread` must report prior
count zero. The same creator thread then continues the event and calls
`DebugActiveProcessStop`; post-detach checks require no remote debugger, a live
exact process, a 1 -> 2 -> 1 suspend-count probe, and the same one-member Job.
Probe-resume failure rejects, while any successful result other than previous
count two fail-fasts. Rejected attached cleanup drops the creator primary-thread
owner before polling the Job to exact zero.

Only afterward is the unchanged `SYNCHRONIZE`-only sentinel installed, and the
80-byte bootstrap is written before the sole user-mode resume. The mapped
artifact remains held through exact process/Job cleanup; retirement of the
system-managed event aliases is excluded and remains in the supported-kernel
**STOP-SHIP** matrix. Equal/distinct-file unit tests, exact-flag/raw-slot/first-
event-classifier tests, and separate ignored current-host kernel tests for the
positive path and `cfg(test)` mismatched-application override are the present
evidence.

The secretless helper still creates or debugs no Key Agent target and receives
no target `DEBUG_EVENT`. This parent-side first-event image proof does not solve
target raw-slot generation, same-object ABA, or atomic compare-close; the target
debug engine must still move atomically into the dedicated process and retain
borrowed target-event aliases until process exit. Signed packaged-artifact,
exact PE version-resource, and Authenticode/signer E2E remain **STOP-SHIP**.
A separate principal and from-birth process DACL with explicit
`PROCESS_DUP_HANDLE` denial, actual target transfer and token/image/suspend/Job
proof, target membership and process-count topology, Job-owner handoff beyond
helper exit, adversarial parent-death containment, and supported-kernel
debug-event-alias retirement and cancellation-drain matrices also remain
**STOP-SHIP**.
There is no production caller, and `COMPILED_RELEASE_POLICY` remains `None`.
When a deadline observes pending overlapped pipe I/O, `CancelIoEx` is only a
cancellation request. Async `ReadFile`/`WriteFile` receive no byte-count output
pointer; one raw `*mut OVERLAPPED` established before initiation is carried
unchanged through completion and cancellation, without forming a shared Rust
reference while the kernel may update it. The parent retains the exact buffer,
manual-reset event, and `OVERLAPPED` through a separate fixed five-second,
non-alertable `GetOverlappedResultEx` drain, which is also the sole source of the
transferred-byte count, and returns only after success,
`ERROR_OPERATION_ABORTED`, or an exact pipe-terminal status. A drain timeout,
incomplete or alertable result, or any ambiguous error invokes
`std::process::abort()` without unwinding, so borrowed storage cannot leave scope
while kernel I/O may still reference it. Abort does not run `Zeroizing` drops;
this lifetime fail-safe is not evidence against WER/minidump, paging, or
hibernation capture, whose host policies remain **STOP-SHIP**. Current-host
pending-read tests exercise
the ordinary terminal-cancellation path; this is bounded fail-closed
implementation evidence, not unconditional kernel liveness. Parent abort closes
its retained Job handle and prevents unsafe parent continuation, but kill-on-close
terminates members only when that is the system-wide last Job handle; this slice
does not prove that condition after helper code runs. Supported-kernel
cancellation-drain liveness remains **STOP-SHIP**.

Every `LOAD_DLL_DEBUG_EVENT` first adopts its optional `hFile` into checked
caller ownership before semantic-proof evaluation, stores the semantic result,
and then finishes checked close. Only after that close may the stored semantic
error or subsequent loader-count-limit error return; a cleanup failure
dominates a simultaneous semantic failure. Rejected authority is single-assignment: if any rejected raw slot,
PID/TID, or canonical anchor is already retained, a second registration takes
an unconditional process-wide fail-fast path before overwrite. These are local
ordering guards, not proof of raw-slot generation or an atomic compare-and-
close primitive, so they do not discharge the kernel-matrix **STOP-SHIP** item.

Ignored host-local kernel probes now cover the common attenuation path for both
Approval and Secret Input. WDK `NtQueryObject`, flags, pipe-local information,
and I/O measure the service-local creator sources and fresh duplicates as exact
request `0x00100001` and response `0x00100002` authority, non-inheritable, and
correctly directed. A separate cross-process probe uses the real
`channel.rs::WindowsDuplicateHandle` production duplication path and then
test-only `DUPLICATE_SAME_ACCESS` pull-back, WDK `NtQueryObject`, object
comparison, and positive/rejected reverse I/O to measure the actual target-table
candidates as exact too. This is test/change-prone evidence for the current
host, not runtime admission or a universal supported-kernel claim. The real
helper child's production `WindowsHandleOperations::duplicate` and capture/
adoption path remains unexecuted end-to-end. UI integration, signed-helper E2E,
installer/service composition, and the supported-kernel matrix also remain
unverified, so `UnverifiedSourceAccessAndDirection` and the Phase 1
**STOP-SHIP** gate remain.

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
