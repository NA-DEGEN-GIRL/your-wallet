# Architecture and trust boundaries

This repository is an incomplete implementation of a self-only Windows 11 and
Chrome private-mainnet canary. It is not authorized for public distribution,
high-value use, or real-mainnet funds.

## Current implementation status

**Release status: STOP-SHIP.** The diagram and trust rules below are target
invariants, not a claim that the current binaries establish every boundary.

ADR 0001 now selects a distinct restricted virtual-account Windows service as
the replacement Key Agent boundary. The implemented no-secret surface consists
of a fixed-name, debug-feature-gated, inert SCM lifecycle fixture, a
dependency-free transport-neutral version-1 wire contract, and a narrow x64
classic-MIDL sys boundary. The fixture
serializes STOP/SHUTDOWN/INTERROGATE handling, latches a stop received before
event publication, and protects event-handle rundown with a locked published
context. The wire admits only open-epoch and epoch/request-bound status frames,
can return only `Unavailable`, fixes every frame to 20, 52, or 72 bytes, and
rejects noncanonical lengths, kinds, reserved fields, sentinels, correlations,
and CRC32C framing corruption. Windows identity, process identity, role, and
trusted deadlines are deliberately absent as wire authority. The sys boundary
compiles byte-pinned MIDL client/server stubs and a handwritten SEH shim from
checked-in sources and fixes its outer ABI to a zero-padded 76-byte frame. An
additional explicit debug feature composes that boundary into a local-only,
packet-private authenticated status server with bounded callback permits,
one-shot process-correlated epochs, SCM rundown, and `Unavailable` as its only
V1 application response. Its desktop admission proves only a local medium-
integrity, interactive, non-AppContainer caller, not an enrolled Broker or role.

That `YWKASV01` version-1 public contract remains immutable. A separate
non-default `debug-feasibility-v2` module defines the debug-only `YWKASV02`
generation as six fixed frames: 20-byte open-epoch request, 52-byte open-epoch
ACK, 72-byte desktop-command request, 72-byte desktop-command response, 68-byte
helper-ready request, and 68-byte helper-ready ACK. Its closed desktop commands
are `Status`, `LaunchApprovalRpcProbe`, and `LaunchSecretInputRpcProbe`; results
are fail-closed `Unavailable` or the matching Approval/Secret Input probe-
completed value. No V2 frame carries caller role, PID, image identity, or other
peer authority. Each epoch slot permanently records V1 or V2, uses a distinct
nonce-derivation domain, and is removed before a wrong-version attempt is denied,
so cross-version use is terminal.

The feature-gated V2 desktop dispatcher authenticates before decode and is wired
into the live `ServerContext`. Open-epoch and Status/`Unavailable` return as
immediate frames. Approval and Secret Input probe requests consume the bound
epoch and return a move-only launch action owning the freshly authenticated peer
plus exact request; a desktop `HelperReady` is authentication-denied before
epoch lookup or consumption. V1 delegates through a separate already-
authenticated method with unchanged wire behavior. The exact consumed desktop
request is the sole source of helper role, epoch, request ID, and matching
completed result.

That desktop admission now rejects `SeDebugPrivilege` by assignment state, not
only by enabled state: absent is the sole accepted state, while assigned-but-
disabled and enabled are both denied. After the one authenticated desktop
process-creation claim is consumed, a same-thread impersonation bookended by
retained/effective-token revalidation must make an exact
`OpenProcess(PROCESS_DUP_HANDLE, FALSE, child_pid)` fail with
`ERROR_ACCESS_DENIED`; an unexpected handle is checked-closed and any other
status fails closed. This proves only the admitted desktop token against that
exact still-suspended child, not administrators or another token.

A separate role-aware path, live only under the LPAC debug feature, classifies a
local low-integrity restricted AppContainer caller only as a service-created-
LPAC transport candidate. Exact profile SID, zero capabilities, image, role,
process, and token facts remain in the service-owned expected peer. Its registry
has exactly eight slots, registers that peer while suspended, revalidates before
a sole resume, holds the slot publication boundary across that resume so
callbacks cannot observe pre-publication state, allows non-consuming callback
observation, and lets the manager consume the matching epoch/request exactly
once. Duplicate, replay, cross-role, race, stop, and cancellation paths retire
and bounded-reap the exact process and Job; retired slots are never reused during
one server lifetime and terminal cleanup has a five-second quiescence bound.
Malformed-candidate manager rejection retires exact and identity-indeterminate
peers while preserving only definitely unrelated peers.

The RPC manager retains each one-shot completion locally and sends a dedicated
coordinator only the authenticated desktop authority plus the exact request
copy. One occupied launch spans the worker and its capacity-one transport, so a
second launch returns correlated `Unavailable` instead of queuing. Cleanup,
registry-internal, debugger-invariant, and role-correlation failures latch fatal
health and close RPC admission.

RPC descriptor selection is feature-specific. Status-only preserves one AU/SY-
`GA`, Medium/`NW` descriptor for both endpoint and If3. The LPAC probe derives
the exact package SID strings for the fixed Approval and Secret Input profile
monikers with OS APIs, then owns a Low/`NW` endpoint descriptor granting connect
`0x1` and a distinct Low/`NW` If3 descriptor granting `GA` to AU, SY, and both
package SIDs. This closes the earlier descriptor-level helper transport
reachability defect, but does not prove an installed restricted-SCM fixed-LPAC
round trip.

Debug-only launch inputs retain and revalidate an exact restricted service
token for service-owned process/thread descriptors, an unnamed non-nested
one-process Job, and fixed target-user Approval or Secret Input LPAC profiles.
The desktop token never crosses as a handle: an auth-owned same-thread lease
contains target impersonation and exact-once cleanup while profile creation,
SID/folder observation, and fresh revalidation run under the shared profile
mutex. The resulting environment binds `LOCALAPPDATA` to the authoritative
AppContainer `...\AC` folder plus only verified `SystemRoot`/`WINDIR`. A
five-slot startup owner binds the Job, full helper mitigation policy, zero-cap
LPAC and AAP opt-out attributes, and restricted-child policy with fixed desktop,
null stdio, and no handle list.

The same dormant feature now has one auth-owned, exact-once process-creation
attempt. Its sole `CreateProcessAsUserW` call supplies the fixed application
name with no command line, `bInheritHandles = FALSE`, the paired non-inheritable
service-owned process/thread security attributes, and exactly
`CREATE_SUSPENDED | DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW |
CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT`. Native success is
immediately adopted into move-only process/thread owners. Before the suspended
child can advance, readback proves both service-owned object descriptors, exact
Job membership/count, and a fresh primary child token with the fixed role SID,
zero capabilities, LPAC/AAP-opt-out membership differential, target session,
and exact desktop `TokenUser`, single logon SID, and `AuthenticationId`.

The pre-event creation subtransition consumes a move-only witness minted only
on one fresh debugger OS thread. That subtransition receives no debug event and
calls none of
`WaitForDebugEvent`, `ContinueDebugEvent`, `ResumeThread`,
`DebugActiveProcessStop`, or `DebugSetProcessKillOnExit(FALSE)`. If a child was
created and any verification fails, it requests termination of that exact
process first and then the whole Job, exits and joins the exact creator/debugger
thread, and only then permits bounded process reap and exact-zero Job cleanup.
The joined-thread proof is matched to the pending cleanup owner. This statement
is scoped to creation and pre-event cleanup; the subsequent debug-only parent
gate below does receive and continue an admitted event sequence.

The helper-bootstrap crate has two deliberately different surfaces. Its
platform-neutral gate-byte specification and secret-free canonical 100-byte
hello/72-byte adoption-ACK codecs plus the separate 72-byte `YWKHRC01` helper-
RPC confirmation codec are available to the optional, default-feature-disabled
`platform-windows` launch-feasibility dependency. All three frames prove framing
and correlation only, not authentication or authority; the confirmation is not
an adoption ACK and its carried role never replaces expected-peer authority.
Child register capture, adoption, bootstrap, and helper-ready completion compile
only for Windows x86_64 with explicit feasibility features and
`debug_assertions`. Only the matching debug probe features on Approval and
Secret Input UI executables reach them; default, release, and production paths
remain unavailable.

The leaf contains one exact 34-byte capture sequence: `movabs` loads independent
public markers into R10 and R11, `INT3` stops the child, two register-only stores
capture R10/R11 through RCX/RDX, two 32-bit XORs clear R10/R11, and `RET`
returns. Adoption rejects zero, negative/invalid or pseudo, equal, standard-
handle-aliasing, nonzero-flag, non-`FILE_TYPE_PIPE`, and same-object
candidates. It makes fresh current-process duplicates with explicit desired
access `0x00100001` for
the request reader and `0x00100002` for the response writer, inheritance false,
and options zero; compares each duplicate with its candidate for object
continuity; and checked-closes both launcher-known candidates. An independent
exact 28-byte adoption-complete sequence loads distinct public R10/R11 markers,
executes its sole `INT3`, clears both registers, and returns. Both byte sequences
and their breakpoint offset 20 are shared with the parent through the safe gate
specification.

After adoption, the child exact-reads and canonically decodes the 100-byte hello
at the trusted service-owned sole-writer boundary. Before emitting an ACK it
binds the role fixed by its calling entrypoint, its current child PID, a distinct
nonzero service PID, its process-creation `FILETIME`, a strict-future deadline
no more than five seconds away, and
both child-owned server-handle client PIDs, observed with
`GetNamedPipeClientProcessId`, to that service PID. It then completes the exact
synchronous 72-byte ACK write and immediately
enters the adoption-complete gate. Every capture,
adoption, read, framing, role, identity, deadline, peer, write, or second-gate
failure calls `std::process::abort()`; no recoverable API can expose a partial
state to UI code. The current debug Approval and Secret Input entrypoints fix
their respective roles; a future production entrypoint must additionally be
signed and immutably installed.

Before the adoption ACK write, the child derives the distinct `YWKHRC01` frame
from the validated hello's epoch nonce, request ID, and fixed role, and retains
that encoded key together with the absolute deadline only inside private
zeroizing continuation state. The retained value is non-cloneable and has no raw
accessor. The role-fixed debug entrypoint uses the fixed `ncalrpc` endpoint with
implicit WINNT credentials, packet privacy, and authz-none, sends exact
`HelperReady`, accepts only the correlated ACK, frees the RPC binding, writes
`YWKHRC01`, closes the response pipe, and blocks on the request pipe until the
service terminates it. Every failure is process-terminal.

The service accepts the completed result only after confirmation plus EOF,
expected-peer admission and role match, and exact process/Job cancellation while
the request writer is retained. Shutdown orders RPC rundown before coordinator
stop/join and helper-registry stop. The LPAC-only 30-second SCM watchdog is a
derived hard fail-fast bound, not proof that every Windows call is interruptible
or a clean per-operation deadline.

The debug-only parent preflights the pinned helper with a bounded read-only,
reparse-point reopen and file-identity checks before and after reading. It
accepts an AMD64 PE32+ executable/non-DLL only when each complete gate sequence
occurs exactly once, the sequences do not overlap, and both lie wholly in
initialized executable nonwritable code. The section table must have canonical
virtual and raw order, each nonempty raw section in a low-alignment image must
use an offset equal to its RVA, and the final aligned section extent must equal
`SizeOfImage`. On the fresh debugger thread it
authenticates the exact create event, PID, primary TID, event aliases, main-image
identity, child creation time, bounded system `ntdll` load, and one system
breakpoint before admitting the exact capture RVA/page/bytes/context/markers.
Every other process/thread event, non-primary thread, extra loader event, or
phase transition fails closed.

Only after revalidating the client, helper, service-created process/thread
descriptors, target LPAC token, Job membership/count, and retained context may
the parent duplicate the two connected child-server pipe handles into that
exact child. The only target masks are `0x00100001` and `0x00100002`;
`bInheritHandle` is false and duplication options are zero. Returned values are
opaque child-table register words, never local `HANDLE` owners. A first remote
duplicate cannot be safely closed from the service if the second step fails, so
every injection error is process-terminal and must consume the exact child and
one-process Job into termination and bounded reap. `DUPLICATE_SAME_ACCESS`,
inherited duplication, rights broadening, and recoverable production callers
are forbidden.

The parent mutates only R10/R11 and requires complete context readback, writes
the exact hello before continuing the capture event, then exact-reads and
canonically binds the ACK before authenticating gate two. It does not call
`PeekNamedPipe`: that API requires `GENERIC_READ`, which would broaden the
minimum request mask. It does not call `FlushFileBuffers`: that API requires
`GENERIC_WRITE`, which would broaden the minimum response mask. The child's
synchronous ACK write-before-gate-two order and the parent's ACK-read-before-
gate-two-authentication order close the continuation race without either API.

At gate two, the parent proves the exact RVA/page/bytes/context/markers, requires
`SuspendThread` to report prior count zero (installing count one), continues the
held debug event, and revalidates liveness, attachment, Job state, and absence of
a queued event. `DebugSetProcessKillOnExit(FALSE)` is the final fallible
debugger-thread operation. Only prevalidated ownership moves follow it before
that thread exits and joins; there is no `DebugActiveProcessStop`,
`WriteProcessMemory`, or `CreateRemoteThread` path. Post-join success must prove
the debugger is absent, reauthenticate every retained create-event alias by
flags, IDs, and same-object comparison, checked-close it, retain exactly one Job
member, and probe the independent suspend count as 1 -> 2 -> 1.

On the measured host, create-event process/thread aliases remained valid and
same-object after no-kill debugger-thread exit; that observation supports the
checked-close model only for this host. Automatic close is documented for
continued exit events, and this protocol admits no exit event. Alias lifetime,
thread-exit detach, context canonicalization, suspend counts, loader ordering,
and close behavior across every claimed kernel remain **STOP-SHIP** matrix
items, not universal claims.

Rejected-event cleanup separately registers query-only, non-inheritable
canonical anchors with
`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID)` or
`OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, TID)` and immediately
applies `CompareObjectHandles` before an alias is eligible for checked close.
That narrows wrong-ID and wrong-object closure; it does not authenticate a raw
`DEBUG_EVENT` slot generation, same-object ABA, or the compare-to-close TOCTOU.
Local closure of a rejected raw event alias therefore
remains debug-only **STOP-SHIP** kernel-matrix evidence, not an activation
safety claim. Discharging this blocker requires an atomic cutover to a
dedicated debugger process
whose isolated handle table contains the borrowed raw event aliases until process exit;
individually closing those borrowed aliases in the product process is not an
acceptable production design.

A separate dormant transport slice now tests only the mechanics needed by that
future process boundary. `key-agent-debugger-wire` defines exact 80-byte
bootstrap, 72-byte `READY_FROZEN`, 56-byte decision, 96-byte `TARGET_FROZEN`,
56-byte parent-death command, and 96-byte parent-death report frames with big-
endian integers, zeroed reserved fields, and CRC32C framing; the CRC is
corruption detection, not authentication. The secretless
`key-agent-debugger.exe` produces no output and exits 78 in ordinary or release
builds, and runs only behind its debug test hook. A private platform typestate
and ignored current-host kernel probes cover the exact three-handle
`HANDLE_LIST`, private control/status pipes, `SYNCHRONIZE`-only sentinel,
`READY_FROZEN`, `TARGET_FROZEN`, `COMMIT`, `ABORT`, EOF, timeout, malformed
input, forced termination, natural-exit/Drop cleanup, and process-exit handle-
table cleanup.

The same debugger creation carries one `PROC_THREAD_ATTRIBUTE_JOB_LIST` entry
backed by an unnamed, non-inheritable Job whose readback must equal
`KILL_ON_JOB_CLOSE | ACTIVE_PROCESS`, `ActiveProcessLimit = 2`, and no
breakaway. The parent creates and retains the only Job handle owned by this
implementation. The fixture proves one debugger member before target creation,
then the exact debugger/target PID set at count two; an attempted third
suspended child must fail with the Job quota. This does not prove that no other
process has duplicated a Job handle system-wide. `READY_FROZEN` still names a
fixed-source, decision-only protocol state rather than an OS suspension claim;
the target reported by `TARGET_FROZEN` is separately proven suspended.

A private umbrella now composes the production-compiled artifact seam with its
sole debug-gated transport consumer. Admission still accepts an already
verified, pinned helper only in this order: the exact manifest-derived
`KeyAgentDebugger` role, opaque whole-release attestation, the dedicated
debugger-manifest digest kept separate from the three generic helpers and the
Broker, an absolute verified path held without write/delete sharing, and full
`FILE_ID_INFO` from that same held handle without reopen or path lookup.
`PreflightDebuggerArtifact`, `PreparedReleaseDebuggerArtifact`, and
`MappedReleaseDebuggerArtifact` remain private, move-only/non-cloneable, and
redacted. Only the sibling transport can borrow the prepared path or consume the
capability; no external path, raw handle, artifact, release digest, or generic
launcher is exposed. Admission and preparation allocate no Job, pipe, channel,
thread, process, or debug resource.

The transport's non-test creation path accepts only the held absolute path and
uses exactly `CREATE_SUSPENDED | CREATE_NO_WINDOW |
CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | DEBUG_PROCESS |
DEBUG_ONLY_THIS_PROCESS`. The existing exact three-entry stdio `HANDLE_LIST`,
one-entry containment Job list, private control/status pipes, sentinel design,
and the three original debugger-wire frame kinds are retained alongside the
target and parent-death frames. Before adopting the native-returned
process/thread owners, raw numeric slots must be pairwise distinct across the
held artifact, Job, all three exact pipe handles, and both outputs; ambiguity
aborts. A creator-thread-bound owner then proves creator PID/TID, thread-owner
PID, zero handle flags, and exact Job limits/membership/count. Its initial
`ResumeThread` must report previous count one or fail-fast; only that result
establishes count zero. `WaitForDebugEventEx` is bounded by the operation
deadline and a five-second first-event cap. It records the returned event before
semantic checks and accepts only the first
`CREATE_PROCESS_DEBUG_EVENT` with exact event PID/TID; borrowed event
process/thread aliases must have the same IDs, owning PID, zero flags, and
compare as the creator-owned objects. Before event-file ownership is adopted,
raw numeric distinctness is rechecked across the held artifact, three pipe
handles, creator process/thread, Job, and event process/thread/file slots. The
event `hFile` must also be present, zero-flag, and exact-object-distinct from the
event process/thread aliases. Exact-object comparison otherwise binds only
those aliases to their creator counterparts; artifact binding is full
`FILE_ID_INFO` equality, not object comparison.

The held event-file handle is borrowed by the safe artifact boundary, which
queries its complete `FILE_ID_INFO` and compares it to the identity retained in
`PreparedReleaseDebuggerArtifact`. Equality alone consumes that prepared value
into `MappedReleaseDebuggerArtifact`; no path, PID, image name,
canonicalization, or expected-file reopen participates. The transferred event
file is checked-closed before later suspend or continuation, and an ambiguous
close aborts the parent. While the create event still freezes every thread,
`SuspendThread` must report prior count zero, installing one explicit count.
The same creator thread then performs `ContinueDebugEvent(DBG_CONTINUE)` followed
by `DebugActiveProcessStop`. Immediately after a successful stop and before any
later Win32 call, that creator thread probes both borrowed `CREATE_PROCESS`
event process/thread raw slots with `GetHandleInformation`. Only two failures
with exact `ERROR_INVALID_HANDLE` retire their accounting record; a live slot,
asymmetric result, or any other error fail-fasts. The same rule applies to
ordinary detach and attached rejection cleanup. The transport never calls
`CloseHandle` on those system-managed borrowed aliases; among event-supplied
handles, checked ownership and close remain limited to `hFile`. Later
post-detach proof requires `CheckRemoteDebuggerPresent == false`, a live exact
process, the suspend probe 1 -> 2 -> 1, and unchanged one-member Job proof. The
mapped artifact remains inside `DebuggerChild` through terminal cleanup. If the
process is not already terminal, rejected attached cleanup first requests exact
Job/process termination. It then releases any pending event, detaches on its
creator thread, proves process termination, drops the creator primary-thread
owner, and only then polls Job count to zero. A failed probe-resume rejects, but
a successful resume reporting anything other than previous count two fail-fasts
because it may have released execution. Other ambiguous cleanup also fail-fasts.

Only after mapped-image authentication and detach does the parent install the
existing `SYNCHRONIZE`-only sentinel. It writes the same 80-byte bootstrap while
the explicit count remains one and performs the sole user-mode resume afterward.
The debug-hook helper then creates a real suspended, inert target, currently by
reopening its own `current_exe`, and sends its PID/TID, creation time, and source
process/thread handle words in `TARGET_FROZEN`. The parent duplicates only
process access `0x00101001` and thread access `0x00100802`. Exact native access
readback on the measured host is `0x00101001` for the process and `0x00101802`
for the thread because the object manager adds `THREAD_RESUME` (`0x1000`) to the
requested `THREAD_SUSPEND_RESUME` mask. Every other mask is rejected.

Current-host topology probes prove Job count `2 -> 1 -> 0`: exact debugger plus
target before handoff, the still-suspended target alone after debugger exit,
and exact-zero after terminal cleanup. They reprove target identity, creation
time, access, liveness, Job membership, and a `1 -> 2 -> 1` suspend probe after
debugger exit. A separate outer-supervisor fixture binds PID plus creation time
and force-terminates the supervisor before `READY_FROZEN`, at `READY_FROZEN`,
and after target handoff; the retained observation handles require both debugger
and target to become terminal at every applicable stage. Parent-death command
and report framing is exact 56/96 bytes.

This is debug-only topology evidence. The inert target is untrusted because the
helper resolves `current_exe`; it is not a parent-pinned, signed Key Agent image
and is never exposed as resumable production authority. The helper-image event
gate also does not authenticate target debug-event aliases. Parent-pinned target
image admission, atomic dedicated-debugger target-event ownership, system-wide
last-Job-handle exclusion, and supported-kernel generalization of the native
thread-mask normalization and parent-death behavior remain open.

The Windows x64 MSVC helper build now embeds one deterministic, header-free
ASCII `VERSIONINFO` definition with fixed file/product version `0.1.0.0` and
exact `0409`/Unicode strings:
`FileDescription = Your Wallet Key Agent Debugger`,
`FileVersion = 0.1.0.0`, `InternalName = key-agent-debugger`,
`OriginalFilename = key-agent-debugger.exe`, `ProductName = Your Wallet`, and
`ProductVersion = 0.1.0.0`. Package-version drift and other Windows targets fail
closed; non-Windows targets do nothing. Locked
`find-msvc-tools 0.1.10` discovers `rc.exe` and the build links the `.res` only
to this binary, but this does not cryptographically pin `rc.exe` or the SDK.

The release artifact set now requires exactly one `key-agent-debugger-exe` at
`payload/key-agent-debugger.exe`. A safe `FileVersionInfo` inspector covers the
built binary, pre-staging unsigned outputs, post-sign Authenticode evidence, and
the final offline pass. The post-sign generator requires an effectively
read-only payload, canonicalizes and pins the output parent, and rejects a
volume-root parent, ADS/existing leaf, payload containment, or post-create
identity drift. It holds canonical payload handles plus a pinned inspector
through inventory, version, signature, hashes, final exact-inventory recheck,
evidence creation, and output-byte confirmation; offline verification combines
its held bundle with the inspector identity inside the independently pinned
exact eight-file/four-directory verifier toolset. Tests include a real built
binary and an exact-name non-PE negative. Runtime helper version decoding now
first requires `VS_FIXEDFILEINFO.dwSignature == 0xFEEF04BD`.

Those are build/scaffold and current-host fixture/proxy guarantees, not a
completed signed-product E2E or the Phase 1 exit gate. The actual product signer,
immutable installation, generated compiled release policy, parent-pinned target
image, system-wide last-Job-handle proof, and supported-kernel generalization of
debug-event-alias retirement, target access normalization, parent-death, and
cancellation-drain matrices remain external **STOP-SHIP** work. The role-aware
registry now has a debug RPC/lifecycle/wire caller but no production caller;
signed immutable-helper `ncalrpc` E2E, an installed restricted SCM identity, an
actual cross-session service-created LPAC exchange under elevation, and the
supported-kernel matrix are unproved. Helpers still exit 78 in default and
release builds, Phase 1 is not passed, and both compiled policies remain `None`.
When a deadline observes pending overlapped pipe I/O, `CancelIoEx` is only a
cancellation request. Async `ReadFile`/`WriteFile` receive no byte-count output
pointer; one raw `*mut OVERLAPPED` established before initiation is carried
unchanged through completion and cancellation, without forming a shared Rust
reference while the kernel may update it. The exact buffer, manual-reset event,
and `OVERLAPPED` remain live through a separate fixed five-second, non-alertable
`GetOverlappedResultEx` drain, which is also the sole source of the transferred-
byte count, and control returns only after success,
`ERROR_OPERATION_ABORTED`, or an exact pipe-terminal status. A drain timeout,
incomplete or alertable result, or any ambiguous error calls
`std::process::abort()` without unwinding, so borrowed storage cannot leave scope
while kernel I/O may still reference it. Abort does not run `Zeroizing` drops;
this lifetime fail-safe is not evidence against WER/minidump, paging, or
hibernation capture, whose host policies remain **STOP-SHIP**. Current-host
pending-read tests exercise
the ordinary terminal-cancellation path; this is bounded fail-closed
implementation evidence rather than a hard kernel-liveness guarantee. Parent
abort closes its retained Job handle and prevents unsafe parent continuation,
but kill-on-close terminates members only when that is the system-wide last Job
handle; this slice does not prove that condition after helper code runs.
Supported-kernel cancellation-drain liveness remains **STOP-SHIP**.

Every `LOAD_DLL_DEBUG_EVENT` first adopts its optional `hFile` into the
caller-owned checked-close path before semantic-proof evaluation. It stores the
semantic result and then completes checked close; only after that close may the
stored semantic error or subsequent loader-count-limit error return. If cleanup
and semantic validation both fail, the cleanup failure dominates. A second rejected-event
registration is never allowed to overwrite retained authority: if any rejected
raw slot, PID/TID, or canonical anchor is already present, the process takes an
unconditional fail-fast path before assignment. This closes the local
resource-order and overwrite hazards; it does not resolve raw-slot generation,
same-object ABA, or compare-to-close atomicity across kernels.

The common attenuation path now has ignored, host-local kernel evidence for
both Approval and Secret Input. Their service-local creator sources and fresh
local duplicates report exact request `0x00100001` and response `0x00100002`
access, zero inheritance, and the intended directions. The actual
`channel.rs::WindowsDuplicateHandle` production duplication path also installs
target-table candidates with that exact authority: test-only
`DUPLICATE_SAME_ACCESS` pull-back, WDK `NtQueryObject`, object comparison, and
positive/rejected reverse I/O measure the candidates without changing the
production API. These ignored native probes are test/change-prone evidence for
the current Windows host, not runtime admission or a universal supported-kernel
claim. The real helper child's production `WindowsHandleOperations::duplicate`
and capture/adoption path, plus signed-helper E2E, remain unverified; the
`UnverifiedSourceAccessAndDirection` marker and Phase 1 **STOP-SHIP** gate stay
in force. Under the exact Windows x64 MSVC debug features, the V2 coordinator
now exercises static preflight, parent injection, and the two-gate protocol, and
the role-fixed Approval/Secret Input probe entrypoints exercise child completion
and helper-ready RPC. This is not installer identity, signed immutable-helper
evidence, or installed cross-session/elevated service composition.

Direct execution, non-Windows/default builds, and feature-enabled release builds
remain silent exit 78. Only those explicit debug RPC/helper entrypoints reach
the creation/two-gate seam; it adds no wallet state, secrets, storage, network
adapter, or signing transition. Required
privilege enablement, exact interactive window-station/desktop DACL adjustment,
child-token query access, the actual Session-0-to-user-session call, real signed
Broker/helpers, and the supported-kernel matrix remain Phase 1 **STOP-SHIP**
obligations.

For the durable-state rows below, a terminal failure means a consumed durable
outcome or receipt-validation failure. Non-consuming request-validation,
duplicate, and replay rejections cannot issue a second or replacement receipt;
they do not invalidate an already-issued exact receipt.

For the Phase 2E row below, “SACL policy” means every omitted SACL semantic,
including audit, mandatory-label, and resource-attribute policy, not only audit
ACEs. Because `SYSTEM` retains `FILE_ALL_ACCESS`, a real LocalSystem deployment
must also prove its restricted service-SID token composition through external
SCM/admin evidence. The focused surrogate suite covers same-process contention,
cross-process crash/reacquisition with stable identities, synchronized child
non-inheritance, and junction rejection. Production opens `run.lock` with
`GENERIC_READ | SYNCHRONIZE`, requires the exact mapped `FILE_GENERIC_READ`
grant, keeps zero sharing, and then acquires the exclusive nonblocking byte
range `[0, 1)`. A test-only raw `NtCreateFile` probe offering all three share
modes accepts only either an exact sharing violation with no handle or an exact
same-identity verified handle whose byte-lock attempt returns
`ERROR_LOCK_VIOLATION`, with every returned handle checked-closed. A separate
non-vacuous test opens two share-readable same-identity handles, requires the
first byte lock to succeed and the second to conflict, and checked-closes both.
`WithLock` retains a valid lock handle but does not claim whether its byte range
was acquired; only a successful writer result proves exclusivity. Normal release
revalidates that writer, explicitly unlocks the exact `[0, 1)` range with
`UnlockFileEx`, checked-closes the lock handle, revalidates the still-held root,
and checked-closes the root before issuing a receipt. A native `UnlockFileEx`
failure retains the writer and range and cannot mint a normal receipt. Retirement
retries the explicit unlock when the range is still held and attempts to
checked-close both handles even if unlock fails; it mints a retired receipt only
if any acquired range was explicitly unlocked and both closes succeed. Byte locks
are cooperative and do not constrain mapped-file I/O. The zero-length/no-write
DACL narrows that surface, but service and `SYSTEM` peers remain trusted not to
bypass the protocol. Retirement/no-receipt close fallback and crash process
termination can still delay range release. The current host test bounds
child-exit observation to 30 seconds
and, after confirmed exit, retries only exact `Contended` acquisitions for five
seconds, checked-retiring every returned `WithLock` handle before retry, then
proves reacquisition with unchanged root and lock identities. This is bounded
repository-host crash-teardown evidence, not an instantaneous-unlock claim or a
supported-kernel, power-loss, or reboot guarantee; those broader guarantees
remain external **STOP-SHIP** evidence. Its `run.lock` symbolic-link negative
is ignored by default and must be invoked explicitly on a qualified host with
Developer Mode or `SeCreateSymbolicLinkPrivilege`; the default suite alone does
not prove that file-symlink negative. These deployment and qualified-host facts
remain external **STOP-SHIP** evidence.

The Phase 2E row below records the root/`run.lock` portion of the shared module;
its word “only” is scoped to that earlier slice. The separate Phase 2F-a row
records the later `state`-directory extension and does not retroactively claim
marker/checkpoint persistence for either phase.

The phase rows below are chronological boundary snapshots. A capability marked
absent in an earlier row is superseded when a later row explicitly adds it. In
particular, Phase 2H supersedes Phase 2G's historical absence of the dormant
production lifecycle-effect backend, source type, and status-RPC leaf. Current
Phase 2I adds only a dormant safe translation boundary for already copied
Windows session-change notifications; it does not activate SCM delivery.
Current gaps still include the production source mint/caller composition,
trusted production Broker/service-peer authentication, mapped-I/O/peer-race
proof, the durable provider, and the external SCM pointer/mailbox/rundown
evidence named in the Phase 2H and Phase 2I rows.

| Component | Current evidence and limitation |
| --- | --- |
| Approval request ordering policy | **Current Phase 3B status: started, not passed.** A private, production-compiled pure policy models only `Admitted -> UIStarting -> UIAuthenticated -> Approved/Rejected` for Approval through the consuming `AdmittedRequestPolicy -> UiStartingRequestPolicy -> UiAuthenticatedRequestPolicy -> ApprovedRequestPolicy | RejectedRequestPolicy` chain and `begin_ui`/`authenticate_ui`/`decide`. This policy-local `Admitted` is distinct from expected-peer `Admitted`, which records `HelperReady` manager admission; Secret Input `Accepted/Cancelled` is a separate future path. One move-only instance binds only the server-derived expected-peer key, nonzero session, Approval role, and original inclusive monotonic deadline and owns the monotonic clock used to enforce it. Every positive edge consumes a fresh move-only one-shot observation and requires exact correlation, Approval role, and a fresh check of that policy-owned clock against the unchanged deadline; clock failure, an at-or-after-deadline observation, mismatch, or failed observation terminally rejects. This is policy-local liveness only: the policy does not inspect an OS process or authenticate a helper, has no production observation constructor, and leaves fresh authenticated Approval UI plus expected-peer proof to a future compositor. Targeted invalidation rejects only matching-session state and preserves unrelated instances, while active-topology invalidation or cancellation rejects `Admitted`, `UIStarting`, `UIAuthenticated`, and `Approved`. The Approved policy state is non-durable and cancellable and grants no signing, intent, candidate, cryptographic-key, or private-key-operation authority. Seed, observation, and policy-state types remain private and move-only, `Rejected` is terminal, and Debug/errors are data-free. The focused inventory is exactly 10/10, and architecture mutations pin the closed order, binding/correlation/deadline rules, targeted versus topology-wide behavior, cancellable Approval, privacy/ownership, and exact zero production seed, observation mint, or callers. Actual Broker-to-policy admission, helper ownership, Approval transcript, authenticated liveness composition, concurrent composition, cleanup/reap, and SCM callback delivery remain unimplemented. Default/release execution remains silent exit 78, both compiled policies remain `None`, and installed-service, signed-helper, kernel, runtime, and release evidence remain **STOP-SHIP**. |
| Session-bound expected-helper invalidation | **Current Phase 3A status: started, not passed.** The production-compiled expected-helper registry binds each suspended helper to a nonzero session obtained only through the service-created target proof (`ExpectedServiceCreatedLpac` to `DetachedSuspendedServiceProbe` to `ExpectedHelperPeer`); the epoch/request key, wire frames, candidates, caller input, and environment remain non-authoritative. A fixed 64-entry quarantine matches the lifecycle policy. Registration checks it under the same mutex. Targeted invalidation commits quarantine first, then extracts only same-session live owners and marks only same-session in-flight owners; active-topology invalidation first commits the departing session and every live/in-flight session, then retires the whole observed topology. Process cancel/reap and the shared five-second settlement wait occur only after unlocking, cleanup `Internal` continues to dominate semantic success or `Stopping`, and unrelated owners survive targeted invalidation. An otherwise-successful consume racing targeted invalidation is rolled back to the unaffected owners' original phases before returning `Denied`, while an otherwise-successful malformed-candidate rejection keeps its planned terminal retirement; selective and global cancellation provenance remain distinct. Exhaustion sets stopping and reaps every owner before returning. The expected-peer inventory is 37/37 with eight session-specific tests, and architecture mutations pin service-only session origin, the synchronized bound, quarantine-before-cleanup order, selective and topology-wide behavior, in-flight settlement, overflow shutdown, data-free diagnostics, and exact zero production invalidation callers. The new invalidation entries are dormant: no lifecycle or SCM production caller exists, `SERVICE_ACCEPT_SESSIONCHANGE`, callback/mailbox delivery, Broker wire activation, helper transcripts, signing, and release composition remain absent. Default/release execution remains silent exit 78, both compiled policies remain `None`, and installed restricted-service, signed-helper, concurrency/rundown, and supported-kernel evidence remain **STOP-SHIP**. |
| Windows service held mutable run-state directory | A production-compiled, Windows-only, module-private, zero-production-authority-mint and zero-production-caller Phase 2F-a extension opens exactly one installer-created `state` directory beneath the already-held fixed `v1` root. It does so only after the existing `run.lock` has acquired and verified its exclusive nonblocking `[0, 1)` range and the root has been revalidated. The one-component root-relative `NtCreateFile(FILE_OPEN)` uses `OBJ_DONT_REPARSE`, `FILE_OPEN_REPARSE_POINT`, directory-only shape, share-read/share-write, and no delete sharing. Its exact grant is the unchanged Phase 2E `ROOT_ACCESS` plus only `FILE_ADD_FILE`; it adds no `FILE_ADD_SUBDIRECTORY`, `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC`, or `WRITE_OWNER`, and the Phase 2E root and lock masks remain unchanged. The expected authority includes a complete non-sentinel installer-recorded state identity. The held directory must have exact-zero handle flags, be non-reparse on the same local fixed NTFS volume, match that identity, and have the service SID as owner with the exact protected three-ACE DACL: `OWNER RIGHTS` deny `WRITE_DAC \| WRITE_OWNER \| DELETE \| FILE_DELETE_CHILD`, service allow exactly the state grant, and `SYSTEM` `FILE_ALL_ACCESS`. Writer revalidation verifies the held root, lock, and state and independently reopens the fixed state leaf with the same no-delete-share contract; candidate verification completes only after checked close, while ambiguous candidate close poisons every later normal or retired receipt. The no-delete-share proof is non-vacuous: a custom from-birth test DACL permits the service `STATE_ACCESS \| DELETE`, the production-held state handle makes a fresh `DELETE` open fail with exact `ERROR_SHARING_VIOLATION`, and the same open succeeds after checked retirement. The writer retains state as opaque future mutation authority; Phase 2F-a itself exposes no raw handle or marker/checkpoint operation, while the separately gated Phase 2F-b adapter below consumes that opaque writer without changing this open/release boundary. Normal release checked-closes state before range unlock, lock close, root revalidation, and root close. Both a successful writer and a `WithLock` failure have explicit terminal retirement; it attempts optional state close, conditional range unlock, and both lock/root closes even after an earlier failure, and issues `FailedRunLockRetired` only if all required steps succeed. Any state-close, unlock, revalidation, or close ambiguity issues no receipt. The focused inventory is exactly 36 tests: 34 passed and two ignored; the seven separately attributed Phase 2F-a tests cover missing state, stale/cross-root identity, wrong type/reparse/security, exact creation-only authority, non-vacuous no-delete-share, successful-writer terminal retirement, and pre/post-native-open impersonation. The current-user fixture covers the installed state boundary but is not installer provenance. The Phase 2F-a evidence boundary has no production caller or expected-authority mint and introduces no marker/checkpoint I/O; Phase 2F-b below supplies a separate bounded fixed-pair adapter. Neither slice provides a Phase 2D, provisioning, Boot, Clean, stopped, secret, signing, or release bridge. Actual ProgramData/service-SID positive evidence, installer state-directory creation/from-birth descriptor and independently sealed identity provenance, closure of all setup/cleanup-capable handles, sealed ancestor ACL and at-rest integrity, SCM/restricted-token composition, group and every SACL policy, mapped-I/O and trusted service/`SYSTEM` peer assumptions, marker/checkpoint recovery, TPM key/non-rollbackable anchor custody, and supported-kernel crash/power-loss/reboot evidence remain external **STOP-SHIP** obligations. Both compiled policies remain `None`, and ordinary/release execution remains silent exit 78. |
| Windows service fixed marker/checkpoint pair | **Current Phase 2F-b status: started, not passed.** A production-compiled, Windows-only, module-private fixed-pair adapter consumes the opaque held Phase 2F-a writer and exposes no native handle. It admits only the four one-component state-relative leaves `marker.v1`, `marker.tmp`, `checkpt.v1`, and `checkpt.tmp`; final leaves are exact `FILE_OPEN`, temps are from-birth `FILE_CREATE`, and every native open is case-insensitive, `OBJ_DONT_REPARSE`, non-directory, reparse-point-aware, synchronous, write-through, and share-zero with pre/post impersonation rejection. Purpose-specific exact access includes `SYNCHRONIZE`: create requests `GENERIC_READ \| GENERIC_WRITE \| DELETE \| SYNCHRONIZE`, final inspection requests `GENERIC_READ \| SYNCHRONIZE`, cleanup requests `GENERIC_READ \| DELETE \| SYNCHRONIZE`, and each granted mask is verified exactly. Pair files are service-owned under an exact protected three-ACE DACL: `OWNER RIGHTS` deny `WRITE_DAC \| WRITE_OWNER`, service allow exactly `FILE_GENERIC_READ \| FILE_GENERIC_WRITE \| DELETE`, and `SYSTEM` `FILE_ALL_ACCESS`; Phase 2E root/lock and Phase 2F-a state masks remain unchanged. Each file must have zero handle flags, exact security/access, one link, no delete-pending state, the root volume's local fixed NTFS identity, default stream only, and no directory, reparse, read-only, sparse, compressed, or encrypted attribute. The state directory must be case-insensitive. Exact records are 148 bytes with a zero-byte EOF probe. Staging performs an exact write, `FlushFileBuffers`, byte-for-byte readback, same-full-ID check, and independent reinspection. The shared production shape predicate has direct compressed/encrypted-bit coverage. Four deterministic one-shot synthetic faults cover marker/checkpoint short writes and flush failures; every case returns `RecordIo` as known-not-committed before rename, leaves rename count zero, removes all pair leaves through checked retirement, and consumes its fault. This does not claim natural NTFS short-write behavior or power-loss evidence. Observation clears only descriptor-valid stale temps of length `0..=148`, preserves oversized or hostile temps, and double-opens the final pair. Commit revalidates the writer, compares complete bytes/lengths/full IDs, stages both records, rejects every old/new identity alias, performs a second full-ID CAS, then uses handle-relative marker-first/checkpoint-second replacement with identity/byte confirmations and final temp absence. The test-only snapshot of the production variable-length rename packet fixes the current Windows x64 ABI fields/alignment/offsets, packet/backing lengths, replace bit, exact parent binding, and exact non-NUL-terminated UTF-16 payloads for both final leaves without widening production. This is ordered two-file replacement, not atomic pair commit or power-loss proof. Every pre-first-rename failure is known-not-committed; from the first native rename attempt onward every outcome is ambiguity-bearing and permits only independent reload or retirement. Ambiguous cleanup is bound to staged full IDs, and any unsafe cleanup or checked-close ambiguity poisons all receipts. Reread and reload revalidate the complete writer and independently reopen the pair. The pre-Phase 2F-c root slice is exactly 49 tests (47 passed, two existing Phase 2E ignored) after excluding seven separately gated F-c release tests, and includes thirteen Phase 2F-b tests; the private `windows_pair` codec child adds six passing tests, for a combined relevant inventory of 55 (53 passed, two ignored). At the pre-Phase 2F-c boundary the child mapped exact private codec envelopes into move-only pair typestates without a production caller, expected-authority mint, authentication-key provider, TPM/non-rollbackable anchor integration, or Phase 2D Boot/Active/Clean/stopped/provisioning/signing/release bridge; the separately gated F-c runtime and Phase 2C Windows provisioning composites are its exact two production consumers and remain dormant. The runtime composite's sole production-compiled caller is the private Phase 2G compositor, while Windows provisioning has no production fresh-authority constructor or caller. Direct compressed/encrypted policy branches, four deterministic synthetic stage-fault branches, and rename-packet ABI/payload evidence are covered. One direct evidence gap remains: a nonzero case-sensitive-directory kernel negative. Actual elevated ProgramData/service-SID and installer from-birth evidence, SCM/restricted-token composition, trusted service/`SYSTEM` peer race analysis, supported-kernel crash/power-loss/reboot recovery, TPM/auth integration, and pair atomicity remain external **STOP-SHIP** obligations. Both compiled policies remain `None`, and ordinary/release execution remains silent exit 78. |
| Windows service logical/OS runtime composite | **Current Phase 2F-c status: started, not passed.** A production-compiled, Windows-only, module-private dormant composite binds one writer-first Phase 2D logical lifecycle to one independently verified Phase 2F-b OS pair. Its exact entry is `start_windows_runtime(writer, authority)`: it consumes an already-held writer and one move-only `RuntimeRunStateAuthority`, with installation and provider identity carried only by that authority. The sole production-compiled caller is the private dormant Phase 2G compositor; neither entry has an executable, top-level, exported, or aliased caller. The provider backend is uninhabited and has zero production constructors, so there is no production protected/TPM provider source or test-secret import. Startup allocates the logical backend binding only after the OS writer exists, freshly observes the exact pair, and authenticates Clean through the lease-owned authority. Before logical binding, the binding-failure wrapper retains the runtime authority directly beside the still-held OS writer; the unbound-terminal wrapper continues to retain it directly after writer retirement. After binding, `SingleWriterLease` is the sole writer-plus-provider carrier; every later writer-holding failure, checked retirement, released-no-receipt, post-release terminal, recovery, and stopped wrapper retains it. No Windows wrapper stores a parallel provider. Active ordering remains logical begin-commit, OS commit, logical receipt, logical begin-reread, independent OS reread, then completion. Pre-first-rename failure is known-not-committed; first-rename-onward ambiguity can only independently reload or retire. Exact prior Boot or candidate Active are the only Active reload results; confirmed-commit reread failure is terminal `RereadDrift`. Clean ambiguity can return Clean only for the exact candidate. Every live/reload state has consuming reason-neutral retirement. Current-host evidence still covers the three exact cfg(test)-only process-death cutpoints and full byte/temp/file-identity matrices in both Clean-to-Active and Active-to-Clean directions, but proves only forced process termination and reopen, not power loss, reboot, torn-sector/storage durability, or pair atomicity. Stop keeps both share-zero finals and the logical authority through verified OS release; only exact pair receipt plus logical completion mints `WindowsStoppedRunEvidence`. Writer-retained failure permits checked retirement; `WindowsReleasedNoReceipt` and `WindowsPostReleaseTerminal` are irreversible and retain hidden authority without retry/recovery/stopped conversion. All composite authority is move-only, Debug-redacted, safe-only, and free of raw ownership/type-erasure escape. Exact evidence is 88/88 durable-run-state tests: 34 parent, two private authentication-child, 25 logical provisioning, six pair-child, seven Windows provisioning, and fourteen runtime composite; kernel root remains 56 total = 54 passed plus two existing environment-dependent ignored. A production protected/TPM provider and anchor source, elevated ProgramData/service-SID installer provenance, OS provenance tying writer/provider to the service, SCM/restricted-token/listener/admission composition, trusted peer and mapped-I/O proof, and supported-kernel crash/power-loss/reboot reconciliation remain external **STOP-SHIP** obligations. Both compiled policies remain `None`, and ordinary/release execution remains silent exit 78. |
| Windows no-secret lifecycle compositor | **Current Phase 2G status: started, not passed.** A separate production-compiled, Windows-only, module-private dormant compositor is the sole direct caller of `start_windows_runtime`. Its exact entry remains `begin_windows_lifecycle(writer, authority)`, with no parallel installation, provider, or effect argument and zero production callers. A private child attaches one move-only lifecycle effect authority only after exact Active at `WindowsListenerPending::prepare_listeners(effects)`. The production effect backend is uninhabited `Unavailable(Infallible)` with zero constructor/source/caller; cfg(test)-only local fixtures validate six exact binding/attempt/purpose receipts for listener prepare, `SCM_RUNNING`, admission open, admission close, listener drain, and `SCM_STOPPED`. Known-not-applied, ambiguous, cross-bound, duplicate/exhausted-attempt, and wrong-purpose results retain typed terminal effect authority. Startup orders each local effect before its matching policy record. Stop is fixed as admission-close effect, begin-stop, reject-new-work, invalidate non-durable authority, listener-drain effect, policy close/drain, six named remaining-cleanup calls, exact Clean commit/reload, writer release, then `SCM_STOPPED` effect; the Windows facade exposes no generic cleanup delegate. Exact writer release produces `WindowsScmStopPending`, and only exact SCM-stopped evidence mints `WindowsLifecycleStopped`. Checked and every irreversible durable terminal retain attached effects; a post-writer-release SCM failure retains both `WindowsStoppedRunEvidence` and `WindowsLifecycleEffectFailure` without retry, retirement, or stopped conversion. Pre-Active terminals remain unattached. Runtime authority remains nested in the logical lease through all durable states, and policy/effect/durable causes remain separate. All authority is move-only, Debug-redacted, safe-only, and exposes no raw handle/path or ownership/type-erasure escape. Exact evidence is 22/22 compositor tests and 14/14 runtime-composite tests; supporting durable evidence is 88/88 (34 parent, two authentication, 25 logical provisioning, six pair, seven Windows provisioning, and fourteen runtime), lifecycle core remains 21/21, and kernel root remains 56 total = 54 passed plus two ignored. Actual listener/admission implementations, a production lifecycle-effect backend/source/caller, SCM `SetServiceStatus`/restricted-token/service-SID composition, elevated installer provenance, a production protected/TPM provider and rollback anchor, OS writer/provider provenance, trusted peer and mapped-I/O proof, signed artifact binding, and supported-kernel crash/power-loss/reboot reconciliation remain external **STOP-SHIP** obligations. Both compiled policies remain `None`; ordinary/release execution remains silent exit 78, and this dormant slice is not release-ready. |
| Windows production lifecycle-effects adapter | **Current Phase 2H status: started, not passed.** Phase 2H adds a dormant production-compiled `WindowsServiceEffectSource` and `WindowsServiceEffectBackend` behind the unchanged Phase 2G compositor. Windows ordinary library builds now compile the SCM/status-RPC mechanics, and `key-agent-service-rpc-sys` plus `key-agent-service-wire` are nonoptional dependencies; debug feasibility hooks remain the only executable probes. The move-only, single-use, Debug-redacted source consumes one sealed `WindowsScmStatusAuthority`; its private registration handle has no raw accessor. The backend is an exact 8-stage automaton that drives six leaf effects in order: listener prepare, `SCM_RUNNING`, admission open, admission close, listener drain, and `SCM_STOPPED`, with `Stopped` and fail-closed `Terminal` endpoints. Cleanly released listener-start failure is known-not-applied; retained startup, SCM publication, admission-open, rundown, and stopped-publication uncertainty are ambiguous and retain authority. The exact registered invocation may open admission only while `SERVICE_RUNNING` with no stop/control/finalization latch; the check and operation execute under `CONTROL_CONTEXT`. Consuming `close_admission` creates the admission-closed typestate before `AdmissionClosedStatusRpcWorker::drain` invalidates epochs, stops listening, unregisters with waiting enabled, waits for rundown, and releases resources. Final status terminalizes `CONTROL_CONTEXT` before the native `SCM_STOPPED` send so a concurrent callback cannot publish a later pending state. Existing compositor evidence remains 22/22 and the separate service-effect inventory is 9/9. `WindowsServiceEffectSource::new`, the registered SCM authority mint, a real durable-provider source, `begin_windows_lifecycle`, and executable/top-level product composition each have zero production callers. Default and release service execution remains silent exit 78, both compiled policies remain `None`, and external SCM registration/source-mint composition, elevated installer/service-SID setup, a real protected durable provider and rollback anchor, crash/power/reboot recovery, TPM/authentication-key custody, supported-kernel matrices, signed immutable artifacts, and release evidence remain **STOP-SHIP**. |
| Windows session-change translation bridge | **Current Phase 2I status: started, not passed.** A private, production-compiled `windows_session_events` module adds a safe closed translation boundary for an already copied native notification. `ValidatedWindowsSessionEvent::decode` accepts the native event type plus an owned `WTSSESSION_NOTIFICATION`, requires `cbSize` to equal `size_of::<WTSSESSION_NOTIFICATION>()`, and requires `dwSessionId` to form a nonzero `SessionId`; consuming `dispatch` then emits exactly one existing lifecycle event, while `handle_windows_session_change` composes those operations. `WTS_SESSION_LOCK`, `WTS_SESSION_UNLOCK`, and `WTS_SESSION_LOGOFF` map to `Lock`, `Unlock`, and `Logoff`; console connect/disconnect, remote connect/disconnect, session logon, and remote control map to `UserSwitch`. Session create, session terminate, unknown types, wrong size, and session zero are rejected without dispatch. The separate inventory is 8/8, covering exact native layout, validation and mapping, move-only evidence, and the sole runtime-facade dispatch route. Rejection failures are unit-only and the runtime failure retains only its policy cause; no failure retains the raw notification, event code, or session identifier, and Debug is fixed/redacted. This does not activate native delivery: no service status includes `SERVICE_ACCEPT_SESSIONCHANGE`, the SCM handler has no session-change branch and does not read `event_data`, and the bridge has zero production callers. Actual callback-pointer validation/copying, bounded mailbox ownership and delivery, cancellation, concurrency, and rundown ordering remain **STOP-SHIP**. Default/release execution remains silent exit 78, both compiled policies remain `None`, and Phase 2I does not pass Phase 1, Phase 2, or the release gate. |
| Windows service lifecycle model | A production-compiled, module-private Phase 2A core models nine externally supplied mandatory startup observations; storage binding and single-instance writer evidence are the other two logical requirements and arrive structurally inside lease-bound `BootEvidence`, never as caller booleans. Its authority-independent split is exactly `StartupChecklist -> CompletedStartupChecklist -> ListenerPendingPolicy -> ScmRunningPendingPolicy -> AdmissionPendingPolicy -> RuntimePolicy`, then `CleanBoundaryPolicy -> ReleaseBoundaryPolicy -> StoppedRuntimePolicy`. The four pure-policy tests plus seventeen lifecycle tests form an exact 21/21 inventory. The core requires exact Active commit/readback before listener preparation; `SERVICE_RUNNING` before admission; bounded work, retained-token, and session-quarantine state; and the fixed eleven-step stop sequence ending in Clean commit/readback while the writer remains held, followed by exact writer release. The logical `SingleWriterLease` owns the provider-bound runtime authority together with the exact writer, so no transition accepts a parallel provider. After writer acquisition, that lease preserves the authority through every later startup/live/reload/release wrapper and every writer-bound failure, recovery, checked-retired, irreversible, and stopped terminal. Before acquisition, typed `StartupBeforeWriterExit` preserves the authority directly and has no writer-retirement path. After the first nine cleanup steps and empty registries, a consuming pre-Clean check creates `CleanCommitPending`; request-scoped hardware/storage cleanup does not release service-lifetime run-state authority. Distinct Clean commit/readback receipts can produce only `CleanCommittedWithWriter`, and exact writer release is the sole path to stopped evidence. Reload wrappers preserve startup or cleanup provenance across ambiguity. Debug output redacts authority and durable identifiers. The dormant Phase 2G compositor is the sole private production-compiled policy consumer, but neither module has an executable, top-level, or exported caller. This is a no-secret ordering model only: it imports no actual SCM, listener, storage, firewall, network, provider source, or signing adapter and mints no signing authority. Retaining the separately gated run-state root, supplying a protected/TPM provider and rollback anchor, proving OS writer/provider provenance, wiring an elevated installer and service ACL/SCM/listener/admission path, and supported-kernel crash/power/reboot evidence remain absent and **STOP-SHIP**. Phase 1 and Phase 2 exit gates remain not passed, both compiled policies remain `None`, and the ordinary/release service remains silent exit 78. |
| Windows service durable run state | A production-compiled, module-private, zero-runtime-root Phase 2B core defines exact 148-byte authenticated `YWRUNV01` marker and independent `YWHIWV01` high-water envelopes for Clean, Active, and RecoveryRequired. A sealed `RunStateAuthenticationProvider` owns the exact installation plus a unique opaque `RunStateProviderIdentity`; two providers made from the same installation and `cfg(test)` bytes still have different identities. Its private production backend is uninhabited and has zero constructors, `Default`, `From`, raw-key/backend accessors, serialization, clone/copy, generic oracle, or type-erasure escape. Only `cfg(test)` accepts a nonzero 32-byte key into `Zeroizing`, and Debug is fixed/redacted. Exact codec and HMAC logic live in the private authentication child behind marker-specific and checkpoint-specific operations. A same-body test proves distinct tags and failed cross-purpose verification. `runtime_authority(&mut self)` mints the move-only provider-bound runtime authority, preventing a second live mint through the same provider borrow. The Boot path observes only after writer acquisition. `SingleWriterLease` owns that authority and exact writer; Active/Clean authentication and every transition derive installation/provider only from the lease and accept no parallel provider. The authority moves through Boot, prepared/committed/reload/release states, all terminal/recovery evidence, and `StoppedRunEvidence`. One-shot receipt phases and exact writer-epoch latches preserve the existing CAS, ambiguity, retry, retirement, and release semantics; wrong-provider, partial advance, drift, rollback, equivocation, wrong installation/backend/lease, missing data, or authentication failure cannot mint Boot/Active/Clean/stopped authority. The internal Phase 2F-c/2G runtime chain and Phase 2C Windows provisioning compositor are its dormant production-compiled consumers, with no executable/top-level caller or production provider source. Exact focused evidence is 88/88: 34 parent, two private authentication-child, 25 logical provisioning, six pair, seven Windows provisioning, and fourteen runtime tests. This is not product persistence: it has no production protected/TPM backend or source, filesystem/registry/SCM/kernel-singleton adapter, service-SID root/DACL, elevated installer-seeded marker provenance, OS provenance tying writer/provider, non-rollbackable anchor, supported-kernel power-loss/reboot evidence, or signing authority. Phase 1 and Phase 2 remain **STOP-SHIP**, both compiled policies remain `None`, and ordinary/release execution remains silent exit 78. |
| Windows service durable provisioning | **Current Phase 2C status: started, not passed.** A production-compiled, module-private, zero-runtime-root Phase 2C typestate replaces the memory fixture's direct generation-one Clean seed. The move-only `WindowsInstallerProvisioningGrant` carries an expected opaque provider identity and nonzero attempt; only a `cfg(test)` current-user fixture can seal/construct it. The sole `bind_windows_fresh_install_authority(provider, grant)` binder creates `WindowsFreshInstallAuthority` only for the exact identity. There is no direct fresh-authority fixture constructor, and another provider is rejected even with the same installation and fixture bytes. The fresh authority cannot become runtime authority. A distinct provisioning writer must precede exact Missing/Missing observation; the only candidate is canonical Clean generation one with zero predecessor. Exact absent/absent CAS, separate commit/reread receipts, backend/installation/writer/attempt/round binding, ambiguity handling, and final writer release remain mandatory. Startup is writer first; known-not-committed, ambiguity/reload, confirmed-reread drift, writer-retained, released-no-receipt, post-release, and checked-retirement semantics remain one-shot and fail closed. Successful logical `ProvisionedRunState` and Windows `WindowsProvisionedRunState` retain the consumed fresh authority in hidden fields; only generation is exposed, with no Boot/runtime conversion. Terminal `ProvisioningRecoveryExitEvidence` and `WindowsProvisioningCheckedRetired` likewise preserve that hidden authority through checked exit. Runtime startup must separately mint/acquire runtime authority and writer before reopening/authenticating Clean, so ordinary missing-state boot never initializes or repairs. Exact evidence is seven Windows provisioning tests, including a non-vacuous same-installation/same-bytes wrong-identity binder test, within 88/88 focused durable tests: 34 parent, two authentication, 25 logical provisioning, six pair, seven Windows provisioning, and fourteen runtime. Kernel root remains 56 = 54 passed plus two ignored; the historical pre-F-c Phase 2F-b inventory remains 55. This is current-user fixture/local composition only. Actual virgin-install deletion detection, a production grant/provider source or caller, elevated installer provenance/lease/journal, `%ProgramData%`/service-SID from-birth DACL and ancestor sealing, service ACL/SCM/restricted-token/listener/admission composition, a protected/TPM backend and non-rollbackable anchor, OS writer/provider provenance, trusted `SYSTEM` peer and mapped-I/O proof, signed artifact/install binding, and supported-kernel crash/power-loss/reboot/torn-sector/storage-durability/pair-atomicity evidence remain external **STOP-SHIP** obligations. Phase 1 and Phase 2 remain **STOP-SHIP**, both compiled policies remain `None`, and ordinary/release execution remains silent exit 78. |
| Windows service lease-first runtime boot | A production-compiled, module-private, zero-runtime-root Phase 2D contract makes the Boot-producing runtime path writer-first and provider-bound. `runtime_authority(&mut self)` returns a move-only `RuntimeRunStateAuthority` and prevents a second mint while that mutable borrow remains live; it carries the installation and unique opaque identity into writer acquisition. `RuntimeWriterAcquired` and then `SingleWriterLease` own that authority together with the exact writer. `finish_runtime_boot` consumes the acquired state once into exact authenticated Clean `BootEvidence` or an authority-bearing failure. Before-writer failure is no longer reason-only: typed `RuntimeBootBeforeWriterFailure` retains the consumed authority through `StartupExitRequired` into terminal `StartupBeforeWriterExit`; no writer exists, so no writer release or checked retirement occurs. Every post-acquisition observation, wrong-provider, non-Clean-state, backend-binding, writer-epoch, release, recovery, and stopped path likewise retains the provider-bound authority. Transition APIs accept no parallel provider. A separate `cfg(test)` inspection carries no lease-binding, Boot, or mutation authority. Missing/Missing, one-sided missing, malformed, wrong-provider, Active, RecoveryRequired, cross-backend, and cross-epoch state never initialize, provision, repair, or mint Boot authority. For writer-acquired failure, exact terminal retirement is required before writer reacquisition. The nine external startup observations plus structurally carried storage binding and single-instance evidence remain eleven logical requirements. At the historical pre-F-c boundary this contract used only the bounded memory fixture and `cfg(test)` sealed provider. The dormant F-c composite is now its sole private Windows runtime adapter, and Phase 2G its sole private policy consumer; there is no top-level production caller or production provider source. Installer/SCM/listener/admission integration, service-SID composition, OS writer/provider provenance, a protected/TPM backend and anchor, and supported-kernel crash/power-loss/reboot proof remain absent and **STOP-SHIP**. Phase 1 and Phase 2 are not passed, both compiled policies remain `None`, and ordinary/release execution remains silent exit 78. |
| Windows service held run-state root | A production-compiled, Windows-only, module-private, zero-production-authority-mint and zero-production-caller Phase 2E adapter opens only the fixed `%ProgramData%\YourWallet\KeyAgent\v1` service root and installer-created `run.lock`. It resolves `FOLDERID_ProgramData`, opens the drive with `OPEN_EXISTING`, and walks every known-folder and product component with held-parent, one-component `NtCreateFile(FILE_OPEN)`, `OBJ_DONT_REPARSE`, and `FILE_OPEN_REPARSE_POINT`; thread impersonation is rejected around known-folder lookup, every open, and revalidation. The final root omits delete sharing and the non-directory, zero-length, single-link lock opens with `GENERIC_READ \| SYNCHRONIZE`, requires the exact mapped `FILE_GENERIC_READ` grant, uses zero sharing, and acquires the exclusive nonblocking byte range `[0, 1)`; both have handle flags exactly zero (so inheritance and protect-from-close are rejected) and are non-reparse, local fixed NTFS objects with persistent ACLs and complete non-sentinel `FILE_ID_INFO` equal to independently supplied installer expectations. The service SID must be owner and the protected, non-inherited DACL must contain exactly an `OWNER RIGHTS` deny for `WRITE_DAC \| WRITE_OWNER \| DELETE \| FILE_DELETE_CHILD`, the exact service operational allow, and `SYSTEM` `FILE_ALL_ACCESS`. `SE_DACL_PROTECTED` plus zero flags on all three ACEs proves current no-inherited-ACE semantics; `SE_DACL_AUTO_INHERITED`, if present, is only a historical/model control marker and is not from-birth provenance. `SE_DACL_AUTO_INHERIT_REQ`, defaulted or unprotected descriptors, and nonzero ACE flags are rejected. The root DACL alone does not prove at-rest delete denial because an ancestor can grant `FILE_DELETE_CHILD`: surrogate fresh root `WRITE_DAC`/`WRITE_OWNER`/`FILE_DELETE_CHILD` opens and fresh lock `DELETE` opens are access-denied, while a fresh root `DELETE` open during the held state is specifically `ERROR_SHARING_VIOLATION` from the root handle's no-delete-share. Actual installer sealing of the `YourWallet`/`KeyAgent` ancestor ACLs against service or untrusted delete-child and rename/delete paths, plus at-rest integrity, remains external **STOP-SHIP** evidence. Root identity/security is revalidated before and after lock acquisition, and each revalidation succeeds only after its reopened no-delete-share root is identity-checked and explicitly checked-closed. Ambiguous probe close after lock acquisition is writer-retaining and cannot mint a receipt. Pre-handle failures are `RuntimeRunLockStartFailure::BeforeLock`; every post-handle status, disposition, impersonation, identity, security, shape, range-lock, revalidation, or probe-close failure is handle-retaining `WithLock`; that state does not claim the byte range was acquired, while only a successful writer result proves exclusivity. Normal release revalidates the writer, explicitly unlocks exact `[0, 1)` with `UnlockFileEx`, checked-closes the lock, revalidates the held root, and checked-closes the root before issuing a receipt. A native unlock failure retains writer and range and cannot mint a normal receipt. Retirement retries explicit unlock when the range is still held, attempts both checked closes even when unlock fails, and issues a retired receipt only if any acquired range was explicitly unlocked and both closes succeed. Only consuming checked release or terminal retirement ends the move-only state. Runtime never creates, repairs, replaces, deletes, or adopts the objects, uses no `OPEN_ALWAYS`, `CREATE_NEW`, global named mutex, enrolled-user/LPAC storage, or signing journal, and exposes no conversion to Phase 2D or provisioning authority. Only the `cfg(test)` current-user surrogate may create fixtures and retain one non-inheritable, share-neutral `READ_CONTROL \| WRITE_DAC` cleanup handle with no data or delete access across the production opener for the test lifetime. It checked-closes the `FILE_ADD_FILE \| FILE_DELETE_CHILD` setup handle and lock creator handle before recording `FILE_ID_INFO` and calling the opener, and closes the retained cleanup handle after the held adapter and test are torn down. This is not from-birth installer evidence and does not prove an actual installer closes every setup or cleanup-capable handle before service start. The adapter reads owner and protected DACL only and does not prove group or any SACL policy (including audit, mandatory-label, and resource attributes), a production expected-authority mint or caller, the actual ProgramData/service-SID positive path, elevated installer from-birth descriptor and independently sealed identity provenance, closure of every installer/setup/cleanup handle before service open, SCM composition, install/repair/upgrade/uninstall, marker/checkpoint I/O or CAS/flush semantics, authentication-key/anchor custody, kernel crash/power-loss/reboot recovery, mapped-I/O exclusion, untrusted service/`SYSTEM` peer enforcement, instantaneous post-crash unlock, secrets, signing, or release activation. These remain external **STOP-SHIP** evidence; both compiled policies remain `None`, and ordinary/release execution remains silent exit 78. |
| MV3 extension | Strict top-level HTTPS routing, exact 128-bit request IDs, bounded envelopes/state, deadline checks, freeze/navigation cancellation, replay handling, and incognito rejection have unit tests. Native response sequences must now be exact rather than merely increasing. Every native reconnect samples a distinct session ID, resets the per-connection sequence, rejects responses from an earlier session, and is bounded to 4,096 attempts per worker lifetime. Default and release operation still receives only the unavailable response; an explicit debug-only subprocess contract can return only the local Sepolia chain ID. |
| Native host | The default executable runs the bounded persistent dispatcher: strict JSON and exact version-1 envelopes, combined inbound sequencing, independent response sequencing, cancellation without response, and a 4,096-frame connection cap. Every valid request receives stable provider error 4900 and the process exits with code 78 on EOF or the first terminal error because it constructs only a disabled release attestation. A Cargo-feature **and** `debug_assertions` gated headless contract hook can spawn only the regular-file `broker` sibling beside its own executable, with hidden, cleared-environment stdio, unwind-safe child kill/wait cleanup, and a typed two-nonce/role/sequence handshake. Broker independently admits at most 4,096 post-handshake commands; the hello is outside that count and the next complete frame fails before dispatch. The local chain-ID execution surface is crate-private and absent from ordinary/release library builds. That hook can execute only Broker-owned `eth_chainId`; every other allowlisted method crosses only as a parameter-free enum plus request correlation, is recorded complete by Broker, and then receives 4900. Exact late cancellation is acknowledged internally as already completed and never produces a Chrome response. No raw unavailable-request params, messages, accounts, addresses, or origins cross that hook. A second Windows-only feature/debug hook uses an exact-image-authenticated, process-bound named pipe and a retained one-process Job instead of Broker stdio; it reuses the same payload-only typed state. Feature-enabled release binaries still take the disabled path and exit 78. Chrome-launched native-host image proof, immutable signed installation/registration, stable release extension identity, RPC, signing, and Key Agent access remain absent and stop-ship. |
| Approval helper | `approval-wire` is the single bounded v2 codec. Its 74-byte parent hello binds an ordinary channel supervisor PID/process/image proof and a distinct logical Key Agent PID/process proof; the 106-byte child hello, 110-byte finish header, bounded request, and 75-byte response retain the existing nonce/transcript framing. The runtime child seals its two stdio objects first, verifies Approval LPAC/Job state, then requires stdio plus all three injected proofs to be five pairwise-distinct exact objects with zero flags. Fresh child-local duplicates of the injected proofs remain authoritative through response write. Pipe PID/session observations bind only to the retained supervisor process, while the logical Key Agent is independently checked for live exact PID, same session, image, fixed `YourWallet.KeyAgent.LPAC.v1` SID, AppContainer/LPAC state, zero capabilities, and least-authority denials. The platform issues one opaque monotonic window and splits matching non-Clone authorization/transport halves; wallet protocol retains both privately, invalidation drops the transport half, and the Key Agent binds its exact digest/nonce/display/protected-phrase request once into `BoundApprovalTransport`. Dormant activation consumes that carrier and checks original expiry before allocation. One private zero-caller transition performs parent hello under `min(original expiry, fresh five-second grace)`, one exact post-gate application resume, child hello, and revalidation; a second sealed zero-caller transition accepts no raw request/deadline, writes the carrier's exact request plus EOF, verifies the fixed response plus EOF, requires the exact held child to exit naturally with code 0 before the same original deadline, finally revalidates the Key Agent, observes that deadline once more, and retains the carrier in opaque `VerifiedParentBoundApprovalExchange`. It has no response or signing conversion. The final Key-Agent check is point-in-time evidence and must be repeated at any future authorization edge. The ordinary supervisor remains transport authority and the Key Agent remains only the logical parent. Before stdio or INT3, the Key Agent child fresh-opens its current token with exact `TOKEN_QUERY \| TOKEN_DUPLICATE`, verifies the fixed zero-capability LPAC policy, and checked-closes it; ordinary non-LPAC execution remains silent exit 78 without entering the gate. The Key Agent launcher supplies process and primary-thread creation attributes as one deny-only protected pair, authenticates the creator and distinct create-event aliases, and registers those aliases in a shared post-join cleanup owner before debugger-thread exit. It retains a separate exact `TOKEN_QUERY \| TOKEN_ADJUST_DEFAULT` handle in `PendingKeyAgentLpac`. Test and production share a strict primary-TID-only/zero-loader-thread policy. The green actual GUI Key Agent regression rejects non-primary loader activity before detach, verifies Job cleanup, and keeps root active-process count one without conhost; it does not reach the semantic gate. A separate green deterministic import-free relocatable GUI PE fixture proves the exact-primary gate, Pending→Verified transition, one verified suspend count, detach, and dormant ownership/cleanup mechanics, but not product compatibility. Seven Rust-startup supervisor integrations are explicitly ignored STOP-SHIP; the green negative maps loader activity to `Activation` and removes the prepared storage root. The pre-resume matrix's no-mutation and original-deep-copy controls exit 0, while every tested deny-first `OWNER RIGHTS` `0x000e0000` plus `SYSTEM`/package/user allow combination exits exact `0xC0000142`; standalone `READ_CONTROL`, `WRITE_DAC`, or `WRITE_OWNER` denies do likewise. Because the package SID is neither a token group nor owner-eligible, the current same-user LPAC principal cannot supply a loader-compatible from-birth `WRITE_DAC` denial. This excludes the current architecture, not every Windows design; a distinct OS principal/service boundary is the next design option. A revised bounded loader policy must still authenticate each worker's provenance, exact thread object/ID, event set, lifetime, exit, and post-exit reopen denial, but it can only exercise the conditional gate mechanism and cannot repair the from-birth gap. If that mechanism reaches the exact PID/primary-TID marker inside `serve`, the launcher may install/read back the deny-only token default DACL, record the post-mutation baseline, checked-close adjust authority, and complete the least-authority final-token bookends. The child independently reads the default back after the later post-gate resume and before later serve work. Every revalidation re-reads both token DACLs and the same current-token object. Worker error, panic, abandoned join proof, and partial closure retain a checked-close/retry path. Attenuation retains the exact `0x00101001` process handle, uses and closes an ephemeral requested-`0x2`/effective-`0x1002` probe before `Held`, and retains only an exact `0x1000` resume-only thread handle. The post-gate application-releasing resume immediately closes that thread handle, so `Running` structurally retains only the narrow process capability. These capabilities are `Send` but `!Sync`, `!Clone`, and `!Copy`. The green post-loader non-primary feasibility test covers real `CreateThread(NULL, ...)` using a default descriptor, but does not prove the real Key Agent's loader-compatible exact-primary production gate. Caller-supplied/native/remote thread creation, pre-gate objects, other existing high-right handles, the Microsoft Learn/SDK `ResumeThread` access disagreement, and Windows-version variance in debug-event cleanup and thread-right behavior remain outside the point-in-time proof. The legacy launcher fails closed before resource allocation because it lacks the complete logical-parent aggregate. Transferable pipe handles, mapped-image and signed DLL/TLS provenance, signed immutable installation, a pre-gate non-thread-object inventory, the loader-worker provenance/lifetime/exit/reopen policy, a distinct OS principal/service design with IPC/lifecycle proof, a supported AMD64/Windows marker/context/system-breakpoint matrix, same-user owner separation, returned/preexisting/duplicated high-right handles, enabled debug/take-owner privileges, bypass-thread policy, bootstrap/provenance, endpoint topology/exclusivity and per-write attribution, signed cleanup, a real GUI Key Agent loader-compatible exact-primary gate E2E, and production composition through signing remain **STOP-SHIP**. `COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` remain `None`, so default builds exit 78. |
| Secret-input helper | The library has exact prompt/outcome codecs, bounded zeroizing response reads, and a non-persisting native secret surface. Its high-level parent API requires the release-attested restricted launcher and exact manifest-derived Secret Input role, atomically owns separate request/response pipes and the held helper/job, transfers the canonical prompt plus EOF, and performs cancellable/drained bounded response reads through EOF. The proof binds the exact prompt, held file/process/LPAC identity, and a fresh OS-CSPRNG challenge, then permits consumption only for that same prompt. Default executable builds exit 78 and the compiled release policy is absent. Direct-launch parent-identity denial and immutable signed-artifact evidence remain stop-ship. |
| Broker/key agent/Windows boundary | Method schemas, state bounds, typed chain evidence, canonical display derivation, request-hashed one-shot approval, nonce lifecycle, signer self-checks, protected pipe/helper verification, and an opaque verified-response capability exist. The Key Agent now also has a crate-private offline-lifecycle wire/controller: exact magic/version/type/request-ID/sequence/deadline/length framing, fixed 64-byte frames, exact EOF, zero reserved fields, a 64-request controller-activation lifetime across one-shot inherited request channels, and distinct duplicate/replay/out-of-order outcomes. Admission pins the bounded wall-clock remainder to a trusted monotonic `Instant`; every frontend receives the exact absolute expiry. After a frontend returns, only the controller can mint a private-field, non-clone checked-deadline capability, and every service/session mutation must consume it. The same capability owns the trusted clock borrow and rechecks the pinned expiry after KDF/derivation/seal/reseal at the last safe point before durable commit, unlock, or pending-state activation; expiry locks without advancing generation or decrypted state. Its closed command set is status, 12/24-word creation, separate backup display/confirmation stages, open, lock, and confirmed-address lookup; no password, mnemonic, confirmation answers, signing, import/export, or network payload is representable. Status, lock, and confirmed-address access use the owned `OfflineWalletService`. Secret-bearing transitions require a crate-sealed frontend capability that can acquire inputs or present a borrowed view but cannot receive the vault service. Recovery display returns a non-clone, live-session-bound capability without mutation; only the deadline-checked controller may consume it into one pending positions-only confirmation, which lock, restart, cross-stage use, or replay clears or rejects. The compiled capability returns stable `Unavailable` and locks because authenticated Secret Input/Recovery adapters and the inherited channel launcher are not wired. The anti-phishing phrase has a sealed Key Agent-only lifecycle: a five-word OS-CSPRNG cue is first committed as pending and is unavailable to prompts until a trusted exact enrollment confirmation. Rotation is a persisted old-to-new pending ceremony. Loads carry typed authenticated-empty/record state, installation/store/class identity, an exclusive owner generation, exact record digest, and previous/high-water anchor evidence; same-generation equivocation, empty-after-observed, rollback, owner takeover, or ambiguous commits lock the lifecycle. The platform storage layer now has a narrow private fixed-role Key Agent generation-store adapter, but no production protected-settings consumer or settings key provisioning is wired yet; independent settings AEAD key custody, exclusive-owner enforcement, and a release-approved non-rollbackable anchor remain blockers. The launcher uses separate deterministic revision-v1, zero-capability LPAC profiles for manifest-derived Approval and Secret Input roles; the names and derived SIDs differ and callers cannot select the profile role. The launcher verifies every suspended child against its exact expected SID, and the Secret Input/recovery bootstrap independently repeats that check. Both use an exact inherited-handle list, minimal environment, suspended token verification, process mitigations, and a single-process kill-on-close job. The authenticated dual-slot store and encrypted Key Agent journal cover reservation, approval-pending, potentially-signed, signed-unbroadcast, broadcasting, submitted, and broadcast-unknown recovery. Raw transaction bytes remain journal-owned and reach an RPC adapter only through a non-clone lease after `Broadcasting` commits. Production rollback-anchor/key provisioning and signed-artifact helper/network/RPC evidence are absent; the compiled release policy is `None`, so launch and signing remain disabled. |
| Key Agent activation proof | A dormant crate-private Windows seam verifies the manifest-derived role, exact image, zero-capability LPAC token, Job, pipes, and independently prepared supervisor-held fixed root before detaching with one proven suspend count. Fresh profile/root creation remains a distinct non-launchable pending path. A separate dormant storage-only opener, with zero production callers, opens only the fixed existing leaf using `OPEN_EXISTING`, `FILE_FLAG_OPEN_REPARSE_POINT`, and no delete sharing; it verifies initial security and complete `FILE_ID_INFO`, canonicalizes and reopens the path, requires identical security and identity, privately retains the canonical path/reopened handle, and revalidates both the held handle and canonical reopen. It neither creates nor repairs/deletes/adopts the root and is distinct from the child `LOCALAPPDATA`/token-derived opener. It cannot observe profile registration or construct `HeldExistingKeyAgentInstallObjects`, `PreparedKeyAgentProvisioning`, or `VerifiedExistingKeyAgentInstall`. The sole production-compiled prepared mint remains the private sealed adoption transition; whole-release binding retains helper-manifest and exact file-object proofs separately, but the opener, adoption transition, release-binding, and dormant supervisor binder all have zero production call sites. The one-shot child/root transcript requires exact request EOF before the child detaches both ambient protocol entries and closes raw stdin; raw stdout survives only in a response capability. Once response output is attempted, write/flush/close results cannot return to `main` and the child enters `Sleep(INFINITE)`. The parent's deadline-bound exact response plus EOF authoritatively proves response-endpoint closure; separate resident-process/Job revalidation completes startup. The parent consumes both endpoints and the retained aggregate has none. This dormant boundary exposes no generic runtime/signing IPC. Production installer key/checkpoint and journal I/O backends, authoritative profile-registration observation and held-aggregate construction, an exclusive installer lease covering checkpoint/observation/reread ordering, production call sites and recovery, atomic same-user/ancestor race closure, rollback-anchor and storage/AEAD-key provisioning, protected settings/lease wiring, authenticated Broker/supervisor topology and single-instance enforcement, signed immutable artifact/DLL/dependency E2E, and release activation remain **STOP-SHIP**; `COMPILED_RELEASE_POLICY` is `None`. |
| Dormant Approval/Key Agent logical-parent binding | One private non-clone binding transition consumes the complete release-prepared Approval artifact and intact storage-proven Key Agent and retains a fresh `PROCESS_QUERY_LIMITED_INFORMATION \| SYNCHRONIZE` duplicate of that same running Key Agent process without PID reopen. A separate consuming transition requires `BoundApprovalTransport`, rejects elapsed original expiry before allocation, launches Approval suspended with the ordinary supervisor proofs, injects the retained capability as the fifth logical-parent proof, and retains the full aggregate plus carrier. A further sealed, consuming, zero-caller transition uses `min(original expiry, fresh five-second grace)`, writes the complete v2 parent hello before resuming the exact primary thread once, reads/decodes the child hello, and revalidates the running child, Job, and parent-bound aggregate. Only another sealed zero-caller transition may consume that opaque bootstrap; it accepts no raw request/deadline and uses the carrier's exact original deadline for arming, finish/request plus request EOF, fixed response plus response EOF, and natural child exit. Response EOF alone remains exit-pending. The exact held child must exit naturally with code 0 before evidence, final Key Agent revalidation occurs after that exit, the same original deadline is checked once more, and only then is opaque `VerifiedParentBoundApprovalExchange` minted with the carrier retained. It has no response/signing/raw-resource accessor or conversion. The final Key-Agent check is point-in-time evidence and must be repeated at any future authorization edge. Early protocol failure and failed natural-exit observation use bounded terminate/reap with cleanup-error precedence; successful evidence is never manufactured by force-terminating a live child. Drop retains kill-on-close fallback without claiming unconditional reap success. Repo-local kernel tests cover the exact query/synchronize process proof, `TOKEN_QUERY` access to its token, and enumerated stronger-right denial, but the logical proof is not Windows process parentage, mapped-image proof, signed release evidence, or runtime readiness. Both compiled policies remain `None`. |
| Device key protection | The crate-private model generates epoch-1 installation bundles with six pairwise-distinct role secrets and releases them only through role-typed views after an anchored open. Rotation preserves the installation ID, advances the key epoch exactly once, rekeys every role, and remains pending until opaque external evidence binds the exact predecessor commitment to the exact new canonical signed envelope at a strictly newer shared-anchor generation. RSA-3072 OAEP-SHA-256/empty-label and low-S P-256 P1363 identities hash one canonical RFC 5280 SPKI form; CNG blobs are adapter-internal inputs only. The raw identity constructors and sealing markers are private to the key-material module, and the architecture gate scans every production Rust source under `key-agent` for an unreviewed PCP implementation. No production PCP or rollback-anchor adapter exists, so this path remains fail-closed and release-blocking. |

### Sepolia demo durable activity boundary

The standalone Sepolia demo keeps a bounded 64-row, fixed-size authenticated
`activity-v1.bin` sidecar derived only from an opened v2 vault. Every decoded
row is rebound to authenticated account 0 or 1. A process-local mutex and a
Windows persistent sibling no-share lock serialize mutation. The writer holds
the exact parent directory, checks a generation baseline, creates a same-dir
temporary file exclusively, flushes it, atomically replaces the destination,
flushes the directory, and authenticates an exact readback. Nonregular and
reparse objects fail closed.

New v1 sends are disabled. A new v2 send holds one activity mutation lease from
the pre-sign capacity and `(account index, sender, nonce)` reservation through
signing, exact pending creation, guarded broadcast, and durable `Submitted`
commit. Only after the installed activity row exactly matches the immutable
transaction identity may the still-open exact pending handle delete that
object. An uncertain commit preserves pending. On retry, an already committed
exact row is cleanup-only. Otherwise an exact typed transaction-by-hash lookup
precedes the sole rebroadcast: an exact node observation commits activity and
cleans pending without sending, `null` may authorize one retry of the same raw
bytes, and mismatch or observation failure preserves pending. No activity
status, including reorg/drop/replacement suspicion, authorizes nonce reuse.

A legacy v1 native pending is migrated without broadcasting or deleting it.
Migration holds its exact lease, verifies the canonical signed bytes/hash,
recovers the legacy account-0 sender, rejects ERC-20/foreign/tampered records,
bookends the namespace, installs and authenticates v2, removes v1 durably, and
transfers the held pending into the v2 retry path. This same-user namespace
protocol does not constitute an OS-wide rollback/creation-prevention service;
production still needs a trusted single-owner storage boundary.

Activity refresh never runs as periodic or background polling. A user may
refresh one row or explicitly start a selected-account sequence frozen from at
most 64 start-of-run `Submitted`, `Pending`, `Reorged`, `DroppedCandidate`, and
`ReplacementSuspected` submission sequences. `Included` and newly appearing
rows are excluded. The coordinator retains only the session epoch, selected
account index, ordered submission sequences, progress, and one deadline; the
sole extra transaction hash remains in the existing zeroizing single-row
target. It dispatches the existing per-row worker request one at a time, sends
the first immediately, and waits at least two seconds after each successful
durable result before the next. The first error, identity drift, lock, or
account change stops and scrubs the coordinator. Here `k/total` counts only
successful responses installed in the UI, and no later queued row is dispatched
after the stop. A failing row may already have reached durable storage before an
authenticated readback error, so its on-disk state is explicitly unknown until
reopen or a direct row refresh; the coordinator does not claim that row stayed
unchanged. There is no bulk backend/storage/RPC method, automatic retry, timer
re-enqueue after completion, or inclusion of rows created after the explicit
click. During the between-row wait the user may stop or switch accounts; no
other wallet mutation may interleave.

Every row still uses stable head bookends around typed transaction, receipt,
canonical-block, and latest nonce observations. Immutable
sender/to/value/input/gas/fees/nonce/hash and transaction-index anchors must
agree. Included success/revert depth is not finality. A single null or
contradictory anchor does not mutate state; three misses spanning at least 64
heads may mark `DroppedCandidate`, and an advanced latest nonce may mark
`ReplacementSuspected`. A stored high-water above the observed head also leaves
the exact row and generation unchanged until the RPC head catches up. This
avoids depth underflow and false reorgs, but can delay updates after a deep
rollback. Starting a sequence discloses the selected sender address, up to 64
transaction hashes, and request timing to the single fixed RPC endpoint.

Each rendered activity row offers an explicit copy of that selected-account
row's already validated full transaction hash. The exact row field is sent to
egui's clipboard command only from the completed button-click branch; the copy
affordance adds no additional retained hash, URL, or explorer-choice state.
Merely rendering the panel, pressing without completing a click, and foreign-
account rows do not copy anything. Lock/session transitions never trigger this
copy, and the copy affordance itself enqueues no worker work. The OS clipboard
may outlive the wallet lock or process, so the UI reports that residual after
copying. The copy affordance deliberately neither constructs nor opens an
explorer URL and grants no external explorer provider authority.

The activity generation is consistency metadata, not an external monotonic
rollback anchor. Every retained row blocks a conflicting nonce slot, but a
deleted or rolled-back valid file can hide ownership; missing history is not
safety evidence. A production design requires an external monotonic anchor and
must not infer nonce reuse from this sidecar's absence.

The fixed `activity-v1.tmp` and `tokens-v1.tmp` names are reconciled only while
their corresponding mutation lease is held. Windows opens the exact orphan with
no sharing and DELETE access, rejects nonregular/reparse/contended objects, then
deletes that same handle and flushes the parent. Brand-new v2 flows pin the
token-then-activity namespaces, re-open and flush both fixed application
directory levels even when they already exist after a crash, and refuse any
pre-existing final sidecar. A wrong-vault, stale, nonregular, or reparse final
sidecar is deliberately not overwritten: open/new-vault activation remains
locked until deliberate manual repair. Legacy migration writes and authenticates
the exact same-directory `vault-v2.migrating` handle, atomically installs that
handle only after final v1/pending/sidecar bookends, rechecks pending once more,
marks v2 committed, and only then deletes the exact held v1 object. A pre-install
crash leaves v1/pending plus a safely reconcilable temp; a post-install cleanup
failure retains the complete v2 and never falls back to v1.

The single fixed TLS RPC remains a trust boundary: it can hide data or fabricate
mutually consistent head/header/receipt views. Canonical signed-transaction
reconstruction proves only local envelope self-consistency; it does not prove
honest propagation or inclusion reporting by that endpoint.

Memory erasure is explicitly incomplete. Owned master/output arrays use
`Zeroizing`, but the `hkdf`/`hmac` 0.12 HMAC/PRK context implements neither
`Zeroize` nor `ZeroizeOnDrop`; password-equivalent derived context can therefore
remain in stack/process remnants. Demo lock scrubs owned secret buffers but is
not a process-memory forensic-erasure guarantee. Production release is
STOP-SHIP without release-attested isolated Key Agent execution and a zeroizing
KDF implementation.

### Sepolia demo receive QR boundary

The receive surface takes only `WalletSnapshot::selected_account()` and the
frame-local constructor independently requires its strict EIP-55 checksum. The
default encoded payload remains exactly `ethereum:<address>@11155111`. An
amount-bearing request exists only behind the user's explicit native-ETH amount
toggle. It accepts a positive decimal ETH input with at most 18 fractional
digits and within the full uint256 range, then canonicalizes it to integer wei
with the existing strict amount parser/formatter and emits exactly
`ethereum:<address>@11155111?value=<canonical-decimal-wei>`. Empty, zero,
malformed, over-precision, overlong, and overflowing inputs fail with the
category-only `InvalidAmount`; no URI, matrix, or URI-copy control is then
created. `pay-` and every other query parameter remain unrepresentable. The
ordinary plain-address copy stays available separately.

QR reveal, the amount toggle, URI copy, and ordinary-address copy are separate
explicit user actions. The selected address, account index, fixed Sepolia chain
ID, and requested amount are public financial metadata. An
amount-bearing EIP-681 URI is only a request: it is neither an enforced invoice
nor proof of payment, and the payer may alter or ignore it. Receipt must be
verified separately against the selected address and on-chain result. Copying a
URI hands it to the OS clipboard, which may retain it after wallet lock or
process exit.

The demo pins `qrcodegen` exactly to 1.8.0 and builds the matrix only in the
revealed frame. Rendering reserves an exact four-module white quiet zone and
uses integer physical-pixel module boundaries with a minimum six-pixel module,
including low pixels-per-point. Layout uses the smaller dimension of the
available rectangle intersected with the current clip rectangle. It verifies
post-allocation that the entire canvas remains inside that clip before painting;
a narrow panel, short viewport, or invalid scale therefore returns a category-
only layout error rather than clipping any part of the symbol. No QR texture,
cache, file, or network path exists.

Receive state retains only the reveal Boolean, the explicit amount-request
Boolean, and a session-only `Zeroizing<String>` input; it never caches a matrix
or URI. Address-only mode is the initialized default. Hiding the receive panel,
turning the amount option off, a valid account-selection request, successful
selection, and a live lock/session scrub all clear the option, zeroize the
amount, and queue deletion of the stable egui text-edit state at the end of that
frame so undo cannot resurrect it. `WalletApp::drop` independently zeroizes the
owned input through
the same frontend scrub. Normal process/context teardown discards egui memory,
but Drop has no `egui::Context` with which to make a separate forensic or
retained-context erasure guarantee. The optional request adds no worker command,
backend/RPC call, storage or schema field, dependency, file access, or network
path; invalid input therefore cannot escape through a fallback URI or copy
action.

### Wallet secret origin firewall

Interactive Sepolia wallet creation accepts only the 12/24-word selection and
password confirmation. `DemoBackend::begin_generate` invokes
`WalletSecret::generate_mnemonic` exactly once; that leaf fills a zeroizing
entropy buffer directly from the operating-system CSPRNG and propagates an
unavailable-randomness error before any wallet is constructed. It never selects
an import path, environment value, seeded generator, fixed entropy, example
mnemonic, private key, or fallback. The Key Agent creation path has the same
boundary: `VaultSession::create_checked` invokes `MnemonicEntropy::generate`
exactly once, and an OS-randomness failure aborts creation.

No production API creates a `WalletSource::RawPrivateKey`-origin wallet from
generated bytes. That wallet source enters only through strict user import or
authenticated vault reopen/migration. Mnemonic account-key derivation and
user-authorized export remain a separate path and do not create a raw-key-origin
wallet. Interactive UI constructors initialize every secret/import field empty,
and the Generate command neither reads nor carries the import buffer. Explicit
headless-smoke sentinels are non-credential-shaped, are consumed only by a fake
backend, and never reach `WalletSecret`, a vault, storage, network, or signing
authority.

Deterministic BIP-39/BIP-32 and raw-key conformance vectors remain public test
fixtures only. They must stay lexically inside `#[cfg(test)]` items or modules
and are not wallets for receiving value. The architecture gate projects all
test-only items out before checking production call inventories, randomness
ordering, fixed-authority sinks, UI defaults, and effective fallback/boundary
mutations.

### Sepolia demo selected-overview hydration boundary

Mnemonic/private-key import, wallet open, legacy migration, and account
selection install their authenticated local snapshot first. Only after that
authoritative transition succeeds does the UI enqueue one epoch-bound overview
request for the exact selected account. Fresh generated-wallet confirmation is
deliberately excluded: its balance remains `조회 전`, so offline creation never
depends on an RPC. Manual refresh uses the same bounded request. The chain
identity subcall retains its bounded three-attempt retry, but there is no timer,
polling, automatic re-enqueue of the overview request, or other-account prefetch.

The worker derives the exact account index and full address again. Its opaque,
non-clone response binds the returned wallet snapshot and saved-token rows to
that index, address, wallet kind, account list, pending record, and activity
rows. The reducer accepts it only for the matching pending action and session,
then requires every non-balance snapshot field to remain exact. A mismatch,
authenticated local-sidecar failure, or revoked permit locks and scrubs. A
chain or balance RPC failure returns a category-only Partial result with ETH
explicitly unknown. An individual token RPC failure marks only that token
Unavailable and may retain an independently verified ETH balance; both cases
leave the wallet open.

Automatic token hydration is bounded to the first three authenticated entries
in stable store order. Every later saved contract remains visible as a deferred
full-address row; the explicit full-token refresh retains the existing 32-entry
path. With `N <= 3`, the no-retry complete path makes exactly `5 + 11N` RPC
calls: the outer trust/balance bookends plus eleven calls per attempted token.
Because each chain-identity verification currently permits three attempts, the
retry-aware hard ceiling is `13 + 19N`, at most 70 calls when `N = 3`. The observation
lease never creates, deletes, reconciles, or flushes a file. On Windows it pins
the existing regular lock/store objects without write/delete sharing, and the
backend compares the exact authenticated token baseline again before cache
installation. True process/share contention is Partial and persistent in the
UI; structural, reparse, read, authentication, or baseline drift is fatal.
Final Sepolia verification discards every earlier network value if its bookend
fails.

This automatic follow-up exposes the selected full address, its timing, and up
to three saved contract addresses to the single fixed TLS RPC. It proves bounded
response and local-object consistency, not provider honesty, propagation, or
chain finality.

### Dormant Windows Broker composition

The Windows composition is reachable only with
`windows-broker-channel-contract-test-hook` and debug assertions. Default builds
and release builds with every feature enabled retain the 4900/exit-78 native
path and the exit-78 Broker path. The hook represents only `eth_chainId`, typed
unavailable completion, and exact cancellation; accounts, arbitrary RPC,
network access, signing, raw calldata, and Key Agent operations have no wire
form.

The native host pins the sibling `broker.exe` without write/delete sharing. A
fresh creator/debugger thread launches it suspended and hidden with an exact
`STARTUPINFOEXW` policy. `HANDLE_LIST` is exactly `[restricted parent process,
shared read/write NUL]`; `STARTF_USESTDHANDLES` binds stdin, stdout, and stderr
to that same NUL handle. `JOB_LIST` is exactly `[job]`, where the retained Job
has active-process limit 1 and kill-on-close, and the child receives only a
minimal two-variable Unicode environment. The first event must be that process's
`CREATE_PROCESS_DEBUG_EVENT`; its executable `hFile` must equal the pinned file
by volume serial plus all 128 `FILE_ID_INFO` bits before the primary thread is
released into user mode. The process, Job, and pinned artifact remain retained
for the channel lifetime, and failure/drop terminates and reaps the exact child.
In the debug-hook child, the numeric parent bootstrap is first required to be
the exact sole inheritable flag, is cleared to non-inheritable, and is copied
with only query/synchronize rights. Rust owns only that fresh non-inheritable
duplicate; the ambient numeric source is never adopted or closed by the safe
API and is reclaimed by process teardown.

The private named pipe has a protected current-logon DACL, a single instance,
remote-client rejection, deadline-cancellable overlapped I/O, and retained peer
process objects on both ends. Pipe-reported process/session identity must match
the retained object and the current TokenUser/logon SID. There is no
`OpenProcess` or PID-derived reopen path, and raw pipe names, handles, and PIDs
do not cross the public facade. The channel alone owns a four-byte big-endian
prefix and an 8,192-byte JSON payload ceiling. Broker's closed typed state
machine is payload-only; its legacy stdio adapter separately owns the same
single prefix, preventing double framing. Replay, partial frames, deadlines,
peer exit, malformed JSON, and the 4,096-command boundary close the session
without resynchronization.

This headless proof authenticates the child Broker image and both local channel
peers, but it cannot authenticate the already-running native host that Chrome
started. Release remains blocked on an immutable signed install, protected
native-messaging registration, a stable release extension ID, and end-to-end
signed-artifact/installer evidence. The debug artifact hold is not an
Authenticode release allowlist and must not be described as one.

The ordinary platform library now also contains a private, dormant Broker
artifact-admission boundary. Release evidence binds a dedicated Broker
transport-suite digest and one non-zero Broker manifest digest separately from
the exactly three signing-TCB helper manifests. Admission consumes the pinned
verified artifact and checks Broker role, complete compiled release evidence,
the dedicated manifest, and an absolute verified path in that order before it
can mint `PreflightBrokerArtifact`. That non-clone capability retains both the
pinned Broker and the opaque whole-release `AttestedArtifactDigest` accepted by
`ReleaseAttestation`. The latter denotes the overall `ReleasePolicy`
`ArtifactDigest`, not the dedicated Broker/helper manifest digest or a Windows
file-object identity, and it has no raw-digest accessor. A Windows-only private
preparation seam then consumes that capability by value. It queries volume
serial and all 128 `FILE_ID_INFO` file-ID bits from the same already-held file handle
and retains the verified artifact, unchanged opaque whole-release proof,
and separate opaque file identity in `PreparedReleaseBrokerSupervisor`. Only the
admission module can invoke the supervisor's `pub(super)` constructor, so no
sibling module can combine an unadmitted artifact with an unrelated ID.

A production-compiled, crate-private Broker activation core consumes the whole
prepared value exactly once. It uses the retained verified path only as the
`CreateProcessW` application name, never to reopen or rederive expected identity;
then a fresh creator/debugger thread verifies the first
`CREATE_PROCESS_DEBUG_EVENT` mapped-image handle against the prepared identity
before user mode. The exact process, active-process-limit-one kill-on-close Job,
private process-bound channel, and entire prepared value stay owned together
through synchronous cleanup. Its release entry accepts no path, raw handle, PID,
command line, application override, or generic launch target. The separate
debug-only sibling-path wrapper remains behind its feature and debug assertions.
The retained release proof is not a Broker-plus-Key-Agent same-release aggregate,
authenticated process topology, single-instance proof, or
runtime/signing authority. No production caller reaches this release-bound
Broker preflight, preparation, or activation path.

`COMPILED_RELEASE_POLICY` remains `None`; the default and all-feature release
binaries therefore remain on the 4900/exit-78 path. This dormant activation core
is not release reachability, signed-install/native-host provenance, authenticated
process topology, or negative release evidence.

### Inheritable-handle process-creation coordination

The linked `platform-windows` crate instance contains one private,
deadline-bound process-wide coordinator for its three production Rust
inheriting-creation paths: restricted helper launch, dormant Broker activation,
and dormant Key Agent activation. Each path acquires a non-reentrant,
thread-bound flight before its first temporary inheritable handle. The Broker
parent/NUL owners, restricted-launch duplicate owner, and Key Agent prepared
stdio owner borrow the flight lifetime. The restricted launch attribute list
also borrows its kill-on-close Job and installs `PROC_THREAD_ATTRIBUTE_JOB_LIST`,
so the suspended child is born in that Job and exact membership is verified
before token verification or resume. Raw Rust `CreateProcessW` with
`bInheritHandles=TRUE` is sealed behind the flight method. After that call
returns, the per-launch `STARTUPINFOEX` attribute list and every temporary
inheritable owner are destroyed before the flight is released; debug-event
authentication, token/Job verification, callbacks, and resume occur afterward.
Waiting is bounded by the caller/startup deadline (and the restricted launcher's
internal coordination limit), same-thread reentry fails, and unwind through a
live flight permanently poisons the coordinator. This deadline bounds flight
acquisition and explicit pre-create admission checks; synchronous Windows
`CreateProcessW` and the fresh worker's eventual join are not interruptible by
the coordinator and can exceed it.

This closes the cooperating in-process race that `HANDLE_LIST` alone cannot:
while the Broker's parent/shared-NUL handles, the Key Agent's three stdio
duplicates, or a restricted helper's duplicates exist, neither of the other
Rust paths can enter its inheriting creation window. The guarantee is scoped to
one loaded crate instance and callers that use its private API. It is not an OS
hook and does not intercept arbitrary foreign FFI, `std::process::Command`, a
separately linked copy, or a different process. The release PowerShell runtime's
C# toolset runner therefore uses a separate matching static lock around its own
inheritable pipe creation, `CreateProcessW`, attribute-list deletion, and
temporary child-end cleanup. That lock serializes only cooperating calls through
that C# runner type and is not shared with the Rust coordinator.

### Key Agent activation invariant (STOP-SHIP)

Windows routes debug events to the thread that created the debuggee. The activation
boundary therefore performs `CreateProcessW`, the complete bounded
create/loader/system-breakpoint/semantic-gate event loop, every
`ContinueDebugEvent`, and `DebugSetProcessKillOnExit(FALSE)` on one fresh
dedicated OS thread that owns no other debuggee. The caller cannot contaminate or
consume that worker's event queue. `DebugActiveProcessStop` is not used: its
PID-only path conflicts with the deny-only process creation DACL. The documented
debugger-thread-exit behavior provides detach without a PID reopen.

The same creator installs an exact five-slot `STARTUPINFOEXW` attribute list in
`HANDLE_LIST` -> `JOB_LIST` -> `MITIGATION_POLICY` ->
`SECURITY_CAPABILITIES` -> `ALL_APPLICATION_PACKAGES_POLICY` order. The
mitigation word is identical to the restricted-helper and service-startup
policy, including the non-Microsoft-binary block, and remains at a heap-stable
`Box<u64>` address until `CreateProcessW` returns and the attribute list is
deleted. This lifetime/order hardening does not make the dormant activation a
production path.

The first event must be the exact pre-user-mode `CREATE_PROCESS_DEBUG_EVENT` for
the returned PID and primary thread. Its image `hFile` is compared with the
still-held verified artifact by volume serial and the complete 128-bit
`FILE_ID_INFO`. Per [MS-FSCC 2.1.10](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/98860416-1caf-4c80-a9ab-8d61e1ccf5a5),
an all-zero ID means the filesystem does not support that identity and all-`FF`
means a unique ID could not be established; both are rejected rather than
compared. A zero volume serial is also rejected.

The original `CREATE_SUSPENDED` count is consumed to let Windows produce this
first event, so the explicit count is zero while the create event itself freezes
the process. Only after the mapped-image proof succeeds does the worker verify
the exact process token and mint the pending token proof. The LPAC proof
requires an exact DWORD `TokenIsAppContainer == 1`, the fixed Key Agent profile
SID, and zero `TokenCapabilities`. It duplicates the primary token at
`SecurityIdentification`, queries its valid `TokenUser` SID, and performs two
`CheckTokenMembershipEx` access-membership checks. `CTMF_INCLUDE_APPCONTAINER`
alone must return false, while adding `CTMF_INCLUDE_LPAC` must return true.
When `TokenIsLessPrivilegedAppContainer` is supported it must also return an
exact DWORD 1. Some supported Windows builds return `ERROR_INVALID_PARAMETER`
for only that information class; that single result omits the DWORD check but
does not relax the exact `(false, true)` differential. Any other query error,
malformed result, SID mismatch, capability, or membership pair fails closed. A
separate suspended ordinary-AppContainer control omits only the AAP opt-out and
must produce `(true, true)`; neither control is resumed into user mode.

Only the verified gate-pending LPAC state may continue the create event. As soon
as that event exposes independently safe process/thread aliases, their raw slots
and PID/TID are registered in a witness-branded shared cleanup owner, before
hFile, mapped-image, ID/object, LPAC, or later fallible checks. A malformed
partial set still retains every independently safe alias. They remain
system-managed while the debugger relationship is attached. The worker then
enters the test/production-identical strict loader loop. The actual
GUI-subsystem Key Agent regression rejects non-primary loader activity before
detach and verifies Job cleanup with root active-process count one; the separate
minimal import-free GUI PE fixture proves exact-primary gate mechanics but not
product compatibility. The pre-resume default-DACL matrix additionally excludes
the current same-user LPAC architecture: it cannot deny `WRITE_DAC` from birth
and remain loader-compatible. A revised loader policy could exercise the
compiled gate mechanism but cannot repair that gap; the next architecture option
is a distinct OS principal/service boundary. Only conditionally, if such a later
event freezes every thread, does the implementation add exactly one explicit
primary-thread suspend count, finalize and read back the default DACL, and
continue while retaining that count. Only after all remaining gate checks may
the no-kill arm require a complete
authenticated registration and make `DebugSetProcessKillOnExit(FALSE)` the final
fallible operation; only infallible phase and ownership moves follow. The opaque
final owner can cross the boundary but exposes no detached, process, or resume
operation. The dedicated OS thread then exits and is joined.

Marking that exact witness joined activates the shared alias cleanup. A worker
`Err`, worker panic, or abandoned joined proof performs post-join checked closure;
normal finalization takes the registered aliases and transfers them into the
pending process owner for reauthentication and closure. Failed adoption restores
the set, partial close retains the unclosed slot, and the last shared owner makes
bounded retries after join. Each cleanup pass attempts the process and thread
aliases independently, even if the other validation or close fails; post-join
process wait/exit-code failure likewise cannot starve alias closure. Explicit cleanup failure takes precedence; `Drop`
cannot report its result.

Caller-side finalization accepts only the exact witness shared by the final
owner, the non-`Send` join proof, and the root Job cleanup gate. It then requires
`CheckRemoteDebuggerPresent == false` on the retained creator process handle,
reauthenticates and closes the registered event aliases, performs an exact
`SuspendThread`/`ResumeThread` 1→2→1 probe on the retained creator primary-thread
handle, and renews LPAC/root-Job, provisioning, and lease checks. Only this path
may reach the private attenuation step described below. The debugger-thread-bound
state stays non-`Send`; the transfer-only pending state exposes no authority; the
detached wrapper is `Send`, neither `Sync` nor cloneable, and exposes no raw
handle or generic resume API. Its only consuming execution transition releases
that one count for the fixed storage-startup proof described below; otherwise it
may only report redacted metadata. Before the exact debugger thread is joined,
cleanup requests retained-handle termination and relies on debugger-thread exit
plus the kill-on-close Job without blocking that thread. After join, ordinary
bounded synchronous process/Job cleanup is restored; Drop cannot report failure.

The three-artifact release allowlist is not launch-role authority. Both generic
restricted-launch entry points reject a manifest-derived Key Agent before
release evaluation or Win32 side effects. Only this private activation module
may create that role.

The private fresh-provisioning selector has no caller input. It can create the
fixed, persistent `YourWallet.KeyAgent.LPAC.v1` profile and the fixed
`YourWallet.KeyAgent.Storage.v1` leaf beneath the exact OS-reported `AC` folder,
but returns only a non-launchable pending capability. Activation accepts a
separate prepared capability, and no direct pending/candidate conversion exists.
The separate dormant `open_existing_fixed_key_agent_storage_root` is a
storage-only root acquisition seam with zero production callers. It accepts only
an observer-validated `AC` folder and live fixed-profile SID, hard-codes that
same fixed leaf, and performs no create, repair, delete, adoption, or recovery.
It rejects thread impersonation, opens with `OPEN_EXISTING`,
`FILE_FLAG_OPEN_REPARSE_POINT`, and no delete sharing, then verifies the initial
handle's directory/non-reparse state, local NTFS, exact owner/protected DACL/
inherited Low-`NW` label, and complete `FILE_ID_INFO`. It canonicalizes and
reopens the path under the same policy, requires identical security and full
identity, and retains only the reopened handle plus a private canonical path.
Its revalidation checks both the held handle and another canonical-path reopen.
Unlike the fresh selector it never calls `CreateDirectoryW`; unlike the child
opener it does not derive `LOCALAPPDATA` or principals from a child token.
It grants no profile-observation, held-aggregate, `Prepared`/`Verified`, journal/
checkpoint, recovery/activation/signing/RPC/GUI, supervisor-owner, or Broker+Key
Agent same-release authority.
The sole production-compiled mint is the private sealed existing-install
transition. It consumes an initial and contractually post-observation
authenticated snapshot plus a fixed-profile binding and retained
no-delete-share root, revalidates the binding and held root before and after the
pure match, and seals the prepared capability inside
`VerifiedExistingKeyAgentInstall`. The implemented dormant release-binding
preflights the held Key Agent, then constant-time compares the authenticated
journal `release_identity` with the whole-release `ReleasePolicy`
`ArtifactDigest` accepted by `ReleaseAttestation`. It is not the helper-manifest
digest or a Windows file identity: those independently bind the child
role/version/executable/signer and exact file object. Only a successful match
constructs `ArtifactBoundExistingKeyAgentInstall`; only the supervisor's
private-field seal can split it, and install continuity remains retained in the
dormant and storage-proven states. The adoption transition, release-binding,
and dormant supervisor binder nevertheless have zero production call sites.
The root-only opener also has zero production call sites and cannot construct
`HeldExistingKeyAgentInstallObjects`, `PreparedKeyAgentProvisioning`, or
`VerifiedExistingKeyAgentInstall`. Production still has no authoritative
profile-registration observer or held-aggregate constructor, and no exclusive
installer lease enforces checkpoint/post-observation reread ordering, so the
opener cannot reach adoption or activation. The newly returned SID must equal an independently
derived SID for the fixed profile name. Process creation installs a null capability pointer,
capability count zero, reserved zero, and the ALL APPLICATION PACKAGES opt-out;
releasing the prepared SID does not delete the OS profile.

The supervisor retains a non-clone proof whose held directory handle omits
delete sharing. It validates a stable current-`TokenUser` owner and exact
protected two-ACE DACL for that SID and the fixed profile SID, the exact inherited
Low/`NW` mandatory-label ACE, fixed local NTFS with persistent ACLs, non-reparse
directory state, and a nonzero-volume, non-sentinel 128-bit `FILE_ID_INFO`. The
proof revalidates that held identity, volume, and security policy plus the
private canonical-path reopen before binding, on the fresh worker, after
activation, and remains held until cleanup closes it last. This path comparison
detects rebinding but does not make metadata-based ancestor validation atomic.

The private storage-startup transition now proves that this exact child opens and
retains the same root object. While the child remains suspended, the parent sends
one fixed request containing a fresh nonce, its held PID and process creation
`FILETIME`, the complete volume-serial/128-bit file identity, and only the fixed
production leaf or exact test-leaf grammar. The consuming write closes the sole
parent request endpoint, and only then does the transition release the verified
suspend count. The child requires the exact 188-byte request followed by EOF
before decoding or opening the root. It then detaches both ambient protocol
entries, closes the raw stdin handle, and retains raw stdout only in a
response-capability object. Only after that preflight does it resolve the leaf
through its OS-rerouted `LOCALAPPDATA`, derive `TokenUser` and the AppContainer
SID from its own token, and verify the directory object, exact owner, protected
DACL, inherited Low/`NW` mandatory label, and full `FILE_ID_INFO`.

The child then consumes its held-root capability into exactly four private,
non-cloneable, thread-bound bindings. `Vault`, `NonceLedger`,
`SignedCandidateJournal`, and `LocalSettings` are minted together once; their
fixed namespace/class/ciphertext-bound tuples are respectively
`vault`/Vault/4,194,416, `nonce-ledger`/NonceLedger/16,777,216,
`signed-candidate-journal`/SignedCandidateJournal/16,777,216, and
`local-settings`/LocalSettings/226. The binding constructor and fields are
private, and `WindowsBackend::open_key_agent` accepts only one sealed binding.
It receives no caller path, SID, record class, bound, or frontend selector. The
public `WindowsGenerationStore` is unchanged and remains
stable-`TokenUser`-only.

For the Key Agent backend, every lock, slot, manifest, and same-directory
temporary file must be owned by the stable `TokenUser`. Its protected DACL has
exactly two canonical explicit allow ACEs in order: `FILE_ALL_ACCESS`
(`0x001f01ff`) for that user and
`FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE` (`0x0013019f`) for the exact
Key Agent profile SID. Its only SACL ACE is the inherited Low/`NW` mandatory
label with `INHERITED_ACE` (`ID`) as the only ACE flag. No frontend or broad
principal, deny/inherited DACL ACE, extra ACE, reordered ACE, or mask drift is
accepted. Persistent-file verification rejects reparses and link counts other
than one, reads full `FILE_ID_INFO`, and requires the root volume. Every fixed
child-path open, create, delete, and replace is surrounded by thread-
impersonation plus held/reopened-root identity revalidation. Atomic replacement
also compares the target's identity/absence baseline before and immediately
before replacement, then reopens and binds exact installed bytes, hash, full
identity, and security. The backend security-context hook likewise bookends
every untrusted fault callback, including both callbacks around rollback-anchor
advancement.

The integrated `cfg(test)` zero-capability LPAC path consumes these bindings and
opens all four stores. It commits/loads generation one, closes/reopens, then
loads and commits generation two. For each role it verifies the lock, two slots,
manifest, and three temporary names. On every one of those seven names,
`WRITE_DAC`, `WRITE_OWNER`, and `FILE_EXECUTE` must return `ACCESS_DENIED`, while
`ACCESS_SYSTEM_SECURITY` must return `PRIVILEGE_NOT_HELD`. The held-root matrix
is separate: an actual `DELETE` open must encounter the retained handle's
`SHARING_VIOLATION` and a separate `AccessCheck` must deny that right;
`FILE_DELETE_CHILD`, `WRITE_DAC`, and `WRITE_OWNER` return `ACCESS_DENIED`, while
`ACCESS_SYSTEM_SECURITY` returns `PRIVILEGE_NOT_HELD`. This retires only the
narrow private generation-file adapter/DACL
implementation gap. The fixture uses a persistent test profile, CSPRNG leaf,
in-memory anchors, and synthetic authentication keys/payloads; it is not a
production fresh fixed profile/root E2E.

Fresh object creation is now a non-launchable pending typestate. The activation
path accepts only a prepared typestate, and no direct pending/candidate
conversion exists. The sole production-compiled prepared mint is the private
sealed existing-install transition described above. A separate pure provenance boundary now
contains both the candidate classifier and a canonical prefix-journal verifier.
The verifier authenticates each fixed record with an installer-owned
HMAC-SHA256 key before parsing, requires the exact `Prepared=1`,
`ProfileCreated=2`, `RootCreated=3`, `Committed=4` phase/generation sequence and
predecessor commitments, and compares the complete current journal commitment
and high-water generation with a separately sealed rollback-resistant
checkpoint. Phase-specific payloads prevent early records from claiming a root
that does not yet exist; the final two phases must bind the same canonical
profile/owner SIDs and full root identity. The committed journal
`release_identity` is exactly the whole-release `ReleasePolicy`
`ArtifactDigest`, not a helper-manifest digest or `FILE_ID_INFO`. A different
committed whole-release identity is therefore recovery-required under the
current contract, not an in-place upgrade. Rollback, gaps, same-generation
equivocation, reordered phases, and malformed or non-canonical bytes fail
closed. The validator produces an authenticated snapshot only after journal and
checkpoint validation. The pure matcher consumes two matching committed
snapshots plus authority-free evidence copied from a fixed-profile-binding and
held-root aggregate; only exact current `Committed=4` consistency can produce
stable evidence. Its sole production-code consumer is the dormant sealed
transition, which bookends that match with revalidation and retains the same
objects inside a private verified aggregate. The provenance module performs no
I/O and retains no root handle. The journal validator has no production
installer-key/checkpoint constructor, reader/writer backend, or caller; the
transition itself has no production caller. Its compiled downstream
release-binding preflights the held child, performs the constant-time
whole-release comparison, and mints only a private artifact-bound aggregate.
The supervisor's sealed split retains journal continuity beside the exact-image
activation proof. Neither the binding nor the supervisor binder has a production
call site, and the retained continuity is not runtime/signing IPC,
installer-key, rollback-anchor, storage/AEAD-key, or
protected-settings/lease authority.

Production still lacks authoritative profile-registration observation and a
held-aggregate constructor, a production caller for the dormant fixed
existing-root opener or adoption/binding path, an exclusive installer lease
enforcing the post-observation reread, production installer-key/checkpoint and
journal I/O backends, recovery, and release-activation orchestration. Without the exclusive installer
lease covering checkpoint/observation/reread ordering, the dormant binding does
not open production upgrade orchestration. The `TokenUser` ACE
still permits other same-user processes, and
ancestor path validation is metadata-based rather than atomic. Production
rollback-anchor and storage/AEAD-key provisioning, protected settings and its
live lease, authenticated Broker/supervisor topology and single-instance,
signed immutable artifact and DLL/dependency E2E, and release activation remain
**STOP-SHIP**. Exact request EOF and the parent's authoritative
response-plus-EOF/deadline proof provide only repo-local startup framing; they
add no generic runtime/signing IPC, signed-artifact evidence, or release
authority. `COMPILED_RELEASE_POLICY` is `None`.

Parent-side Key Agent, Approval, and Secret Input profile creation/derivation,
plus Key Agent `GetAppContainerFolderPath`, share one process-wide non-reentrant
coordinator. This central profile API rejects thread impersonation before gate
acquisition and again after waiting for the mutex. Every protected
`CreateAppContainerProfile`, `DeriveAppContainerSidFromAppContainerName`, and
`GetAppContainerFolderPath` call is immediately preceded and followed by the
same check. A successful raw SID or `CoTaskMem` path is captured in a private
RAII owner before the post-call check, so that owner releases it even when the
check or later validation fails. Except for the binding's necessary
success/error split used to capture a successful allocation, specific native-
error branching and inspection, pointer/SID validity, path decoding and
validation, SID comparisons, and application use occur only after the post-call
check succeeds. These bookends are fail-closed observations, not an atomic
proof that an impersonation token could not be installed and removed between
the checks. A failed post-call check after a successful
`CreateAppContainerProfile` deliberately performs no automatic
`DeleteAppContainerProfile` or rollback: fresh Key Agent provisioning may
already have created the profile and requires recovery. This contract neither
mints profile-registration authority nor expands production reachability, and
there is no production `DeleteAppContainerProfile` path. Same-thread reentry and
a poisoned gate fail closed, and the gate is released before inherited-handle
launch coordination or process creation.

The separate Secret Input child process does not share that parent-side mutex.
Its sole deterministic `DeriveAppContainerSidFromAppContainerName` call uses
child-local pre- and post-call thread-impersonation checks and captures any
successful raw SID in a private RAII owner before the post-call check. Except
for the minimal success/error split needed for that capture, native-error
interpretation, SID-validity checking, and `EqualSid` occur only after the
post-call check succeeds; the owner releases the SID on every failure path.
These bookends are likewise fail-closed observations, not atomic proof that an
impersonation token could not be installed and removed between them. This child
boundary adds no `CreateAppContainerProfile`, `GetAppContainerFolderPath`, or
`DeleteAppContainerProfile` call, profile-registration authority, or new
production reachability. `COMPILED_PARENT_POLICY` remains `None`.

Approval now has a separate dormant release-admission type state before any
activation machinery. It consumes a pinned `VerifiedHelper` into
`PreflightApprovalArtifact` only after the manifest-derived Approval role,
complete release attestation, helper-manifest allowlist, and absolute path pass
in that order. Its sole preparation transition
queries `FILE_ID_INFO` from the same retained file handle and moves the artifact,
opaque whole-release identity, and exact file identity into the non-cloneable
`PreparedReleaseApprovalSupervisor`. The module allocates no process, Job, pipe,
channel, thread, launch state, or second file handle and exposes no artifact,
path, identity, PID, or raw-handle accessor. The legacy direct Approval launcher,
pending response owner, broad `LaunchedHelper`, and `RestrictedLauncher::spawn`
are crate-private and have no production orchestration caller. The legacy
launcher fails before nonce, pipe, process, or request work when the logical
parent aggregate is absent; generic `spawn` independently rejects Approval with
`ApprovalRequiresParentBoundActivation`, and its internal legacy launch leaf
accepts only Secret Input, so neither is a parentless Approval resume edge.

At Approval-session issuance, the platform samples one opaque monotonic window
internally and splits it into non-Clone authorization and transport halves with
the same issuance identity. `wallet-protocol` retains both privately and drops
the unused transport half on invalidation. The Key Agent constructs one request
from the exact authorization digest, one-shot nonce, canonical display, and
protected anti-phishing phrase; only the matching authorization half can consume
the transport half and bind that whole request into opaque
`BoundApprovalTransport`.

The next private transition consumes that complete Approval preparation and an
intact `BoundStorageProvenKeyAgent`. It duplicates the same retained running Key
Agent process object directly—never by reopening its PID—into one fresh,
non-inheritable handle with exactly
`PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`. Pre/post duplication checks
revalidate resident-process liveness, storage, root-Job membership and limits,
and the permitted Key Agent root-Job topology. The resulting
`ParentBoundReleaseApprovalSupervisor` owns the full storage-proven aggregate,
the narrow handle, and the full Approval preparation without exposing any
constituent, identity, PID, path, raw handle, desired-access selector, or launch
operation. The production binder has exactly one private consumer. That
consumer first consumes `BoundApprovalTransport` and rejects elapsed original
expiry before pipe or process allocation. It then creates the fixed two-object
Approval stdio boundary and exact Approval process in the revision-v1 LPAC and
single-process Job, but leaves the primary thread suspended. It preserves the
existing channel-supervisor process/image proof and separately copies the narrow
Key Agent handle into the child as a fifth non-inheritable logical-parent
capability. The resulting `BoundDormantApproval` owns
the process, thread, Job, unused parent endpoints, complete parent-bound
aggregate, and carrier, exposes no direct resume/request/response/signing
or resource accessor, and attempts bounded Approval termination and reap before
releasing the pipes and Key Agent tree. This outer transition has zero
production callers.

One further sealed consuming transition derives the bootstrap deadline as the
earlier of the carrier's original expiry and a fresh five-second grace. It
writes the exact version-2 parent hello before releasing exactly one
primary-thread suspend count, reads and decodes the exact child hello, and
revalidates the live child/Job and intact parent-bound
aggregate. Its opaque `AuthenticatedApprovalBootstrap` retains the running
Approval, unused endpoints, both hellos, the full Key Agent aggregate, and the
carrier. It has no protocol method; only one separate sealed function may
consume it, and that function accepts no raw request or deadline. The transition
has zero production callers.

That full-exchange function opens the carrier internally and uses its exact
canonical request and original monotonic deadline for response arming, the
consuming finish-plus-request write and request EOF, the fixed response and response EOF,
and the exact held child's natural-exit wait. It revalidates child/Job and Key
Agent state before arming and before reading the response. The verified response
remains exit-pending until the exact process exits naturally with code 0 before
the same deadline. No success evidence is manufactured by terminating a live
child. Final Key Agent revalidation occurs only after that successful exit,
followed by one last observation of the same deadline. Only then does the
transition mint crate-private opaque `VerifiedParentBoundApprovalExchange`,
which retains the exited child, intact parent-bound aggregate, both hellos,
sealed response evidence, and original request/lifetime carrier but exposes no
response or signing conversion. This transition also has zero production
callers. The post-exit Key Agent check is
point-in-time evidence; any future evidence-to-authorization transition must
revalidate the retained exact Key Agent again immediately before use. No such
transition exists. Early failures and natural-exit
timeout, nonzero code, or wait failure use separate bounded terminate/reap where
a child remains owned; cleanup error takes precedence. Drop retains the
kill-on-close fallback without claiming unconditional reap success. Bootstrap
v2 binds the distinct supervisor and Key Agent authorities into one child
transcript while retaining the supervisor as the pipe peer. The
logical-parent capability does not set `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, select
the child's Windows parent, authenticate a mapped image, or establish a runtime
security boundary. A `cfg(test)` integration now copies the exact narrow handle
non-inheritable into an actual zero-capability Approval LPAC. The child proves
`OpenProcessToken(..., TOKEN_QUERY)` on that Key Agent logical-parent process
proof, `TokenSessionId`, image query, exact
PID/liveness/zero flags, then rejects twelve stronger or standard-control token
rights. Its local `DuplicateHandle` denial matrix requests
`PROCESS_DUP_HANDLE`, `PROCESS_TERMINATE`, `PROCESS_CREATE_THREAD`,
`PROCESS_VM_OPERATION`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`,
`PROCESS_CREATE_PROCESS`, `PROCESS_QUERY_INFORMATION`, `PROCESS_SET_QUOTA`,
`PROCESS_SET_INFORMATION`, `PROCESS_SET_LIMITED_INFORMATION` (`0x2000`),
`PROCESS_SUSPEND_RESUME`, `WRITE_DAC`, `WRITE_OWNER`, `READ_CONTROL`, and
`DELETE`. Its PID-only reopen denial matrix requests `PROCESS_DUP_HANDLE`,
`PROCESS_QUERY_INFORMATION`, `PROCESS_QUERY_LIMITED_INFORMATION`,
`PROCESS_SET_LIMITED_INFORMATION` (`0x2000`), `SYNCHRONIZE`, the exact
query-limited/synchronize combined mask, and `WRITE_DAC`; it also proves the parent-supplied
`SeDebugPrivilege` LUID is absent.

The production activation path now also prepares process and primary-thread
creation security from the launcher's current token. Bounded exact token queries
capture `TokenOwner` and `TokenPrimaryGroup`; two distinct `LocalAlloc`
self-relative descriptors each back a non-inheritable `SECURITY_ATTRIBUTES`.
Each descriptor has a protected DACL with no allow ACE and exactly one zero-flag
`OWNER RIGHTS` (`S-1-3-4`) deny ACE. Its mask is exactly `0x000e0000`, or
`READ_CONTROL | WRITE_DAC | WRITE_OWNER`. The process and primary-thread
attributes are an inseparable pair passed together to `CreateProcessW` as
`lpProcessAttributes` and `lpThreadAttributes`.

Before the first `ResumeThread`, the exact process and primary-thread handles
returned to the creator must match their returned PID/TID and return flags
exactly zero from `GetHandleInformation`. Bounded exact
`GetKernelObjectSecurity` descriptor readback must match the captured owner and
primary group, expected self-relative/DACL-present/protected control state, a zero
SACL offset in the requested owner/group/DACL projection, the single exact no-flag
deny ACE and binary `OWNER RIGHTS` SID, and exact ACL/descriptor bounds with no
slack or trailing bytes. The readback does not request the SACL and therefore does
not prove its actual absence. Any mismatch aborts and cleans up the child;
descriptor owners are dropped before resume. The creator handles remain the
pre-detach authority without any PID/TID reopen, but do not enter `Held`.

The first `CREATE_PROCESS_DEBUG_EVENT` must also supply valid process and thread
aliases that are distinct from each other and from the creator handles, report the
same PID/TID, and compare as the same two kernel objects. They are only observed
while the debugger relationship is live, when Windows manages them. Every
independently safe raw alias moves into the shared per-run cleanup registry
immediately after event extraction and before hFile or any other fallible
authentication; no-kill later requires the complete authenticated set. After the matching debugger OS thread
is joined and `CheckRemoteDebuggerPresent` returns false, normal finalization
requires both aliases still to be present and distinct, reauthenticates their
object equality, PID/TID, and exact-zero handle flags, and performs checked
`CloseHandle` calls on the thread alias and process alias exactly once. Worker
error, panic, abandoned join proof, adoption failure, and partial closure retain a
post-join owner and checked-close/retry route. Each pass attempts both aliases
independently, and process cleanup failure cannot prevent post-join alias closure. This thread-exit detach path
supplies no later exit event on which the supervisor can rely; the tested host
kernel leaves the aliases live. Equivalent kernel evidence across supported
Windows variants remains **STOP-SHIP**.

Only after detach verification does the supervisor use `DuplicateHandle` to make
three non-inheritable, options-zero capabilities. The resident process handle has
exact mask `0x00101001` (`PROCESS_TERMINATE |
PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`). An ephemeral post-detach probe
requests exactly `THREAD_SUSPEND_RESUME` (`0x2`); modern-host kernel readback shows
that Windows automatically adds `THREAD_RESUME`, producing effective
`GrantedAccess == 0x1002` with attributes zero. A separate storage-startup handle
requests and retains only `THREAD_RESUME` (`0x1000`). Every duplicate must have
exact-zero flags and compare as the same kernel object as its creator source.

The narrow process itself proves PID and liveness and revalidates current-token
and root-Job continuity. The ephemeral `0x1002` handle itself performs the second
exact 1→2→1 suspend-count probe and is checked-closed before `Held`; a failed
checked close retains the RAII owner so ordinary `Drop` immediately retries. Kernel tests
read back the retained thread as exact `0x1000`/zero attributes and prove that
`SuspendThread` through it fails with `ERROR_ACCESS_DENIED`. Only after those
checks are the creator thread and process handles closed, in that order, with
checked kernel results; `Held` cannot be minted earlier.

The current Microsoft Learn [`ResumeThread` contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
still says that a thread handle must have `THREAD_SUSPEND_RESUME`, while the
current SDK exposes the distinct `THREAD_RESUME` (`0x1000`) right and host plus
integration kernel tests prove the resume-only operation. This documentation/SDK
disagreement, automatic-right addition, and behavior across supported Windows
versions remain **STOP-SHIP** kernel-proof obligations.

The detached suspended capability is `Send` but `!Sync`, `!Clone`, and `!Copy`.
Its sole consuming startup transition revalidates the narrow process, requires
`ResumeThread` on the exact resume-only `THREAD_RESUME` handle to return the prior
count one, and immediately checked-closes that handle, again retaining RAII retry
ownership on a failed checked close. The running type
structurally owns no thread handle, only the narrow process capability, and has
the same transfer traits. That process mask is sufficient for resident
PID/liveness/token checks and bounded reject termination/wait/exit-code cleanup.
Explicit transition failures perform synchronous cleanup with cleanup-error
precedence; `Drop` retries cleanup but cannot report failure.

Kernel tests preserve process and primary-thread pseudo-handle behavior, then
disable `SeDebugPrivilege` and `SeTakeOwnershipPrivilege` and prove fresh owner
PID/TID single-access opens are denied.

Token hardening has gate-pending and final phases. At
`CREATE_PROCESS_DEBUG_EVENT`, the supervisor opens the then-current token as
`Hwrite` with exactly `TOKEN_QUERY | WRITE_DAC | READ_CONTROL` and separately
opens `Hadjust` with exactly `TOKEN_QUERY | TOKEN_ADJUST_DEFAULT`. Before
mutation, `CompareObjectHandles` must prove exact token-object equality. This
phase installs only the token-object DACL and immediately performs a bounded
two-pass
`GetKernelObjectSecurity(DACL_SECURITY_INFORMATION)` readback through that same
opened handle. The first pass must return `ERROR_INSUFFICIENT_BUFFER` with a
1..=64 KiB requirement; the aligned second pass, its returned length, and
`GetSecurityDescriptorLength` must agree exactly. The result must be a valid
self-relative descriptor with a present/protected, non-defaulted,
non-auto-inherited DACL. Its self-relative bounds, `ACL_REVISION`, zero reserved
fields, and exact ACL/descriptor end admit exactly three zero-flag explicit
`ACCESS_ALLOWED_ACE`s in order: stable `TokenUser` SID with `TOKEN_ALL_ACCESS`,
fixed Key Agent SID with `TOKEN_QUERY | TOKEN_DUPLICATE`, then fixed Approval SID
with `TOKEN_QUERY`. Every mask, declared SID length, SID byte sequence, and ACE
size must consume its exact region; extra ACEs and ACE/ACL/descriptor slack or
trailing bytes fail closed. A fresh `Hfinal` with exactly
`TOKEN_QUERY | TOKEN_DUPLICATE | READ_CONTROL` must compare as the same object
and pass LPAC, token-object-DACL, and identity checks. `Hwrite` is checked-closed;
`Hadjust` remains only inside opaque `PendingKeyAgentLpac`, minted by
`PreparedKeyAgentLpac::prepare_suspended_process_for_gate(...)`.

The eight-case pre-resume `TokenDefaultDacl` kernel matrix now fixes the current
same-user LPAC boundary. In the green
`pre_resume_token_default_dacl_matrix_proves_loader_and_same_user_boundary`, the
no-mutation and exact original-DACL deep-copy controls both reach user mode and
exit 0. All six deny-first cases exit exact `0xC0000142`
(`STATUS_DLL_INIT_FAILED`): an `OWNER RIGHTS` deny mask `0x000e0000` remains
loader-fatal across the tested `SYSTEM`, exact-package, and child-user
`GENERIC_ALL` combinations. The green
`pre_resume_owner_rights_deny_mask_axis_proves_each_standard_right_breaks_loader`
also grants all three principals `GENERIC_ALL` and shows that a standalone
`READ_CONTROL`, `WRITE_DAC`, or `WRITE_OWNER` `OWNER RIGHTS` deny is individually
loader-fatal. The sanitized original default DACL is exactly child-user
`GENERIC_ALL`, `SYSTEM` `GENERIC_ALL`, logon-session
`GENERIC_READ | GENERIC_EXECUTE`, and exact-package `GENERIC_ALL` allows. The
green `lpac_package_sid_is_absent_from_groups_and_not_token_owner_eligible`
proves that the package SID is absent from `TokenGroups` and that making it
`TokenOwner` fails with `ERROR_INVALID_OWNER`.

The precise inference is that the current same-user LPAC principal cannot supply
a loader-compatible from-birth policy that denies `WRITE_DAC`. This excludes the
current architecture, not every possible Windows design. Post-loader final-DACL
and gate feasibility cannot retroactively close that gap. The next design option
is a distinct OS principal/service boundary with new principal, IPC, and service
lifecycle proofs. The compiled finalization remains a conditional mechanism at
the reviewed semantic gate inside `serve`, after loader, DLL, TLS, and CRT
initialization. It is not the first machine or Rust instruction, and objects
created before it remain outside the proof.

Child-side eligibility precedes the marker.
`serve_inherited_key_agent_storage_startup()` first calls
`verify_current_key_agent_lpac_before_gate()`, before stdio or INT3. That
read-only check opens the current process token through a fresh exact
`TOKEN_QUERY | TOKEN_DUPLICATE` handle, verifies the fixed Key Agent SID and
complete zero-capability LPAC policy, and checked-closes the handle. Only
successful verification may enter the debugger gate. The green
`default_disabled` proves that
ordinary non-LPAC `key-agent.exe` execution remains a silent exit 78 without
executing INT3; an LPAC-policy mismatch likewise fails before stdio and INT3.
This is eligibility-ordering evidence, not actual production-gate success.

Before launch, the already-held authenticated Key Agent file is parsed as a
bounded AMD64 PE32+ image. Exactly one whole-file
`49 BA <marker-le> CC` sequence must exist, with all 11 bytes in initialized raw
(non-padding) bytes of one executable section. The create-event hFile must
authenticate that same held file and be checked-closed before its event is
continued. The expected runtime INT3 is derived only from
authenticated `lpBaseOfImage + int3_rva`, never preferred `ImageBase` or
`lpStartAddress`.

The original `CREATE_SUSPENDED` count was consumed 1→0 to produce the first
debug event; the authenticated CREATE_PROCESS event itself is the process-wide
stop. Only after pending-token verification and checked create-event hFile close
may it be continued into the loader. The currently compiled candidate loop is
monotonic-deadline bounded to 160 post-create events and 128
`LOAD_DLL_DEBUG_EVENT`s, requires every event to carry the expected PID/primary
TID, and rejects `CREATE_THREAD`/`EXIT_THREAD`, `UNLOAD_DLL`, and non-landmark
exceptions. It fails closed but is not a production-compatible contract. Test
and production now use this same strict policy; no diagnostic worker allowance
remains. The green
`real_key_agent_loader_activity_fails_closed_before_detach` copies the exact
GUI-subsystem `key-agent.exe` reported by a fresh Cargo build into the
profile-private fixture and launches that copy rather than a guessed profile
sibling. It records the non-primary loader `CREATE_THREAD` as the
pending event, authenticates and registers the event's zero-flag `hThread` alias
for post-join cleanup, rejects before detach, and proves that raw alias returns
`ERROR_INVALID_HANDLE` after join. It also verifies joined Job cleanup. GUI
subsystem selection structurally avoids `conhost.exe`, and the root Job
active-process count stays one. This proves rejection and cleanup, not a
product-compatible gate. An
earlier CUI diagnostic fixture had an exact System32 `conhost.exe` and root count
two and observed multiple loader workers, worker-TID DLL loads, first-chance C++
`0xe06d7363`, and DLL unload. Those observations are historical threat-model
input, not the current accepted event contract or gate evidence.

A replacement bounded allowlist must authenticate each loader worker's creation
provenance, exact thread object/ID, admitted event set and lifetime, proof that
every worker exits before the semantic gate, and fresh post-exit
reopen denial, while checked-closing every non-null hFile before
continue. Its policy and bounds remain **STOP-SHIP**. Any eventual automatic
system breakpoint must still follow an exact pre-held System32 `ntdll.dll`
`FILE_ID_INFO` match that pins `lpBaseOfDll`, then require a
`MEM_COMMIT | MEM_IMAGE`, executable, non-guard page whose `AllocationBase`
equals that ntdll base, remote byte `0xCC`, and
`RIP == ExceptionAddress + 1`. No unproven `DbgBreakPoint` export RVA or fixed
exception `NumberParameters` shape is assumed.
Even if that replacement policy succeeds, it does not close the measured
from-birth `WRITE_DAC` gap and therefore is not sufficient to admit the current
same-user architecture into production.

If that revised loader policy reaches and authenticates it, the cooperative gate
must arrive as a first-chance
`EXCEPTION_BREAKPOINT` from the exact process and primary TID. Its
`ExceptionAddress` is the authenticated INT3, `RIP == address + 1`,
`R10 == marker`, remote memory is the exact 11-byte sequence, and
`VirtualQueryEx` must report a `MEM_COMMIT | MEM_IMAGE`, executable, non-guard
region with `AllocationBase` equal to the authenticated main-image base. Before
continue, the debugger uses an explicitly 16-byte-aligned AMD64 `CONTEXT`
wrapper, zeros `R10`, and verifies context readback. Only the reserved
always-one EFLAGS bit 1 representation may canonicalize; every mutable flag bit
and every other reviewed context field remains exact. While the
debug event holds every thread, primary `SuspendThread` must observe prior count
zero and leave explicit count one.

The separately green
`minimal_primary_gate_proof_detaches_with_one_verified_suspend_count` uses a
deterministic import-free relocatable GUI PE fixture to prove the exact
PID/primary-TID gate, `PendingKeyAgentLpac`→`VerifiedKeyAgentLpac`, one verified
suspend count, detach, and root Job count one. It proves the gate machinery, not
actual Key Agent loader compatibility, a signed artifact, or product E2E.

Supervisor tests preserve that layering. The green minimal-PE
`integrated_kernel_binding_owns_one_member_and_no_inheritable_parent_handles`
and `dormant_aggregate_unwind_synchronously_aborts_the_exact_process` cover only
dormant ownership, non-inheritance, and drop/unwind cleanup. All seven supervisor
integration tests that drive the Rust-startup fixture through storage or
Approval are explicitly ignored **STOP-SHIP** because loader workers precede the
exact-primary gate. The green
`rust_startup_fixture_loader_activity_fails_closed_before_supervisor_binding`
instead proves that activity maps to `KeyAgentSupervisorError::Activation` and
removes the prepared storage root. No actual production gate or storage-startup
success is claimed.

Only then may `PendingKeyAgentLpac::finalize_after_gate(...)` consume the pending
proof into `VerifiedKeyAgentLpac`. It revalidates current-token
association, `Hfinal`/`Hadjust` object and identity continuity, LPAC, and the
token-object DACL. `Hadjust` installs the exact 28-byte `TokenDefaultDacl`:
`ACL_REVISION`, zero reserved fields, no allow ACE, and one zero-flag
`ACCESS_DENIED_ACE` for binary `OWNER RIGHTS` (`S-1-3-4`) with mask
`0x000e0000` (`READ_CONTROL | WRITE_DAC | WRITE_OWNER`), with no ACL slack or
trailing bytes. Its immediate bounded readback validates the fixed prefix and
returned range, then proves with checked arithmetic that the non-null aligned
`PACL` header and entire 28-byte ACL lie inside initialized bytes before forming
a slice. Initialized API-wrapper padding/trailing bytes may surround the pointed
ACL, but the 28-byte ACL itself permits no internal slack. A post-mutation
statistics read creates the final baseline and preserves
provisional `TokenId` continuity; `Hadjust` is then checked-closed. With adjustment
authority gone, `Hfinal` bookends full policy, both DACLs, identity, and
baseline-equal statistics and must match a fresh current-token object. Only the
unchanged least-authority `Hfinal` remains in the final proof. When the
later sole post-gate `ResumeThread` releases the explicit count, the child's
first semantic step calls
`verify_current_key_agent_default_dacl_after_gate()`, opens its current token
with a fresh `TOKEN_QUERY` handle, and reads back the same exact default DACL
before later `serve` work.

Final revalidation runs after detach, through narrow-process attenuation,
immediately before the sole `ResumeThread` that releases post-gate application
execution, and at resident authority edges. It bookends `Hfinal` LPAC policy,
both DACLs, and baseline-equal statistics, then requires a fresh current token
to be the same object and identity. These are point-in-time checks, not an atomic
freeze; the last-check/resume and swap-away/back races remain **STOP-SHIP**, and
no DACL mutation is assumed to update `ModifiedId`.

A green
`post_loader_worker_feasibility_default_dacl_hardens_later_null_security_thread`
proves a separate cooperative post-loader child and parent
install/readback/adjust-close, child independent readback, actual
`CreateThread(NULL, ...)`, pseudo `GetThreadTimes`,
`OpenThreadToken(ERROR_NO_TOKEN)`, exact default owner/group and one-ACE DACL,
parent and child one-bit denial matrices, privilege bookends, checked cleanup,
and natural exit 0. The descriptor parser requires only
`SE_SELF_RELATIVE | SE_DACL_PRESENT`; it does not equate
`SE_DACL_PROTECTED` or `SE_DACL_DEFAULTED` with the explicit protected creation
descriptor. That ignored libtest probe runs on a non-primary TID, so it is
kernel feasibility, not a substitute for the real Key Agent's loader-compatible
exact-primary production gate.

In post-loader feasibility on the tested host, default-security Win32 later
threads created after the final lock inherit the policy. Because the actual Key
Agent gate has not succeeded and a loader-compatible from-birth `WRITE_DAC`
denial is unavailable, this is not production coverage for the current
architecture. Caller-supplied descriptors, raw native or remote
thread creation, returned/preexisting/duplicated high-right handles, and objects
created under the old default before the gate remain outside it.
`TokenDefaultDacl` is token-global rather than thread-only, and the observed
loader-worker thread history is neither authenticated yet nor a non-thread-object
inventory. A distinct OS principal/service boundary, enabled
debug/take-ownership behavior, signed DLL/TLS provenance,
pre-gate object inventory, and supported architecture/Windows matrices for the
AMD64 context and ntdll breakpoint remain **STOP-SHIP**; release still requires
that distinct-principal/service design or an explicitly narrower threat model.

The authorization and transport lifetime now share one platform-issued
monotonic identity. No caller supplies its absolute deadline, invalidation drops
the unbound transport half, and no exchange-start reconstruction from the wire's
relative lifetime remains. Dormant activation, bootstrap, full exchange, and the
terminal evidence retain the same opaque carrier and original deadline.

That is repo-local kernel feasibility evidence, not release evidence. The
Approval fixture does not directly read back the copied image's mandatory-label
state. Its test-only mitigation removes exactly the `NO_LOW_LABEL` bit to permit
the profile-scoped copy; production mitigation remains unchanged. Complete
signed DLL/TLS provenance, a pre-gate non-thread-object inventory, supported
architecture/Windows evidence for the marker/context/system breakpoint, a
bounded loader-worker provenance/lifetime/exit/reopen-denial policy, a distinct
OS principal/service design with IPC/lifecycle proof, a real GUI Key Agent
loader-compatible exact-primary gate E2E, same-user owner separation,
caller-supplied/raw-native/remote-thread and existing/duplicated high-right-handle
policy, enabled-privilege constraints, bootstrap/provenance, endpoint
topology/exclusivity, signed-artifact cleanup evidence, and production
composition/signing remain **STOP-SHIP**. The production binder still has zero
callers and both compiled policies stay `None`.

The runtime-enabled Approval child begins its Windows bootstrap by retrieving
the three numeric standard-handle values and requiring exactly two distinct
`PIPE` objects: stdin must differ from stdout, while stdout and stderr must be
the same numeric handle-table value (`stdout == stderr`). As its first
Windows/CRT application operation, before binary-mode conversion, it validates
both unique objects as having exactly `HANDLE_FLAG_INHERIT`, attempts both
`SetHandleInformation` clears without rollback, and requires exact-zero flag
readback for both.

The Approval launch target does not add the parent proofs to `HANDLE_LIST`:
that list remains exactly the two synchronous server pipe objects inherited by
the child; the parent retains the corresponding overlapped client ends. While
the Approval child is suspended, the launcher remotely injects supervisor-process,
supervisor-image, and Key Agent logical-parent process proof handles with
inheritance disabled. After sealing stdio, the child verifies its Approval LPAC
and Job and requires stdin, the shared output object, both supervisor proofs, and
the Key Agent process proof to be five pairwise-distinct exact kernel objects
whose handle flags are all zero. Only fresh child-local duplicates of all three
injected proofs become authoritative and remain retained through response write;
the launcher-known original injected slots are never adopted and are left only
for bounded process-exit cleanup. It derives the authoritative supervisor PID
and process-token `TokenSessionId` from the retained live exact supervisor process
handle and requires the parent-hello supervisor PID, both pipes' reported client
PID/session, and the child token session to match. The binding remains owned and
is revalidated across UI presentation and response write. The distinct retained
Key Agent process must match the logical-parent PID, remain live and
image-queryable in the same session, and expose through `TOKEN_QUERY` the fixed
Key Agent LPAC SID, AppContainer/LPAC state, zero capabilities, and the expected
least-authority denials. While both retained process handles are live, this
prevents PID-reuse substitution and corroborates the pipe observations against
the exact live supervisor process object. Because pipe
handles are transferable and duplicable, this does not prove exclusive endpoint
ownership, endpoint topology/exclusivity, or per-write attribution. For the image
proof, the child applies case-preserving exact normalized path-string equality:
it strips an optional `\\?\` prefix, normalizes separators, and compares the
live process image path with the final path of a separate held file; a casing
mismatch fails closed. It then checks the held path's `\\key-agent.exe` suffix
and version metadata, supplies the held handle plus path to Authenticode signer
validation, and computes SHA-256 through a cloned held handle. That path equality
plus those checks does not prove that the live process was
mapped from that exact file object.

The wire and child runtime define this complete fail-closed exchange order: a fixed 74-byte version-2 parent hello, a fixed 106-byte
child hello, a 110-byte parent-finish header plus the exact request and request
EOF, then a fixed 75-byte response plus response EOF. The parent supplies a
fresh nonzero nonce; the child echoes it, supplies an independently fresh
nonzero child nonce, and binds its hello to the domain-separated SHA-256
bootstrap transcript. The parent-finish header binds both nonces, the canonical
Approval request hash, and the exact request length. The child accepts the
request only after exact EOF. After response-plus-EOF, the parent locally hashes
the held child PID and file identity, manifest digest, profile revision, request
 digest, one-shot Approval nonce and canonical request hash, exact response
 bytes, a fresh parent-local transcript salt, and both bootstrap nonces. The
 salt is never sent to the child and is not challenge-response evidence. The Job remains
a separately checked live gate, not hashed identity. The fixed 75-byte response
is ordered as magic, version, decision, request digest, and one-shot Approval
request nonce. Only the digest and nonce echo request fields; neither bootstrap
nonce is echoed. Replay resistance therefore also depends on the private one-shot
endpoint and a fresh one-shot Approval request nonce. Direct executable launch
cannot construct this sequence and exits without diagnostics; the legacy Rust
API returns `LogicalParentUnavailable` before resource allocation.

The sealed parent separates hello bootstrap from the consuming full exchange.
The full transition writes finish plus the exact request and request EOF,
verifies the fixed response plus EOF, requires natural exit code 0 from the
exact held child under the same transport deadline, performs final Key Agent
revalidation after exit, and returns only opaque
`VerifiedParentBoundApprovalExchange`. The state has no conversion into the
public verified response or signing. Both transitions have zero production
callers. The legacy `launch_approval_frontend` still fails before allocation
with `LogicalParentUnavailable`.

A repo-local Approval child/grandchild kernel test makes a separate positive
sentinel inheritable for a broad-inheritance grandchild. It uses
`CompareObjectHandles` to prove that the sentinel arrives while neither of the
two original exact stdio objects does. The sequential clears are not atomic,
do not prevent later inherit-bit re-enabling or explicit duplication, and this
two-object negative is not exhaustive enumeration proving that no stray handle
entered the child; it is not a five-object grandchild proof for the injected
parent handles. It is also not evidence for the exact signed helper, intended
supervisor topology, immutable installation, DLL/dependency identity, or
release activation. Signed release-path positive evidence covering
case-sensitive directories and alternate path forms, proof of the live mapped
exact file object and complete DLL/dependency graph, immutable installation, a
release-proven resumable supervisor-held activation capability, and exact endpoint topology/exclusivity
remain **STOP-SHIP**. There are zero production orchestration callers for the
sealed launch-to-`VerifiedParentBoundApprovalExchange` transition, no conversion
from that evidence into signing, and no positive signed-handshake E2E. A
repo-local `cfg(test)` probe now proves that an
actual zero-capability Approval LPAC can query the exact injected logical-parent
handle and denies only the local `DuplicateHandle` and PID-reopen requests
enumerated above. The copied image's mandatory-label state is not directly read
back, and the test-only `NO_LOW_LABEL` removal only permits the profile-scoped
copy; production mitigation remains unchanged. This is not signed/mapped
release evidence. `COMPILED_PARENT_POLICY` and
`COMPILED_RELEASE_POLICY` remain `None`, so default Approval builds still exit
78. No signed-artifact, topology, or release-activation evidence is claimed.

The runtime-enabled Secret Input/recovery child begins its Windows bootstrap by
validating the two unique stdio pipe objects: stdin and the single shared
stdout/stderr handle-table entry, with exact inherit-only flags. Before any
other Windows or CRT application operation, it attempts both
`SetHandleInformation` clears without rollback and requires exact-zero
readback. The parent `HANDLE_LIST` contains only those two objects. After the
child exists suspended and its Job and LPAC token have been checked, the parent
uses `DuplicateHandle` to inject the parent-process and image-file proof handles
directly into that child with inheritance disabled, then resumes it. Immediately
after the fixed parent hello, the child requires the two sealed stdio objects
and the two proof objects to be four pairwise-distinct exact kernel objects with
zero handle flags before using the parent proofs.

A repo-local child/grandchild kernel test includes a positive inheritable
sentinel and uses `CompareObjectHandles` to show that none of those four exact
objects reaches a broad-inheritance grandchild. The sequential stdio clears are
not an atomic bulk operation, do not prevent later re-enabling or explicit
duplication, and the four-object negative is not exhaustive enumeration proving
that no stray handle crossed the boundary. It is also not evidence for the
exact signed helper, intended supervisor topology, immutable installation, DLL
identity, or release activation; the parent-policy STOP-SHIP invariant below is
unchanged.

Restricted helpers and the Key Agent share one private immutable base process
context. It derives exact `SystemRoot` and `WINDIR` entries from
`GetSystemWindowsDirectoryW`, and supplies the `GetSystemDirectoryW` result only
when it is a plain absolute DOS path whose parent is that system-shared Windows
root and whose leaf is `System32`. That double-NUL two-name block is only the
immutable base context. After preparing the exact role profile, every restricted
helper and the Key Agent validates `GetAppContainerFolderPath` as an absolute
`Packages` / exact profile-name / `AC` layout, derives the containing
profile-specific `AC` folder, and prepends that exact returned path as
`LOCALAPPDATA`. Each final environment contains exactly
`LOCALAPPDATA`, `SystemRoot`, and `WINDIR`; none inherits the parent's ambient
values or current directory. The production policy rejects directory reparses,
path-replacement/delete/ACL rights on every ancestor, and file/subdirectory
creation rights on the Windows root and System32 under the current primary
token. It deliberately does not treat the system-drive root's
create-sibling-directory right alone as authority to replace the fixed Windows
path. Restricted helpers prepare the base context before parent-proof discovery,
persistent frontend profile creation/open, or Job creation; the Key Agent
prepares it before acquiring its inheritable-handle flight. Each retains the
UTF-16 owner through `CreateProcessW` and rejects thread impersonation both
during preparation and again immediately before that call.

This is a string/layout, metadata/reparse, and current-token rights proof. It
retains no directory handle and is not an atomic kernel-object identity proof;
it does not establish DLL/dependency identity or resolution and makes no claim
about inherited error mode, priority, or every other Win32 process setting. A
`cfg(test)`-only Key Agent kernel-test constructor may skip the writable-right
rejection so elevated developer tests can exercise process creation, while
retaining the OS paths, shape/layout, reparse, and impersonation checks. That
constructor is absent from the release path; production has no elevated bypass.

The separate `cfg(test)`-only LPAC launch fixture opens the persistent fixed
profile, copies the current test image into a CSPRNG-named directory beneath its
OS-managed `AC` folder, requires the exact current-user owner, and explicitly
applies a protected DACL granting the current user full access and only the
fixed profile SID read/execute. On both the directory and copied executable it
then reads back that owner/DACL and a non-defaulted, one-ACE Medium/`NW`
mandatory label. This models a medium-integrity installed image while retaining
the unchanged full Key Agent mitigation policy, including `NO_LOW_LABEL`. The kernel-only
provisioning seam likewise reuses that persistent test profile and creates a
separate CSPRNG-named storage leaf. Drop removes only those exact test objects;
it neither changes the workspace image ACL nor deletes the persistent profile.
Together with the one-shot startup test this proves repo-local child opening and
binding of that exact test root. It does not prove the production fresh fixed
profile/root, install root, or exact signed artifact end to end.

The dormant supervisor composition initially binds that exact-image proof to one
preconfigured two-process kill-on-close root Job, one private request pipe, one
separate private response pipe, and one internally timed one-shot startup nonce.
Each `CreateNamedPipeW` call retains first-instance exclusion even though
`FILE_FLAG_FIRST_PIPE_INSTANCE` shares the numeric `0x0008_0000` bit with
`WRITE_OWNER` in a returned handle's access mask. Immediately after creation,
the pipe owner duplicates the persistent request server source to exact
read-plus-synchronize `0x00100001` or the response server source to exact
write-plus-synchronize `0x00100002`, with inheritance false and duplication
options zero, then checked-closes the original before opening the corresponding
parent client. Child stdin, stdout, and NUL-backed stderr are separate
inheritable duplicates with those exact directional masks; none of these
production child-stdio duplicates uses `DUPLICATE_SAME_ACCESS`.

An ignored host-local kernel-matrix test uses the official `windows` WDK
`NtQueryObject(ObjectBasicInformation)` and
`NtQueryInformationFile(FilePipeLocalInformation)` function/class bindings; the
result buffer is a test-only `repr(C)` local ABI mirror guarded by size, alignment,
and offset assertions. Exact server sources intentionally omit
`FILE_READ_ATTRIBUTES`, so pipe-local information is observed only through the
sealed `parent_response` client (outbound/client end), while request direction is
proved by successful parent-to-child I/O and rejected reverse I/O. Handle flags
and same-object comparison additionally check inheritance and continuity. The WDK
wrappers create native-symbol load-time imports in the test binary rather than
resolving them dynamically, so this ignored evidence has a test-host compatibility
limit; no query or import is production-reachable. It is evidence for
`PrivateKeyAgentPipes` on that host, not runtime admission. Separate ignored
probes now cover the common attenuation path and Phase 1 service-helper target
candidates; neither evidence set permits production activation.

The activation-owned fresh thread creates the Job and pipes, acquires the shared
flight up to the startup-lease deadline, and creates exactly three short-lived
inheritable stdio duplicates plus one borrowed Job handle through an exact
five-slot `STARTUPINFOEXW` attribute list: `HANDLE_LIST`, `JOB_LIST`, the full
immutable helper `MITIGATION_POLICY`, `SECURITY_CAPABILITIES`, and
`ALL_APPLICATION_PACKAGES_POLICY`. The policy is the same one used by restricted
helper and service startup and includes the non-Microsoft-binary block. The
attribute list retains its three-handle array, Job value, heap-stable boxed
mitigation word, profile SID, and both LPAC values through `CreateProcessW`; it
is then deleted and all three duplicates close before the flight is released
and mapped-image authentication begins. The Job
context is checked before creation, after exact-image/LPAC detach while the child
is still suspended, and once more before the aggregate crosses the join. Exactly
one active Job member is required. The aggregate is non-clone, `!Sync`, and
externally private, with no raw-handle or generic resume operation. Drop first
attempts bounded synchronous cleanup of the exact process tree; it cannot report
cleanup failure, so retained kill-on-close Job closure remains the fail-closed
fallback. Its sole consuming transition writes the complete 188-byte
`YWKSREQ1` request while suspended, consumes and closes the request writer, and
then releases exactly the verified suspend count for storage startup. The child
must observe exact request EOF, detach the ambient stdin/stdout entries, and
close raw stdin before decoding or opening the root. Raw stdout remains only as
the response-capability handle.

On the measured Windows host, where third-party injected modules were observed
in the surrounding process, the full-policy kernel matrix fails closed earlier
at process creation. This is narrow host-local evidence, not proof that
injection caused the failures and not a supported-kernel result. Neither the
mitigation change nor this observation resolves generation authentication for raw
`DEBUG_EVENT` aliases, same-object ABA, or atomic compare-and-close. The separate
Phase 1 ignored probes now measure exact Approval/Secret Input service-local
sources and actual `WindowsDuplicateHandle` target-table candidates on this
host, but do not exercise the real helper child's production duplicate/capture/
adoption path or provide runtime admission, signed-helper E2E, or a supported-
kernel matrix. Raw debug aliases still require the atomic dedicated-debugger
cutover described above;
production activation therefore remains forbidden and the compiled policies
remain `None`.

The child constructs one exact 88-byte `YWKSRES1` response only when the request's
nonce, PID, creation time, and complete root identity equal its own observations.
Its first write attempt is a commit point: it ignores that result and the results
of `FlushFileBuffers` and `CloseHandle` on the retained response handle, returns
no post-output error to `main`, and leaves a startup-only lexical scope. The live
request frame, decoded request, response, and response frame run their
`Zeroizing` drops at that boundary; only the resident stderr proof and fixed
store bindings escape into a non-alertable `Sleep(INFINITE)` loop.
The parent requires the whole response followed by EOF within the original
startup deadline before decoding. That exact response-plus-EOF observation is
the authoritative protocol proof that the child response endpoint closed. It
compares all four fields again and revalidates the held root's volume/security/identity,
exact resident-process liveness and root-Job membership, supervisor/Job context
and limits, and permitted Job topology before and again after consuming the
monotonic startup lease, so an exited child cannot cross the join merely by
producing EOF. It computes a
domain-separated SHA-256 commitment over the held artifact
`FILE_ID_INFO`, exact request frame, and exact response frame. The resulting
private type retains the running process, root Job, verified handshake, and
parent-held no-delete-share root, but no startup endpoint. The child retains
sealed stderr and fixed generation-store bindings derived from its independently
opened root in that infinite-sleep loop until Job termination. A failed or
partial write, flush failure, or close failure cannot mint this aggregate: the
parent rejects or times out and tears down the Job. The type offers neither a
follow-on read/write method nor signing authority; the startup streams are not
reused as a runtime channel.

At process creation the Key Agent child receives inheritable stdio handles.
Its entrypoint now makes child-side sealing the first Windows application
operation. Before any mutation it borrows all three standard handles, proves
they are three distinct kernel objects, requires exact `PIPE`/`PIPE`/`CHAR`
types and exact `HANDLE_FLAG_INHERIT` flag words, then attempts to clear all
three inherit bits and requires every flag word to read back as exactly zero.
A partial clear is never rolled back; any error terminates with code 78 before
another Key Agent application operation. The non-clone, `!Send + !Sync` result
exposes no handle. An isolated child/grandchild kernel test retains the original
three object identities and proves with `CompareObjectHandles` that no matching
object exists in the grandchild.

Immediately after sealing, the Key Agent reads exactly one 188-byte startup
request followed by EOF, then detaches the ambient stdin/stdout entries and closes
raw stdin before decoding or root work. It retains raw stdout only inside a
response capability. After the process/root checks, it attempts one exact
response, ignores the write/flush/close results, and leaves the lexical scope
that owns all four zeroizing startup transcript values before entering a non-alertable
`Sleep(INFINITE)` loop rather than returning an error to `main`. It retains
sealed stderr and fixed generation-store bindings derived from the child-opened
root until Job termination. Only the parent's exact response plus EOF under the
startup deadline proves response-handle closure; no startup handle is reused for
runtime I/O.
All seven Rust-startup supervisor integration positives are explicitly ignored
**STOP-SHIP**. Their fixture code, when deliberately invoked, has two
`cfg(test)` accommodations: its reader consumes only the pinned terse libtest
preamble before the exact response, and its Job topology permits only the fixture
plus at most the exact `GetSystemDirectoryW` `conhost.exe`. Production requires
response magic at byte zero and exactly one Job member. The green minimal-PE
dormant ownership/cleanup positives and Rust-startup failure-cleanup negative
prove neither storage-startup success nor release evidence.

**STOP-SHIP (English):** the in-crate coordinator does not prove that a standalone
supervisor is single-instance, does not authenticate the Native Host/Broker/Key
Agent process topology, and cannot coordinate a foreign or otherwise
non-cooperating process-creation call. Release evidence must establish those
boundaries across all loaded code and processes. The repo-local child bootstrap,
LPAC token proof, and kernel tests are not evidence that the exact signed Key
Agent image reached those steps under the intended supervisor. Signed immutable
installation, Native Host provenance, durable installer provenance/recovery for
an existing fixed profile, production rollback-anchor and storage/AEAD-key
provisioning, live protected-settings/lease authority, authenticated
Broker/supervisor/process topology and single-instance enforcement, exact
signed-artifact and DLL/dependency E2E, and
`COMPILED_RELEASE_POLICY` remain separate blockers. The implemented one-shot
resume, root transcript commitment, and private generation-file policy do not
satisfy any of those release conditions.

**릴리스 차단 조건 (한국어):** crate 내부 coordinator는 독립 supervisor 단일
인스턴스나 Native Host/Broker/Key Agent 프로세스 topology를 증명하지 않으며, 그
비공개 API를 사용하지 않는 FFI·표준 라이브러리·다른 프로세스의 생성을 조정할 수도
없습니다. 릴리스 증거는 적재된 모든 코드와 프로세스에서 이 경계를 별도로 입증해야
합니다. Key Agent 자식의 첫 Windows application 동작은 이제 정확한 세 stdio 객체를
`PIPE`/`PIPE`/`CHAR`와 inherit-only flags로 사전검사하고 inherit bit를 모두 제거한 뒤
flags 0을 재검사하며, grandchild exact-object 음성 테스트도 있습니다. 그러나 이
repo-local 증거는 intended supervisor 아래 exact signed image가 그 단계에 도달했음을
입증하지 않습니다. repo-local LPAC 토큰 증명과 kernel test도 exact signed image가
intended supervisor 아래 같은 경계를 통과했다는 증거는 아닙니다. signed immutable
installation, Native Host provenance, 기존 고정 profile의 durable installer
provenance/recovery, production rollback anchor와 storage/AEAD key provisioning,
live protected-settings/lease authority, 인증된 Broker/supervisor/process
topology와 single-instance, exact
signed-artifact 및 DLL/dependency E2E, `COMPILED_RELEASE_POLICY`는 계속 별도 차단
조건입니다. 구현된 one-shot resume, root transcript commitment와 private
generation-file policy는 이 릴리스 조건을 대신하지 않습니다.

This proof remains dormant for release even though the private child/root
one-shot is implemented. It must not be armed until the authenticated Broker and
supervisor topology consumes the sealed four-role bindings with a production
rollback anchor and provisioned storage/AEAD keys, durable installer
provenance/recovery covers existing profiles through authenticated
rollback-resistant journal inputs, authoritative profile-registration
observation and a held-aggregate constructor that actually calls the dormant
root opener, an exclusive lease/post-observation reread, and downstream wiring
for the dormant adoption transition, a live protected-settings
lease is connected, and concurrent/event-contamination, panic, timeout, cleanup,
and signed-artifact tests are release evidence. Preventing an external Job
assignment after the dormant aggregate returns additionally needs a standalone
single-instance supervisor bootstrap and reviewed supervisor process ACL.

Non-launchable fresh fixed-profile/root creation, the dormant root-only existing-
root opener with canonical-path revalidation, a pure non-authoritative provenance
candidate classifier, fixed zero-capability LPAC construction, suspended-token
verification, and a repo-local test-root child/open transcript commitment plus
the private fixed-role generation-file policy are implemented.
The `cfg(test)` integrated LPAC path proves that narrow composition, but does not
authorize a production protected setting or signing operation. The public
persistent-store facade still grants only the `TokenUser`; the separate private
backend obtains the exact fixed Key Agent profile SID only from its sealed
child-root binding and grants neither frontend profile access. The root's user
ACE still permits other same-user processes. A trusted installer/supervisor must
connect authenticated rollback-resistant journal inputs, authoritative
profile-registration observation, a held-aggregate constructor and production
caller for the dormant root opener, exclusive lease/post-observation reread
orchestration, and an exact downstream consumer/recovery path to the implemented dormant
adoption transition; it must also supply production anchor and key provisioning,
and keep any certificate-store, registry, or profile-dependent trust
work outside the zero-capability child. Do not add `registryRead`, reuse a
frontend profile, add generic runtime/signing IPC, or activate the dormant Key
Agent as a workaround.

### Secret Input parent activation invariant (STOP-SHIP)

Approval shares this parent-activation invariant. `COMPILED_PARENT_POLICY` must
remain `None`. Today the Approval child normalizes only the optional `\\?\`
prefix and separators, preserves case, and requires exact path-string equality
between the live process image path and a separate held file's final path; an
ambiguous casing mismatch fails closed. It then checks the held path's
executable suffix and version metadata, uses the held handle plus path for
Authenticode signer validation, and computes SHA-256 through a cloned held
handle. Neither that path equality nor a separately hashed file handle proves that the running process was
mapped from that exact file object. The child holds synchronous server pipe ends
while the parent holds overlapped client ends. It derives PID and process-token
`TokenSessionId` from the retained live exact ordinary channel-supervisor
process object, requires
the parent hello, both server-end client PID/session observations, and the child
token session to match, and retains and revalidates that binding through UI and
response write. This prevents PID-reuse substitution while the retained handle
is live and corroborates the pipe observations against the exact process object.
Transferable and duplicable pipe handles nevertheless leave exclusive endpoint
ownership, topology/exclusivity, and per-write attribution unproven. The
repo-local `cfg(test)` logical-parent probe now proves exact `TOKEN_QUERY`
availability and denial of the exact local `DuplicateHandle` and PID-reopen
request matrices documented above in a real zero-capability Approval LPAC. It
uses a separate Key Agent logical handle, does
not prove this channel-supervisor binding or a mapped release image, and leaves
`COMPILED_PARENT_POLICY` as `None`. The policy may become `Some` only after
reviewed release evidence proves all of the following as one fail-closed launch
capability:

- a trusted supervisor opens the exact Key Agent artifact without write or delete
  sharing before launch and retains that same handle through the helper session;
- the supervisor binds that held artifact to the exact launched PID and process
  creation time, and to the mapped file object, not merely to an equal path
  string; signed release-path evidence must cover case-sensitive directories
  and alternate path forms;
- the same release-proven resumable supervisor-held activation capability binds both inherited request/response pipe peers
  as exact endpoint objects, including their
  direction and topology/exclusivity, plus the child Job/profile and fresh
  bootstrap nonces, to that launched process;
- the immutable installation and complete loaded DLL/dependency graph are
  covered by the signed release identity; and
- adversarial replacement, rename, stale-PID, handle-substitution, and parent-exit
  tests pass against the signed release artifacts.

Path equality from `QueryFullProcessImageNameW` and
`GetFinalPathNameByHandleW`, including the current case-preserving exact
normalized path-string comparison, is explicitly insufficient activation
evidence. Approval's sealed bootstrap and full-exchange transitions both have
zero production callers. The platform-issued window now reaches them through
matching non-Clone halves and a one-shot bound request carrier. Bootstrap is
capped by the earlier of original expiry and a fresh five-second grace; the
full exchange accepts no raw request/deadline and requires finish/request EOF,
fixed
response/EOF, natural child exit code 0, and post-exit final Key Agent
revalidation before minting opaque `VerifiedParentBoundApprovalExchange`, but
it retains that carrier but provides no public verified-response or signing
conversion and no positive signed-handshake E2E.

```text
dApp -> MV3 extension -> native-host shim -> broker -> inherited private channel -> key-agent
                                           ^                                |
                                           |                                +-> approval-ui
                                      dashboard                             +-> secret-input-ui
```

## Target trust rules

- The extension, native-host shim, dashboard, and broker never receive wallet
  entropy, private keys, passphrases, or vault keys.
- Browser origins and document identifiers are browser-reported provenance, not
  independently authenticated identities.
- The broker treats every public IPC client as hostile. It has no raw-sign,
  export, secret-input, or policy-bypass method.
- The key agent has no public listener and accepts only bounded typed messages
  over one inherited channel. It canonicalizes operations, builds the display
  model and approval digest, validates the one-shot decision, signs, and then
  decodes and recovers the signed artifact before release.
- The authorization TCB projects every admitted type-0/type-1/type-2 transaction
  field and every admitted personal-message byte into distinct frontend-known
  semantics. Values are never truncated or ambiguously concatenated; requests
  exceeding the exact display bounds are denied. EIP-712 remains denied until
  an exact structured display exists.
- Approval and secret input are designed as separate one-shot executables that
  do not share the dashboard toolkit or accept external rich text. Their
  default entry points are disabled, and the opt-in runtime contracts do not
  make release attestation or restricted launch available.
- A signed transaction candidate is never made safe for nonce reuse merely
  because broadcast timed out, an endpoint stopped reporting it, or a reorg
  occurred.
- Before any raw transaction byte reaches RPC, the durable journal must commit
  `Broadcasting`. Only an exact local/returned transaction-hash match may commit
  `Submitted`; every timeout, transport error, RPC error, mismatch, or
  interrupted attempt remains `BroadcastUnknown` and quarantined.

## Release boundary

The eventual target is `PrivateMainnetCanary`: one maintainer, one Windows 11 x64
machine, one Chrome Stable profile, isolated low-value accounts, and no third-
party distribution. General-mainnet release requires a separate independent
review and removal of canary-only warning overrides.

The independent-review attestation is schema v2 and signs two distinct
commitments: the final payload artifact-set hash and
`reviewedEvidenceSetSha256`. The latter is computed over canonical
`{bytes,path,sha256}` records for every mandatory evidence file and every one
of the 17 Windows-negative logs, excluding only the review attestation and its
detached signature to avoid a cycle; the reviewer public key is included. A
separate read-only subject command derives this commitment directly from an
exact, reparse-free, non-hard-linked staging tree before the two excluded files
exist.

Both ceremony wrappers execute from a separately controlled verifier toolset,
never from the candidate tree. Its independently checkpointed aggregate covers
exactly `node.exe`, both wrappers, `common.ps1`, the two release MJS modules,
and the native-host manifest validator in a fixed four-directory tree. Exact
case, no extra entry, one hard link and default stream per file, read-only
attributes, separate failed file-creation and subdirectory-creation probes in
every directory, full volume/file identity, and disjoint candidate/toolset roots
are mandatory. This runtime aggregate is a consistency/version pin; it cannot
make the already executing wrapper, `common.ps1`, system PowerShell image, or
Windows OS authenticate itself. The wrapper and `common.ps1` must therefore come
from the independently reviewed write-protected toolset.

The repository architecture gate recursively inventories every executable
PowerShell source (`.ps1`, `.psm1`, and `.psd1`) outside its explicit generated
and control-directory exclusions. It rejects reparse entries, NUL bytes, and
anything other than ASCII without a BOM or valid BOM-marked UTF-8, then requires
both the exact approved path set and an exact raw-byte SHA-256 pin for every
source. Adding or editing any PowerShell source therefore requires an explicit
reviewed update to the pin table in `scripts/architecture-scan.mjs`. These pins
are a repository change-review checkpoint; because the scanner and pins live in
the same repository, they are not an independent trust anchor or runtime
authentication mechanism.

The five top-level `scripts/release/*.test.mjs` suites are likewise discovered
as one exact regular-file inventory, decoded and hashed from the same single
read, and matched to reviewed raw-byte SHA-256 pins before their contents are
used by the architecture assertions. `scripts/release/check.ps1` independently
requires the same ordered filenames and hashes immediately before invoking the
Node test runner, so an unchanged test count cannot hide a hollowed callback.
This remains a deterministic repository review gate, not protection against a
same-user process that can rewrite files concurrently with the developer check.

The static release check is itself one of the sealed `common.ps1` consumers. It
must run under the exact system Windows PowerShell argv shown below, accepts an
explicit absolute Node executable path rather than resolving `node` through its
own `PATH`, and delegates every child launch to the common Application-only
runner. Exit zero is insufficient: every child must also produce empty stderr,
and the two PowerShell behavior tests must each produce their one exact stdout
sentinel. Both Windows CI workflows carry this same invocation contract.

Every entry that consumes `common.ps1` begins by setting
`$PSModuleAutoLoadingPreference` to `None` and accepting only the exact system
64-bit Desktop Windows PowerShell 5.1 image invoked exactly as follows:

```powershell
$systemPowerShell = [System.IO.Path]::Combine([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System), "WindowsPowerShell\v1.0\powershell.exe")
& $systemPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <current-entry>
```

Only that entry's arguments may follow. A different image, 32-bit host,
PowerShell Core, missing/extra/abbreviated engine option, or different
`-File` target fails before any caller-controlled release, toolset, or candidate
path is opened. `common.ps1` requires exactly zero loaded modules at
initialization, zero pre-existing protected `YourWallet.*` types, and zero
function, alias, script, or application shadows for critical command names.
`PSModulePath` is never searched. Beneath `$PSHOME\Modules`, the bootstrap imports
only the absolute manifests `Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1`,
`Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1`, and
`Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1`; the
script-based `Microsoft.PowerShell.Archive` module is not imported. Authenticode
and `Add-Type` operations invoke their verified `CmdletInfo` objects directly.
ZIP handling validates and retains the exact strong-named GAC framework types,
and its source extractor rejects traversal, automatic `~`-form DOS 8.3
aliases, device-name aliases, duplicate Windows paths, reparse output, and
symbolic-link entries. The bootstrap also rejects every
long-form alias, while generic build-tool names resolve only as applications and
are invoked through the resulting absolute paths. Profiles, module autoload,
ambient command shadows, and preloaded replacement runtime types therefore fail
closed rather than becoming an operating assumption.

The wrapper bootstrap-opens each requested data root, converts it to a
handle-derived local volume-GUID path, locks every canonical ancestor from the
volume root down without delete sharing, and accepts the canonical root only
when its non-sentinel volume serial and complete 128-bit file ID match the
bootstrap handle. It then discards the original alias, holds every staging
directory and file with no write/delete sharing, proves effective read-only
state, and repeats its tree checks around the deterministic calculation. The
Node path resolver enumerates every volume-path parent and requires the actual
entry spelling to match exactly, including the root `evidence` entry. The same
path pinning applies to the bundle and every external input in final offline
verification.

Final verification requires one rollback-resistant checkpoint-derived
`ExpectedReleaseSequence` whose only accepted spelling is `[1-9][0-9]{0,31}`.
Sequence `1` is valid only for a deliberately empty initial-release ledger; each
successor value is the canonical increment of the last accepted sequence in the
write-protected offline checkpoint. The PowerShell raw-argument
binder treats it as an exact mandatory value: `1` forbids both previous-manifest
arguments, while every greater value requires the previous manifest and its
independent SHA-256 pin as a pair. PowerShell and Node enforce that shape and
their exact initial/successor argument counts before any candidate file or tree
is opened or read. Node then parses the candidate and compares its exact sequence
with the external assertion immediately after the independent release-key and
extension-ID pins, before the signer-certificate and previous-manifest hash pins
and before any bundle or evidence read. A correctly signed old sequence-1 tree
therefore cannot replay when the independent offline checkpoint expects a
successor; no rejected sequence value is echoed.

The runner bypasses function, alias, and `PATH` resolution. One fresh one-shot
thread owns process creation, every debug event, image authentication,
continuation, detach, and fail-closed debugger-thread exit. It creates the pinned
Node image with a minimal three-variable environment, closed stdin, bounded raw
output, no addons/global lookup, and a hard deadline. Before any user-mode
instruction is released, its first `CREATE_PROCESS_DEBUG_EVENT` image handle
must equal the retained `node.exe` by volume serial and all 128 file-ID bits. The
three pinned JavaScript files are read through retained volume-GUID paths and
evaluated as one in-memory `vm.SourceTextModule` graph in a distinct,
string/wasm-code-generation-disabled context. That context exposes only the pinned source's
required `Buffer` and `TextDecoder` globals and a minimal `node:process` facade.
Only the exact review-to-release and release-to-native-validator relative edges
and the five required `node:` built-ins can resolve. This separately closes both
the DOS executable mapping race and a DOS script/module path race. The VM
context blocks accidental ambient CommonJS/global lookup but is not a
hostile-JavaScript sandbox; independently reviewed source bytes remain inside
the verifier-toolset trust boundary.

This C# runner has its own static process-creation lock. The lock begins before
its inheritable pipe ends are created and is retained through `CreateProcessW`,
attribute-list deletion, and closure of every temporary child end. It therefore
matches the Rust lifetime rule for concurrent calls through this runner, but it
is a separate lock: it neither joins the `platform-windows` coordinator nor
intercepts arbitrary foreign or standard-library process creation. Lock
acquisition is bounded by the operation deadline, but synchronous
`CreateProcessW` and the fail-closed outer worker join remain non-interruptible.

Ancestor junction, mount, drive-alias, or DOS-device retargets therefore cannot
redirect a pass to different executable, module, or candidate bytes;
unsupported or UNC identities fail closed. Both wrappers require exact exit,
stderr, and stdout bytes and collapse every failure to fixed category lines
without path disclosure. Raw argument names are case-sensitive and unknown,
missing, duplicate, or wrong-case names are rejected inside that protected
boundary. The Windows release gate stages an exact toolset, deliberately blocks
its pinned proxy child, retargets the ancestor junction from valid tree A to
different valid tree B, proves the canonical root still denies rename, and
requires the exact subject bytes to remain A plus one LF. Running the Node core
alone does not prove the Windows share-mode, mapped-image, module-graph,
volume-identity, or offline properties.
Assembly and final verification independently recompute the same value,
and v1 or stale attestations fail closed. This prevents a release-manifest key
holder from replacing installer/native-host, advisory, or Windows-negative
evidence and reusing an earlier independent-review signature. The subject is
not release eligibility, and organizational independence, read-only staging,
final evidence production, and hardware-backed reviewer key custody remain
external ceremony requirements. For the ambient PowerShell bootstrap itself,
the remaining external boundary is only the Windows OS and exact system
Windows PowerShell image, the independently reviewed write-protected toolset,
and live same-integrity process injection during or after admission. Release
preparation separately assumes no concurrent same-user mutation of its fresh
temporary extraction tree. Module/type/command cleanliness is enforced
in-process. Release remains
STOP-SHIP until a production offline transcript records the accepted
exact-system-host invocation and write-protected verifier-toolset checkpoint
together with the other mandatory evidence.
