# Frozen security decisions

These decisions are normative targets for version 0.1. They do not certify that
the current binaries satisfy them. A change requires an ADR, new vectors, and
security review.

**Current release status: STOP-SHIP.** `broker` and default builds of
`approval-ui` and `secret-input-ui` exit with code 78 immediately. A directly
started `key-agent` also fails closed; only the private inherited startup shape
can make it seal stdio, require exact request EOF, close startup stdin and detach
the ambient stdout entry before root work, attempt one response, and enter an
inert `Sleep(INFINITE)` loop under the supervisor's kill-on-close Job. Only the
parent's deadline-bound exact response-plus-EOF observation completes the
storage-object proof. The child exposes no runtime or signing protocol.
`native-host` validates one bounded persistent stream, returns error 4900 for
each valid request without reaching a Broker, then exits 78 on EOF or the first
terminal error. The UI helpers have opt-in inherited-stream runtime
entry points for contract testing. Direct executable Approval launch cannot
complete the parent-auth exchange and exits without diagnostics; the legacy
Rust API returns `LogicalParentUnavailable` before resource allocation.
`COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` are `None`, so no
ordinary build can complete restricted launch or reach signing. The sealed
hello bootstrap and full-exchange transitions both have zero production
callers. A platform-issued opaque monotonic window is split into matching
non-Clone authorization/transport halves; the exact Key-Agent request is bound
once and its carrier is consumed before dormant allocation. Bootstrap is capped
by the earlier of original expiry and a fresh five-second grace. The full
exchange accepts no raw request/deadline and mints only opaque crate-private
`VerifiedParentBoundApprovalExchange` after finish/request EOF, fixed
response/EOF, exact child natural exit code 0, and post-exit final Key Agent
revalidation under that exact original deadline; it retains the carrier and has
no public verified-response or signing conversion. No
positive signed-handshake E2E exists. Activating the helpers through exact
signed-artifact attestation and the end-to-end suite remain release blockers.

A private dormant Broker preflight now distinguishes Broker transport evidence
and the exact Broker manifest from the three signing-TCB helper manifests. It
can only mint `PreflightBrokerArtifact` after role, complete release evidence,
manifest, and absolute-path checks. That non-clone capability retains the pinned
Broker plus the opaque whole-release `AttestedArtifactDigest` accepted by
`ReleaseAttestation`. The whole-release proof denotes the overall
`ReleasePolicy` `ArtifactDigest`, not a Broker/helper manifest digest or Windows
file-object identity, and exposes no raw digest. On Windows, the admission module
alone can mint `PreparedReleaseBrokerSupervisor`, which carries that same opaque
release proof while separately retaining volume serial plus all 128
`FILE_ID_INFO` file-ID bits derived from the same already-held handle alongside
the admitted artifact. The value is non-cloneable, redacted under `Debug`, and
drop-only.

A production-compiled, crate-private exact-image activation core now consumes
that whole prepared value exactly once. Before user mode it matches the first
debug-event mapped-image handle to the held identity, then retains the value with
the exact process, one-member kill-on-close Job, and private process-bound
channel through cleanup. Its release entry accepts no path, raw handle, PID,
command line, application override, or generic launch target. The compiled
policy remains absent, so the core is dormant and is not signed-install,
native-host provenance, authenticated process topology, or release evidence.
The retained identity does not establish a Broker-plus-Key-Agent same-release aggregate,
topology, single-instance enforcement, or runtime/signing authority;
the release-bound Broker preflight, preparation, and activation path still has
no production caller.

The three production Rust inheriting-creation paths in one loaded
`platform-windows` crate instance use a single private, deadline-bound
process-wide coordinator. Temporary inheritable-handle owners borrow its
thread-bound flight; after the sealed `CreateProcessW` returns, the per-launch
attribute list and temporary handles are destroyed before release. The
restricted launcher also assigns the suspended child to its retained
kill-on-close Job atomically through `PROC_THREAD_ATTRIBUTE_JOB_LIST` and checks
membership before token verification or resume. The release
PowerShell runtime's C# toolset runner has a separate matching static lock over
its own inheritable-pipe/create/cleanup window. Neither coordination boundary
is an OS-wide hook:
arbitrary foreign FFI or standard-library launches, separately linked copies,
and other processes remain outside their scope. Deadlines bound coordinator or
lock acquisition and explicit pre-create checks, not a synchronous
`CreateProcessW` call or the fail-closed worker join.

Restricted helpers and the Key Agent now use one private immutable base process
context. It creates exact `SystemRoot` and `WINDIR` entries from the OS-reported
system-shared Windows root and passes a verified System32 current directory.
Those two names form only the immutable base block. Every restricted helper and
the Key Agent prepares its exact role profile, validates
`GetAppContainerFolderPath` as the absolute `Packages` / profile-name / `AC`
layout and prepends that returned `FOLDERID_LocalAppData` path itself as
`LOCALAPPDATA`. Each final
environment therefore contains exactly `LOCALAPPDATA`, `SystemRoot`, and
`WINDIR`; no child inherits the parent's ambient environment or current
directory. Restricted helpers complete the base
preflight before parent-proof, persistent frontend profile, or Job work; the Key
Agent completes it before acquiring the inheritable-handle flight. Both recheck
thread impersonation immediately before `CreateProcessW`. The proof is limited
to DOS path shape, Windows-root/System32 layout, directory/reparse state,
path-replacement rights on every ancestor, and content-creation rights on the
Windows root and System32 available to the current primary token. A create-only
right on the system-drive root does not by itself permit replacement of the
fixed Windows path and is not rejected. The proof retains no directory handle,
is not atomic object-identity proof, and does not prove error-mode/priority or
other Win32 process-state isolation, DLL/dependency identity, or signed-artifact
execution.

The dormant Key Agent fresh-provisioning seam can create the fixed
`YourWallet.KeyAgent.LPAC.v1` AppContainer profile and the fixed
`YourWallet.KeyAgent.Storage.v1` leaf beneath its validated `AC` folder, but it
returns only a non-launchable pending capability. Activation requires a separate
prepared capability, and no direct pending/candidate conversion exists. The
sole production-compiled prepared mint is the private sealed existing-install
adoption transition. It consumes an initial and contractually post-observation
authenticated snapshot plus a fixed-profile binding and retained
no-delete-share root, revalidates that binding/root before and after the match,
and seals the result inside `VerifiedExistingKeyAgentInstall`. Production has no
held-aggregate constructor or transition/downstream caller, so existing profiles
or roots still fail closed and are not opened, adopted, repaired, or deleted. A
future production adapter's fixed-profile-binding/held-root aggregate must
require the stable current `TokenUser` SID as owner and an exact protected
two-ACE DACL for that SID plus the fixed profile SID, the exact inherited
Low/`NW` mandatory label, a local fixed NTFS non-reparse directory with
persistent ACLs, and a nonzero-volume, non-sentinel 128-bit `FILE_ID_INFO`. It
keeps the directory open without delete sharing, revalidates the held identity,
volume, and security policy throughout binding, and closes that handle last
during cleanup.

The private one-shot storage-startup transition now binds the child to that root.
The parent writes a fixed request while the exact child is still suspended; it
contains a fresh nonce, the held PID and process creation `FILETIME`, the full
volume-serial/128-bit root identity, and only the compiled production leaf or
exact `cfg(test)` leaf grammar. Only then does the consuming transition release
the sole verified suspend count; the consumed parent writer closes after the
exact request, so the child must read both the fixed 188-byte frame and EOF
before decoding or opening the root. Any suffix or missing EOF fails closed
before a response. The child then detaches both ambient protocol entries, closes
the raw startup-stdin handle, and retains the now-non-ambient raw response handle
inside a response-only capability. This preflight must succeed before request
decoding or root work. The child then resolves the leaf beneath the exact
OS-rerouted `LOCALAPPDATA`, derives
`TokenUser` and the AppContainer SID from its own process token, and checks the
directory object, owner, protected two-ACE DACL, inherited Low/`NW` label, and
complete `FILE_ID_INFO` before constructing one response that echoes the nonce and
binds its PID, creation time, and root identity.

Once response output is attempted, no fallible result returns to `main`. The
child attempts the exact 88-byte write, `FlushFileBuffers`, and `CloseHandle` on
the retained response handle, ignores all three results, and unconditionally
leaves the startup-only lexical scope. The live `request_frame`, decoded
`request`, `response`, and `response_frame` owners therefore run their
`Zeroizing` drops before only the resident stderr boundary and fixed store
bindings escape into the non-alertable `Sleep(INFINITE)` loop. A failed write or close therefore
cannot turn into a post-output exit-78 path. The parent requires the complete
frame followed by EOF within the original startup deadline before it decodes or
accepts the response. That exact response-plus-EOF observation is the
authoritative protocol proof that the response endpoint closed. It then
independently compares every response field and revalidates the held root's
volume/security/identity, exact resident-process liveness and root-Job
membership, and Job context/limits/topology before and again after consuming the
monotonic lease; an exited child cannot cross this join merely by producing EOF.
The parent commits the held artifact identity plus the exact request and response into a
domain-separated SHA-256 transcript commitment. The resulting private aggregate
retains the process, Job, handshake, and no-delete-share root handle, but no
startup endpoint. The child retains only sealed stderr and fixed generation-store
bindings derived from its independently opened root in that infinite-sleep loop
until Job termination. Neither side exposes generic runtime I/O or signing
authority, and the startup streams are never reused as a runtime channel.

The narrow generation-file boundary is now implemented without changing the
public facade. Consuming the child-held root mints one private, unconstructible
set of `Vault`, `NonceLedger`, `SignedCandidateJournal`, and `LocalSettings`
bindings; `WindowsBackend::open_key_agent` accepts only one such binding and
derives its namespace, class, bound, root, stable-user SID, and exact fixed
profile SID internally. No caller path/principal/class selector or frontend
reference enters this call graph. Public `WindowsGenerationStore` remains
stable-`TokenUser`-only.

Each Key Agent lock, slot, manifest, and temporary file must read back with the
stable `TokenUser` owner, a protected DACL containing exactly two explicit allow
ACEs in canonical order, and exactly one inherited Low/`NW` mandatory-label ACE
whose only flag is `INHERITED_ACE` (`ID`). The user mask is
`FILE_ALL_ACCESS` (`0x001f01ff`); the exact Key Agent profile mask is
`FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE` (`0x0013019f`). Broad,
frontend, wrong, extra, reordered, deny, or inherited-DACL principals/ACEs and
mask or label drift fail closed. Each path operation is bookended by
thread-impersonation and full held/reopened-root `FILE_ID_INFO` revalidation;
files must be non-reparse, single-link, and on the held root volume. Replacement
requires the target identity/absence baseline to remain unchanged and verifies
the installed bytes, digest, full identity, and security afterward. The backend
security-context hook also bookends every untrusted fault callback, including
the two callbacks around rollback-anchor advancement.

The integrated `cfg(test)` zero-capability LPAC path exercises all four roles
through generation-one commit/load and generation-two close/reopen/commit/load.
For every role it verifies seven physical file names. On each name,
`WRITE_DAC`, `WRITE_OWNER`, and `FILE_EXECUTE` must fail with `ACCESS_DENIED`,
while `ACCESS_SYSTEM_SECURITY` must fail with `PRIVILEGE_NOT_HELD`. The root
matrix separately requires an actual `DELETE` open to hit the retained handle's
`SHARING_VIOLATION` plus a denied `AccessCheck`; `FILE_DELETE_CHILD`,
`WRITE_DAC`, and `WRITE_OWNER` return `ACCESS_DENIED`, and
`ACCESS_SYSTEM_SECURITY` returns `PRIVILEGE_NOT_HELD`. This test uses the persistent test profile,
CSPRNG leaf, in-memory anchors, and synthetic keys/payloads; it is not a
production fresh-fixed-profile/root E2E or release authority.

Fresh creation is now quarantined as non-launchable
`PendingKeyAgentProvisioning`; only `PreparedKeyAgentProvisioning` enters the
activation boundary, and no direct pending/candidate conversion can mint it.
The sole production-compiled mint is the private sealed existing-install
adoption transition. The private pure provenance boundary includes a canonical
prefix-journal verifier before the existing classifier. Every fixed record is
authenticated with an installer-owned HMAC-SHA256 key before parsing. Exact
phase-specific payloads, the `Prepared=1`, `ProfileCreated=2`, `RootCreated=3`,
`Committed=4` sequence, predecessor commitments, and a separately sealed
rollback-resistant checkpoint bind the independent installation/release
identities, high-water generation, and current commitment. The authenticated
journal `release_identity` is the whole-release `ReleasePolicy`
`ArtifactDigest` accepted by `ReleaseAttestation`, not the helper-manifest
digest or a Windows file identity. The manifest separately binds the exact child
role, version, executable hash, and signer; the retained handle and full
`FILE_ID_INFO` bind the child file object. A changed committed whole-release
identity is `RecoveryRequired`, not an in-place upgrade. No exclusive installer
lease yet serializes checkpoint, observation, and post-observation reread, so
production upgrade orchestration remains closed. Lower/higher
generations, gaps, reorderings, same-generation alternate histories, malformed
bytes, non-canonical unused fields, or root evidence before creation fail
closed. Only `RootCreated` and `Committed` carry the same canonical profile/owner
SIDs and full root identity. The journal validator produces an authenticated
snapshot. The pure matcher consumes two matching committed snapshots plus
authority-free evidence copied from a fixed-profile-binding and held-root
aggregate; only current `Committed=4` consistency produces stable evidence. Its
sole production-code consumer is the dormant sealed transition, which
revalidates the same binding/root around the match and retains the prepared
capability inside `VerifiedExistingKeyAgentInstall`. The implemented dormant
release-binding preflights the exact child, constant-time compares that whole
release identity, and only then creates `ArtifactBoundExistingKeyAgentInstall`.
Only the supervisor's private-field seal can split it, and install continuity is
retained through dormant and storage-proven states. This is not runtime/signing
IPC, installer-key, rollback-anchor, storage/AEAD-key, or
protected-settings/lease authority. The journal validator has no
production key/checkpoint constructor, journal reader/writer backend, or caller.
The adoption transition, release-binding, and dormant supervisor binder all have
zero production call sites.

Once storage startup has produced `BoundStorageProvenKeyAgent`, a separate
private transition can preserve that whole aggregate while minting one exact
Approval logical-parent process capability. It duplicates the already retained
running process object directly with inheritance disabled and the fixed access
mask `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`; it takes no PID or
caller-selected access mask and never reopens the process. Its pre/post
revalidation and opaque ownership are useful type-state evidence, but the final
Approval/Key Agent binder remains unreachable from production and grants no
launch or runtime authority.

The separate dormant `open_existing_fixed_key_agent_storage_root` is only a
root-object proof and also has zero production callers. It accepts an
observer-validated `AC` folder and live fixed-profile SID but hard-codes the
fixed leaf, performs no create/repair/delete/adoption/recovery, and opens with
`OPEN_EXISTING`, `FILE_FLAG_OPEN_REPARSE_POINT`, and no delete sharing. After
validating the initial directory/non-reparse object, local NTFS, exact owner/
protected DACL/inherited Low-`NW` label, and complete `FILE_ID_INFO`, it
canonicalizes and reopens the path under the same policy and requires identical
security and full identity. The root capability privately retains the canonical
path and reopened handle; `revalidate` checks both that held handle and another
canonical-path reopen. This is distinct from the fresh `CreateDirectoryW`
pending path and the child `LOCALAPPDATA`/process-token opener.

The remaining limits are immediate. Existing production profiles still lack
installer-owned key/checkpoint provisioning, authoritative profile-registration
observation and a held-aggregate constructor, a production caller for the
dormant root opener or adoption/binding path, an exclusive installer lease
enforcing the post-observation reread, production installer-key/checkpoint and
journal I/O backends, recovery, and release-activation orchestration. The
root-only seam cannot mint `HeldExistingKeyAgentInstallObjects`, `Prepared`,
`Verified`, journal/checkpoint authority, recovery/activation/signing/RPC/GUI,
supervisor ownership, or a Broker+Key Agent same-release aggregate. The root
`TokenUser` ACE leaves other same-user processes able to access it, and the
canonical-path comparison detects mismatch but does not atomically close
same-user/ancestor races. Production rollback-anchor and storage/AEAD-key provisioning,
protected settings and a live lease, authenticated Broker/supervisor/process
topology and single-instance enforcement, signed immutable artifacts and
DLL/dependency E2E, and release activation remain **STOP-SHIP**. The exact
request EOF and parent-authoritative response-plus-EOF checks are repo-local
startup-framing proof only; they do
not provide a runtime channel, signing authority, signed-artifact evidence, or
release activation. No generic runtime/signing IPC exists.
`COMPILED_RELEASE_POLICY` is `None`. The central
AppContainer profile API rejects thread impersonation before its process-wide
non-reentrant gate and rechecks it after mutex wait. It also bookends every
protected `CreateAppContainerProfile`,
`DeriveAppContainerSidFromAppContainerName`, and
`GetAppContainerFolderPath` call with immediate pre- and post-call checks. Any
successful raw SID or `CoTaskMem` path enters a private RAII owner before the
post-call check and is released if that check or subsequent validation fails.
Except for the binding's necessary success/error split used to capture a
successful allocation, specific native-error branching and inspection,
pointer/SID validity, path decoding and validation, SID comparisons, and
application use occur only after the post-call check. These bookends are
fail-closed observations, not an atomic proof that an impersonation token could
not be installed and removed between checks. If that check fails
after a successful `CreateAppContainerProfile`, the code does not automatically
call `DeleteAppContainerProfile` or roll back: fresh Key Agent provisioning may
already have created the profile and requires recovery. This adds neither
profile-registration authority nor production reachability, and there is no
production `DeleteAppContainerProfile` path. Same-thread reentry and mutex
poison also fail closed.

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

The activation supplies an exact five-entry process-creation attribute list in
`HANDLE_LIST` -> `JOB_LIST` -> `MITIGATION_POLICY` ->
`SECURITY_CAPABILITIES` -> `ALL_APPLICATION_PACKAGES_POLICY` order. Its full
immutable mitigation word is identical to the restricted-helper and
service-startup policy, including the non-Microsoft-binary block, and remains in
heap-stable `Box<u64>` storage through `CreateProcessW` and attribute-list
deletion. The LPAC entries still supply zero capabilities plus the ALL
APPLICATION PACKAGES opt-out. The original `CREATE_SUSPENDED` count is consumed
to let Windows produce the first
pre-user-mode create event. While that event remains held, activation
authenticates the mapped image and verifies the exact primary token into the
gate-pending proof; it does not add the later explicit suspend count there.
Accepted tokens must report AppContainer, match
the fixed profile SID, and have zero capabilities. The process token is
duplicated at `SecurityIdentification`; two `CheckTokenMembershipEx` checks over
its valid `TokenUser` SID must produce exactly false with
`CTMF_INCLUDE_APPCONTAINER` and true only after `CTMF_INCLUDE_LPAC` is added. A
supported `TokenIsLessPrivilegedAppContainer` query must return an exact DWORD
1. Only `ERROR_INVALID_PARAMETER` for that one class omits the direct DWORD
check; the exact membership differential remains mandatory and every other
error fails closed. A suspended ordinary-AppContainer control that omits only
the AAP opt-out must produce `(true, true)`, and neither control is resumed into
user mode. Every independently safe CREATE_PROCESS event alias is first recorded
in the run's shared join-cleanup owner before hFile, mapped-image, ID/object,
LPAC, or later fallible checks; malformed partial events retain every safe alias.
The worker next enters the currently strict loader loop. A real Key Agent
regression now proves that the test/production-identical policy rejects
non-primary loader activity and cleans the Job before detach. A separate minimal
import-free GUI PE fixture proves the exact-primary gate mechanics but not
product compatibility. The pre-resume default-DACL matrix additionally excludes
the current same-user LPAC architecture because no loader-compatible from-birth
policy can deny `WRITE_DAC`. A revised loader policy could exercise the compiled
gate mechanism but cannot repair that gap; a distinct OS principal/service is
the next design option. Only conditionally, if such a later gate event holds
all threads, does the implementation add one explicit primary-thread suspend
count, finalize and read back the default DACL, and continue while retaining
that count. Only after every remaining gate check may no-kill require the
complete authenticated set;
`DebugSetProcessKillOnExit(FALSE)` is then the fresh debugger OS thread's final
fallible operation. An opaque final owner crosses the join boundary without
exposing detached or resume authority. The thread exits; caller-side finalization
requires the identical final/join/root-Job witness, debugger absence on the
retained process handle, authenticated closure of the registered aliases, the
retained creator primary thread's exact 1→2→1 suspend probe, and renewed token,
Job, provisioning, and lease checks. A worker error, panic, or abandoned joined
proof instead invokes the same post-join checked-close owner, which retains
partial failures for bounded retry, attempts both aliases independently on each
pass, and closes aliases even when post-join process cleanup fails. This documented thread-exit detach avoids the
PID-only `DebugActiveProcessStop` path that the deny-only process DACL blocks. The
detached Key Agent capability exposes no generic resume API; its only consuming
resume transition is the fixed storage-startup exchange above.

The dormant Key Agent pipe owner preserves `FILE_FLAG_FIRST_PIPE_INSTANCE` at
`CreateNamedPipeW` even though its `0x00080000` value is also `WRITE_OWNER` in
the resulting access mask. It immediately duplicates each persistent server
source to exact request read-plus-synchronize `0x00100001` or response
write-plus-synchronize `0x00100002`, inheritance false and options zero, then
checked-closes the original before client open. Child stdin, stdout, and
NUL-backed stderr are separate exact-access inheritable duplicates; none uses
`DUPLICATE_SAME_ACCESS`.

One ignored host-local kernel test uses the official `windows` WDK native-query
function/class bindings and a test-only `repr(C)` local pipe-information ABI
mirror guarded by size, alignment, and offset assertions. Exact sources omit
`FILE_READ_ATTRIBUTES`, so only the sealed `parent_response` client supplies
pipe-local outbound/client-end information; request direction is proved by
successful forward I/O and rejected reverse I/O. Handle flags and same-object
comparison cover inheritance and continuity. The WDK wrappers create native-symbol
load-time imports in the test binary rather than resolving them dynamically,
which leaves a test-host compatibility limit but no production call or import
reachability. This is test-only kernel evidence for `PrivateKeyAgentPipes`, not
runtime admission. Separate ignored probes now cover the common attenuation
path and Phase 1 service-helper target candidates; neither evidence set enables
production activation.

On 2026-08-27, the locked `platform-windows` all-target/all-feature run on Windows
build 26200, with the freshly built Key Agent test executable explicitly bound,
reported 567 passed, 16 failed, and 27 ignored. The affected cases failed
earlier at process creation on a host where third-party injected modules were
observed; coexistence is not causal proof. This result does not authenticate raw
`DEBUG_EVENT` slot generations or eliminate same-object ABA or the compare-to-
close TOCTOU. The separate Phase 1 ignored probes measure source and target-
candidate pipe authority on this host, but do not provide runtime admission,
real child adoption, or a supported-kernel result. Production activation
remains forbidden and both compiled policies remain `None`.
The new dormant debugger-process transport probe verifies solution mechanics
only; it does not alter any raw-`DEBUG_EVENT` or release conclusion below.

The Key Agent executable now seals its child-side standard handles as its first
Windows application operation. It prevalidates exactly three distinct inherited
objects with exact `PIPE`/`PIPE`/`CHAR` types and exact inherit-only flags,
attempts to clear all three inherit bits without rollback, and accepts only an
exact zero-flag readback. Any rejection exits 78 before another application
operation. An isolated child/grandchild kernel test uses exact object comparison
to prove that none of the original three stdio objects propagates. This is a
repo-local implementation proof, not signed-artifact, supervisor-topology, or
release-activation evidence. Immediately afterward the child reads exactly one
startup request and requires EOF before decoding or opening the root. It then
detaches the ambient stdin/stdout entries and closes raw stdin before decoding or
root work, while retaining the raw response handle only inside a response-only
capability. After its process/root checks it attempts exactly one response, then
attempts to flush and close that handle without propagating any result to
`main`, and enters a non-alertable `Sleep(INFINITE)` loop. It retains sealed
stderr and fixed generation-store bindings derived from its independently opened
root until Job termination; no startup handle is reused for runtime I/O. The
parent's exact response plus EOF under the original deadline is authoritative
for successful response-handle closure.

Approval release admission is now a separate dormant private type state. It
consumes one pinned helper into `PreflightApprovalArtifact` only after the
manifest-derived Approval role, complete release attestation, exact
helper-manifest allowlist membership, and absolute path succeed in that order.
Preparation derives `FILE_ID_INFO` from that same held file and moves the
artifact, opaque whole-release identity, and exact file identity into
non-cloneable `PreparedReleaseApprovalSupervisor`.
Neither state exposes its artifact, path, identity, PID, or raw handle, and the
module allocates no process, Job, pipe, channel, thread, launch state, or second
file handle. The legacy Approval launcher, pending response state, and broad
`LaunchedHelper` are crate-private. The legacy launcher now distinguishes a
wrong helper role and otherwise returns `LogicalParentUnavailable` before nonce,
pipe, process, or request work because it lacks the complete logical-parent
aggregate. It no longer calls crate-private `RestrictedLauncher::spawn`; that
generic method rejects Approval with `ApprovalRequiresParentBoundActivation`
before resource work, and its internal legacy launch leaf accepts only Secret
Input as a second check. The generic method has no non-test caller, and the
legacy launcher likewise has zero production callers.

The following private type-state edge consumes both that complete Approval proof
and the intact `BoundStorageProvenKeyAgent`. It obtains a fresh,
non-inheritable duplicate of the same already held running Key Agent process
object with exactly `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`; it neither
accepts nor reopens a PID. Pre/post checks cover the resident process, storage,
root-Job membership/limits, and permitted Key Agent root-Job topology. The opaque
`ParentBoundReleaseApprovalSupervisor` preserves both full aggregates, exposes
no constituent, identity, PID, path, raw handle, generic access mask, resource
operation, or launch operation, and retains no newly allocated OS resource
except that narrow handle. Its production binder has exactly one private
consumer: the dormant Approval preparation below.

At session issuance the platform samples one opaque monotonic window internally
and splits it into non-Clone authorization and transport halves with one exact
issuance identity. `wallet-protocol` retains both privately and invalidation
drops the unused transport half. The Key Agent constructs one canonical request
from the exact digest, one-shot nonce, display, and protected anti-phishing
phrase; the matching authorization half consumes the transport half once into
opaque `BoundApprovalTransport`.

The dormant consumer requires that carrier and rejects elapsed original expiry
before allocating the fixed private Approval pipes and exact two-object
stdio allowlist, then uses the pinned verified Approval artifact to create a
process suspended in the fixed revision-v1 LPAC and single-process Job. This is
not mapped-image provenance. The ordinary channel-supervisor process
and image proofs are still injected unchanged. In addition, a sealed
production-compiled leaf copies the exact narrow Key Agent handle into the
suspended child as a fifth, non-inheritable logical-parent capability. The
resulting non-cloneable `BoundDormantApproval` retains the suspended process,
primary thread, Job, both unused parent pipe endpoints, full parent-bound
aggregate, and the bound carrier. It exposes no resume, request, response,
signing, path, PID, handle, profile, launcher, or attestation operation. Drop
first makes a bounded
terminate-and-reap attempt for the Approval child before releasing pipes and the
Key Agent tree. The outer dormant preparation itself has zero production
callers.

A second sealed consuming transition uses the earlier of original expiry and a
fresh five-second grace as its bootstrap deadline. It writes the complete
version-2 parent hello to the private request pipe before releasing exactly one
primary-thread suspend count. It then reads and decodes the exact child hello and revalidates the live
Approval process/Job plus the complete parent-bound Key Agent aggregate. Its
opaque `AuthenticatedApprovalBootstrap` retains the running Approval, both
still-open parent endpoints, both hellos, that aggregate, and the carrier. It
exposes no protocol method; only one separate sealed function may consume it,
with no raw request or deadline input. This transition has zero production
callers. Explicit bootstrap failure performs a bounded terminate/reap attempt
first and gives
cleanup failure precedence. Drop retains kill-on-close fallback without
claiming unconditional reap success.

The separate full-exchange function uses the carrier's exact canonical request
and original monotonic deadline for response arming, the consuming parent-finish
plus canonical request and request EOF, the fixed response plus EOF, and natural
exit of the exact held child. It
revalidates child/Job and Key Agent state before arming and before response read.
Verified response bytes remain exit-pending: success additionally requires the
same exact process to exit naturally with code 0 before that same deadline.
Only after natural exit does the parent perform final Key Agent revalidation
and a final deadline check, then mint crate-private opaque
`VerifiedParentBoundApprovalExchange`, retaining the original carrier. The
evidence has no response accessor or conversion to `VerifiedApprovalResponse`
or signing. The transition also has
zero production callers. The post-exit Key Agent check is point-in-time
evidence; any future evidence-to-authorization transition must revalidate the
retained exact Key Agent again immediately before use. No such transition
exists. Success never comes from force-terminating a live
child. Protocol failure, timeout, nonzero exit, or wait failure rejects and uses
a separate bounded terminate/reap where a child remains owned; cleanup failure
takes precedence.

This handle records only the intended logical parent proof source. It is not a
`PROCESS_CREATE_PROCESS` capability, does not set
`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, and does not establish Windows process
parentage, a security boundary, or runtime readiness. A repo-local `cfg(test)`
integration now copies the exact non-inheritable handle into an actual
zero-capability Approval LPAC. It proves `OpenProcessToken(..., TOKEN_QUERY)`,
session/image/PID/liveness/zero flags, rejects twelve stronger or standard token
rights, and proves `SeDebugPrivilege` absence. Its local `DuplicateHandle`
denial matrix requests `PROCESS_DUP_HANDLE`, `PROCESS_TERMINATE`,
`PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`,
`PROCESS_VM_WRITE`, `PROCESS_CREATE_PROCESS`, `PROCESS_QUERY_INFORMATION`,
`PROCESS_SET_QUOTA`,
`PROCESS_SET_INFORMATION`, `PROCESS_SET_LIMITED_INFORMATION` (`0x2000`),
`PROCESS_SUSPEND_RESUME`, `WRITE_DAC`,
`WRITE_OWNER`, `READ_CONTROL`, and `DELETE`. Its PID-reopen denial matrix
requests `PROCESS_DUP_HANDLE`, `PROCESS_QUERY_INFORMATION`,
`PROCESS_QUERY_LIMITED_INFORMATION`, `PROCESS_SET_LIMITED_INFORMATION`
(`0x2000`), `SYNCHRONIZE`, the exact query-limited/synchronize combined mask,
and `WRITE_DAC`. At `CREATE_PROCESS_DEBUG_EVENT`, production Key Agent
activation opens the then-current token as `Hwrite` with exactly
`TOKEN_QUERY | WRITE_DAC | READ_CONTROL` and separately opens `Hadjust` with
exactly `TOKEN_QUERY | TOKEN_ADJUST_DEFAULT`. Before mutation,
`CompareObjectHandles(Hwrite, Hadjust)` must prove exact token-object equality.
This pending phase installs only the protected token-object DACL and performs a
bounded two-pass
`GetKernelObjectSecurity(DACL_SECURITY_INFORMATION)` readback through that same
opened handle. The sizing call must fail with `ERROR_INSUFFICIENT_BUFFER` and a
1..=64 KiB requirement; the aligned second pass, its returned size, and
`GetSecurityDescriptorLength` must match that requirement exactly. The returned
descriptor must be valid and self-relative, with a present/protected,
non-defaulted, non-auto-inherited DACL. Exact self-relative bounds,
`ACL_REVISION`, zero reserved fields, ACL size, and descriptor end admit only
three zero-flag explicit `ACCESS_ALLOWED_ACE`s, ordered as stable `TokenUser` SID
with `TOKEN_ALL_ACCESS`, fixed Key Agent SID with
`TOKEN_QUERY | TOKEN_DUPLICATE`, then fixed Approval SID with exactly
`TOKEN_QUERY`. Masks, declared SID lengths, binary SID bytes, and ACE sizes must
consume the exact ACL/descriptor with no extra ACE, slack, or trailing byte.

A fresh `Hfinal` with exactly
`TOKEN_QUERY | TOKEN_DUPLICATE | READ_CONTROL` must compare as the same token and
pass LPAC, token-object-DACL, and identity checks. `Hwrite` is checked-closed;
`Hadjust` remains only inside opaque `PendingKeyAgentLpac`, returned by
`PreparedKeyAgentLpac::prepare_suspended_process_for_gate(...)`. The eight-case
pre-resume `TokenDefaultDacl` kernel matrix now fixes the current same-user LPAC
boundary.
In the green
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

The precise decision is that the current same-user LPAC principal cannot supply
a loader-compatible from-birth policy that denies `WRITE_DAC`. This excludes the
current architecture, not every possible Windows design. Post-loader final-DACL
and gate feasibility cannot retroactively close that gap. The next design option
is a distinct OS principal/service boundary with new principal, IPC, and service
lifecycle proofs. Compiled finalization remains only a conditional mechanism at
the reviewed semantic gate inside `serve`, after loader, DLL, TLS, and CRT
initialization. This is not the first machine or Rust instruction, and objects
created before the gate remain outside the proof.

ADR 0001 and the accepted Windows Key Agent Service Design Brief now select
that distinct-principal direction. The committed Phase 1 work remains an
explicit debug-only, no-secret feasibility surface: an inert SCM lifecycle, a
dependency-free bounded service wire, a checked-in classic-MIDL x64 sys
boundary, and an opt-in local-RPC `Status -> Unavailable` server fixture. The
immutable default `YWKASV01` wire can only open an epoch or request status,
binds status responses to a nonzero epoch nonce and request identifier, and
never accepts identity, role, or deadline fields as authority. The sys boundary
fixes one zero-padded 76-byte RPC frame, distinct client/server symbols, a call-
lifetime server binding, closed manager errors, and an SEH containment shim. The
generated 76-byte MIDL
frame plus canonical Rust decoder are the hard message boundary. The
`MaxCalls = 8` and `MaxRpcSize = 76` values passed to the RPC runtime are only
registration/listen hints. The application independently caps concurrent If3
callback-authentication work at eight permits and serializes manager dispatch
behind one mutex.

A separate non-default `debug-feasibility-v2` module leaves that V1 contract
unchanged and defines debug-only `YWKASV02` V2. Its six exact frame lengths are
20/52 bytes for open-epoch request/ACK, 72/72 bytes for desktop-command
request/response, and 68/68 bytes for helper-ready request/ACK. Desktop commands
are closed to Status, Approval RPC probe, and Secret Input RPC probe. Results are
closed to fail-closed `Unavailable` plus the two role-matching probe-completed
values. `Unavailable` is permitted for every command; completed results cannot
cross-bind. The V2 wire accepts no role, PID, image identity, or other peer
authority.

The feature-gated V2 desktop dispatch boundary authenticates once before
decoding and is now consumed by the live `ServerContext` RPC manager. It returns
immediate open-epoch or Status/`Unavailable` responses, or a move-only Approval/
Secret Input launch action that owns the freshly authenticated peer and exact
consumed request. A desktop `HelperReady` is authentication-denied before epoch
lookup or consumption. V1 dispatch delegates to an explicit already-
authenticated V1 method without changing behavior.

The exact consumed desktop request is the only source of helper role, epoch,
request ID, and matching completed result. The manager thread keeps the one-shot
pending-completion capability and sends only the authenticated desktop authority
plus an exact request copy to a dedicated coordinator. One occupied launch spans
that worker and its capacity-one transport; a second launch cannot queue behind
it and completes locally as correlated `Unavailable`. Stop, queue rejection,
worker disconnect, and the bounded manager wait also settle that same local
capability exactly once.

The status-only debug server preserves its original single explicit security
descriptor for endpoint and If3: AU and SY receive `GA`, with a Medium/`NW`
mandatory label. The LPAC probe instead derives canonical, distinct package SID
strings from the fixed `YourWallet.ApprovalFrontend.LPAC.v1` and
`YourWallet.SecretInputFrontend.LPAC.v1` profile monikers with
`DeriveAppContainerSidFromAppContainerName`, then canonicalizes them through
`ConvertSidToStringSidW`. It retains two Low/`NW` descriptors: the endpoint grants
connect `0x1` to AU, SY, and both exact package SIDs, while the separate If3
descriptor grants `GA` to the same four principals. Derivation, canonicalization,
distinctness, SDDL construction, or descriptor conversion failure returns only
`Unavailable`. This closes the previous descriptor-level LPAC transport-
reachability defect in the debug composition, but is not evidence that an
installed restricted SCM service completed the fixed-LPAC exchange.

The server registers WINNT authentication plus an If3 callback with local-only,
secure-only, and no-security-cache flags, and requires packet privacy. Both the
If3 callback and the manager independently re-query the active call,
impersonation token, and a freshly opened process/primary token. The call must
be local, normal, and in the
active state: the Windows SDK defines `CallStatus` as cancellation and
disconnection bits, so the accepted value is exactly zero and values 1, 2, and
3 are denied. `TokenHasRestrictions` is accepted only in the canonical native
one-byte or documented four-byte shape, and its value must match across the
impersonation and primary-token observations. This preserves normal
UAC-filtered desktop callers without treating filtered state as unconstrained.
The resulting predicate proves at most a local, medium-integrity, interactive,
non-AppContainer caller. It performs no enrolled-Broker, role, image, or helper
authentication. RPC
supplies a numeric PID rather than an atomic process object; sampling that PID
twice around `OpenProcess` and retaining the resulting handle reduces ambiguity
but does not prove that the handle names the original RPC client across PID
reuse.

Only the manager path may turn that authenticated desktop observation into a
launch-token capability. While the exact call is impersonated it duplicates a
move-only primary token with precisely `TOKEN_QUERY | TOKEN_DUPLICATE |
TOKEN_ASSIGN_PRIMARY`, verifies that the new handle is non-inheritable, compares
the duplicate to both effective client-token observations before revert, and
revalidates its complete identity and token ID while the epoch lives. The If3
callback repeats identity authentication independently but returns only a
private data-free marker; it never creates or retains a primary token. The
passing same-process live round trip exercises this primitive, but still does
not authenticate an enrolled Broker or prove `CreateProcessAsUserW`.

Desktop admission MUST reject assignment of `SeDebugPrivilege`, including an
assigned-but-disabled privilege; checking only the enabled bit is forbidden
because the admitted token could enable it later. Once the authenticated
desktop process-creation claim has been consumed and the service-created child
is still suspended, the one-shot post-create verifier MUST impersonate that
exact retained desktop token and require
`OpenProcess(PROCESS_DUP_HANDLE, FALSE, child_pid)` to fail with exact
`ERROR_ACCESS_DENIED`. Retained-client and effective-token checks MUST bookend
the access check, failed impersonation MUST NOT continue in process context,
revert MUST be exact-once, and an unexpected success MUST be checked-closed.
This decision proves only that authenticated token against that exact child; it
does not exclude administrators, another token, or a copied Job handle.

Helper RPC transport identity and helper authority MUST remain separate. A
role-aware transport classifier may return a service-created-LPAC candidate only
for a local low-integrity restricted AppContainer with limited elevation, no UI
access, no interactive SID, and absent `SeDebugPrivilege`. Exact LPAC profile
SID, zero capabilities, image, process/token object, and Approval or Secret
Input role MUST come from the independently retained expected peer, never from
client fields. The registry has exactly eight slots and MUST register while
suspended, revalidate before the sole resume, serialize resume with
`ExpectedRunning` publication so a resumed callback cannot observe an in-flight
phase, keep callback observation non-consuming, and consume a key-bearing
manager admission exactly once. Retired slots MUST NOT be reused during that
server lifetime. Duplicate keys/processes, replay, role or phase mismatch,
races, stop, and cancel MUST fail closed. Terminal cancellation MUST request
termination, bounded-wait the exact process, and prove the Job empty; an in-
flight cleanup request MUST NOT report quiet success before the owner settles.
Registry cancellation and stop use a fixed five-second quiescence bound.

If a malformed helper manager frame cannot yield a trustworthy expected-peer
key, rejection MUST still settle related authority. The role-aware manager scan
retires exact matches and any peer whose relationship query is indeterminate,
while only definite non-matches may remain live. Candidate revalidation failure
does not spare an exact match; ambiguous matches, query failure, panic, and a
conflicting registration race retire affected owners and fail closed.

The 72-byte `YWKHBA01` helper-adoption ACK MUST NOT be reused as proof of the
later RPC round trip. The distinct 72-byte `YWKHRC01` confirmation carries the
validated bootstrap epoch, request ID, and fixed role only as correlation after
the exact helper-ready acknowledgement; it does not authenticate the helper or
grant role authority. Child bootstrap retains the encoded correlation key and
absolute hello deadline only in private zeroizing, non-cloneable state.

Separate debug-feature-gated Approval and Secret Input executable entrypoints
fix their roles and enter the helper RPC transition. The helper uses the fixed
local endpoint with implicit WINNT credentials, packet privacy, and authz-none;
it sends the exact 68-byte `HelperReady`, accepts only the correlated 68-byte
ACK, frees the binding, exact-writes `YWKHRC01`, closes the response pipe, and
blocks on the request pipe until service termination. Every failure is process-
terminal. The service accepts success only after confirmation plus EOF, expected-
peer admission and role match, and exact process/Job cancellation while the
request writer remains retained.

These rules now have debug-only RPC-manager, coordinator, helper-send, and
executable reachability, but still authorize no production helper operation or
release-policy change. There is no evidence from an actual installed restricted
SCM service, cross-session/elevated service-created LPAC round trip, or signed
immutable helper `ncalrpc` E2E.

The separate debug service-token observer runs before SCM publishes
`SERVICE_RUNNING`. Its safe policy and narrow Windows adapter can verify the
fixed virtual-account user SID, primary Session-0 restricted-token shape,
documented service/logon/Local normal-group facts, the exact documented
restricted-SID identity quartet, and the four-name candidate privilege set.
The opaque result deliberately carries `Unverified` markers for restricted-SID
attributes, privilege enablement/necessity, integrity, and SCM configuration.
Its positive test requires the exact installed restricted service and remains
ignored; parser and one-field negative policy evidence cannot substitute for
that elevated disposable-VM kernel probe.

The observer now retains the handle opened with exactly `TOKEN_QUERY`, with
inheritance disabled, together with the complete canonical service-token
baseline. Its exclusive creation-token marker is available only after rejecting
thread impersonation, reopening the current process token, comparing the two
handles as kernel objects, and rechecking zero handle flags plus exact token IDs,
identity, `TokenOwner`, `TokenPrimaryGroup`, normal and restricted groups,
privileges, and the resolved privilege catalog. The owner must equal the fixed
service SID and the primary group must be an exact `TokenGroups` member. The
marker exposes only a lifetime-bound borrow to the sibling creation-security
module; it exports no identity or owned-handle value.

Behind the distinct debug-only LPAC feature, that sibling module derives two
separate non-inheritable process/thread descriptors from the service marker and
compares the owner/group bytes copied by descriptor construction to the sealed
baseline. It then repeats the same-object/full-baseline check before retaining
the marker through created-object readback. It cannot accept the desktop launch
token. A disjoint service-helper Job owner also proves an unnamed non-nested Job
with exact `KILL_ON_JOB_CLOSE | ACTIVE_PROCESS`, an
`ActiveProcessLimit` of one, stable lifetime-bound creation-attribute storage,
and bounded whole-Job termination.

The authenticated desktop token remains sealed inside RPC auth. It has no raw
or borrowed-handle getter. Target-user profile preparation can instead obtain a
must-use, same-thread impersonation lease whose explicit finish and drop
fallback own the only exact-once `RevertToSelf`, residual-token check, and
retained-client revalidation authority. The target profile guard holds that
lease ahead of the existing process-wide profile mutex owner, so implicit and
explicit cleanup both remove impersonation before another profile caller can
enter. Fixed Approval and Secret Input constructors individually bookend
`CreateAppContainerProfile`, SID derivation/equality,
`GetAppContainerFolderPath`, and folder validation with effective-token
rechecks. A successful newly allocated SID or path is RAII-owned before the
post-call check. The retained profile SID must remain equal on fresh derivation,
and the folder must remain the exact absolute
`...\Packages\<fixed-profile>\AC` path. The minimal environment sets
`LOCALAPPDATA` to that authoritative returned `...\AC` folder and contains only
the verified `SystemRoot` and `WINDIR`. Its stable creation values contain zero
capabilities and the ALL APPLICATION PACKAGES opt-out.

A separate five-slot startup owner installs the lifetime-bound one-process Job,
the existing full helper mitigation policy, the target-user security
capabilities, the opt-out policy, and the restricted-child policy in that
order. It fixes `winsta0\default`; title, reserved fields, and all standard
handles are null; `STARTF_USESTDHANDLES` and a handle-list attribute are absent.
The attribute list is destroyed before any backing Job, SID, policy, or scalar
storage.

An auth-owned one-shot attempt now consumes those inputs at the sole
`CreateProcessAsUserW` boundary. The call accepts only the fixed application
name, no command line, `bInheritHandles = FALSE`, paired non-inheritable
service-owned process/thread security attributes, the exact target environment
and current directory, and exactly `CREATE_SUSPENDED |
DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT |
EXTENDED_STARTUPINFO_PRESENT`. A native error cannot expose uninitialized
`PROCESS_INFORMATION`; native success immediately transfers both returned
handles into non-copyable owners after exact handle, ID, flag, and liveness
checks. Malformed native success terminates the uniquely validated process and
fails fast rather than returning partial authority.

The attempt requires a move-only witness minted only by a fresh scoped debugger
OS thread. Its pre-event success state remains suspended and debug-attached:
this creation subtransition never receives or continues a debug event, releases
the initial suspend count, detaches, or calls
`DebugSetProcessKillOnExit(FALSE)`. Post-create readback proves the helper/path,
paired service-owned process/thread descriptors, one-process Job membership and
count, and a retained/fresh child-token pair. Each token must be primary, in the
target session, exact-role zero-capability LPAC, and show the required AAP
opt-out membership differential; its `TokenUser`, exactly one logon SID, and
`AuthenticationId` must match the authenticated desktop baseline. There is no
ordinary-AppContainer or unsupported-LPAC fallback.

Every post-create failure first requests termination of the exact process and
then latches whole-Job termination. The pending owner may cross the creator
thread boundary, but bounded process wait/close and exact-zero Job completion
are accepted only after the matching debugger thread has exited and joined.
Pre-event cleanup therefore does not use `WaitForDebugEvent`,
`ContinueDebugEvent`, `ResumeThread`, `DebugActiveProcessStop`, or a kill-on-exit
opt-out.
That statement is scoped to creation/pre-event cleanup; the subsequent debug-
only parent gate owns a bounded admitted debug-event sequence.

The debug-only V2 RPC coordinator now reaches the service-owned creation and
two-gate primitives, and the role-fixed Approval/Secret Input probe entrypoints
reach child bootstrap plus `HelperReady`. This is executable composition, not a
successful installed-service proof. Required privilege enablement, exact
interactive desktop DACL access, child-token query access, and an actual
cross-session/elevated restricted-SCM call remain **STOP-SHIP** work.

The service keeps at most sixteen five-second process-correlated epochs,
removes a nonce before every expiry/identity/state check, returns only
`Unavailable`, and invalidates all epochs before exact stop/unregister/wait
rundown. If failed-listen rollback or stop rundown cannot prove release, the
RPC-referenced runtime remains retained until process exit and the SCM host
omits `SERVICE_STOPPED`. In the LPAC slice, shutdown completes RPC rundown first,
then stops and joins the coordinator, then stops the eight-slot helper registry
with its five-second quiescence bound. Cleanup, registry-internal, debugger-
invariant, and role-correlation failures latch fatal coordinator health, close
RPC admission, and make a clean stop unavailable.

While a worker drains, a shutdown reporter advances `SERVICE_STOP_PENDING`
every 500 ms with a 3-second wait hint. The ordinary status fixture retains its
15-second fail-fast bound. Only the debug LPAC probe build derives a 30-second
hard fail-fast watchdog from the two-gate, registry-quiescence, process-cleanup,
Job-cleanup, and margin constants. Either reporter aborts on deadline, status-
report failure, or disconnect. The 30-second watchdog does not prove that each
Windows call is interruptible and MUST NOT be described as a clean per-operation
deadline or unconditional liveness proof.

The debug epoch foundation now shares that fixed capacity across V1 and V2 while
permanently recording the issuing protocol generation in every slot and deriving
the nonce under a generation-specific domain. A consume attempt removes the
matching nonce before checking the requested generation. Presenting a V1 epoch
to V2 or a V2 epoch to V1 is therefore a terminal denial, not a retryable version
probe. This binding and V2 desktop dispatch exist only behind the LPAC-launch
debug feature. Under that feature the live `ServerContext` role-aware manager
routes V1, V2 desktop, and helper-ready calls; immutable V1 behavior is
unchanged.

Only the exact Windows debug feature can enter that server. Direct launch,
default and production configurations, non-Windows builds, and every release
build still fail closed silently with the unavailable code. There is no
production client binding. The only live binding exercise is the ignored
same-process authenticated Windows round-trip test, which passes on the current
interactive host. That is positive evidence only for this narrow local debug
composition, not for a claimed Windows-build matrix. Endpoint squatting, final
service identity and mutual authentication, a cross-session zero-capability
LPAC exchange, and a real Broker client remain
**STOP-SHIP**, as do the installer/restricted-virtual-account proof, actual
installed interactive helper creation and cross-session bootstrap evidence,
signing composition, and complete live kernel matrix. The fixture is not
production authorization, and the release remains **STOP-SHIP**.

Preflight parses the exact held Key Agent image as AMD64 PE32+ and admits exactly
one whole-file 11-byte `49 BA <marker-le> CC` sequence. All 11 bytes must lie in
initialized raw, non-padding bytes of exactly one executable section. The
`CREATE_PROCESS_DEBUG_EVENT` hFile identity authenticates that same held image
and is checked-closed before that event is continued. The only runtime gate
address is authenticated
`lpBaseOfImage + sequence_rva + 10`, never the preferred image base or
`lpStartAddress`.

Process and primary-thread creation security is deny-only and fail-closed. The
launcher derives `TokenOwner` and `TokenPrimaryGroup` with bounded exact token
queries and builds two distinct `LocalAlloc` self-relative descriptors. Each
descriptor belongs to a non-inheritable `SECURITY_ATTRIBUTES` and carries a
protected DACL with no allow ACE and exactly one zero-flag `OWNER RIGHTS` deny
ACE for `S-1-3-4`. Its exact mask is `0x000e0000`, meaning
`READ_CONTROL | WRITE_DAC | WRITE_OWNER`. A caller cannot select one side: an
inseparable pair supplies both `CreateProcessW` `lpProcessAttributes` and
`lpThreadAttributes`.

The returned creator-owned exact process and primary-thread handles are the
authorities for pre-resume verification and debugger-detach finalization. Before
the first `ResumeThread`, their PID/TID must match the returned identities, both
`GetHandleInformation` results must be exactly zero, and bounded exact
`GetKernelObjectSecurity` readback must match the captured owner/group, expected
self-relative/DACL-present/protected control state, a zero SACL offset in the
requested owner/group/DACL projection, the single exact no-flag deny ACE and mask,
and the ACL/descriptor end with no slack or trailing bytes. The readback does not
request the SACL and therefore does not prove its actual absence. A mismatch
aborts and cleans up the child. Descriptor owners are dropped before resume; no
PID/TID reopen substitutes for either creator handle.

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

The `CREATE_PROCESS_DEBUG_EVENT` process and thread values are separate aliases,
not creator-owned slots. On the first event they must be valid, distinct from one
another and both creator handles, report the expected PID/primary TID, and compare
as the same process and thread objects. Windows manages them while debugging.
Every independently safe raw alias moves into a witness-branded shared cleanup
owner immediately after event extraction and before hFile or any other fallible
authentication; no-kill later requires the complete authenticated set.

One debugger OS thread owns the loader/gate loop. The currently compiled
candidate is monotonic-deadline bounded to 160 post-create events and 128
`LOAD_DLL_DEBUG_EVENT`s, requires every event to carry the expected PID/primary
TID, and rejects `CREATE_THREAD`/`EXIT_THREAD`, `UNLOAD_DLL`, and non-landmark
exceptions. It fails closed but is not a production-compatible decision. Test
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
reopen denial, while checked-closing every non-null event hFile before
continue. Its policy and bounds remain **STOP-SHIP**. Any eventual automatic
first-chance system breakpoint must still follow an exact System32 `ntdll.dll`
`FILE_ID_INFO` match whose `lpBaseOfDll` pins the allocation base. Its address
must be in a committed, image-backed, executable, non-guarded page with that
`AllocationBase`, the remote byte exactly `0xCC`, and RIP equal to exception
address plus one. No `DbgBreakPoint` export RVA or fixed exception
`NumberParameters` shape is assumed.
Even a successful replacement loader policy would not close the measured
from-birth `WRITE_DAC` gap, so it is not sufficient to admit the current
same-user architecture into production.

The initial `CREATE_SUSPENDED` count was consumed 1→0 to produce the first debug
event; that event itself prevented user-mode execution until continued. It is
continued only to admit the authenticated primary thread through loader, DLL/TLS,
and CRT initialization. If the revised loader policy reaches and authenticates
it, the semantic gate must be a first-chance `EXCEPTION_BREAKPOINT` from the exact PID/primary TID at
the authenticated main-image INT3, with RIP equal to the address plus one, R10
equal to the preflight marker, and an exact remote reread of all 11 bytes. The
page must be committed, image-backed, executable, non-guarded, and allocated from
the authenticated main base. Before continue, the debugger uses an explicitly
16-byte-aligned AMD64 `CONTEXT` wrapper, zeroes R10, and proves the context
readback. Only the reserved always-one EFLAGS bit 1 representation may
canonicalize; every mutable flag bit and every other reviewed context field
remains exact. It then calls `SuspendThread` on the exact primary-thread
object. Its prior count must be zero, leaving one explicit post-gate suspend count
while the debug event keeps every thread stopped.

The separately green
`minimal_primary_gate_proof_detaches_with_one_verified_suspend_count` uses a
deterministic import-free relocatable GUI PE fixture to prove the exact
PID/primary-TID gate, `PendingKeyAgentLpac`→`VerifiedKeyAgentLpac`, one verified
suspend count, detach, and root Job count one. It proves the gate machinery, not
actual Key Agent loader compatibility, a signed artifact, or product E2E.

Supervisor evidence keeps this layering explicit. The green minimal-PE
`integrated_kernel_binding_owns_one_member_and_no_inheritable_parent_handles`
and `dormant_aggregate_unwind_synchronously_aborts_the_exact_process` cover only
dormant ownership, non-inheritance, and drop/unwind cleanup. All seven supervisor
integration tests that drive the Rust-startup fixture through storage or
Approval are explicitly ignored **STOP-SHIP** because loader workers precede the
exact-primary gate. The green
`rust_startup_fixture_loader_activity_fails_closed_before_supervisor_binding`
instead proves that activity returns `KeyAgentSupervisorError::Activation` and
removes the prepared storage root. No actual production gate or storage-startup
success is claimed.

At that stopped boundary, `PendingKeyAgentLpac::finalize_after_gate(...)`
consumes the gate-pending proof into `VerifiedKeyAgentLpac`, re-reads the current-token
association, proves `Hfinal` and `Hadjust` are the same current token, and
revalidates LPAC and the token-object DACL. `Hadjust` installs the exact 28-byte
`TokenDefaultDacl`: `ACL_REVISION`, zero reserved fields, no allow ACE, and one
zero-flag `ACCESS_DENIED_ACE` for binary `OWNER RIGHTS` (`S-1-3-4`) with exact
mask `0x000e0000` (`READ_CONTROL | WRITE_DAC | WRITE_OWNER`), without an extra
ACE, ACL slack, or trailing byte. Its immediate bounded
`GetTokenInformation(TokenDefaultDacl)` readback validates the complete returned
prefix and initialized range and, before forming an ACL slice, uses checked
arithmetic to prove the non-null aligned `PACL` header and complete ACL lie
inside that range. Initialized API-wrapper padding/trailing bytes may surround
the pointed ACL, but the 28-byte ACL itself permits no internal slack. A new
`TokenStatistics` baseline is recorded only after the
mutations and provisional `TokenId` continuity is checked. `Hadjust` is then
checked-closed. With adjustment authority gone, `Hfinal` bookends the full LPAC
policy, identity, exact token-object DACL, exact default DACL, and baseline-equal
statistics and must match a fresh current-token object. The final proof retains
only the unchanged least-authority `Hfinal`, with neither `WRITE_DAC` nor
`TOKEN_ADJUST_DEFAULT`. When the later sole
post-gate `ResumeThread` releases the explicit count, the child's first semantic
step calls `verify_current_key_agent_default_dacl_after_gate()`, independently
opens its current token with `TOKEN_QUERY`, and reads the same default DACL back
before later `serve` work is admitted.

After the matching debugger OS thread exits and joins and
`CheckRemoteDebuggerPresent == false`, normal finalization takes the registered
set, requires both aliases still to be present and distinct, reauthenticates exact
object/ID/zero-flag state, and checked-closes the thread alias and process alias
exactly once. The tested host kernel leaves them live and this thread-exit detach
path offers no later exit event for cleanup.

The registry is also the authoritative failure path after registration. Worker
`Err`, worker panic, or abandonment of the joined proof invokes post-join checked
closure. Failed adoption restores the set, partial closure preserves the
remaining slot, and last-owner `Drop` makes bounded retries. Each pass attempts
the thread and process aliases independently, and a post-join process cleanup
failure cannot starve alias closure. Explicit cleanup
failure takes precedence. Evidence for the same semantics on every supported
Windows kernel/version remains **STOP-SHIP**.

After the creator-handle post-detach 1→2→1 probe and token/root-Job checks, the
supervisor duplicates rather than reopens three least-authority handles. The
resident process mask is exactly `0x00101001`
(`PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`). The
ephemeral post-detach probe requests exact `THREAD_SUSPEND_RESUME` (`0x2`), for
which the modern host reports effective `GrantedAccess == 0x1002` because Windows
automatically adds `THREAD_RESUME`; its attributes remain zero. The separately
retained startup thread requests only `THREAD_RESUME` (`0x1000`). Inheritance is
false and duplication options are zero. Every duplicate must have zero handle
flags and compare as the same object as its creator source.

The narrow process itself repeats PID/liveness/current-token/root-Job
verification. The ephemeral `0x1002` handle itself repeats the exact 1→2→1 probe
and is checked-closed before `Held`; checked-close failure preserves RAII ownership
for an immediate `Drop` retry. Host/integration kernel tests read back the
retained thread as exact `0x1000` with zero attributes and require
`SuspendThread` through it to fail with `ERROR_ACCESS_DENIED`. The creator thread
and process handles are then checked-closed in that order. A close failure rejects
and reaps through the already-proven narrow process; no `Held` value precedes all
three closes.

The Microsoft Learn [`ResumeThread` documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
still names `THREAD_SUSPEND_RESUME` as required access, whereas the current SDK
exposes `THREAD_RESUME` and the kernel tests above prove resume-only behavior.
That documentation/SDK disagreement, automatic-right addition, and supported-OS
variance remain **STOP-SHIP** kernel-proof obligations.

`Held` owns only that narrow process, the one resume-only startup thread, and its
other sealed proofs. It is `Send` but `!Sync`, `!Clone`, and `!Copy`. Its consuming
startup transition revalidates the resident process, requires the one
post-gate application-releasing `ResumeThread` through exact `THREAD_RESUME`
(`0x1000`) to
observe prior count one, and immediately checked-closes the thread handle with
the same RAII retry ownership on failure. The
`Running` type has the same transfer traits and structurally contains no thread
handle. The retained process rights support bounded terminate/wait and exact
reject-exit-code cleanup. Explicit failure paths give cleanup errors precedence;
`Drop` attempts the same cleanup but cannot report failure.

The green
`post_loader_worker_feasibility_default_dacl_hardens_later_null_security_thread`
post-loader kernel feasibility test independently reads the exact default
DACL from the child and then succeeds at a real `CreateThread(NULL, ...)`.
`GetThreadTimes` works on the thread pseudo-handle, `OpenThreadToken` returns
`ERROR_NO_TOKEN`, and exact owner/group plus the single `OWNER RIGHTS` deny ACE
read back. Parent and child denial matrices are green with `SeDebugPrivilege`
and `SeTakeOwnershipPrivilege` disabled. For a descriptor produced from a token
default DACL, the parser requires `SE_SELF_RELATIVE | SE_DACL_PRESENT` but does
not assume `SE_DACL_PROTECTED` or `SE_DACL_DEFAULTED` equals the explicit
protected creation descriptor. The ignored libtest child runs on a non-primary TID, so this proves
post-loader feasibility, not the real Key Agent's loader-compatible
exact-primary production gate.

On the tested host, a post-lock later thread using a default security descriptor
is governed by the new `TokenDefaultDacl`. Because the actual Key Agent gate has
not succeeded and a loader-compatible from-birth `WRITE_DAC` denial is
unavailable, that fact is not production coverage for the current architecture.
Caller-supplied security
descriptors, raw native or remote creation paths, and returned, preexisting, or
duplicated high-right handles remain bypasses. Because `TokenDefaultDacl` applies
to token-default object creation rather than threads alone, pre-gate objects and
un-inventoried non-thread object classes remain outside this decision's evidence.

Revalidation runs after the creator-handle post-detach suspend probe, again
through the narrow process after the ephemeral `0x1002` probe, immediately before
the sole post-gate `ResumeThread`, and at resident authority checks. Every pass
re-reads and bookends the retained `Hfinal`'s full policy, exact token-object DACL,
and exact `TokenDefaultDacl` with baseline-equal statistics, then opens a fresh current
`TOKEN_QUERY` handle and requires exact-object plus `TokenId`/`ModifiedId`
equality. These are fail-closed point-in-time checks, not an atomic freeze:
holding `Hfinal` freezes neither the process's current-token association nor the
token contents. The last-check/`ResumeThread` gap and swap-away/back races remain
**STOP-SHIP**, and DACL changes are not assumed to update `ModifiedId`.
Preexisting, returned, or duplicated high-right handles remain **STOP-SHIP**, as
does behavior with enabled debug or take-ownership privileges. The next design
requires a distinct OS principal/service boundary or an explicitly narrower
threat model. Signed DLL/TLS
provenance during the pre-gate interval, a complete non-thread default-security
object inventory and policy, a bounded loader-worker
provenance/lifetime/exit/reopen-denial policy, a distinct OS principal/service
design with IPC/lifecycle proof, a real GUI Key Agent
loader-compatible exact-primary gate E2E, and a supported Windows/AMD64 architecture matrix
for marker decoding, context semantics, and the authenticated ntdll breakpoint,
are also **STOP-SHIP**. The `cfg(test)`
integration executes the production-compiled token and creation hardening,
proves the Approval query-only result, and supplies the creation DACL kernel
evidence. On both its profile-private directory and copied executable, the Key
Agent launch fixture requires and reads back the exact current-user owner,
explicitly applies and reads back the protected two-ACE DACL plus a
Medium/`NW` mandatory label, and retains the full image-load mitigation
including `NO_LOW_LABEL`.

That test is kernel feasibility, not release evidence. Bootstrap version 2 now
binds the ordinary supervisor PID/process/image proof and the separately
injected Key Agent PID/process capability into the same child transcript. The
Key Agent remains a logical authority: replacing the ordinary supervisor proof
with it would conflict with the pipe server's client-PID/session observations,
so the child authenticates and retains both authorities separately. The sealed
parent now separates the hello bootstrap from the full exchange described
above. The separate Approval fixture does not directly read back the copied
image's mandatory-label state. Its test-only
mitigation removes exactly `NO_LOW_LABEL` to permit the profile-scoped copy;
production mitigation is unchanged. Mapped-image provenance, endpoint
topology/exclusivity, signed-artifact cleanup evidence, DLL/TLS graph, resumable
production orchestration, signing composition, and release activation remain
unimplemented. Both compiled policies remain `None`. A supervisor and hostile launcher running
as the same unrestricted owner SID cannot be strongly separated by an ordinary
process DACL alone: the deny-only `OWNER RIGHTS` creation policy blocks the tested
fresh opens but cannot revoke a returned, preexisting, or duplicated handle, and
a caller retaining or reacquiring `PROCESS_DUP_HANDLE` can still target
child-local proof handles. Release activation therefore requires a distinct
supervisor principal (or an explicitly narrower threat model), policies for
caller-supplied/native/remote thread bypass and existing high-right handles,
disabled or otherwise constrained debug/take-owner privileges, signed DLL/TLS
provenance, a pre-gate non-thread object inventory, a supported
architecture/version matrix, and production bootstrap/provenance/endpoint
composition. The creation DACL and corresponding disabled-privilege denial
evidence do not satisfy those remaining requirements.

A separate helper-bootstrap crate exposes safe platform-neutral gate bytes,
secret-free canonical 100-byte hello/72-byte ACK codecs, and the distinct
72-byte helper-RPC confirmation codec to the optional, default-feature-disabled
`platform-windows` launch feature. Those frames are correlation evidence, not
authentication or authority. The child capture/adoption/completion API remains
confined to Windows x86_64, explicit feasibility features, and
`debug_assertions`. The additional helper-ready feature is reached only through
the matching debug probe features on `approval-ui.exe` and
`secret-input-ui.exe`; default, release, and production entrypoints remain
unavailable.

The child capture primitive is one exact 34-byte sequence with independent
`movabs` R10/R11 markers, `INT3`, RCX/RDX stores, register clears, and `RET`.
Candidate adoption rejects zero, negative/invalid or pseudo, equal, standard-
handle-aliasing, nonzero-flag, non-`FILE_TYPE_PIPE`, and same-object values. It
requests only `0x00100001` and `0x00100002` fresh local duplicates with
inheritance false/options zero, proves object continuity, and checked-closes
both candidates. A distinct exact 28-byte adoption-complete sequence loads
separate markers, executes its only `INT3`, clears both registers, and returns;
both breakpoint offsets are 20.

Completion exact-reads and canonically decodes the 100-byte hello before any
identity query. It binds the role fixed by its calling entrypoint, current child
PID, distinct service PID, child creation `FILETIME`, a strict-future deadline
at most five seconds away, and both child-server client PIDs to the service. The
two present debug executable entrypoints fix Approval and Secret Input
respectively; a future production entrypoint must additionally be signed and
immutably installed. The child synchronously exact-writes the 72-byte ACK and
immediately enters gate two. Every capture,
adoption, frame, role, identity, deadline, peer, write, or gate failure is
process-terminal through `std::process::abort()`.

The parent statically accepts exactly one nonoverlapping copy of both full gate
sequences in initialized executable nonwritable AMD64 PE32+ code from a bounded
read-only reparse-point reopen whose file identity is checked before and after
reading. It also requires canonical virtual/raw section order, raw offset equal
to RVA for every nonempty raw section in a low-alignment image, and a final
aligned section extent equal to `SizeOfImage`. Its fresh debugger thread admits
only the exact create event, main-
image identity/creation time, primary TID, bounded system `ntdll` load and one
system breakpoint before authenticating the capture RVA/page/bytes/context and
markers. Every extra process/thread/loader event fails closed, and client,
service descriptors, target LPAC token, context, and one-member Job facts are
revalidated before injection.

Parent injection performs exactly two target-process `DuplicateHandle` calls
with masks `0x00100001`/`0x00100002`, inheritance false, and options zero.
Target values remain opaque register words. If the first remote duplicate exists
when a later step fails, the service cannot close that target-table value
locally; every injection error therefore consumes the exact child and Job into
termination and bounded reap. `DUPLICATE_SAME_ACCESS`, inherited duplication,
rights broadening, and recoverable production use are forbidden.

The parent changes only R10/R11 with complete context readback, writes hello
before continuing capture, exact-reads/binds ACK, then authenticates gate two.
The child's synchronous ACK-write-before-gate-two and parent's ACK-read-before-
gate-two-authentication are the ordering proof. `PeekNamedPipe` would require
broader `GENERIC_READ`, and `FlushFileBuffers` would require broader
`GENERIC_WRITE`, so neither is admitted. Gate two installs suspend count one
from prior zero and is continued only into live/attached/Job/no-pending-event
revalidation. `DebugSetProcessKillOnExit(FALSE)` is the final fallible debugger-
thread operation; `DebugActiveProcessStop`, `WriteProcessMemory`, and
`CreateRemoteThread` are absent.

Post-join success proves debugger absence, reauthenticates retained create-event
aliases by flags, IDs, and same-object comparison before checked close, requires
Job count one, and probes suspend count 1 -> 2 -> 1. Alias survival after no-kill
thread exit was observed on this host only. Alias lifetime, thread-exit detach,
loader order, context, suspend, and cleanup behavior across every supported
kernel remain **STOP-SHIP**.

Rejected-event cleanup registers query-only, non-inheritable canonical anchors
with `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID)` or
`OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, TID)` and immediately
compares each raw alias with `CompareObjectHandles` before checked close. This
rejects a wrong ID or different object, but a raw `DEBUG_EVENT` slot has no
authenticated generation. Same-object ABA and the compare-to-close TOCTOU remain
unresolved, so local closure of rejected raw aliases is debug-only
**STOP-SHIP** kernel-matrix evidence rather than activation safety. Production
resolution requires a dedicated debugger process to contain every borrowed raw
event alias in an isolated handle table until that process exits; the product
process must not close the aliases individually.

The dedicated-process feasibility slice remains narrower than production
resolution. `key-agent-debugger-wire` carries exact 80-byte bootstrap, 72-byte
`READY_FROZEN`, 56-byte decision, 96-byte `TARGET_FROZEN`, 56-byte parent-death
command, and 96-byte parent-death report frames with big-endian integers, zeroed
reserved fields, and CRC32C framing. CRC32C, the per-run nonce, and private-pipe
PID topology are neither peer authentication nor authority. The secretless
`key-agent-debugger.exe` emits nothing and exits 78 for default and release
builds; only its explicit debug test hook enables this protocol. Private
platform typestate plus ignored current-host kernel probes cover the exact three-
entry inherited `HANDLE_LIST`, private pipes, `SYNCHRONIZE` sentinel,
`READY_FROZEN`, `TARGET_FROZEN`, decision/EOF/error paths, and terminal cleanup.

The exact debugger Job is unnamed and non-inheritable and MUST read back only
`KILL_ON_JOB_CLOSE | ACTIVE_PROCESS`, `ActiveProcessLimit = 2`, and no
breakaway. The parent retains the sole Job owner created by this implementation;
this is not a system-wide last-handle proof. The fixture MUST show debugger-only
count one, exact debugger/target PID membership at count two, denial of a third
suspended member at the quota, target-only count one after debugger exit, and
exact-zero terminal cleanup. `READY_FROZEN` remains only a fixed-source,
decision-only state; `TARGET_FROZEN` separately binds the actually suspended
target.

A private debugger umbrella now composes the dormant artifact-admission and
release transport boundaries. Admission still accepts an already verified,
pinned helper only in this order: the exact manifest-derived
`KeyAgentDebugger` role, opaque whole-release attestation, the dedicated
debugger-manifest digest kept distinct from the three generic helpers and the
Broker, an absolute verified path whose file is held without write/delete
sharing, and complete `FILE_ID_INFO` queried from that same held file handle
without reopen or path lookup. Its `PreflightDebuggerArtifact`,
`PreparedReleaseDebuggerArtifact`, and `MappedReleaseDebuggerArtifact`
capabilities are private, move-only/non-cloneable, and redacted; they expose no
path, raw handle, artifact, or release digest. Admission and preparation still
allocate no Job, pipe, channel, thread, process, or debug resource. Only the
private sibling transport can consume `PreparedReleaseDebuggerArtifact`; there
is no production caller, and `COMPILED_RELEASE_POLICY` remains `None`, so
ordinary evaluation cannot mint or consume these capabilities.

The transport's non-test path launches only the held absolute path. It creates
the helper with exactly `CREATE_SUSPENDED | CREATE_NO_WINDOW |
CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | DEBUG_PROCESS |
DEBUG_ONLY_THIS_PROCESS`; the exact three-entry standard-handle
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, one-entry Job list, six exact debugger-wire
frame kinds, and sentinel ownership model are retained. Before the returned
process/thread slots are adopted, raw numeric
values must be pairwise distinct across the held artifact, Job, all three exact
pipe slots, and both outputs; ambiguity aborts. A creator-thread-bound attached
owner then validates the retained creator process/thread handles and one-member
Job. Initial `ResumeThread` must report previous count one or fail-fast; only
that exact result establishes count zero before bounded `WaitForDebugEventEx`.
It records the pending event before interpretation and accepts only the first
`CREATE_PROCESS_DEBUG_EVENT` with exact process/thread IDs, process/thread
aliases proven to identify the retained creator objects, zero alias-handle
flags, correct thread ownership, and a present zero-flag `hFile` distinct from
those aliases. Before adopting event-file ownership, the raw numeric check is
repeated across the held artifact, three pipes, creator process/thread, Job, and
event process/thread/file slots. Exact-object comparison binds only the event
process/thread aliases to their creator counterparts and keeps `hFile` distinct
from those aliases; artifact binding uses full `FILE_ID_INFO` equality instead.

While that first event still freezes the process, the transport borrows the
event `hFile` to compare its complete `FILE_ID_INFO` with the identity retained
inside `PreparedReleaseDebuggerArtifact`. Equality is the only transition to
`MappedReleaseDebuggerArtifact`; mismatch cannot mint the capability. The exact
owned `hFile` is then closed through a checked close whose ambiguous failure
aborts the parent, and `SuspendThread` must report the prior zero count before
installing one explicit suspension. Only then does the same creator thread
continue the pending event with `DBG_CONTINUE` and detach with
`DebugActiveProcessStop`. Immediately after a successful stop and before any
later Win32 call, that creator thread probes both borrowed `CREATE_PROCESS`
event process/thread raw slots with `GetHandleInformation`. Only two failures
with exact `ERROR_INVALID_HANDLE` retire their accounting record; a live slot,
asymmetric result, or any other error fail-fasts. The same rule applies to
ordinary detach and attached rejection cleanup. The transport never calls
`CloseHandle` on those system-managed borrowed aliases; among event-supplied
handles, checked ownership and close remain limited to `hFile`. Later
post-detach probes require no remote debugger, a live process, the exact suspend-
count transition and restoration, and unchanged one-member Job accounting. The
mapped capability stays retained by the child; the sentinel is installed only
after authentication and detach, the bootstrap is written while the child is
still suspended, and the final user-mode resume must remove exactly that one
explicit count. Rejection requests Job/process termination only if the process
is not already terminal. It then continues a pending event, detaches, proves
process terminal state, drops the creator primary-thread owner, and only then
polls exact-zero Job accounting. A failed post-probe resume rejects; a successful
resume that reports anything other than previous count two fail-fasts because it
may have released execution. Other ambiguous attached cleanup also aborts
instead of returning an unproved state.

Source-local tests pin the exact six creation flags, raw-slot distinctness, and
the first-event identity classifier. Ignored current-host feasibility tests cover
matching and mismatched debugger mapped images, then create an actual suspended,
inert target by resolving the debug helper's own `current_exe`. The
`TARGET_FROZEN` proof carries PID/TID, creation time, and source process/thread
handle words. Parent pull-back is restricted to process request/grant
`0x00101001` and thread request `0x00100802`; measured native thread readback is
exactly `0x00101802` because `THREAD_RESUME` (`0x1000`) is added. Other access
masks are forbidden. The current-host topology is exactly `2 -> 1 -> 0`, with
target identity, liveness, Job membership, and `1 -> 2 -> 1` suspend state
reproved after debugger exit.

A separate outer-supervisor probe force-terminates its parent before
`READY_FROZEN`, at `READY_FROZEN`, and after target handoff. Exact PID plus
creation-time observation requires debugger and, where present, target terminal
state. This is adversarial current-host containment evidence, not proof of the
system-wide last Job handle or every supported kernel.

The target remains untrusted/debug-only: `current_exe` is resolved inside the
helper rather than pinned by the parent, so no signed Key Agent image, token, or
production authority follows. Target debug-event alias generation, same-object
ABA, atomic compare-close, and the final atomic dedicated-debugger target engine
also remain unresolved.

The Windows x64 MSVC helper build now embeds one deterministic, header-free
ASCII `VERSIONINFO` definition. Its fixed file and product versions are
`0.1.0.0`; the exact `0409`/Unicode strings are
`FileDescription = Your Wallet Key Agent Debugger`,
`FileVersion = 0.1.0.0`, `InternalName = key-agent-debugger`,
`OriginalFilename = key-agent-debugger.exe`, `ProductName = Your Wallet`, and
`ProductVersion = 0.1.0.0`. The build rejects package-version drift and
non-x64-MSVC Windows targets, is inert for non-Windows targets, and uses locked
`find-msvc-tools 0.1.10` to discover `rc.exe` and link the `.res` only into this
binary. Discovery is not a cryptographic pin of `rc.exe` or the Windows SDK.

The release contract now makes `key-agent-debugger-exe` at
`payload/key-agent-debugger.exe` mandatory. A safe `FileVersionInfo` inspector
runs on the built binary, before unsigned staging, after signing during
Authenticode-evidence generation, and against the held bundle in final offline
verification. The post-sign generator requires an effectively read-only
payload, canonicalizes and pins the output parent, and rejects a volume-root
parent, ADS/existing leaf, payload containment, or post-create identity drift.
It retains canonical payload handles plus a pinned inspector source
through inventory, version, signature, hashes, final exact-inventory recheck,
evidence creation, and output-byte confirmation; the offline pass combines the
held bundle with that inspector identity inside the independently pinned exact
eight-file/four-directory verifier toolset. Tests cover the real built binary
and an exact-name non-PE negative. Runtime helper version parsing also requires
`VS_FIXEDFILEINFO.dwSignature == 0xFEEF04BD` before field extraction.

This is build/scaffold and fixture/proxy enforcement, not an actual signed-
product E2E or the Phase 1 exit gate. A real product signer, immutable
installation, generated compiled release policy, parent-pinned target image,
system-wide last-Job-handle proof, and supported-kernel generalization of debug-
alias retirement, native target access, parent-death, and cancellation-drain
matrices remain **STOP-SHIP**. The expected-peer registry has a debug-only RPC/
lifecycle/wire caller but no production caller; signed-helper `ncalrpc`, an
installed restricted SCM service, cross-session LPAC, and elevated-service E2E
remain unproved. Phase 1 is not passed, both compiled policies stay `None`, and
the helper continues to exit 78 in default and release builds.
When a deadline observes pending overlapped pipe I/O, `CancelIoEx` is treated
only as a cancellation request and never as completion evidence. Async
`ReadFile`/`WriteFile` receive no byte-count output pointer; one raw
`*mut OVERLAPPED` established before initiation is carried unchanged through
completion and cancellation, without forming a shared Rust reference while the
kernel may update it. The same exact buffer, manual-reset event, and
`OVERLAPPED` remain live through a separate fixed five-second, non-alertable
`GetOverlappedResultEx` drain, which is also the sole source of the transferred-
byte count. Only success,
`ERROR_OPERATION_ABORTED`, or an exact pipe-terminal status may return. A drain
timeout, incomplete or alertable result, or any ambiguous error invokes
`std::process::abort()` without unwinding, so stack and borrowed buffer lifetimes
cannot end while kernel I/O may still reference them. Abort does not run
`Zeroizing` drops; this lifetime fail-safe is not evidence against WER/minidump,
paging, or hibernation capture, whose host policies remain **STOP-SHIP**.
Current-host pending-read
tests exercise the ordinary terminal-cancellation path. This is bounded
fail-closed implementation evidence, not unconditional kernel liveness.
Process-wide abort closes the Job handle retained by the parent and prevents
unsafe parent continuation, but kill-on-close terminates members only when that
is the system-wide last Job handle; this slice does not prove that condition
after helper code runs. Supported-kernel cancellation-drain liveness remains
**STOP-SHIP**.

Each `LOAD_DLL_DEBUG_EVENT` adopts its optional `hFile` into checked caller
ownership before semantic-proof evaluation, stores the semantic result, and
then completes checked close. Only after that close may the stored semantic
error or subsequent loader-count-limit error return; cleanup failure wins when
both fail. Rejected-event
authority is also single-assignment: a second registration that observes any
retained rejected raw slot, PID/TID, or canonical anchor unconditionally
fail-fasts before an overwrite. These orderings prevent a local leak or
registry replacement but do not authenticate raw-slot generation or make the
compare-to-close step atomic, so the kernel-matrix blocker remains.

The common attenuation path now has ignored, host-local kernel evidence for
Approval and Secret Input service-local creator sources and fresh local
duplicates: WDK `NtQueryObject`, handle flags, pipe-local information, and I/O
report exact request `0x00100001` and response `0x00100002` authority, zero
inheritance, and the intended directions. A separate cross-process ignored test
uses the real `channel.rs::WindowsDuplicateHandle` production duplication path,
then test-only `DUPLICATE_SAME_ACCESS` pull-back, WDK `NtQueryObject`, object
comparison, and positive/rejected reverse I/O to measure the actual target-table
candidates as exact too. These native probes are test/change-prone evidence for
the current host, not runtime admission or a universal supported-kernel claim.
The real helper child's production `WindowsHandleOperations::duplicate` and
capture/adoption path is now reachable from the two debug UI probe entrypoints,
but has not run in an actual installed restricted-service end-to-end test.
Signed-helper E2E, immutable UI artifacts, installer/service composition, and
the full kernel matrix remain unverified.
The `UnverifiedSourceAccessAndDirection` marker and **STOP-SHIP** gate therefore
remain.

The debug-only V2 launch commands and role-fixed UI probe entrypoints now reach
these primitives. Required privilege enablement, exact interactive desktop DACL
access, child-token query access, an actual installed cross-session/elevated
call, real signed immutable helpers, and complete negative/kernel evidence remain
**STOP-SHIP** work.

The runtime-enabled Approval child has exactly two unique inherited stdio pipe
objects. As its first Windows/CRT application operation, before binary-mode
conversion, it requires stdin to differ from stdout, requires stdout and stderr
to be the same numeric handle-table value, and requires both unique objects to
be exact `PIPE`s with preflags exactly `HANDLE_FLAG_INHERIT`. It attempts both
inherit-bit clears without rollback and accepts only exact-zero readback for
both. The launcher `HANDLE_LIST` remains limited to the two synchronous server
pipe ends inherited by the child; the parent retains the corresponding
overlapped client ends. While the child is suspended, the launcher remotely
injects supervisor-process, supervisor-image, and Key Agent logical-parent
process proof handles with inheritance disabled. After sealing stdio, the child
verifies the Approval LPAC and Job and requires the two stdio objects, supervisor
process/image proofs, and Key Agent process proof to be five pairwise-distinct
exact objects with zero flags. Only fresh child-local duplicates of all three
injected proofs become authoritative and remain retained through response write;
the launcher-known original injected slots are never adopted and are left only
for bounded process-exit cleanup. The child derives the authoritative
channel-supervisor PID and process-token `TokenSessionId` from the retained live
exact supervisor process handle, then requires the parent-hello supervisor PID, both child-held server ends'
client PID/session observations, and the child token session to match that
identity. The distinct retained Key Agent handle must independently match the
logical-parent PID, stay live and image-queryable in the same session, and expose
through `TOKEN_QUERY` the fixed `YourWallet.KeyAgent.LPAC.v1` SID, AppContainer
and LPAC bits, and zero capabilities while stronger token/process access and PID
reopen attempts remain denied. The child retains and revalidates both bindings
across UI presentation and response write. While both process handles remain
live, this prevents PID-reuse substitution and corroborates the pipe observations
against the exact live supervisor process object. Transferable and duplicable pipe handles still prevent
proof of exclusive endpoint ownership, endpoint topology/exclusivity, or
per-write attribution. The image check applies case-preserving exact normalized
path-string equality: it
normalizes only an optional `\\?\` prefix and separators and compares the live
process image path with a separate held file's final path; a casing mismatch
fails closed. It then checks the held path's `\\key-agent.exe` suffix and version
metadata, supplies the held handle plus path to Authenticode signer validation,
and computes SHA-256 through a cloned held handle against the compiled policy. It does not prove that the live
process was mapped from that exact file object.

The wire and child runtime define a complete parent-auth exchange order: a fixed 74-byte version-2 parent hello, fixed 106-byte
child hello, a 110-byte parent-finish header plus exact request and request EOF,
then a fixed 75-byte response and response EOF. A fresh nonzero parent nonce and
independently fresh nonzero child nonce are bound by the child's
domain-separated SHA-256 bootstrap transcript. The parent-finish header binds
both nonces, the canonical request hash, and the exact request length. After
response-plus-EOF the parent locally hashes held child PID/file identity,
manifest digest, profile revision, request digest, one-shot Approval nonce and
canonical request hash, exact response bytes, a fresh parent-local transcript
salt, and both bootstrap nonces. The salt is never sent to the child and is not
challenge-response evidence. Job policy/membership is a live gate, not hashed
identity. The fixed 75-byte response is ordered as magic, version, decision,
request digest, and the one-shot Approval request nonce. Only the digest and
nonce echo request fields; neither bootstrap nonce is echoed. Replay resistance
therefore also depends on the private one-shot endpoint and a fresh one-shot
Approval request nonce. Direct executable launch exits without diagnostics; the
legacy Rust API returns `LogicalParentUnavailable` before allocation.

The sealed parent now implements hello bootstrap and full exchange as separate
consuming typestates. Bootstrap is capped by the earlier of original expiry and
a fresh five-second grace. The full transition accepts no raw request/deadline,
writes finish plus the carrier's exact request and EOF, verifies fixed response
plus EOF, requires natural exit code 0 from the
exact held child under the same deadline, and finally revalidates the Key Agent
after exit. It retains the carrier and returns only
`VerifiedParentBoundApprovalExchange`; no conversion to the public verified
response or signing exists. The legacy
`launch_approval_frontend` still fails before allocation with
`LogicalParentUnavailable`.

The session lifetime now comes from one platform-issued monotonic window. Its
matching non-Clone halves preserve issuance identity, invalidation drops the
unbound transport half, and the bound carrier carries the original deadline
through dormant activation, bootstrap, full exchange, and terminal retention.
No exchange-start reconstruction from wire-relative expiry remains.

A repo-local child/grandchild kernel test makes a separate positive sentinel
inheritable and uses `CompareObjectHandles` to prove that the sentinel reaches
a broad-inheritance grandchild while neither original exact stdio object does.
The sequential clears are non-atomic and do not prevent later re-enabling or
explicit duplication. This remains a two-object negative, not a five-object
grandchild proof; it is not exhaustive stray-handle enumeration or evidence for
the exact signed artifact, intended supervisor topology, immutable
installation, DLL/dependency identity, or release activation. Signed
release-path positive evidence covering case-sensitive directories and
alternate path forms, live mapped exact-file-object proof, the complete
DLL/dependency graph, immutable installation, a supervisor-held activation
capability, and exact endpoint topology/exclusivity remain **STOP-SHIP**. There
is now repo-local kernel evidence that an actual zero-capability Approval LPAC
can use the exact QLI-plus-synchronize Key Agent handle, complete
`OpenProcessToken(..., TOKEN_QUERY)` on that logical-parent process proof, and deny the exact local
`DuplicateHandle` and PID-reopen requests enumerated above. The copied image's
mandatory-label state is not directly read back, and the test-only
`NO_LOW_LABEL` removal only permits the profile-scoped copy; production
mitigation remains unchanged. This is not
signed/mapped release evidence, so the handle-first production path remains
release-unproven. The repository has zero production orchestration callers for
the sealed launch-to-`VerifiedParentBoundApprovalExchange` transition, no
conversion from that evidence into the verified-response/signing path, and no
positive signed-handshake E2E.
`COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` remain `None`, so default
Approval builds still exit 78. No signed-artifact, topology, or release evidence
is claimed.

The runtime-enabled Secret Input/recovery child instead has two unique stdio
objects: stdin and one stdout/stderr pipe. Its first Windows/CRT application
operation validates their exact shape and inherit-only flags, attempts to clear
both inherit bits without rollback, and requires exact-zero readback. The
parent's `HANDLE_LIST` contains only those stdio objects. While the child remains
suspended, the parent remotely duplicates its process and image-file proof
handles into the child with inheritance disabled, after Job/LPAC verification
and before resume. After reading the fixed parent hello, the child requires the
two sealed stdio objects and two proof objects to be four pairwise-distinct
exact objects with zero flags. A positive-control child/grandchild kernel test
uses `CompareObjectHandles` to prove that those four exact objects do not
propagate. The sequential clear is not atomic, does not prevent later
re-enabling or explicit duplication, and is neither exhaustive stray-handle
enumeration nor signed-artifact, topology, immutable-install, or release proof.
`COMPILED_PARENT_POLICY` remains `None`.

**Current Phase 2H status: started, not passed.** We allow the Windows library
to production-compile the dormant SCM/status-RPC mechanics, with
`key-agent-service-rpc-sys` and `key-agent-service-wire` as nonoptional
dependencies, because compilation does not itself grant lifecycle authority or
make an executable caller. `WindowsServiceEffectSource` is move-only,
single-use, and Debug-redacted. It can consume only one sealed
`WindowsScmStatusAuthority`, and `WindowsServiceEffectBackend` is an exact
8-stage state machine over six leaf effects: listener prepare, `SCM_RUNNING`,
admission open, admission close, listener drain, and `SCM_STOPPED`, followed by
`Stopped` or irreversible `Terminal`.

The SCM registration handle remains private and has no raw accessor. Admission
may open only while the exact invocation is authoritatively `SERVICE_RUNNING`;
the predicate and operation stay under the same `CONTROL_CONTEXT` lock. The
consuming `close_admission` transition must precede
`AdmissionClosedStatusRpcWorker::drain`, which then invalidates epochs, stops
listening, unregisters with waiting enabled, waits for rundown, and releases
resources. Any unproved startup, admission, rundown, or SCM publication retains
authority and is classified fail-closed. Before the final native `SCM_STOPPED`
send, the shared context is terminalized under that lock so a concurrent
callback cannot publish a later pending state.

This is local implementation evidence: the existing Phase 2G compositor remains
22/22 and the separate Phase 2H service-effect suite is 9/9.
`WindowsServiceEffectSource::new`, the registered authority mint, a real durable
provider source, `begin_windows_lifecycle`, and executable/top-level production
composition each still have zero production call sites. Default and release
service execution remains silent exit 78 and both compiled policies remain
`None`. External SCM registration/source mint, elevated installer and
service-SID composition, a protected durable provider and rollback anchor,
trusted production Broker/service-peer authentication and mapped-I/O/peer-race
proof, crash/power/reboot recovery, TPM/authentication-key custody,
supported-kernel matrices, signed immutable artifacts, and release evidence
remain **STOP-SHIP**.

**Current Phase 2I status: started, not passed.** The Windows library may
production-compile the private `windows_session_events` semantic bridge, but it
may not activate SCM session-change delivery. The bridge accepts an already
copied `WTSSESSION_NOTIFICATION` only with an exact native `cbSize` and a
nonzero `dwSessionId`. `ValidatedWindowsSessionEvent::decode` receives the
native event type and produces a closed typed value; its consuming `dispatch`
emits exactly one existing session lifecycle event.
`handle_windows_session_change` is the sole safe composition.

The accepted mapping is fixed: lock, unlock, and logoff map directly; console
connect/disconnect, remote connect/disconnect, session logon, and remote control
all map to `UserSwitch`. Session create, session terminate, unknown event types,
a wrong size, and session zero fail closed without dispatch. The separate Phase
2I suite is 8/8, covering the exact native layout, validation and mapping matrix,
move-only redacted evidence, and the sole runtime-facade dispatch route.
Rejection failures are unit-only and the runtime failure retains only its
policy cause; no failure retains the raw notification, event code, or session
identifier, and Debug output is fixed and redacted.

This is local semantic evidence only. No service status advertises
`SERVICE_ACCEPT_SESSIONCHANGE`; the current SCM control handler has no session-
change branch and does not inspect `event_data`; and the bridge has zero
production callers. Native callback-pointer validation and copying, bounded
mailbox ownership and delivery, concurrent cancellation, and callback/mailbox/
service rundown ordering remain **STOP-SHIP**. Default and release service
execution remains silent exit 78, both compiled policies remain `None`, and
Phase 2I does not pass Phase 1, Phase 2, or the release gate.

**Current Phase 3A status: started, not passed.** Expected-helper ownership now
includes one nonzero Windows session, but that value is accepted only from the
service-created token/process proof. `ExpectedHelperPeer::session_id` delegates
through the retained `DetachedSuspendedServiceProbe` to
`ExpectedServiceCreatedLpac`; `ExpectedPeerKey` remains exactly epoch nonce plus
request ID. No wire field, candidate observation, caller request, environment
value, PID, or session-change notification is allowed to supply helper session
authority.

The registry keeps a fixed 64-entry session quarantine, synchronized by the
architecture gate with the lifecycle quarantine bound. Under the registry mutex,
targeted invalidation records the session before extracting matching live owners
or setting matching in-flight `cancel_requested`. Active-topology invalidation
first records the departing session and every session represented by live or
in-flight owners, then selects the entire observed topology. Only after the
mutex is released may either path call process cancellation/reap or wait for
in-flight settlement. Therefore registration is ordered on one side of the
same mutex: it is either observed and selected by invalidation, or sees the
committed quarantine and is rejected with terminal cleanup outside the lock.
Targeted invalidation preserves every unrelated live and in-flight owner.
For an otherwise-successful consume racing that invalidation, preservation
means restoring the unrelated owner to its original phase before returning
`Denied`; a successful malformed-candidate rejection keeps its planned terminal
retirement even when the same race changes the public result to `Denied`.
Selective cancellation is tracked separately from stronger global cancellation.

The bound is fail-closed. A 65th distinct quarantine request sets `stopping`,
marks all in-flight owners for cancellation, extracts all live owners, performs
the same five-second bounded settlement, and only then reports `Stopping`;
cleanup `Internal` retains precedence. Errors and Debug surfaces remain data-
free and never retain or print a session identifier. The focused registry suite
is 37/37, including eight new session-origin, race, selectivity, active-topology,
exhaustion, and privacy tests.

Both invalidation methods deliberately have zero production callers. Phase 3A
does not advertise `SERVICE_ACCEPT_SESSIONCHANGE`, consume callback data, add a
mailbox or lifecycle-to-registry composition, widen the Broker/service wire,
run Approval or Secret Input transcripts, or enable signing. Native callback
copying/delivery, bounded mailbox cancellation/concurrency/rundown, installed
restricted-service and signed-helper E2E, and supported-kernel evidence remain
**STOP-SHIP**. Default/release execution remains silent exit 78, both compiled
policies remain `None`, and Phase 3A does not pass Phase 1, Phase 2, Phase 3, or
the release gate.

**Current Phase 3B status: started, not passed.** A private, production-compiled
pure policy admits only the Approval order
`Admitted -> UIStarting -> UIAuthenticated -> Approved/Rejected`. The policy's
`Admitted` is not expected-peer `Admitted`: the latter means the service
accepted `HelperReady` through manager admission. Secret Input
`Accepted/Cancelled` remains a distinct future path and cannot be substituted
for an Approval decision.

The concrete consuming type chain is
`AdmittedRequestPolicy -> UiStartingRequestPolicy ->
UiAuthenticatedRequestPolicy -> ApprovedRequestPolicy | RejectedRequestPolicy`,
through `begin_ui`, `authenticate_ui`, and `decide`. Every non-rejected state
also has consuming `recheck_liveness`, `cancel`, `invalidate_session`, and
`invalidate_active_sessions` transitions.

The policy is move-only and binds the server-derived expected-peer key, nonzero
session, Approval role, and original inclusive monotonic deadline and owns the
monotonic clock used to enforce it. Each positive transition consumes a fresh
move-only one-shot observation and requires exact correlation, the Approval
role, and a fresh check of that policy-owned clock against the unchanged
deadline. This slice's liveness is limited to that one-shot observation shape
and policy-local deadline check; the policy neither inspects an OS process nor
authenticates a helper. A clock failure, an observation at or after the deadline,
any role/key/session mismatch, or failed observation terminally rejects; no
caller can repair or retry the same state.

Targeted invalidation rejects only matching-session policy state and preserves
unrelated state. Active-topology invalidation and cancellation reject every live
phase, including `Admitted`, `UIStarting`, `UIAuthenticated`, and `Approved`.
Thus `Approved` is intentionally non-durable and cancellable. It is not signing
authority and conveys no intent, candidate, cryptographic-key, or private-key-operation
authority. Seed, observation, and policy-state types are private and move-only,
`Rejected` is terminal, and failure plus `Debug` surfaces retain no key,
session, deadline, or other request data.

The focused policy suite is exactly 10/10. The architecture mutation gate pins
the exact order, server-only binding, positive-edge correlation/liveness,
inclusive deadline and terminal rejection, targeted isolation, topology-wide
cancellation, non-authoritative cancellable Approval, privacy/ownership, and
exact zero production seed, observation mint, or callers. A future compositor
must mint every observation only after fresh authenticated Approval UI and
expected-peer liveness proof. This does not implement actual Broker-to-policy
admission, helper-owner transfer, an Approval transcript, authenticated liveness
composition, concurrent composition, cleanup/reap, or SCM callback delivery.
Default/release execution remains silent exit 78 and both compiled policies
remain `None`; installed restricted-service, signed-helper, supported-kernel,
and complete runtime/release evidence remain **STOP-SHIP**. Phase 3B does not
pass Phase 1, Phase 2, Phase 3, or the release gate.

All seven Rust-startup supervisor integration positives are explicitly ignored
**STOP-SHIP**. Their fixture code, when deliberately invoked, has two
`cfg(test)` accommodations: an exact pinned terse libtest preamble may precede
the response, and Job topology may contain only the fixture process plus at most
the exact System32 `conhost.exe`. Production requires response magic at byte zero
and exactly one Job member. The green minimal-PE dormant ownership/cleanup
positives and Rust-startup failure-cleanup negative prove neither storage-startup
success, the production fresh fixed root, nor the exact signed release artifact.

| Area | Decision |
| --- | --- |
| Native stack | Rust 2024; plain JavaScript MV3 extension |
| Password profile | NFC, no case mapping, 12--1024 Unicode scalars/UTF-8 bound |
| KDF | Argon2id v1.3, 256 MiB, 3 passes, 4 lanes, 16-byte random salt |
| Vault AEAD | XChaCha20-Poly1305, 24-byte random nonce, canonical header as AAD |
| Key derivation | HKDF-SHA-256 domain-separated subkeys |
| Approval digest | SHA-256 over a versioned, length-prefixed transcript containing the canonical label-free `approval-wire` display bytes |
| Default path | `m/44'/60'/0'/0/{actual_child_index}` |
| Default mnemonic | BIP-39 English, 12 words; optional 24 words |
| Wallet creation entropy | Fresh operating-system CSPRNG output only; failure aborts and no fixed/example/import/environment/seeded fallback is permitted |
| Session lifetime | No idle timeout; lock on explicit lock/logout, exit/crash, Windows lock/switch/suspend/hibernate |
| Transaction types | EIP-155 legacy, EIP-2930 type 1, EIP-1559 type 2 only |
| EIP-712 exceptions | Version 0.1 has no exception path: missing `chainId`, missing/zero `verifyingContract`, and chain mismatch are denied |
| Unknown calldata | Canary-only warning plus hold confirmation; never silently decoded |
| Registry overrides | Only authenticated `ExpiredReview` or `RuleCoverageUnknown`; invalid signature, rollback, identity mismatch and known-invalid rules always deny |
| Signed nonce | Quarantined until canonical finality proves consumption/supersession |
| RPC credentials | Session memory only; never written to configuration or logs |

Demo and Key Agent creation each have one production entropy origin: a direct
operating-system CSPRNG fill into zeroizing mnemonic entropy, followed only by
the corresponding mnemonic constructor. Import errors, missing/corrupt vaults,
headless execution, and unavailable randomness must never select generation or
substitute an example mnemonic, fixed private key, fixed seed, repeated entropy,
environment value, or deterministic generator. No production API creates a
`WalletSource::RawPrivateKey`-origin wallet from generated bytes; that wallet
source is limited to strict user import and authenticated reopen/migration.
Mnemonic account-key derivation and user-authorized export remain separate.
Interactive secret fields start empty, and Generate is separate from the import
buffer.

Published deterministic protocol vectors are allowed only in lexically proven
`#[cfg(test)]` items or modules. They are conformance data, not funded wallets,
and no production wallet, vault, or signing sink may reference them. The
architecture mutation gate removes both bottom test modules and item-level test
helpers before proving the production call inventory and fail-closed randomness
ordering.

## Phase-zero stop-ship items

Before any real mainnet value is used, the Windows build must prove:

1. End-to-end release-artifact tests proving the implemented zero-capability
   LPAC token blocks TCP, UDP, DNS, loopback, private addresses, remote pipes,
   and inherited sockets for the key agent and both helpers; no permissive
   fallback is permitted. The narrowly scoped
   `TokenIsLessPrivilegedAppContainer == ERROR_INVALID_PARAMETER` compatibility
   branch is not such a relaxation: the exact AppContainer-denied/LPAC-allowed
   `CheckTokenMembershipEx` differential remains mandatory, and the local token
   proof does not replace these signed-artifact network tests.
2. Exact inherited-handle allowlisting and negative tests for stray handles.
   The Key Agent three-object, Approval two-object, and Secret Input/recovery
   four-object negatives prove only that those selected exact objects do not
   reach their test grandchildren; none is exhaustive enumeration proving that
   no stray handle entered the child.
3. Helper executable code-signing identity, manifest hash, version, and install
   ACL verification before launch without a writable-path time-of-check race,
   plus exact loaded DLL/dependency identity and resolution evidence.
4. Reproducible signed artifacts, dependency/SBOM review, recovery drill, and
   independent review of the secret and authorization TCBs.
5. Exact extension-envelope dispatch through the native host and authenticated
   broker endpoint, including aggregate structural-limit and negative tests.
   The dormant exact-image core now consumes `PreparedReleaseBrokerSupervisor`,
   but it must still be covered by signed immutable-install, manifest,
   native-host provenance, process/Job/channel, and negative release evidence.
   The in-crate and C# runner coordinators cover their exact cooperating call
   sites, but release evidence must still prove standalone-supervisor
   single-instance/topology and the absence or mediation of every foreign or
   otherwise uncoordinated inheriting launch. The Key Agent child now clears the
   inherit bit on its exact three received stdio handles as its first Windows
   application operation, and its repo-local grandchild test proves those exact
   objects do not propagate. Release evidence must still bind that behavior to
   the exact signed image and intended supervisor. The runtime-enabled Approval
   child likewise seals its two unique pipe objects first, requires stdout and
   stderr to be the same numeric handle value, and has a positive-sentinel
   grandchild negative for those exact objects. Its `HANDLE_LIST` still carries
   only those two objects; the suspended child separately receives
   non-inheritable supervisor-process, supervisor-image, and logical Key Agent
   process proofs and validates all five objects as pairwise distinct with zero
   flags after its Approval LPAC/Job checks. From the retained live exact
   supervisor process handle, the child derives the authoritative PID and
   process-token `TokenSessionId`, matches the v2 parent hello, both server-end
   client PID/session observations, and child token session, and retains and
   revalidates that binding through UI and response write. It independently
   binds the retained logical-parent process to the hello's Key Agent PID,
   same session, live image, fixed LPAC SID, AppContainer/LPAC state, zero
   capabilities, and stronger-right denials. This prevents PID-reuse
   substitution while both process handles are live and corroborates the pipe
   observations against the exact supervisor process object. It still does not
   establish exclusive endpoint ownership,
   topology/exclusivity, or per-write attribution because pipe handles are
   transferable and duplicable. A separate repo-local `cfg(test)` logical-parent
   probe proves exact `TOKEN_QUERY` availability and denial of the exact local
   `DuplicateHandle` and PID-reopen request matrices documented above in a real
   zero-capability Approval LPAC, but does not prove this
   channel binding or a signed/mapped image; compiled policies remain `None`.
   Likewise, the case-preserving exact
   normalized process/held-file path-string
   equality, held-path suffix/version metadata, held-handle-plus-path
   Authenticode validation, and cloned-held-handle SHA do not prove the mapped
   exact file object. The positive-sentinel test still covers
   only the two stdio
   objects. Its sequential clears are not atomic, do not prevent later
   re-enabling or explicit duplication, and are not exhaustive enumeration or
   exact signed-artifact/topology evidence. The
   runtime-enabled Secret Input/recovery child likewise seals its two unique
   stdio objects first,
   accepts its two parent-proof handles only with exact-zero flags, validates
   all four exact objects as pairwise distinct, and has a repo-local grandchild
   negative for those objects. This is not atomic clearing, exhaustive stray-
   handle enumeration, or exact signed-artifact/topology evidence. The
   restricted helpers' and Key Agent's exact three-name environments, including
   OS-derived `LOCALAPPDATA`, share the same verified System32
   current-directory boundary; that policy remains repo-local and is not atomic
   directory identity or signed-artifact E2E evidence. The verified/prepared
   held-root proof, five creation attributes, suspended-token proof, and private
   request-before-resume storage transcript commitment now bind the kernel-test
   child to its exact CSPRNG test root. The same integrated `cfg(test)` path now
   exercises the four fixed private generation stores and their exact
   dual-principal file policy. Fresh creation now yields only a non-launchable
   pending state, and the pure provenance classifier yields only
   non-authoritative candidates. A separate sealed dormant transition now tests
   the adoption-rule composition over test-held objects. The compiled
   whole-release binding then separates the journal `release_identity` from the
   helper-manifest and exact file-object identities and retains continuity, but
   neither it nor the dormant Key Agent supervisor binder has a production call
   site. The Approval parent binder now has one private suspended-only consumer,
   whose outer transition has zero production callers. A
   separate dormant root-only fixed existing-root opener implements exact
   security/identity checking and canonical-path rebinding but likewise has no
   production caller. It cannot open an installation into adoption because
   authoritative profile-registration observation, a held-aggregate
   constructor, production snapshot/lease/reread orchestration, production
   installer-key/checkpoint and journal I/O backends, recovery, and release
   activation are absent. These proofs also do not
   authenticate or anchor production installer provenance or provision a
   production rollback anchor or storage/AEAD keys, connect protected settings
   and its live lease, authenticate the Broker/supervisor/process topology or
   single-instance, establish Native Host provenance or a signed immutable
   installation, or prove exact loaded DLL/dependency identity. The pinned
   libtest preamble and optional System32 `conhost.exe` are test-only.
   `COMPILED_RELEASE_POLICY` remains `None`; these local proofs are neither a
   production fresh-root E2E nor release activation proof.
6. Production provisioning and rotation for the implemented encrypted
   nonce/signing/broadcast journal, backed by a real rollback-resistant anchor;
   signed-artifact crash tests must cover every persistence and RPC boundary.
7. End-to-end authorization tests proving that displayed fields, EIP-712 source
   data, protocol evidence, the signed artifact, and post-sign recovery all bind
   to the same operation.
8. Signed-artifact end-to-end tests for the implemented one-shot helper channel,
   proving exact request hash, child identity, transcript, decision, digest,
   nonce, timeout/cancellation, extra-output rejection, and inherited-handle
   enumeration through the real helper entry point. The repo-local Approval
   two-object and Secret Input four-object negatives do not satisfy this exact-
   artifact enumeration. Approval evidence must additionally exercise the fixed
   74-byte version-2 parent hello, fixed 106-byte child hello, fresh nonzero parent and
   child nonces, 110-byte finish header, exact request EOF, fixed 75-byte response
   and response EOF, and the exact transcript fields: held child PID/file
   identity, manifest/profile, request digest/one-shot nonce/hash, response, a
   fresh parent-local transcript salt, and both bootstrap nonces. The salt is
   never sent to the child and is not challenge-response evidence. Job policy/membership must remain
   a separately revalidated live gate, not be described as hashed identity. The
   response does not echo the bootstrap nonces, so replay evidence must also
   cover the private one-shot endpoint and fresh one-shot Approval request nonce.
   Signed release evidence must cover case-sensitive directories and alternate
   path forms and prove the live mapped exact file object, complete
   DLL/dependency graph, immutable installation, a supervisor-held activation
   capability, and exact endpoint topology/exclusivity. The handle-first child
   does corroborate both pipe PID/session observations against a retained live
   exact ordinary channel-supervisor process object and blocks PID-reuse substitution while that
   handle is live, but transferable/duplicable pipe handles leave exclusive
   endpoint ownership, topology/exclusivity, and per-write attribution
   unproven. The repo-local zero-capability Approval LPAC kernel probe proves
   `OpenProcessToken(..., TOKEN_QUERY)` only for its exact injected Key Agent
   logical-parent process proof and
   rejects the exact local `DuplicateHandle` and PID-reopen requests documented
   above. The copied image's mandatory-label state is not directly read back;
   the test-only `NO_LOW_LABEL` removal only permits the profile-scoped copy,
   while production mitigation remains unchanged. That fixture and separate
   held-file policy checks remain insufficient for
   mapped-image identity. The sealed bootstrap and full exchange both have zero
   production callers. The full exchange requires natural exit code 0 and
   post-exit final Key Agent revalidation, but its opaque evidence has no
   verified-response/signing conversion and a positive signed-handshake E2E is
   absent. The bound carrier now retains and enforces the original monotonic
   session deadline without accepting caller-supplied timing. Direct-executable silent failure,
   legacy pre-allocation `LogicalParentUnavailable`, and local wire
   tests do not provide signed-artifact, supervisor-topology, or release-
   activation evidence.
9. Production wiring for the implemented sealed Key Agent settings lifecycle.
   The platform store now reserves a dedicated `LocalSettings` record class,
   and the private fixed-role adapter can open that class, but no production
   composition or trusted ceremony consumes it. Release still requires
   independent settings AEAD key custody, exact installation/store/class
   identity, exclusive process-owner generation, and a release-approved
   non-rollbackable high-water anchor. The model commits
   enrollment and old-to-new rotation as pending, exposes neither cue until an
   exact trusted-surface confirmation commits `Ready`, and freshly reloads the
   authenticated record before issuing and consuming each one-shot approval
   lease. Generation, revision, exact record digest, previous/high-water
   evidence, and owner/session identity are bound; rollback, authenticated empty
   after observation, same-generation equivocation, owner takeover, replay, or
   ambiguous store outcome locks the lifecycle. No broker or public API can
   construct the cue, prompt, settings lease, or signing entry point.

The authorization library now owns approval nonce generation, the 120-second
TTL, and a compiled `PrivateCanary` channel. Public callers cannot select a
weaker policy, create a nonce lease binding, inject EIP-712 parser limits, or
install a schema-exception verifier. `scripts/architecture-scan.mjs` enforces
these and the secret/network dependency boundaries in the normal quality gate.
