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
entry points for contract testing. Raw or legacy direct Approval launch cannot
complete the parent-auth exchange and fails without diagnostics.
`COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` are `None`, so no
ordinary build can complete restricted launch or reach signing. There are zero
production orchestration callers composing `launch_approval_frontend` through a
verified response into signing, and no positive signed-handshake E2E. Activating
the helpers through exact signed-artifact attestation and the end-to-end suite
remain release blockers.

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
layout, derives the containing user-local-data base, and prepends it as
`LOCALAPPDATA` for Windows to rebase inside the AppContainer. Each final
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

The activation still supplies zero capabilities plus the ALL APPLICATION
PACKAGES opt-out in its exact four-entry process-creation attribute list. While
the first pre-user-mode create event remains held, it authenticates the mapped
image, installs one explicit suspend count, and verifies the exact primary token
before continuation or detach. Accepted tokens must report AppContainer, match
the fixed profile SID, and have zero capabilities. The process token is
duplicated at `SecurityIdentification`; two `CheckTokenMembershipEx` checks over
its valid `TokenUser` SID must produce exactly false with
`CTMF_INCLUDE_APPCONTAINER` and true only after `CTMF_INCLUDE_LPAC` is added. A
supported `TokenIsLessPrivilegedAppContainer` query must return an exact DWORD
1. Only `ERROR_INVALID_PARAMETER` for that one class omits the direct DWORD
check; the exact membership differential remains mandatory and every other
error fails closed. A suspended ordinary-AppContainer control that omits only
the AAP opt-out must produce `(true, true)`, and neither control is resumed into
user mode. The detached Key Agent capability exposes no generic resume API; its
only consuming resume transition is the fixed storage-startup exchange above.

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
`LaunchedHelper` are crate-private. `RestrictedLauncher::spawn` is crate-private
too, and its only remaining call site is inside that dormant legacy launcher.
The launcher has zero production callers.

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

That consumer creates the fixed private Approval pipes and exact two-object
stdio allowlist, then uses the pinned verified Approval artifact to create a
process suspended in the fixed revision-v1 LPAC and single-process Job. This is
not mapped-image provenance. The ordinary channel-supervisor process
and image proofs are still injected unchanged. In addition, a sealed
production-compiled leaf copies the exact narrow Key Agent handle into the
suspended child as a fifth, non-inheritable logical-parent capability. The
resulting non-cloneable `BoundDormantApproval` retains the suspended process,
primary thread, Job, both unused parent pipe endpoints, and the full parent-bound
aggregate. It exposes no resume, request, response, signing, path, PID, handle,
profile, launcher, or attestation operation. Drop first makes a bounded
terminate-and-reap attempt for the Approval child before releasing pipes and the
Key Agent tree. The outer dormant preparation itself has zero production
callers.

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
and `WRITE_DAC`. Before resume, production Key Agent activation successfully
installs a protected three-ACE token DACL for the stable user `TOKEN_ALL_ACCESS`,
Key Agent `TOKEN_QUERY | TOKEN_DUPLICATE`, and Approval exactly `TOKEN_QUERY`.
The `cfg(test)` integration executes that production-compiled hardening and proves
the Approval query-only outcome. Ordinary LPAC/token attributes are verified
before and after installation; this slice does not read back the
token security descriptor.

That test is kernel feasibility, not release evidence. The new suspended-only
preparation does not teach the current Approval wire to authenticate the fifth
logical-parent capability and deliberately never resumes the child. Replacing
the ordinary supervisor proof with the Key Agent proof would conflict with the
pipe server's client-PID/session observations, so both authorities must remain
distinct until a later topology protocol authenticates them together. The
fixture does not directly read back the copied image's mandatory-label state. Its test-only
mitigation removes exactly `NO_LOW_LABEL` to permit the profile-scoped copy;
production mitigation is unchanged. Mapped-image provenance, endpoint
topology/exclusivity, signed-artifact cleanup evidence, DLL graph, resumable
production orchestration, signing, and release activation remain unimplemented;
both compiled policies remain `None`. A supervisor and hostile launcher running
as the same unrestricted owner SID cannot be strongly separated by an ordinary
process DACL: the owner can reacquire ACL-changing authority, and a caller
retaining or reacquiring `PROCESS_DUP_HANDLE` can still target child-local proof
handles. Release activation therefore requires a distinct supervisor principal
(or an explicitly narrower threat model), protected process and thread DACLs
supplied at creation, corresponding denial evidence, and the debug-privilege
absence proof.

The runtime-enabled Approval child has exactly two unique inherited stdio pipe
objects. As its first Windows/CRT application operation, before binary-mode
conversion, it requires stdin to differ from stdout, requires stdout and stderr
to be the same numeric handle-table value, and requires both unique objects to
be exact `PIPE`s with preflags exactly `HANDLE_FLAG_INHERIT`. It attempts both
inherit-bit clears without rollback and accepts only exact-zero readback for
both. The launcher `HANDLE_LIST` remains limited to the two synchronous server
pipe ends inherited by the child; the parent retains the corresponding
overlapped client ends. While the child is suspended, the launcher remotely
injects parent-process and parent-image proof handles with inheritance disabled.
After sealing stdio, the child verifies the Approval LPAC and Job and requires
the two stdio objects and two proof objects to be four pairwise-distinct exact
objects with zero flags. Only fresh child-local duplicates become authoritative
and remain retained through response write; the launcher-known original injected
slots are never adopted and are left only for bounded process-exit cleanup. The
child derives the authoritative parent PID and
process-token `TokenSessionId` from the retained live exact parent process
handle, then requires the parent-hello PID, both child-held server ends'
client PID/session observations, and the child token session to match that
identity. It retains and revalidates the binding across UI presentation and
response write. While the process handle remains live, this prevents PID-reuse
substitution and corroborates the pipe observations against the exact live
parent process object. Transferable and duplicable pipe handles still prevent
proof of exclusive endpoint ownership, endpoint topology/exclusivity, or
per-write attribution. The image check applies case-preserving exact normalized
path-string equality: it
normalizes only an optional `\\?\` prefix and separators and compares the live
process image path with a separate held file's final path; a casing mismatch
fails closed. It then checks the held path's `\\key-agent.exe` suffix and version
metadata, supplies the held handle plus path to Authenticode signer validation,
and computes SHA-256 through a cloned held handle against the compiled policy. It does not prove that the live
process was mapped from that exact file object.

The parent-auth exchange order is a fixed 62-byte parent hello, fixed 106-byte
child hello, a 110-byte parent-finish header plus exact request and request EOF,
then a fixed 75-byte response and response EOF. A fresh nonzero parent nonce and
independently fresh nonzero child nonce are bound by the child's
domain-separated SHA-256 bootstrap transcript. The parent-finish header binds
both nonces, the canonical request hash, and the exact request length. After
response-plus-EOF the parent locally hashes held child PID/file identity,
manifest digest, profile revision, request digest, one-shot Approval nonce and
canonical request hash, exact response bytes, fresh local channel challenge,
and both bootstrap nonces. Job policy/membership is a live gate, not hashed
identity. The fixed 75-byte response is ordered as magic, version, decision,
request digest, and the one-shot Approval request nonce. Only the digest and
nonce echo request fields; neither bootstrap nonce is echoed. Replay resistance
therefore also depends on the private one-shot endpoint and a fresh one-shot
Approval request nonce. Raw or legacy direct launch fails silently.

A repo-local child/grandchild kernel test makes a separate positive sentinel
inheritable and uses `CompareObjectHandles` to prove that the sentinel reaches
a broad-inheritance grandchild while neither original exact stdio object does.
The sequential clears are non-atomic and do not prevent later re-enabling or
explicit duplication. This remains a two-object negative, not a four-object
grandchild proof; it is not exhaustive stray-handle enumeration or evidence for
the exact signed artifact, intended supervisor topology, immutable
installation, DLL/dependency identity, or release activation. Signed
release-path positive evidence covering case-sensitive directories and
alternate path forms, live mapped exact-file-object proof, the complete
DLL/dependency graph, immutable installation, a supervisor-held activation
capability, and exact endpoint topology/exclusivity remain **STOP-SHIP**. There
is now repo-local kernel evidence that an actual zero-capability Approval LPAC
can use the exact QLI-plus-synchronize Key Agent handle, complete
`OpenProcessToken(parent, TOKEN_QUERY)`, and deny the exact local
`DuplicateHandle` and PID-reopen requests enumerated above. The copied image's
mandatory-label state is not directly read back, and the test-only
`NO_LOW_LABEL` removal only permits the profile-scoped copy; production
mitigation remains unchanged. This is not
signed/mapped release evidence, so the handle-first production path remains
release-unproven. The
repository has zero production orchestration callers composing
`launch_approval_frontend`
through a verified response into signing and no positive signed-handshake E2E.
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

The integrated kernel positive has two explicit `cfg(test)` accommodations: an
exact pinned terse libtest preamble may precede the response, and Job topology may
contain only the fixture process plus at most the exact System32 `conhost.exe`.
Production requires response magic at byte zero and exactly one Job member. These
test accommodations prove neither the production fresh fixed root nor execution
of the exact signed release artifact.

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
| Session lifetime | No idle timeout; lock on explicit lock/logout, exit/crash, Windows lock/switch/suspend/hibernate |
| Transaction types | EIP-155 legacy, EIP-2930 type 1, EIP-1559 type 2 only |
| EIP-712 exceptions | Version 0.1 has no exception path: missing `chainId`, missing/zero `verifyingContract`, and chain mismatch are denied |
| Unknown calldata | Canary-only warning plus hold confirmation; never silently decoded |
| Registry overrides | Only authenticated `ExpiredReview` or `RuleCoverageUnknown`; invalid signature, rollback, identity mismatch and known-invalid rules always deny |
| Signed nonce | Quarantined until canonical finality proves consumption/supersession |
| RPC credentials | Session memory only; never written to configuration or logs |

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
   non-inheritable parent-process and parent-image proofs and validates all four
   objects as pairwise distinct with zero flags after its Approval
   LPAC/Job/pipe-peer checks. From the retained live exact parent process handle,
   the child derives the authoritative PID and process-token `TokenSessionId`,
   matches the parent hello, both server-end client PID/session observations,
   and child token session, and retains and revalidates that binding through UI
   and response write. This prevents PID-reuse substitution while the handle is
   live and corroborates the pipe observations against that exact process
   object. It still does not establish exclusive endpoint ownership,
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
   held-root proof, four creation attributes, suspended-token proof, and private
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
   62-byte parent hello, fixed 106-byte child hello, fresh nonzero parent and
   child nonces, 110-byte finish header, exact request EOF, fixed 75-byte response
   and response EOF, and the exact transcript fields: held child PID/file
   identity, manifest/profile, request digest/one-shot nonce/hash, response,
   local challenge, and both bootstrap nonces. Job policy/membership must remain
   a separately revalidated live gate, not be described as hashed identity. The
   response does not echo the bootstrap nonces, so replay evidence must also
   cover the private one-shot endpoint and fresh one-shot Approval request nonce.
   Signed release evidence must cover case-sensitive directories and alternate
   path forms and prove the live mapped exact file object, complete
   DLL/dependency graph, immutable installation, a supervisor-held activation
   capability, and exact endpoint topology/exclusivity. The handle-first child
   does corroborate both pipe PID/session observations against a retained live
   exact parent process object and blocks PID-reuse substitution while that
   handle is live, but transferable/duplicable pipe handles leave exclusive
   endpoint ownership, topology/exclusivity, and per-write attribution
   unproven. The repo-local zero-capability Approval LPAC kernel probe proves
   `OpenProcessToken(parent, TOKEN_QUERY)` only for its exact injected handle and
   rejects the exact local `DuplicateHandle` and PID-reopen requests documented
   above. The copied image's mandatory-label state is not directly read back;
   the test-only `NO_LOW_LABEL` removal only permits the profile-scoped copy,
   while production mitigation remains unchanged. That fixture and separate
   held-file policy checks remain insufficient for
   mapped-image identity. There are currently zero production callers
   composing `launch_approval_frontend` through verified response into signing
   and no positive signed-handshake E2E. Raw/legacy silent failure and local wire
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
