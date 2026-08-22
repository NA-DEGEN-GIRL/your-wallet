# Frozen security decisions

These decisions are normative targets for version 0.1. They do not certify that
the current binaries satisfy them. A change requires an ADR, new vectors, and
security review.

**Current release status: STOP-SHIP.** `broker` and default builds of
`approval-ui` and `secret-input-ui` exit with code 78 immediately. A directly
started `key-agent` also fails closed; only the private inherited startup shape
can make it seal stdio, complete one storage-object proof, and wait for its
supervisor endpoint to close before it exits 78. It exposes no runtime or signing
protocol.
`native-host` validates one bounded persistent stream, returns error 4900 for
each valid request without reaching a Broker, then exits 78 on EOF or the first
terminal error. The UI helpers have opt-in inherited-stream runtime
entry points for contract testing, but `COMPILED_RELEASE_POLICY` is `None`, so
no ordinary build can complete restricted launch or reach signing. Activating
the helpers through exact signed-artifact attestation and the end-to-end suite
remain release blockers.

A private dormant Broker preflight now distinguishes Broker transport evidence
and the exact Broker manifest from the three signing-TCB helper manifests. It
can only retain an opaque pinned-artifact capability after role, complete
release evidence, manifest, and absolute-path checks. On Windows, the admission
module alone can mint `PreparedReleaseBrokerSupervisor`, which retains volume
serial plus all 128 `FILE_ID_INFO` file-ID bits derived from the same already-held
handle alongside the admitted artifact. The value is non-cloneable, redacted
under `Debug`, and drop-only.

A production-compiled, crate-private exact-image activation core now consumes
that whole prepared value exactly once. Before user mode it matches the first
debug-event mapped-image handle to the held identity, then retains the value with
the exact process, one-member kill-on-close Job, and private process-bound
channel through cleanup. Its release entry accepts no path, raw handle, PID,
command line, application override, or generic launch target. The compiled
policy remains absent, so the core is dormant and is not signed-install,
native-host provenance, authenticated process topology, or release evidence.

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
system-shared Windows root and passes a verified System32 current directory. A
restricted helper's fixed double-NUL Unicode environment contains only those two
names. The Key Agent prepares its fixed profile first, validates the
`GetAppContainerFolderPath` result as the exact absolute
`Packages` / profile-name / `AC` layout, and uses that exact OS-returned `AC`
path directly as `LOCALAPPDATA`; its environment therefore contains exactly
`LOCALAPPDATA`, `SystemRoot`, and `WINDIR`. Neither child inherits the parent's
ambient environment or current directory. Restricted helpers complete the base
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
prepared capability for which production has no constructor or
pending/candidate conversion. Existing production profiles or roots fail closed
and are not opened, adopted, repaired, or deleted. A future trusted adapter's
supervisor-held proof must require the stable current `TokenUser` SID as owner
and an exact protected two-ACE DACL for that SID plus the fixed profile SID, the
exact inherited Low/`NW` mandatory label, a local fixed NTFS non-reparse
directory with persistent ACLs, and a nonzero-volume, non-sentinel 128-bit
`FILE_ID_INFO`. It keeps the directory open without delete sharing, revalidates
the held identity, volume, and security policy throughout binding, and closes
that handle last during cleanup.

The private one-shot storage-startup transition now binds the child to that root.
The parent writes a fixed request while the exact child is still suspended; it
contains a fresh nonce, the held PID and process creation `FILETIME`, the full
volume-serial/128-bit root identity, and only the compiled production leaf or
exact `cfg(test)` leaf grammar. Only then does the consuming transition release
the sole verified suspend count. After reading the exact 188-byte request, the
child immediately uses `PeekNamedPipe` to reject any already-buffered suffix. It
then resolves the leaf beneath the exact OS-rerouted `LOCALAPPDATA`, derives
`TokenUser` and the AppContainer SID from its own process token, and checks the
directory object, owner, protected two-ACE DACL, inherited Low/`NW` label, and
complete `FILE_ID_INFO` before returning one response that echoes the nonce and
binds its PID, creation time, and root identity.

After reading the exact 88-byte response, the parent immediately uses
`PeekNamedPipe` to reject any already-buffered suffix. It then independently
compares every response field, revalidates the held root's
volume/security/identity, Job context/limits/topology, and monotonic lease, and
commits the held artifact identity plus the exact request and response into a
domain-separated SHA-256 transcript commitment. The resulting private aggregate
retains the process, Job, parent pipe endpoints, handshake, and no-delete-share
root handle while the child retains its own root handle. These immediate peeks on
persistent open streams prove neither the absence of a future delayed suffix nor
EOF. Neither side exposes generic runtime I/O or signing authority.

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
activation boundary, and production has no constructor or conversion that can
mint it. A separate pure classifier models authenticated-journal,
independently-expected identity, and live-object inputs with distinct sealed
types. It binds exact schema/policy, canonical fixed profile name/SIDs, full root
identity, and pairwise-distinct transaction/installation/release identities. It
fixes all four phase-to-generation mappings, but only current `Committed=4`
consistency can produce the existing candidate; every other phase requires
recovery. It observes no predecessor history, so journal sequence, gaps,
rollback, and equivocation remain the future authenticated adapter's
responsibility. Its uninitialized and consistent-existing
results are non-authoritative candidates, not creation, adoption, or launch
capabilities; the latter retains no root handle. The module has no production
input constructor, I/O, OS observer, or consumer. Journal read/authentication,
rollback, gap, or equivocation failures must therefore fail closed before this
model can be called by a future adapter.

The remaining limits are immediate. Existing production profiles still lack an
installer-owned authenticated rollback-resistant provenance journal,
authoritative held-object adoption, and recovery; the root `TokenUser` ACE leaves
other same-user processes able to access it, and ancestor path validation is
not atomic. Production rollback-anchor and storage/AEAD-key provisioning,
protected settings and a live lease, authenticated Broker/supervisor/process
topology and single-instance enforcement, signed immutable artifacts and
DLL/dependency E2E, and release activation remain **STOP-SHIP**. Persistent
startup streams prove neither a future delayed suffix nor EOF, and no generic
runtime/signing IPC exists. `COMPILED_RELEASE_POLICY` is `None`. The central
AppContainer profile API rejects thread impersonation before its process-wide
non-reentrant gate; same-thread reentry and mutex poison also fail closed.

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
startup request, rejects an already-buffered suffix before its process/root
checks, writes exactly one response only after those checks, fails closed on any
input byte that arrives later, and retains its sealed handles and independently
opened root until the parent request endpoint disconnects.

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
   the exact signed image and intended supervisor. The restricted helpers'
   exact two-name environment and the Key Agent's exact three-name environment,
   including OS-derived `LOCALAPPDATA`, share the same verified System32
   current-directory boundary; that policy remains repo-local and is not atomic
   directory identity or signed-artifact E2E evidence. The verified/prepared
   held-root proof, four creation attributes, suspended-token proof, and private
   request-before-resume storage transcript commitment now bind the kernel-test
   child to its exact CSPRNG test root. The same integrated `cfg(test)` path now
   exercises the four fixed private generation stores and their exact
   dual-principal file policy. Fresh creation now yields only a non-launchable
   pending state, and the pure provenance classifier yields only
   non-authoritative candidates. These proofs do not adopt an existing
   production profile, authenticate or anchor installer provenance, implement
   authoritative adoption/recovery, provision a
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
   enumeration through the real helper entry point.
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
