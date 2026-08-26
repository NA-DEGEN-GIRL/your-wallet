# Design Brief: Windows Key Agent Service Boundary

**Status:** Accepted
**Decision date:** 2026-08-25
**Brief path:** `docs/designs/windows-key-agent-service.md`

## Problem / why

The current Key Agent prototype runs as a same-user zero-capability LPAC. The
repository has substantial launch, token, Job, storage, and protocol hardening,
but Windows kernel evidence shows that this principal cannot receive a
loader-compatible process/thread policy that denies `WRITE_DAC` from birth.
Installing a stricter default DACL at the later authenticated application gate
cannot protect objects or handles created before that gate.

The signing authority therefore needs a Windows principal that ordinary
same-user processes do not possess. The accepted direction is to move Key Agent
authority into a headless Windows service and keep only the Approval and Secret
Input frontends in the interactive user's session as zero-capability LPAC
children created and owned by that service.

This brief records the accepted direction. It does not certify an implementation
and does not itself override the frozen decisions in
[`docs/security-decisions.md`](../security-decisions.md). Any normative change to
those decisions still requires an ADR, new vectors, and security review.

## Success looks like

On the enrolled Windows 11 x64 machine, unprivileged malware running as the
enrolled user, a compromised Browser/Native Host/Broker, and another local
interactive session cannot obtain Key Agent secrets, authorize a signature,
create or control a trusted UI helper, reopen a privileged service/helper
process or thread handle, or make a crashed/restarted service repeat a signing
operation. Only the restricted Key Agent service can own keys, durable signing
state, UI-helper creation, and the final signing transition.

## Threat model

### In scope

- Same-user, non-elevated malicious processes, including a compromised Browser,
  extension, Native Host, or Broker.
- PID reuse, endpoint squatting, handle duplication, inherited-handle leakage,
  process/thread reopen, `WRITE_DAC`/`WRITE_OWNER`, VM access, remote thread
  creation, debugger attachment, and token substitution attempts available to
  that attacker.
- Cross-session confusion, lock/logoff, fast user switching, helper/service
  crashes, SCM restart, deadline expiry, partial IPC, and ambiguous durable
  commits.
- Malicious or malformed requests from the Broker. Broker assertions are data,
  not authorization evidence.
- Network access accidentally acquired by the service or either UI helper.

### Out of scope for this boundary

- Local Administrator, kernel, hypervisor, firmware, or compromised Windows TCB.
- Physical attacks against a running unlocked machine.
- Protection after an attacker obtains an approved recovery secret or valid
  Windows administrator authority.
- Multiple enrolled Windows users, multiple machines, roaming profiles,
  cross-device sync, or unattended/background signing in the first release.

Administrator compromise remains out of scope, but installer and release tests
must still prove that ordinary users cannot reconfigure the service, replace its
binary, alter its storage ACL, or change its firewall rule.

## Current repository evidence

The following are existing facts, not new service claims:

- The current release is `STOP-SHIP`; `COMPILED_PARENT_POLICY` and
  `COMPILED_RELEASE_POLICY` are `None`, and ordinary executable paths remain
  fail-closed. See [`docs/security-decisions.md`](../security-decisions.md),
  `crates/platform-windows/src/attestation.rs`, and the two UI bootstrap modules.
- `crates/platform-windows/src/key_agent_lpac.rs` implements the fixed
  zero-capability Key Agent LPAC, protected process/thread creation descriptors,
  token-object DACL proof, and conditional post-gate `TokenDefaultDacl` proof.
- `crates/platform-windows/src/key_agent_activation.rs` implements exact-image
  preflight, debugger-event authentication, the current R10/INT3 cooperative
  gate, debugger detach, and least-authority resident-handle attenuation.
- `crates/platform-windows/src/key_agent_root_job.rs` implements a bounded
  kill-on-close Job, and `crates/platform-windows/src/key_agent_storage.rs`
  implements fixed-root security and `FILE_ID_INFO` rebinding.
- `crates/platform-windows/src/approval_activation.rs` implements a sealed
  parent-bound Approval exchange, but the terminal evidence has no signing
  conversion and the transition has no production caller.
- The current named-pipe primitive uses `\\.\pipe\LOCAL\...`, a current-logon
  DACL, remote-client rejection, and PID/session checks. Its own module states
  that it is not a security boundary against same-user same-session malware.
- The current Key Agent child performs only its storage-startup exchange and
  then remains inert. There is no production runtime/signing protocol.
- There is no SCM service host, service installer/configuration, service SID,
  `CreateProcessAsUserW` launch path, or service IPC implementation in the
  repository at acceptance time.
- Subsequent Phase 1 slices add an inert debug SCM host, a bounded four-frame
  service wire, checked-in MIDL-generated x64 stubs behind a narrow Rust/C SEH
  boundary, and an opt-in authenticated local-RPC server. The RPC surface is
  compiled only by the explicit Windows debug feature. Default, production,
  non-Windows, and release paths remain silent and fail closed as unavailable.
- The debug caller predicate proves only a local, medium-integrity, interactive,
  non-AppContainer caller. It requires the SDK-defined `CallStatus`
  cancellation/disconnection bit field to be zero and rejects 1, 2, and 3. It
  accepts both canonical one- and four-byte `TokenHasRestrictions` observations
  and binds the filtered state across the impersonation and primary tokens; a
  standard UAC-filtered token is not denied solely for having been filtered.
  It performs no Broker role or image proof. RPC exposes a numeric PID rather
  than an atomic origin-process object, so the retained PID-opened handle is
  only a correlation observation. There is no production RPC client or helper
  proof.
- The manager-side debug path now duplicates the already impersonated caller
  into one move-only `TokenPrimary` handle with exactly `TOKEN_QUERY |
  TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`, verifies non-inheritance and full
  identity continuity before revert, and revalidates the retained token across
  the epoch. The If3 callback still performs an independent identity check and
  returns no token or launch authority. This proves the same-host token
  derivation primitive only; it does not prove an enrolled Broker or
  `CreateProcessAsUserW`.
- A separate debug-only service-token fixture can verify the current process
  before `SERVICE_RUNNING`: exact fixed virtual-account `TokenUser`, primary
  Session-0 restricted-token shape, documented service/logon/Local group facts,
  the documented four restricted-SID identities, and an exact four-name
  candidate privilege set. Its proof is explicitly `Unverified` for restricted
  SID attributes, privilege state/necessity, integrity, and SCM configuration.
  The positive test remains ignored until an elevated disposable-VM harness
  installs and starts the exact restricted service.
- That fixture now retains the non-inheritable token handle opened with exactly
  `TOKEN_QUERY` and its complete canonical baseline. Before lending a
  lifetime-bound service-principal capability to creation security, it rejects
  thread impersonation, reopens the current process token, requires the retained
  and fresh handles to name the same kernel object, and rechecks handle flags,
  token identity/IDs, `TokenOwner`, `TokenPrimaryGroup`, groups, restricted SIDs,
  privileges, and resolved privilege catalog. The owner must equal the fixed
  service SID and the primary group must occur exactly once in `TokenGroups`.
  The capability is an exclusive borrow and exposes no SID, PID, or raw owned
  handle.
- A compile-only service launch-input feature can consume that capability to
  create two distinct, non-inheritable process/thread security descriptors and
  later verify both created objects. Before returning the pair, it compares the
  owner/group bytes copied into the descriptors with the sealed baseline and
  repeats the same-object/full-baseline token check, so a mixed or modified
  principal snapshot fails closed. The authenticated desktop primary token is
  not accepted as the descriptor principal. The same feature also owns a
  distinct unnamed non-nested Job primitive with exact
  `KILL_ON_JOB_CLOSE | ACTIVE_PROCESS`, `ActiveProcessLimit = 1`, a
  lifetime-bound creation attribute, and bounded whole-Job cleanup. Fixed
  target-user Approval and Secret Input profile owners now run profile APIs
  through the auth-owned exact-once impersonation lease, bind the returned
  `...\AC` folder as `LOCALAPPDATA`, and retain zero-capability/AAP-opt-out
  attributes. A five-slot extended-startup owner adds the Job, full helper
  mitigation, those LPAC attributes, and restricted-child policy with null
  standard handles and no handle list. Its process-creation view is move-only
  and lifetime-bound rather than a copyable `STARTUPINFOW`. There is still no
  RPC command, process creation, or executable entrypoint using these
  primitives; a future launch-attempt owner must consume them once and retain
  them through post-create readback.
- The fixed zero-padded 76-byte MIDL frame and canonical decoder are the hard
  message bound. RPC `MaxCalls = 8` and `MaxRpcSize = 76` are runtime hints; the
  server independently caps callback-authentication work at eight concurrent
  permits and serializes all manager dispatch.
- The ignored same-process authenticated Windows round-trip passes on the
  current interactive host. That is narrow local kernel evidence, not a claimed
  build matrix or service-identity proof. Endpoint squatting, final service
  identity, a cross-session zero-capability LPAC exchange, and a real production
  Broker client remain **STOP-SHIP**.

The decisive existing result is documented in
[`docs/security-decisions.md`](../security-decisions.md): a same-user LPAC cannot
combine loader compatibility with a from-birth `WRITE_DAC` denial. This excludes
the current architecture. It does not prove the service design below feasible.

## In scope

- One own-process Windows Key Agent service under a restricted virtual service
  account.
- Admin-only install, upgrade, repair, and uninstall configuration for the
  service, binary, storage, network block, and fixed identities.
- One enrolled interactive user SID and one active supported Windows session.
- Service-owned key material, TPM/PCP operations, protected settings, durable
  nonce/signing/broadcast journal, rollback-anchor adapter, and signing
  authorization state.
- Authenticated local control IPC between Broker and service.
- Service-owned creation of Approval and Secret Input LPAC helpers in the
  enrolled user's interactive session.
- A non-inherited helper bootstrap and exact one-shot service/helper channel.
- Lock/logoff/session-change, cancellation, timeout, crash, restart, cleanup,
  and ambiguous-commit behavior.
- Signed-artifact, kernel, negative, and lifecycle evidence required before a
  Private Mainnet Canary policy can be compiled.

## Non-goals

- Keeping the current LPAC Key Agent process as a coequal signing authority.
- Letting the Broker create, resume, debug, inject, or hold process/thread/Job/
  IPC handles for a trusted helper.
- Interactive Session 0 UI or `SERVICE_INTERACTIVE_PROCESS`.
- LocalSystem, NetworkService, shared LocalService, or a password-managed domain
  account as the final service identity.
- `WTSQueryUserToken` plus `SeTcbPrivilege` as the user-token acquisition path.
- Any service network/RPC-to-chain responsibility. Chain RPC and broadcast stay
  in the untrusted Broker.
- Inherited stdio or `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` across Session 0 and an
  interactive user session.
- Automatic adoption or silent migration of an existing LPAC Key Agent profile,
  storage root, or secret material. Migration requires a separately approved
  ceremony and recovery design.
- ARM64, x86, Windows 10, multiple simultaneous enrolled users, or public
  mainnet enablement in the first proof target.

## Accepted design decisions

### 1. The service is the Key Agent security boundary

The service is the only process allowed to hold decrypted key-bundle material,
PCP/TPM private-key handles, protected settings authority, durable signing state,
or a callable signing transition. The existing Key Agent domain, validation,
authorization, vault, journal, and signing types should be retained where their
contracts still fit, but the current inherited-startup process shell,
AppContainer-owned persistent storage, and supervisor lifecycle are replaced by
SCM service equivalents.

The Broker remains an untrusted network and routing component. It may submit a
canonicalizable request and later broadcast exact service-produced bytes, but it
cannot assert approval, choose a signing key, inject display fields, supply a
trusted deadline, or convert an IPC success into signing authority.

### 2. Fixed SCM and service-principal policy

The fixed service identity is:

- service name: `YourWalletKeyAgent`;
- service type: `SERVICE_WIN32_OWN_PROCESS`;
- account: virtual account `NT SERVICE\YourWalletKeyAgent`;
- service SID: `SERVICE_SID_TYPE_RESTRICTED`;
- no desktop interaction;
- demand/trigger start, with any automatic restart treated only as a fresh
  recovery boot, never as continuation of an in-flight request.

The installed service image must be an absolute, immutable, signed path beneath
the fixed machine installation root. SCM configuration, service-object DACL,
binary/DLL tree, registry configuration, storage, and firewall policy must be
installed by an elevated installer and read back exactly. An ordinary enrolled
user may use authenticated application IPC but may not change configuration,
replace the image, change the account, stop/debug the service, or alter its
security descriptor.

The final service token must contain only the privileges proven necessary by the
kernel matrix. The feasibility build may test `SeImpersonatePrivilege`,
`SeIncreaseQuotaPrivilege`, and, only if Windows requires it for the exact
primary-token relationship, `SeAssignPrimaryTokenPrivilege`. The final policy
must remove every unneeded privilege and read back enablement/state on each
start. `SeTcbPrivilege`, `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, and
`SeRestorePrivilege` are forbidden in the final design. If the service cannot
create the required boundary without one of those privileges, this design
returns to review rather than silently adding it.

LocalSystem, NetworkService, and shared LocalService are rejected because they
unnecessarily enlarge the authority and confused-deputy surface. A dedicated
password account is rejected because password provisioning and rotation would
add a new secret lifecycle without improving the one-machine target.

### 3. Service-owned storage and key custody

The service uses one fixed machine-local storage root, for example
`%ProgramData%\YourWallet\KeyAgent\v1`, whose owner and protected DACL are bound
to the service SID and the minimum required system installer/recovery authority.
The enrolled user and UI AppContainer SIDs receive no direct key, journal,
settings, or rollback-anchor access. Every open is by fixed role, uses
no-delete-share and reparse-safe semantics where applicable, and retains
file-object identity through critical transitions.

The canonical key-bundle/envelope and durable journal models already present in
`crates/key-agent` remain the data contracts. Production custody requires exact
Microsoft Platform Crypto Provider provisioning, non-exportable hardware-backed
key proof, TPM/NV or equally rollback-resistant anchor proof, rotation, recovery,
and crash evidence under the service identity. DPAPI is not accepted as the sole
rollback or hardware-custody boundary.

### 4. Authenticated local RPC is the control-plane default

The first IPC design to prove is local RPC over `ncalrpc`, not the current
session-scoped `LOCAL` named pipe. The server must use an explicit endpoint,
explicit security descriptor, `RpcServerRegisterIf3`-class security callback,
local-only policy, and the strongest locally supported authentication/integrity/
privacy settings compatible with the fixed clients. Anonymous or merely
name-secret endpoints are rejected.

For every connection or call epoch, the service must derive rather than trust:

- the caller's exact token user SID, integrity/elevation/AppContainer state, and
  session/logon identity;
- the local client PID and a retained query-only process object;
- the live process image and immutable installed-artifact policy;
- whether the caller is the enrolled Broker role or the exact service-created
  LPAC helper role;
- a fresh, nonzero, service-issued connection nonce and monotonic deadline.

The service compares the RPC-observed client PID/token/session to its retained
process object and rejects PID reuse, a second session, an unregistered user,
wrong AppContainer SID, wrong image, wrong role, or transferred/replayed epoch.
The Broker endpoint admits only non-secret request/control data. Secret Input
and Approval results are accepted only from exact helper processes that the
service created and still owns.

Zero-capability LPAC-to-Session-0 `ncalrpc`, endpoint ACL behavior, service
authentication as observed by the child, client PID attribution, and endpoint
exclusivity are kernel-feasibility obligations, not assumed facts. Failure of
this proof requires an explicit design review. It must not fall back to a
same-user named pipe or Broker-mediated secret channel.

### 5. The service derives an interactive user token without becoming LocalSystem

The Broker first authenticates to the service as the single enrolled user. On a
dedicated request thread, the service impersonates that already authenticated
local RPC client, opens the thread token, and uses `DuplicateTokenEx` to produce
the exact primary token used only for helper creation. It then reverts
impersonation and verifies both the source and duplicated token.

The service requires:

- exact enrolled `TokenUser` SID and logon SID;
- medium, non-elevated interactive user policy;
- the currently active target `TokenSessionId`;
- no AppContainer or UIAccess state on the source token;
- no unexpected restricted/elevated identity;
- continuity between the authenticated IPC client, impersonation token, primary
  token, target session, and service request epoch.

`WTSQueryUserToken` is not used because its LocalSystem/`SeTcbPrivilege`
requirement conflicts with the selected service principal. A numeric session ID
or Broker-supplied token handle is never sufficient evidence.

### 6. The service creates each interactive LPAC helper directly

Approval and Secret Input remain separate fixed zero-capability AppContainer
profiles. The service launches the exact signed helper in the target token's
interactive session with `CreateProcessAsUserW`, `STARTUPINFOEXW`, and
`lpDesktop = "winsta0\\default"`. The service never displays UI in Session 0 and
does not broadly loosen the interactive window-station or desktop DACL. Any
access adjustment must be exact, user/logon-SID-scoped, reversible or naturally
session-scoped, and independently read back.

The creation contract is:

- `bInheritHandles = FALSE`;
- no `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`;
- `CREATE_SUSPENDED | DEBUG_ONLY_THIS_PROCESS | EXTENDED_STARTUPINFO_PRESENT`
  plus only reviewed headless/Unicode flags;
- fixed `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` with zero capabilities and
  the LPAC `ALL_APPLICATION_PACKAGES` opt-out;
- fixed child-process and mitigation policies;
- creation-time assignment to a service-owned, one-helper, kill-on-close Job via
  `PROC_THREAD_ATTRIBUTE_JOB_LIST`, if and only if the cross-session kernel
  matrix proves that combination;
- explicit, non-inheritable process and primary-thread security descriptors
  owned by the service principal and denying the enrolled user all control,
  duplication, VM, debug, DACL/owner, suspend/resume, and terminate authority;
- exact image, PID/TID, session, token, creation DACL, Job membership, handle
  flags, and mitigation readback before application code is released.

Only the service retains the returned creator process/thread handles. The
Broker receives no process, thread, Job, token, debug, pipe, event, or section
handle. A Broker-owned helper launch followed by handle transfer to the service
is a forbidden downgrade, not a fallback.

### 7. Helper handles are injected after creation, never inherited

The preferred one-shot data-plane bootstrap uses two service-created handles:
one exact request input and one exact response output. They begin
non-inheritable. After the child reaches an authenticated child-owned breakpoint
while still debug-stopped, the service calls `DuplicateHandle` into the exact
retained child process with explicit minimum access, `bInheritHandle = FALSE`,
and zero duplication options. The returned values are child-table numeric handle
values; no command line, environment variable, stdio slot, shared global name,
or Broker message transports them.

The service retains the peer ends and binds the pair to the authenticated RPC
connection epoch, exact child process object, request nonce, deadline, role, and
expected transcript. The child accepts the injected candidates only after it
has authenticated the service/control epoch and verified:

- both values are nonzero, distinct, not pseudo handles, and not equal to any
  ambient standard handle;
- both have exact-zero handle flags and expected object type/direction/access;
- each can be converted immediately to a fresh child-local least-authority
  duplicate, after which the launcher-known candidate is closed;
- the first bounded hello matches the service-issued nonce, request role,
  service identity proof, exact child PID/creation identity, and deadline;
- EOF, trailing-data, timeout, cancellation, and extra-handle conditions fail
  closed.

Partial duplication, context write/readback failure, a wrong gate, or child-side
validation failure terminates and reaps the exact child and closes its whole Job.
The service must not continue a partially bootstrapped child. Remote duplicate
cleanup should be attempted where its exact semantics are proven; process/Job
termination remains the authoritative close of all child-table values.

### 8. Primary bootstrap: exact R10/R11 child-owned breakpoint gate

The first implementation candidate is a new x64 helper bootstrap stub, distinct
from the current Key Agent R10-only gate. The signed helper contains exactly one
preflighted executable sequence equivalent to:

1. load fixed independent public markers into `R10` and `R11`;
2. execute `INT3`;
3. after debugger continuation, capture the two resulting register values into
   child-owned locals without a call, allocation, TLS use, stdio use, or other
   externally visible operation;
4. clear `R10` and `R11` before ordinary Rust/UI code;
5. validate and adopt the two handle candidates as described above.

The service accepts the breakpoint only when all of the following match the
retained creation proof:

- exact PID and primary TID;
- first-chance breakpoint at the unique preflighted main-image RVA;
- committed, image-backed, executable, non-guarded page with the authenticated
  main-image allocation base;
- exact remote sequence reread and exact RIP;
- both expected marker registers before mutation;
- no unadmitted loader thread/event history;
- exact target token, session, creation DACL, Job, and live process continuity.

Only after these checks may the service duplicate the two handles, replace R10
and R11 with the returned child-table values through `SetThreadContext`, and
read the complete reviewed context back. Every field other than the two intended
registers must remain exact except a separately documented kernel
canonicalization. The child then captures the values immediately. Compiler
output, PE uniqueness, register liveness, CFG/CET behavior, debugger event
ordering, and supported-Windows variance are release evidence, not assumptions.

The debugger relationship and all debug-event aliases remain on one dedicated
service OS thread. Detach occurs only after the child reports successful handle
adoption while an independent suspend count still prevents UI execution.
Creator-strength handles are then closed or attenuated to the exact cleanup and
query rights required by the service lifecycle.

### 9. Conditional fallback: fixed remote bootstrap cell

If the real signed helper cannot provide a stable, independently reviewable
R10/R11 capture on every claimed x64 build, the only preapproved direction for
another feasibility probe is a fixed remote bootstrap cell. This is not an
automatic production fallback.

The cell must have a fixed symbol/RVA and fixed versioned layout in the
authenticated helper image, reside in a non-executable writable image section,
and be unreachable from ordinary UI logic until the same exact child-owned
breakpoint. The service may write only the two child handle values plus a fixed
version, role, one-shot nonce, and bounded integrity fields using its retained
creator process authority. It must read back the exact bytes, change no code or
control-flow data, and never accept a child- or Broker-supplied address. The child
must atomically claim, validate, and zero the cell before continuing.

This path adds `PROCESS_VM_WRITE`/`PROCESS_VM_OPERATION`, remote-memory lifetime,
and compiler/linker placement risks. It therefore requires its own ADR,
red-team review, negative matrix, and proof that creator VM authority is closed
before the helper becomes interactive. If either the register path or this cell
path fails, helper activation remains disabled; command-line, environment,
inherited-handle, Broker-launch, and broadly named IPC substitutions are not
allowed.

### 10. Authorization and signing remain service-owned

The service independently parses and canonicalizes every admitted operation,
selects the fixed policy, binds the enrolled account/chain/nonce/deadline,
derives the display model, and constructs the exact Approval request. The UI
helper can return only a decision bound to that exact request/transcript. A
Broker-provided “approved” bit, display string, digest, timeout, key selection,
or nonce is ignored.

Before the private-key operation, the service durably commits an intent that
quarantines the exact nonce. After signing, it verifies the encoding, recovered
sender, transaction hash, and approved operation, then durably records the exact
signed candidate before any bytes may be leased to the Broker for broadcast.
Ambiguous storage or RPC outcomes retain quarantine and require authenticated
reload/reconciliation.

Service or machine restart never automatically repeats an unfinished sign. On
recovery, an intent without a committed signed candidate remains quarantined and
requires an explicit fresh user ceremony or a separately proven recovery
transition. A committed candidate may be rebroadcast only through the existing
durable broadcast lifecycle; it is never re-signed.

### 11. Lifecycle is fail-closed

On every start, before accepting requests, the service verifies its token,
service SID/restricted state, privilege set, executable/file identity,
configuration, storage/PCP/anchor bindings, firewall policy, single-instance
lease, enrolled user state, and durable recovery state. Any mismatch leaves the
service unavailable without repairing security-sensitive state automatically.

For each request, the service owns one finite state machine:

`Admitted -> UIStarting -> UIAuthenticated -> Approved/Rejected -> IntentDurable -> SignedDurable -> BroadcastLeased -> Terminal`

No transition is inferred from connection close or process exit. Every state is
bound to one service-issued nonce and monotonic deadline. Cancellation,
timeout, wrong-session activity, lock, logoff, service stop, helper exit, RPC
disconnect, Job violation, or revalidation failure kills/reaps the helper and
invalidates all non-durable authority.

The service registers for session-change notifications. Lock invalidates live
approval/secret sessions; logoff and user switch additionally terminate all
helpers and discard user-token capabilities. SCM stop rejects new work, closes
listeners, cancels/terminates helpers, flushes only already-defined durable
records, releases hardware handles, and reports stopped only after bounded
cleanup. If cleanup cannot be proven, the service exits fail-closed and the next
start enters recovery before listening.

The current debug fixture implements only the SCM/RPC rundown subset of this
policy. If startup rollback or stop rundown cannot prove that RPC-referenced
runtime state was released, it retains that state until process exit and omits
`SERVICE_STOPPED`. While a worker drains, a dedicated reporter advances the
`SERVICE_STOP_PENDING` checkpoint every 500 ms with a 3-second wait hint. It
aborts the process at 15 seconds, on a status-report failure, or on reporter
disconnect, and therefore never converts uncertain rundown into a false clean
stop.

### 12. The service has no network authority

The service contains no chain RPC, DNS, HTTP, WebSocket, update, telemetry, or
browser transport adapter. Installation creates an explicit outbound firewall
block scoped to the exact service identity/image as supported by the target
Windows version. Runtime and release tests must prove denial of TCP, UDP, DNS,
loopback, private addresses, remote named pipes, inherited sockets, and machine-
credential outbound access. A virtual service account can otherwise use machine
credentials; “the code does not call networking” is insufficient evidence.

Approval and Secret Input LPAC helpers retain their independent zero-network
proof requirement. Broker is the sole networking process and never receives
service credentials or secret-bearing handles.

### 13. Release gates remain disabled until the whole boundary is proven

`COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` remain `None` throughout
feasibility and integration. No fixture, local green test, or partial service
host enables signing. A compiled policy requires the exact signed service,
installer, Broker, Approval, Secret Input, dependency graph, service
configuration, endpoint policy, kernel matrix, lifecycle tests, PCP/TPM evidence,
and independent review to bind to one immutable artifact set.

## Unverified assumptions and required feasibility decisions

These items are deliberately separated from accepted decisions. None may be
described as implemented or safe until the corresponding kernel proof succeeds.

| Assumption to prove | Required evidence | Failure result |
| --- | --- | --- |
| A restricted virtual service account can obtain the minimum privileges needed to impersonate the authenticated client and call `CreateProcessAsUserW`. | Exact service-token before/after readback and positive/negative privilege matrix. | Revisit service identity/launch design; do not switch to LocalSystem silently. |
| The service SID can be the effective owner/controller of process and primary-thread objects created for a user-token LPAC without privileged owner bypass. | From-birth security-descriptor readback plus user/service access matrices before first resume. | Service design remains STOP-SHIP; no post-creation DACL repair. |
| `CreateProcessAsUserW` composes with `STARTUPINFOEXW`, zero-capability LPAC security capabilities, mitigation/child policy, debug flags, and creation-time Job assignment across Session 0 to the user session. | Real kernel fixture and real signed Rust helper on every claimed OS build. | Review MSIX/OS activation as a new design; never delegate launch to Broker. |
| `winsta0\\default` access works for the exact interactive token without broad or durable desktop-DACL weakening. | Exact window-station/desktop access and negative cross-user/session tests. | Stop and design a narrower OS activation path. |
| Zero-capability LPAC can authenticate to the Session-0 `ncalrpc` service endpoint and both parties can bind exact PID/token/session/service identity. | Positive service/helper exchange plus endpoint squatting, token substitution, PID reuse, transferred-handle, and second-session negatives. | New IPC ADR; no current-user `LOCAL` pipe fallback. |
| `DuplicateHandle` into the LPAC child after creation yields usable exact non-inheritable data-plane handles and no broader access. | Handle type/access/flag/object readback in both processes and leak/reopen/duplication negatives. | Use authenticated RPC-only data plane if it proves equivalent; otherwise stop. |
| The R10/R11 stub remains unique and captures both values before any clobber on supported compilers, mitigations, and Windows builds. | Disassembly/PE preflight, remote-context proof, real-helper E2E, CFG/CET matrix, and negative marker variants. | Evaluate the separately reviewed fixed remote-cell probe. |
| Debugger exit/detach, event aliases, suspend counts, Job cleanup, and narrow handle rights are stable across every claimed kernel. | Exact event/lifetime/close/readback matrix, including crash and forced error at each edge. | Remove that OS build from support or redesign; no best-effort continuation. |
| PCP/TPM keys and rollback-resistant anchor operations can be provisioned and ACLed to the restricted service identity. | Hardware-backed/non-exportable property readback, reboot/rollback/rotation/recovery drills, and same-user denial. | No secret migration or signing enablement. |
| The service-scoped firewall policy blocks all required outbound classes and survives repair/upgrade. | Exact final-artifact network negative suite and configuration readback. | Service unavailable; release policy remains absent. |

## Acceptance criteria

- [ ] An elevated installer creates the fixed restricted virtual-account service,
  immutable signed image tree, exact service/configuration DACLs, fixed storage,
  and outbound block; install, repair, upgrade, and uninstall readback match the
  manifest exactly.
- [ ] On every start, service token readback proves the exact service SID,
  restricted SID state, integrity, groups, owner, session, and minimal privilege
  set; every forbidden privilege is absent or disabled as required.
- [ ] The service authenticates only the enrolled user/Broker and exact
  service-created helper principals over local RPC, with retained PID/process/
  token/session/image continuity and a one-shot epoch nonce.
- [ ] A real Session-0 service creates a real signed zero-capability Approval and
  Secret Input LPAC in the active user session with `bInheritHandles = FALSE` and
  no inherited stdio, socket, token, Job, section, pipe, or debug handle.
- [ ] Process/thread creation security, LPAC token, mitigations, one-process Job,
  image mapping, desktop/session binding, and returned handle identities read
  back exactly before UI code executes.
- [ ] Same-user attackers fail exact process/thread/token reopen,
  `DuplicateHandle`, debug, VM read/write/operation, remote-thread, suspend/
  resume, terminate, `READ_CONTROL`, `WRITE_DAC`, and `WRITE_OWNER` matrices for
  service and helper objects.
- [ ] The selected R10/R11 or separately approved remote-cell bootstrap injects
  only two exact non-inheritable one-shot handles after the authenticated child
  gate, and the child validates, fresh-duplicates, and binds them to the service
  epoch before parsing a request.
- [ ] Broker cannot launch a trusted helper, obtain a trusted-helper control
  handle, submit a UI decision, replace displayed data, reuse a transcript, or
  cause signing after cancellation/expiry/session invalidation.
- [ ] Lock, logoff, user switch, Broker exit, helper crash, service crash, SCM
  stop/restart, power loss, and forced failure at every persistence/IPC boundary
  leave no helper alive and never automatically re-sign an intent.
- [ ] Service, Approval, and Secret Input final artifacts fail the complete
  network-denial suite while Broker networking remains isolated from service
  credentials and secret handles.
- [ ] PCP/TPM provisioning, non-exportability, service-only access, rollback
  anchor, rotation, recovery, and reboot evidence bind to the same installation
  and release identities as durable storage and signed artifacts.
- [ ] The complete Approval/signing/broadcast lifecycle binds canonical source
  data, displayed fields, request/response transcript, protected settings,
  nonce lease, signing intent, signature, recovered sender, signed bytes, local
  transaction hash, durable candidate, and broadcast result to one operation.
- [ ] Independent signed-artifact review and the offline release verifier pass
  before either compiled policy changes from `None`.

## Kernel and release test matrix

Every result records exact OS build/patch, SDK, compiler/linker, CPU architecture,
mitigation state, Secure Boot/TPM state, executable and dependency hashes, service
configuration, and test artifact identity. A passing result on one development
binary is not evidence for another artifact.

### Required axes

- Every Windows 11 x64 build and patch level claimed by the release, including
  the oldest supported build and the current fully patched build. x86/ARM64 are
  rejected rather than inferred.
- Service stopped/starting/running/stopping, clean restart, crash restart,
  machine reboot, repair, upgrade, uninstall, and rollback attempt.
- Active/unlocked, locked, disconnected, logged off, fast-user-switched, second
  user, second session, stale token, elevated Broker, and wrong logon SID.
- Real signed Approval and Secret Input helpers plus a deterministic minimal PE
  mechanics fixture. Fixture success never substitutes for real-helper success.
- R10/R11 success and every single-field marker/context/page/image/TID/event
  mutation; remote-cell cases only if that path receives its separate ADR.
- RPC endpoint squatting, anonymous calls, wrong SID/AppContainer/image/session,
  PID reuse, transferred binding, duplicate request, replayed nonce, deadline
  expiry, partial/trailing frames, and service impersonation attempts.
- Zero inherited handles, exact injected-handle rights, child/grandchild leak,
  user reopen/duplicate matrices, preexisting/returned/duplicated high-right
  handles, and enabled attacker `SeDebug`/take-ownership negative controls where
  the threat model permits them.
- Loader/DLL/TLS/CRT event provenance, unexpected worker threads, debugger
  detach, suspend counts, Job membership/limits, helper child-process attempts,
  conhost absence, and cleanup after every injected failure.
- TCP/UDP/DNS/loopback/private/remote-pipe/inherited-socket/machine-credential
  denial for service and helpers.
- Durable write interruption at every create/write/flush/rename/checkpoint/
  anchor edge, ambiguous RPC broadcast outcomes, and restart reconciliation.

## Phased rollout

### Phase 0 — Decision record only

Keep the current runtime disabled and both compiled policies `None`. Add the ADR
required by the frozen security decisions before implementation changes their
normative architecture.

**Exit gate:** accepted brief and ADR agree on threat model, principal, IPC,
helper ownership, forbidden fallbacks, and release evidence.

### Phase 1 — No-secret SCM/kernel feasibility fixture

Build an inert service and inert signed LPAC fixture. Prove the virtual account,
restricted service SID, exact privileges, client impersonation/primary-token
derivation, cross-session `CreateProcessAsUserW`, explicit creation security,
Job-at-create, ncalrpc authentication, `bInheritHandles = FALSE`, post-create
`DuplicateHandle`, R10/R11 capture, detach, and cleanup. No wallet storage,
secret, key, approval, signing, or policy enablement enters this phase.

**Exit gate:** every unverified Windows composition above has positive and
negative kernel evidence on the initial exact support target. A failure chooses
review or abandonment, never a weaker hidden fallback.

**Current status:** not passed. The ignored same-process authenticated RPC probe
passes on the current interactive Windows host and now includes manager-only
primary-token duplication and retained-token revalidation, but it is only a
narrow local kernel round trip. The service-token parser and negative policy
matrix are implemented, while the installed restricted-service positive probe
remains intentionally ignored. A further compile-only debug seam now retains
the exact service token for paired service-owned process/thread descriptors,
prepares a separate one-process Job, and can prepare either fixed target-user
Approval or Secret Input LPAC profile while an auth-owned, same-thread,
exact-once impersonation lease is active. Profile creation, SID derivation, and
the authoritative `GetAppContainerFolderPath` observation are individually
bookended by identity revalidation. The prepared environment binds
`LOCALAPPDATA` to that returned AppContainer `...\AC` folder and adds only the
verified `SystemRoot` and `WINDIR`; creation attributes contain zero
capabilities and the ALL APPLICATION PACKAGES opt-out. A disjoint five-slot
startup owner binds the one-process Job, existing helper mitigation policy,
LPAC attributes, and restricted-child policy without standard handles or a
handle list. These types have no RPC/executable caller and still perform no
`CreateProcessAsUserW`, remote-handle injection, or R10/R11 gate. The
claimed-build matrix, endpoint-squatting, SCM configuration/service identity,
cross-session LPAC launch, and real Broker-client evidence are still absent.

### Phase 2 — Installer, service host, storage, and network boundary

Add production SCM lifecycle, immutable installation/configuration readback,
service-only storage adapters, single-instance/recovery state, outbound block,
session notifications, and deterministic stop/crash cleanup. The cryptographic
models may be loaded with fixture keys only.

**Exit gate:** install/repair/upgrade/uninstall, token/DACL, storage identity,
network denial, session, crash, and reboot suites pass with no signing surface.

### Phase 3 — Authenticated Broker and helper runtime

Add the bounded Broker control protocol, exact request admission, service-owned
Approval/Secret Input creation, selected non-inherited bootstrap, full helper
transcripts, deadlines, cancellation, session invalidation, and cleanup. UI
decisions terminate in opaque service evidence with no private-key operation.

**Exit gate:** real signed helper E2E and attacker matrices prove that only exact
service-created helpers can return a bound result and Broker owns no helper
authority.

### Phase 4 — Hardware key custody and durable authorization state

Provision PCP/TPM keys, rollback-resistant anchors, protected settings, durable
nonce/signing/broadcast journal, rotation, backup/recovery, and crash
reconciliation under the service SID. Migration from any earlier local state is
separately approved or omitted.

**Exit gate:** hardware, rollback, rotation, recovery, reboot, corruption,
ambiguous-commit, and same-user denial evidence pass without exposing signing to
Broker or UI.

### Phase 5 — Signing composition

Connect exact Approval evidence to the existing authorization/signing/durable
candidate types inside the service. Prove canonical request-to-display-to-
signature-to-broadcast binding and every no-resign recovery invariant. Continue
to return release-disabled behavior outside the gated test artifact.

**Exit gate:** full signed-artifact authorization, persistence, RPC, lifecycle,
and post-sign recovery suites pass on the complete candidate.

### Phase 6 — Private Mainnet Canary release evidence

Produce the immutable installer/artifact set, complete dependency and loaded-DLL
identity, final Windows negative files, Authenticode identities, independent
review, offline checkpoint/lineage, hardware-key drills, and offline verifier
result required by [`docs/release-security.md`](../release-security.md).

**Exit gate:** only the reviewed reproducible generated source step may replace
the compiled `None` policies for the exact attested artifact set. Any later
service, IPC, helper, compiler, OS-support, key, or installer change invalidates
the corresponding evidence and returns release status to disabled.

## Rejected alternatives and forbidden downgrades

- **Keep hardening the same-user LPAC Key Agent:** rejected because the measured
  from-birth `WRITE_DAC` gap precedes the conditional application gate.
- **Broker launches helpers and transfers handles to the service:** rejected
  because the attacker would begin with creator-strength authority.
- **LocalSystem plus `WTSQueryUserToken`:** rejected as unnecessarily powerful;
  it also hides rather than proves the minimum principal design.
- **Interactive service UI:** rejected by Session 0 isolation and the required
  headless service boundary.
- **Current `\\.\pipe\LOCAL\...` as service/helper IPC:** rejected because it is
  login-session scoped and its current DACL is not a same-user malware boundary.
- **Inherited handles across sessions:** rejected by the Windows cross-session
  inheritance contract and by this design's `bInheritHandles = FALSE` invariant.
- **Command-line/environment/raw numeric PID bootstrap:** rejected because those
  values are ambient, forgeable, transferable, or observable without the exact
  service-owned process proof.
- **Post-creation DACL repair as birth security:** rejected because an attacker
  may obtain authority before repair.
- **Service network access for convenience:** rejected; Broker remains the only
  network component.
- **Enable release policy after a local fixture passes:** rejected; feasibility
  evidence is not signed-artifact release evidence.

## Open risks

- Windows may require a privilege or desktop/session behavior incompatible with
  the selected restricted virtual-account service. The service design is not
  considered viable until Phase 1 resolves this.
- Zero-capability LPAC `ncalrpc` behavior may not provide the required
  cross-session mutual identity proof. There is intentionally no preselected
  weaker fallback.
- The R10/R11 sequence may be unstable under a real optimized signed Rust helper
  or future compiler/mitigation. The remote cell is more invasive and remains
  conditional on a separate ADR.
- A distinct service principal solves the same-user ownership problem only if
  process/thread/storage/IPC objects are born under and remain bound to that
  principal. Any temporary user-owned creator or broad ACE recreates the
  excluded architecture.
- This boundary still trusts Windows, SCM, RPC, AppContainer, the compiler,
  Authenticode, PCP/TPM, and the elevated installer. Release review must make
  those trust assumptions explicit rather than calling the service a sandbox.

## Changelog

- 2026-08-26 - Added compile-only target-user launch inputs: auth-owned
  exact-once desktop impersonation, fixed Approval/Secret Input profile
  observation, exact AppContainer `LOCALAPPDATA`, zero-capability/AAP-opt-out
  storage, and a five-slot no-handle-list startup owner. No process creation,
  helper execution, or release authority was enabled.
- 2026-08-26 — Added manager-only authenticated desktop `TokenPrimary`
  duplication/retention and the debug-only restricted-service-token observer.
  Callback authentication retains no launch authority, exact token access and
  non-inheritance are read back, and the installed-service positive remains an
  explicit ignored kernel obligation. Release remains `STOP-SHIP`.
- 2026-08-26 — Added the no-secret Phase 1 SCM, bounded wire, checked-in MIDL
  boundary, and Windows-debug-only authenticated local-RPC
  `Status -> Unavailable` server slices. Recorded the hard 76-byte canonical
  frame, hint-only RPC call/size values, eight-permit callback cap, serialized
  manager, exact active-zero SDK call-status check, canonical one-/four-byte
  token-filter observation and continuity, retained-runtime stop behavior, and
  bounded stop reporter. The ignored same-process authenticated round-trip now
  passes on the current interactive host. No production client, role/image,
  service-identity, endpoint-squatting, claimed-build matrix, or cross-session
  LPAC proof exists; all release gates remain disabled.
- 2026-08-25 — Accepted the distinct-OS-principal Windows service direction
  after the same-user LPAC from-birth `WRITE_DAC` gap was reproduced. Recorded
  service-owned user-session helper creation, non-inherited handle injection,
  ncalrpc-first authentication, R10/R11 primary bootstrap, conditional remote-
  memory fallback, fail-closed lifecycle, kernel matrix, and gated rollout.
