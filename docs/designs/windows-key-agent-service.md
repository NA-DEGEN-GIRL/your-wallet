# Design Brief: Windows Key Agent Service Boundary

Current Phase 3D checkpoint: debug-only, non-signing Approval transport now
continues after `HelperReady` to a real native presenter. Secret Input remains
ready-only. Exact request/response correlation, EOF before termination, fresh
admitted-helper liveness, unconditional cleanup, and the original five-second
deadline are enforced. No decision becomes signing authority; Phase 3 is not
passed, both compiled policies remain `None`, and release remains **STOP-SHIP**.
See [current implementation and remaining completion gates](../development-status.md).
The standalone debug desktop V2 client and the separate unsigned operator
[service-probe harness](../../scripts/service-probe/README.md) now provide the
next real no-secret fixture workflow. They do not satisfy the installed,
signed-helper, cross-session, or release exit gates below.

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
  Its `cfg(test)` launch fixture requires and reads back the exact current-user
  owner, explicitly applies and reads back the protected two-ACE DACL plus a
  Medium/`NW` label on both the profile-private directory and copied executable,
  and does not weaken `NO_LOW_LABEL`.
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
- The four-frame `YWKASV01` V1 public contract remains immutable. A separate
  non-default `debug-feasibility-v2` module adds the debug-only `YWKASV02`
  foundation with exact 20/52-byte open-epoch, 72/72-byte desktop-command, and
  68/68-byte helper-ready request/response frames. Desktop commands are closed
  to Status, Approval RPC probe, and Secret Input RPC probe; results are closed
  to fail-closed `Unavailable` plus the two matching probe-completed values. No
  V2 frame carries caller role, PID, or image authority.
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
  service SID. The primary group must equal that verified user or occur exactly
  once in `TokenGroups`; LSA logon-token construction does not require primary
  group metadata to be an assigned group. No token entry is discarded, and
  either representation remains bound by complete baseline revalidation.
  The capability is an exclusive borrow and exposes no SID, PID, or raw owned
  handle.
- A debug-only service launch-input feature can consume that capability to
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
  and lifetime-bound rather than a copyable `STARTUPINFOW`.
- A debug-only auth-owned launch attempt consumes those inputs exactly once at
  the sole `CreateProcessAsUserW` call. It passes the fixed application name,
  no command line, `bInheritHandles = FALSE`, paired non-inheritable
  service-owned process/thread security attributes, and exactly
  `CREATE_SUSPENDED | DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW |
  CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT`. Native success is
  adopted immediately; before any debug event, post-create readback proves the
  paired descriptors, exact one-process Job, and retained/fresh primary child
  token. The child must have the fixed role SID, zero capabilities, LPAC/AAP
  opt-out state, the target session, and the authenticated desktop user's exact
  `TokenUser`, single logon SID, and `AuthenticationId`.
- The pre-event creation attempt consumes a move-only fresh-debugger-thread
  witness. That subtransition neither receives/continues a debug event nor
  resumes/detaches the child, and never
  calls `DebugSetProcessKillOnExit(FALSE)`. On failure after creation it requests
  exact-process termination and then whole-Job termination before leaving that
  thread. Bounded process and Job reap requires the matching thread-exit/join
  proof. The LPAC V2 probe coordinator is its only executable/RPC caller and
  still enables no release path. The later debug-only parent gate below
  separately owns its admitted debug-event sequence.
- The helper-bootstrap crate exposes a safe platform-neutral gate-byte
  specification, secret-free canonical 100-byte hello/72-byte ACK codecs, and a
  separate 72-byte `YWKHRC01` helper-RPC confirmation codec to the optional,
  default-feature-disabled `platform-windows` launch feature. Those values
  provide correlation only, not authentication or authority. The child capture/
  adoption/completion API remains limited to Windows x86_64 plus explicit
  feasibility features and `debug_assertions`. Only the matching debug probe
  features on `approval-ui.exe` and `secret-input-ui.exe` reach it; default,
  release, and production entrypoints remain unavailable and it must not run
  without the authenticated parent debugger ready for its breakpoint.
- The capture stub is exactly 34 bytes: `movabs` public markers into R10
  and R11, `INT3`, stores of R10/R11 through RCX/RDX, 32-bit XOR clears of both
  registers, and `RET`. Adoption rejects zero, negative/invalid or pseudo,
  equal, standard-handle-aliasing, nonzero-flag, non-`FILE_TYPE_PIPE`, and
  same-object candidates. It makes fresh child-local duplicates with explicit
  desired access `0x00100001`/`0x00100002`, inheritance false, and options zero,
  verifies object continuity, and checked-closes both launcher-known
  candidates. The independent adoption-complete stub is exactly 28 bytes with
  different R10/R11 markers, one `INT3`, both register clears, and `RET`; both
  breakpoints are at offset 20.
- The child exact-reads/canonically decodes the 100-byte hello, binds expected
  role, its current child PID, a distinct service PID, child-creation `FILETIME`, a strict
  future deadline no more than five seconds away, and both pipe client PIDs to
  the service. It completes one exact synchronous 72-byte ACK write and enters
  gate two. Every capture, adoption, framing, role, identity, deadline, peer,
  write, or second-gate failure calls `std::process::abort()`.
- The debug-only parent uses a bounded read-only reparse-point reopen with file
  identity checked before and after reading, then preflights exactly one
  nonoverlapping copy of each complete gate in initialized executable
  nonwritable AMD64 PE32+ code. It requires canonical virtual/raw section order,
  raw-equals-RVA mapping for every nonempty raw section in a low-alignment image,
  and final aligned extent equal to `SizeOfImage`; it then authenticates the
  bounded create/loader/system-breakpoint/capture sequence and revalidates the
  exact client, process/thread descriptors, LPAC token, context, and one-member
  Job before channel injection.
- Parent injection uses exactly `0x00100001`/`0x00100002`, inheritance false,
  options zero, and opaque child-table words. A partial remote duplicate is not
  locally closeable, so every injection error must terminate and bounded-reap
  the exact child and Job. `DUPLICATE_SAME_ACCESS`, inherited duplication, and
  rights broadening are forbidden.
- The parent mutates only R10/R11 with complete readback, writes hello before
  continuing capture, reads/binds ACK before authenticating gate two, installs
  suspend count one from prior zero, continues gate two, and revalidates live/
  attached/Job/no-pending-event state. No `PeekNamedPipe` is used because it
  requires broader `GENERIC_READ`; no `FlushFileBuffers` is used because it
  requires broader `GENERIC_WRITE`. Synchronous ACK-write-before-gate-two and
  ACK-read-before-gate-two-authentication provide the ordering boundary.
- `DebugSetProcessKillOnExit(FALSE)` is the final fallible debugger-thread
  operation. After join, success requires debugger absence, create-event alias
  flags/ID/same-object reauthentication and checked close, Job count one, and a
  1 -> 2 -> 1 suspend probe. Alias survival after thread-exit detach is proven
  only on the measured host and remains a **STOP-SHIP** kernel matrix item. No
  `DebugActiveProcessStop`, `WriteProcessMemory`, or `CreateRemoteThread` path
  exists. Required privilege and endpoint-squatting evidence remain
  **STOP-SHIP**.
- Rejected-event cleanup registers query-only, non-inheritable anchors with
  `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID)` or
  `OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, TID)` and immediately
  uses `CompareObjectHandles` before checked close. This does not authenticate a
  raw `DEBUG_EVENT` slot generation or eliminate same-object ABA and the
  compare-to-close TOCTOU. Local rejected-alias closure remains debug-only
  **STOP-SHIP** kernel-matrix evidence, not activation safety. Removing this
  blocker requires a dedicated debugger process whose isolated handle table
  retains every borrowed raw event alias until process exit; the product process
  must not close those aliases individually.
- The dormant solution-mechanics slice adds `key-agent-debugger-wire`, whose
  bootstrap, `READY_FROZEN`, decision, `TARGET_FROZEN`, parent-death command,
  and parent-death report frames are exactly 80, 72, 56, 96, 56, and 96 bytes,
  respectively, with big-endian integers, zeroed reserved fields, and CRC32C framing.
  CRC32C, the run nonce, and private-pipe PID topology do not authenticate a
  peer or grant authority. Secretless `key-agent-debugger.exe` is silent and
  exits 78 in default and release builds; its one-shot protocol exists only
  behind an explicit debug test hook. Private platform typestate and an ignored
  current-host kernel test cover a suspended helper, an exact three-entry
  `HANDLE_LIST` with private control/status pipes, parent-to-helper installation
  of a `SYNCHRONIZE`-only sentinel, `READY_FROZEN`, test-only helper-to-parent
  `DUPLICATE_SAME_ACCESS` pull-back, `COMMIT`, `ABORT`, parent EOF, timeout,
  malformed input, forced termination, natural-exit/Drop cleanup, and
  process-exit handle-table cleanup. The same creation call installs a
  one-entry `PROC_THREAD_ATTRIBUTE_JOB_LIST` backed by an unnamed,
  non-inheritable Job. Its exact policy is
  `KILL_ON_JOB_CLOSE | ACTIVE_PROCESS`, `ActiveProcessLimit = 2`, with no
  breakaway mode. The parent retains the only Job handle created by this
  implementation; this is not system-wide sole-handle proof. Current-host tests
  prove exact debugger/target membership, count `2 -> 1 -> 0`, and denial of an
  attempted third suspended member at the Job quota.
  `READY_FROZEN` means only fixed sentinel-source and decision-only protocol
  state, not that the helper is suspended by the OS.
- A private umbrella composes the production-compiled artifact-admission seam
  with its sole debug-gated transport consumer. Admission accepts an already
  verified and pinned helper only in this order: exact manifest-derived
  `KeyAgentDebugger` role, opaque whole-release attestation, the dedicated
  debugger-manifest digest kept separate from the three generic helpers and the
  Broker, an absolute verified path held without write/delete sharing, and full
  `FILE_ID_INFO` from that same held handle without reopen or path lookup.
  `PreflightDebuggerArtifact`, `PreparedReleaseDebuggerArtifact`, and
  `MappedReleaseDebuggerArtifact` are private, move-only/non-cloneable, and
  redacted. Only the sibling transport may borrow the prepared path or consume
  the capability; there is no external path, raw-handle, artifact,
  release-digest, or generic-launch surface. Admission and preparation remain
  free of Job, pipe, channel, thread, process, and debug-event allocation.
- The transport's ordinary path creates only that prepared absolute path with
  the exact six flags `CREATE_SUSPENDED | CREATE_NO_WINDOW |
  CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | DEBUG_PROCESS |
  DEBUG_ONLY_THIS_PROCESS`; only the mismatch test has a `cfg(test)` application
  override. The existing exact three-entry stdio `HANDLE_LIST`, one-entry Job
  list, private pipes, all six debugger-wire frame kinds, and sentinel mechanics
  are retained.
  Before the native process/thread outputs are adopted, raw numeric slots must
  be distinct across the held artifact, Job, all three exact pipe handles, and
  both outputs; ambiguity aborts. A creator-thread-bound owner then verifies
  PID/TID, thread owner PID, zero flags, and exact one-member Job. Initial
  `ResumeThread` must report previous count one or fail-fast; only that exact
  result establishes count zero before a bounded
  `WaitForDebugEventEx`. The first event must be `CREATE_PROCESS_DEBUG_EVENT`
  with exact event PID/TID. Its borrowed process/thread aliases must have the
  exact IDs and owner PID, zero flags, and compare as the creator-owned objects;
  before event-file ownership is adopted, raw numeric distinctness is rechecked
  across the held artifact, all three pipes, creator process/thread, Job, and
  event process/thread/file slots. `hFile` must also be present, zero-flag, and
  exact-object-distinct from the event process/thread aliases. Exact-object
  comparison otherwise binds only those aliases to their creator counterparts;
  artifact binding uses full `FILE_ID_INFO` equality rather than object
  comparison.
- The artifact boundary borrows that event file, queries its complete
  `FILE_ID_INFO`, and compares it to the identity retained in
  `PreparedReleaseDebuggerArtifact`. Equality alone consumes Prepared into the
  linear `MappedReleaseDebuggerArtifact`; no path, PID, image name,
  canonicalization, or expected-file reopen participates. The event file is
  checked-closed before any continuation and ambiguous close fail-fasts. While
  the event still freezes the process, `SuspendThread` must report previous
  count zero. The creator thread then performs
  `ContinueDebugEvent(DBG_CONTINUE)` followed by `DebugActiveProcessStop`.
  Immediately after a successful stop and before any later Win32 call, that
  creator thread probes both borrowed `CREATE_PROCESS` event process/thread raw
  slots with `GetHandleInformation`. Only two failures with exact
  `ERROR_INVALID_HANDLE` retire their accounting record; a live slot, asymmetric
  result, or any other error fail-fasts. The same rule applies to ordinary detach
  and attached rejection cleanup. The transport never calls `CloseHandle` on
  those system-managed borrowed aliases; among event-supplied handles, checked
  ownership and close remain limited to `hFile`. Later post-detach proof requires
  no remote debugger, a live exact process, a 1 -> 2 -> 1 suspend-count probe,
  and the same one-member Job. The mapped artifact remains owned through child
  cleanup. Only after this proof does the parent install the existing
  `SYNCHRONIZE`-only sentinel, write the unchanged 80-byte bootstrap, and consume
  the sole explicit count to enter helper user mode. If the process is not
  already terminal, rejected attached cleanup requests Job/process termination.
  It then releases a pending event, detaches, proves process terminal, drops the
  creator primary-thread owner, and polls the Job empty. A failed post-probe
  resume rejects, while a successful result other than previous count two
  fail-fasts because execution may have escaped; other ambiguous cleanup aborts.
- Same-file and distinct-file artifact tests cover the linear mapped capability;
  source-local tests fix the exact six flags, raw-slot distinctness, and every
  first-event classifier field. Both ignored current-host kernel tests pass: the
  admitted positive path exercises normal-detach retirement, and a mismatched
  prepared-file/`cfg(test)` application pair returns `MappedImage` after attached
  rejection cleanup proves the same result. This establishes only that both
  numeric slots were invalid at those observation points on the measured host,
  not object destruction or a Windows-wide contract. The existing sentinel,
  `READY_FROZEN`, decision, EOF, timeout, malformed-input, and cleanup cases are
  preserved.
- The debug-hook helper now creates a real suspended inert target by resolving
  its own `current_exe` and reports PID/TID, creation time, and source
  process/thread handle words in `TARGET_FROZEN`. Parent pull-back admits only
  process access `0x00101001` and thread request `0x00100802`; current-host
  native readback is `0x00101001`/`0x00101802`, where the extra `0x1000` is the
  measured `THREAD_RESUME` normalization. Post-debugger-exit proof repeats exact
  target identity, Job membership, liveness, and suspend `1 -> 2 -> 1`.
  A forced outer-parent-death fixture covers pre-`READY_FROZEN`,
  `READY_FROZEN`, and post-handoff stages using PID-plus-creation-time
  observations and terminal debugger/target waits.
- That target is untrusted and debug-only: the helper's `current_exe` lookup is
  not a parent-pinned signed target-image proof, and no target resume authority
  is exported. Target raw-slot generation, same-object ABA, atomic compare-close,
  system-wide last-Job-handle exclusion, and supported-kernel generalization
  remain unresolved.
- The Windows x64 MSVC build now embeds one deterministic, header-free ASCII
  `VERSIONINFO` definition. Fixed file and product versions are `0.1.0.0`; the
  exact `0409`/Unicode strings are
  `FileDescription = Your Wallet Key Agent Debugger`,
  `FileVersion = 0.1.0.0`, `InternalName = key-agent-debugger`,
  `OriginalFilename = key-agent-debugger.exe`, `ProductName = Your Wallet`, and
  `ProductVersion = 0.1.0.0`. Package-version drift and other Windows targets
  fail closed, while non-Windows targets do
  nothing. Locked `find-msvc-tools 0.1.10` discovers `rc.exe` and links the
  `.res` only to this binary; it does not cryptographically pin that tool or the
  Windows SDK.
- The release scaffold requires the exact `key-agent-debugger-exe` role at
  `payload/key-agent-debugger.exe`. A safe `FileVersionInfo` inspector runs on
  the built binary, both unsigned outputs before staging, the signed payload
  while generating Authenticode evidence, and the held final bundle during
  offline verification. Post-sign generation requires an effectively read-only
  payload, canonicalizes and pins the output parent, and rejects a volume-root
  parent, ADS/existing leaf, payload containment, or post-create identity drift.
  It retains canonical payload handles plus a pinned inspector source
  through inventory, version, signature, hashes, final exact-inventory recheck,
  evidence creation, and output-byte confirmation. Offline verification
  uses the held bundle plus the inspector identity in the independently pinned
  exact eight-file/four-directory verifier toolset. Tests include a real-binary
  positive and an exact-name non-PE negative; runtime helper decoding also
  requires `VS_FIXEDFILEINFO.dwSignature == 0xFEEF04BD`.
- Desktop RPC admission now distinguishes `SeDebugPrivilege` absent,
  assigned-but-disabled, and enabled states and admits only absent. After the
  one-shot desktop creation claim, same-thread impersonation with retained and
  effective-token bookends requires exact `ERROR_ACCESS_DENIED` from
  `OpenProcess(PROCESS_DUP_HANDLE, FALSE, suspended_child_pid)`. This proves the
  authenticated desktop token against that exact child only.
- Under the LPAC debug feature, the live role-aware manager and independently
  authenticating If3 callback split the low-integrity restricted AppContainer
  transport candidate from service-owned exact LPAC profile/capability/image/
  process/role evidence. The expected-peer registry has exactly eight slots,
  registers the exact suspended helper, revalidates before the sole resume,
  publishes running state before callbacks can proceed, keeps callbacks non-
  consuming, gives the key-bearing manager exact-once consumption, and uses a
  five-second terminal-cleanup quiescence bound. Retired slots are not reused
  during one server lifetime. There is still no production caller.
- Epoch slots share fixed capacity across V1 and V2 but permanently bind the
  issuing generation and derive under distinct domains. A wrong-version attempt
  removes the nonce before denial and is terminal. Malformed-candidate manager
  rejection retires exact and identity-indeterminate expected peers and preserves
  only definite non-matches.
- The V2 desktop dispatcher authenticates before decode and is wired into the
  live `ServerContext`. It returns immediate open-epoch and
  Status/`Unavailable` responses and returns either probe as a move-only launch
  action owning the freshly authenticated peer plus exact request. Desktop
  `HelperReady` is authentication-denied before epoch consumption. V1 dispatch
  behavior is unchanged. The exact consumed desktop request is the only source
  of helper role, epoch, request ID, and matching completed result.
- The RPC manager thread retains the one-shot pending-completion authority and
  gives one coordinator worker only the authenticated desktop authority plus an
  exact request copy. One occupied launch spans the worker and its capacity-one
  transport, so another launch returns correlated `Unavailable` rather than
  queuing. Cleanup, registry-internal, debugger-invariant, and role-correlation
  failures latch fatal health and close admission.
- Status-only retains its original single AU/SY-`GA`, Medium/`NW` descriptor for
  endpoint and If3. The LPAC probe derives the exact package SIDs for the fixed
  Approval and Secret Input profile monikers with OS APIs, then uses distinct
  Low/`NW` descriptors: endpoint connect `0x1`, and If3 `GA`, each for AU, SY,
  and both package SIDs. This closes the prior descriptor-level transport-
  reachability defect, not the installed restricted-SCM fixed-LPAC E2E gate.
- The helper bootstrap retains the validated 100-byte hello's epoch/request/
  role key and absolute deadline in private zeroizing continuation state. The
  role-fixed debug Approval and Secret Input entrypoints use the fixed local RPC
  endpoint with WINNT packet privacy and authz-none, send exact `HelperReady`,
  accept only the correlated ACK, free the binding, exact-write the separate
  72-byte `YWKHRC01` confirmation, close the response pipe, and wait for service
  termination on the request pipe. `YWKHRC01` is correlation only, does not
  reuse the 72-byte adoption ACK, and never replaces expected-peer authority.
- Shutdown orders RPC rundown, coordinator stop/join, and helper-registry stop
  with five-second quiescence. The LPAC-only SCM reporter derives a 30-second
  hard fail-fast watchdog from the terminal-resource bounds and margin. It does
  not prove that each Windows call is interruptible and is not a clean operation
  deadline.
- These are build/scaffold and fixture/proxy checks, not an actual signed-product
  E2E or the Phase 1 exit gate. The real product signer, immutable installation,
  generated compiled policy, parent-pinned target image, system-wide sole Job-
  handle proof, and supported-kernel alias/access/parent-death/cancellation
  matrices remain external **STOP-SHIP** work. Signed-helper `ncalrpc` E2E,
  installed SCM identity, cross-session LPAC, and elevated-service proof are
  also absent. The debug path is executable but has not completed an actual
  installed restricted-SCM, cross-session/elevated, signed immutable-helper
  round trip. Helpers still exit 78 in default and release builds, there is no
  production caller, Phase 1 is not passed, and both compiled policies remain
  `None`.
- When a transport deadline observes pending overlapped pipe I/O, `CancelIoEx`
  is only a cancellation request. Async `ReadFile`/`WriteFile` receive no byte-
  count output pointer; one raw `*mut OVERLAPPED` established before initiation
  is carried unchanged through completion and cancellation, without forming a
  shared Rust reference while the kernel may update it. The exact buffer,
  manual-reset event, and `OVERLAPPED` remain live through a separate fixed five-
  second, non-alertable `GetOverlappedResultEx` drain, which is also the sole
  source of the transferred-byte count, and control returns only after success,
  `ERROR_OPERATION_ABORTED`, or an exact pipe-terminal status. A drain timeout,
  incomplete or alertable result, or any ambiguous error calls
  `std::process::abort()` without unwinding, so borrowed storage cannot leave
  scope while kernel I/O may still reference it. Abort does not run `Zeroizing`
  drops; this lifetime fail-safe is not evidence against WER/minidump, paging,
  or hibernation capture, whose host policies remain **STOP-SHIP**. Current-host
  pending-read tests
  exercise the ordinary terminal-cancellation path; this is bounded fail-closed
  implementation evidence rather than an unconditional kernel-liveness
  guarantee. Parent abort closes its retained Job handle and prevents unsafe
  parent continuation, but kill-on-close terminates members only when that is
  the system-wide last Job handle; this slice does not prove that condition
  after helper code runs. Supported-kernel cancellation-drain liveness remains
  **STOP-SHIP**.
- Every `LOAD_DLL_DEBUG_EVENT` adopts its optional `hFile` into checked caller
  ownership before semantic-proof evaluation, stores the semantic result, and
  then completes checked close. Only after that close may the stored semantic
  error or subsequent loader-count-limit error return; cleanup failure
  dominates if both fail. Rejected
  authority is single-assignment: if any rejected raw slot, PID/TID, or
  canonical anchor already exists, a second registration unconditionally
  fail-fasts before overwrite. This fixes local ordering/overwrite hazards but
  does not remove the raw-generation, ABA, or compare-to-close limitations.
- The common attenuation path has ignored host-local kernel evidence for both
  Approval and Secret Input: service-local creator sources and fresh duplicates
  have exact request `0x00100001` and response `0x00100002` access, zero
  inheritance, and the intended direction. A separate ignored cross-process
  probe uses the real `channel.rs::WindowsDuplicateHandle` production
  duplication path and then test-only `DUPLICATE_SAME_ACCESS` pull-back, WDK
  `NtQueryObject`, object comparison, and I/O to measure the target-table
  candidates as exact. This is test/change-prone evidence for the current host,
  not runtime admission or a universal supported-kernel claim. The real helper
  child's production `WindowsHandleOperations::duplicate` and capture/adoption
  path, UI/production integration, signed-helper E2E, and the complete kernel
  matrix remain unverified. `UnverifiedSourceAccessAndDirection` and the Phase 1
  **STOP-SHIP** gate remain.
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
- exactly `CREATE_SUSPENDED | DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW |
  CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT`;
- a fixed application name and no command line;
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
- both have exact-zero handle flags and `FILE_TYPE_PIPE`; supported Win32 APIs
  do not yet prove each source's exact access mask or effective direction;
- each can be converted immediately to a fresh child-local least-authority
  duplicate, after which the launcher-known candidate is closed;
- the exact 100-byte hello binds epoch nonce, request ID, fixed role, distinct
  service/current-child PIDs, child-creation `FILETIME`, a strict-future deadline
  no more than five seconds away, and both child-server peer PIDs to the service;
- EOF, trailing-data, timeout, cancellation, and extra-handle conditions fail
  closed.

Partial duplication, context write/readback failure, a wrong gate, or child-side
validation failure terminates and reaps the exact child and closes its whole Job.
The service must not continue a partially bootstrapped child. Remote duplicate
cleanup cannot be performed locally when only the first target value was
installed; process/Job termination is the authoritative close of all
child-table values. No caller may recover and reuse the child after an injection
error.

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
5. validate and adopt the two handle candidates as described above;
6. exact-read and bind the 100-byte hello, exact-write the 72-byte ACK, and enter
   one separate exact 28-byte adoption-complete gate with independent markers.

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

The debugger relationship and all debug events remain on one dedicated service
OS thread. The parent writes hello before continuing capture; the child finishes
the synchronous ACK write before gate two; the parent exact-reads and binds the
ACK before authenticating that gate. `PeekNamedPipe` and `FlushFileBuffers` are
not substitutes for this order because their documented generic access
requirements would broaden the two minimum masks.

At gate two, `SuspendThread` must report prior count zero, installing the
independent suspend before the event is continued. After live/attached/Job/no-
pending-event revalidation, `DebugSetProcessKillOnExit(FALSE)` is the final
fallible debugger-thread operation. No explicit `DebugActiveProcessStop`, remote
write, or remote-thread path is admitted. After debugger-thread join, success
requires debugger absence, exact flags/IDs/same-object reauthentication and
checked close of retained create-event aliases, Job count one, and a 1 -> 2 -> 1
suspend probe. The observed alias lifetime/thread-exit detach behavior is
kernel-matrix evidence, not a cross-version assumption. Creator-strength
handles are then closed or attenuated to the exact cleanup/query rights required
by the service lifecycle.

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

On every start, before accepting requests, nine externally supplied observations
verify the service token, restricted service SID, privilege set, executable/file
identity, configuration, PCP provider binding, rollback-anchor binding, firewall
policy, and enrolled user state. The remaining storage-binding and single-
instance requirements are not caller-supplied booleans: lease-first runtime boot
must acquire the exact backend/installation writer before observing either
durable file, and only the resulting lease-bound `BootEvidence` carries those
requirements structurally. Any mismatch leaves the service unavailable without
repairing security-sensitive state automatically.

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
records, and releases request-scoped hardware and storage handles. The dormant
Phase 2F-c/2G chain now structurally carries the exact OS-pair writer and the
provider-bound runtime authority through Clean commit, independent reread,
final release, every checked or irreversible terminal, and stopped evidence.
The independently gated Phase 2E adapter still has no production composition
that binds its service-lifetime root and `run.lock` to that chain. A future
product adapter must also supply OS-proven writer/provider provenance, an
independently protected authentication backend, and a rollback/high-water
anchor, and retain every such authority through the same bounded sequence. The
service reports stopped only after that sequence. If cleanup cannot be proven,
the service exits fail-closed and the next start enters recovery before
listening.

The debug fixtures implement the SCM/RPC rundown subset of this policy. If
startup rollback or stop rundown cannot prove that RPC-referenced runtime state
was released, it retains that state until process exit and omits
`SERVICE_STOPPED`. While a worker drains, a dedicated reporter advances the
`SERVICE_STOP_PENDING` checkpoint every 500 ms with a 3-second wait hint. The
ordinary status-only fixture aborts at 15 seconds. The LPAC probe fixture instead
uses its derived 30-second hard fail-fast watchdog; neither bound is a clean
operation deadline or proof that every Windows call is interruptible. Status-
report failure or reporter disconnect also aborts, so uncertain rundown never
becomes a false clean stop.

The debug-only pre-event creation seam adds a narrower per-attempt cleanup proof.
It runs under a token minted only on one fresh debugger OS thread and leaves a
successful child suspended and debug-attached without receiving, continuing,
resuming, or detaching any event and without disabling debugger-exit kill
semantics. If creation succeeded but later readback fails, the service requests
termination of that exact process first, then latches termination of its whole
one-process Job. Only after the exact creator/debugger thread exits and joins
may the sendable pending owner perform the bounded process wait/close and
exact-zero Job reap. The V2 coordinator now exercises this lifecycle, but that
debug reachability is not an installed cross-session/elevated cleanup result.

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

**Current status:** not passed. The service-token parser, negative policy matrix,
paired service-owned creation descriptors, target-user LPAC preparation, exact
one-shot `CreateProcessAsUserW`, two-gate debug handoff, and current-host pipe-
authority probes remain debug-only feasibility code. The installed restricted-
service positive probe, real cross-session call, endpoint/service identity,
interactive desktop access, elevated service, and supported-build matrix are
still absent.

Desktop admission now rejects `SeDebugPrivilege` whenever it is assigned,
including assigned-but-disabled, rather than checking only its enabled state.
After the authenticated desktop process-creation claim is consumed, one exact
same-thread impersonation and token-bookended access check requires
`OpenProcess(PROCESS_DUP_HANDLE, FALSE, suspended_child_pid)` to fail with exact
`ERROR_ACCESS_DENIED`. This discharges the local post-create denial primitive for
that authenticated token and exact child only; it is not evidence about an
administrator, another token, or the installed service environment.

The debugger transport now has exact 80/72/56/96/56/96-byte bootstrap,
`READY_FROZEN`, decision, `TARGET_FROZEN`, parent-death command, and parent-death
report frames. Its debug hook creates an actual suspended inert target and the
parent pulls back narrow process/thread handles. The exact containment Job is
`KILL_ON_JOB_CLOSE | ACTIVE_PROCESS`, `ActiveProcessLimit = 2`, without
breakaway. Current-host probes cover exact debugger/target membership, a third-
member quota denial, topology `2 -> 1 -> 0`, post-debugger-exit target identity
and suspend reproof, and forced outer-parent death before `READY_FROZEN`, at
`READY_FROZEN`, and after handoff. The measured target masks are process
`0x00101001` and thread `0x00101802` from request `0x00100802`; the extra
`THREAD_RESUME` bit is current-host normalization, not a supported-kernel claim.

The target is still untrusted/debug-only because the helper resolves its own
`current_exe`; the parent has not pinned and authenticated a signed target image.
The code proves only the Job handle retained by this implementation, not that it
is the system-wide last handle. Target raw-event ownership, parent-pinned image,
and supported-kernel topology/access/parent-death matrices remain open.

A role-aware RPC path, live only under the LPAC debug feature, splits the helper
transport candidate from the service-owned expected peer. Its exact eight-slot
registry supports suspended registration, exact role/process revalidation, sole
resume with running-state publication before callback progress, non-consuming
callback observation, exact-once key-bearing manager consumption, replay/race
rejection, and bounded terminal cancel/reap with five-second quiescence. Retired
slots are never reused during one server lifetime. A malformed-candidate
rejection retires exact and identity-indeterminate peers even when no trustworthy
manager key can be decoded, preserving only definitely unrelated entries.

The immutable `YWKASV01` V1 codec and behavior remain unchanged. The non-default
debug-only `YWKASV02` V2 codec defines exact 20/52/72/72/68/68-byte open-epoch,
desktop-command, and helper-ready frames. Its closed desktop command/result
matrix permits Status, Approval/Secret Input RPC probes, matching probe-completed
results, and fail-closed `Unavailable`; the wire has no role, PID, or image
authority. Epoch slots permanently bind V1 or V2 and a wrong-version use consumes
the nonce before denial.

Under `key-agent-service-lpac-launch-feasibility-test-hook`, the live
`ServerContext` manager and independently authenticating callback use the role-
aware router. The V2 desktop dispatch authenticates before decode, returns open-
epoch and Status/`Unavailable` immediately, and transfers either probe into a
move-only action owning the authenticated peer and exact consumed request.
Desktop `HelperReady` is authentication-denied before epoch lookup; V1 delegates
to its existing already-authenticated path. The exact `DesktopCommandRequest`
derives role, epoch, request ID, and matching completion internally.

The RPC manager retains the one-shot completion locally while a dedicated
coordinator receives only the desktop authority and exact request copy. One
occupied launch covers both the worker and capacity-one transport, so launches
cannot queue behind active work. The coordinator holds and hashes the exact
fixed sibling helper, but this is not signer, version, manifest, or immutable-
installation proof. It performs service-owned LPAC creation and both debugger
gates, registers the helper in the exact eight-slot expected-peer registry before
the sole resume, then waits for RPC correlation. Retired slots remain retired
for the server lifetime and terminal registry cleanup has a five-second
quiescence bound.

Status-only keeps the existing single AU/SY-`GA`, Medium/`NW` security
descriptor for endpoint and If3. Under the LPAC feature, the service derives the
exact package SIDs from the fixed Approval and Secret Input profile monikers via
OS APIs and owns separate Low/`NW` descriptors: connect `0x1` for the endpoint
and `GA` for If3, each granted only to AU, SY, and both package SIDs. This closes
the earlier descriptor-level transport-reachability defect in the debug slice;
an installed restricted-SCM fixed-LPAC round trip remains unproved.

The feature-gated Approval and Secret Input entrypoints fix their roles and use
the fixed local endpoint with WINNT packet privacy and authz-none. They send exact
`HelperReady`, accept only its correlated ACK, release the RPC binding, write the
separate 72-byte `YWKHRC01` confirmation and close its pipe, then block until
service termination. The confirmation is not the adoption ACK or role authority.
Only confirmation plus EOF, expected-peer admission/role match, and exact
process/Job cancellation can produce the matching completed result. Cleanup,
registry-internal, debugger-invariant, and role-correlation failures latch fatal
health and close admission.

Shutdown orders RPC rundown before coordinator stop/join and helper-registry
stop. The LPAC-only 30-second SCM watchdog is a derived hard fail-fast bound, not
proof that OS calls are interruptible or a clean per-operation deadline. This
debug wiring has not passed the actual installed restricted-SCM, cross-session/
elevated, signed immutable-helper E2E or the supported-kernel matrix. Production
callers remain absent, Phase 1 remains **STOP-SHIP**, and neither compiled policy
may change from `None`.

### Phase 2 — Installer, service host, storage, and network boundary

Add production SCM lifecycle, immutable installation/configuration readback,
service-only storage adapters, single-instance/recovery state, outbound block,
session notifications, and deterministic stop/crash cleanup. The current
cryptographic model has a sealed installation-bound provider: its production
backend is uninhabited and has zero production constructors, while only a
`cfg(test)` fixture provider can hold nonzero test bytes.

**Exit gate:** install/repair/upgrade/uninstall, token/DACL, storage identity,
network denial, session, crash, and reboot suites pass with no signing surface.

**Current Phase 2A status: started, not passed.** A production-compiled,
module-private lifecycle core now models nine
externally supplied no-secret startup observations. Storage binding and the
single-instance writer are the other two logical startup requirements, but they
arrive structurally inside lease-bound `BootEvidence` rather than as caller-
supplied observations. The core requires exact Active-marker commit and
readback before listener preparation; `SERVICE_RUNNING` publication before
admission; lock, unlock, logoff, and user-switch invalidation; and the fixed
eleven-step stop sequence ending in exact Clean-marker commit/readback followed
by single-instance release. Each startup typestate consumes its preceding
authority. After the first nine exact cleanup steps and empty work/token
registries are proven, a final pre-Clean check consumes the live runtime into
`CleanCommitPending` while retaining the exact writer lease. The ninth cleanup
step, `CleanupStep::ReleaseRequestHardwareAndStorageHandles`, names only
request-scoped cleanup. The provider-bound runtime authority is owned by the
logical `SingleWriterLease` together with the exact writer, and survives through
Clean commit, independent reread, final release, every terminal/recovery path,
and stopped evidence. Retaining the future run-state-root handle and a
production rollback/high-water-anchor handle across the same boundary remains
an adapter obligation; so do OS provenance tying the writer and provider to the
intended service installation and an actual protected provider backend.
Distinct committed and reread Clean receipts can produce only
`CleanCommittedWithWriter`; the sole stopped-report permit requires its final
backend-bound writer-release receipt. Invalid or ambiguous evidence cannot
claim a clean stop, and a Clean reload still retains the writer-release
obligation. Work, retained-token, and quarantined-session registries are bounded
at 256, 64, and 64 entries. Quarantine exhaustion invalidates every live fixture
authority, discards retained tokens, and latches the first fatal reason. Durable
Active evidence remains authoritative until exact Clean commit, and stopped
evidence remains withheld until exact writer release. Work and session
identifiers and every durable identity/generation/commitment surface are
redacted from debug output, and no session is automatically revalidated.

The authority-independent policy split is explicit:
`StartupChecklist -> CompletedStartupChecklist -> ListenerPendingPolicy ->
ScmRunningPendingPolicy -> AdmissionPendingPolicy -> RuntimePolicy`, followed
only by `CleanBoundaryPolicy -> ReleaseBoundaryPolicy -> StoppedRuntimePolicy`.
The four pure-policy tests are separate from the seventeen legacy lifecycle
tests, for an exact 21-test core inventory; the dormant Phase 2G compositor
consumes only this narrow policy surface and independently retains Windows
durable authority.

This is an ordering model and test slice only. It creates no SCM listener,
handle, process, RPC endpoint, storage or rollback-anchor binding, firewall
rule, cryptographic key, secret, approval result, or signing authority. There
is no executable or top-level production caller or OS adapter; the sole
production-compiled consumer is the private dormant Phase 2G compositor.
Installer/configuration readback,
service-token and DACL enforcement, durable storage/recovery, a live
single-instance lease, outbound-denial proof, session-notification hookup, and
crash/reboot kernel evidence remain absent. Phase 1 and Phase 2 exit gates
remain not passed; `COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` remain
`None`, and the ordinary/release service executable remains silent exit 78.

**Current Phase 2B status: started, not passed.** A second production-compiled,
module-private, zero-runtime-root core now defines exact 148-byte `YWRUNV01`
run-marker and `YWHIWV01` independent high-water envelopes. Both bind the fixed
installation identity, nonzero generation, predecessor/current lineage
commitments, and reserved-zero schema. Exact codec and HMAC operations live only
inside a private authentication child behind marker-specific and checkpoint-
specific signing/verification; there is no caller-selected domain, raw-key, or
generic tag oracle. A same-body test proves that the two purposes yield distinct
tags and reject cross-purpose verification. The sealed
`RunStateAuthenticationProvider` owns the exact installation and a unique opaque
provider identity that differs even for providers constructed from the same
installation and fixture bytes. Its production backend is uninhabited with zero
production constructors; only `cfg(test)` can construct it from a nonzero key
held in `Zeroizing`, and its Debug surface is redacted. Its move-only runtime
authority is minted through `runtime_authority(&mut self)`, preventing a second
live mint from the same provider. The Boot-producing runtime path first acquires
the exact backend/installation writer and only then freshly observes and
authenticates the marker and checkpoint; only an exact Clean pair under that
writer and provider-bound authority can produce `BootEvidence`. A separate
`cfg(test)` inspection carries no lease-binding, Boot, or mutation authority.
`SingleWriterLease` owns both the exact writer and runtime authority throughout
the sealed chain
`PreparedActiveTransition -> ActiveRunLease ->
PreparedCleanTransition -> CleanCommittedWithWriter ->
PendingFinalWriterRelease -> StoppedRunEvidence`; raw durable observations, raw
receipt wrappers, copied generation authority, and the former
`single_instance_released` boolean are no longer lifecycle inputs. Transition
methods do not accept a parallel provider or installation argument.

Active and Clean each require exact prior-state CAS, distinct commit and reread
receipts, agreement of marker plus high-water checkpoint, and the same opaque
backend/lease/provider binding as their originating transition. Every ambiguous
commit consumes its transition into a lifecycle-branded Active or Clean reload
state. Before either successor is constructed, the lease-owned authority
reauthenticates the exact held prior marker and checkpoint. No transition can
substitute a replacement provider; wrong-provider evidence retains only
terminal writer-exit authority.
Each prepared commit carries a private one-shot phase from attempt through
commit receipt and independent reread. Reload, normal release, and terminal-
retirement receipts are likewise one-shot. The bounded backend latches an ambiguous or terminal commit and any
unresolved release against the exact writer epoch, blocking direct retry and
writer reacquisition until the matching reload or terminal retirement.
Exact prior Clean requires the full startup observations again before an Active
retry, exact fully committed Active may resume only through its startup reload
wrapper, and an exact reloaded Clean candidate can produce only
`CleanCommittedWithWriter`; the cleanup wrapper and exact final writer release
remain mandatory before stopped evidence. A marker-only advance, checkpoint
drift, rollback, equivocation, authentication failure, missing object, wrong
installation, backend or writer mismatch, CAS conflict, or reread drift
requires terminal recovery. Every consumed durable-outcome or receipt-
validation failure retains a move-only, terminal-only writer-exit authority
that can prove exact release without any conversion to Boot, Active, Clean, or
Stopped authority. A non-consuming request-validation, duplicate, or replay
rejection cannot issue a second or replacement receipt and does not invalidate
an already-issued exact receipt. Clean commit and
readback occur while the writer remains held, so a second boot cannot enter the
release boundary; fixture crash/exit release preserves the last authenticated
durable state without minting a stopped report.

This remains a no-OS fault model, not product storage. Its only storage backend
is a fixed-capacity `cfg(test)` memory fixture, and the authentication provider's
production backend is deliberately uninhabited rather than a production key
source. There is still no `%ProgramData%` service-owned root, service-SID
owner/DACL adapter, installer-seeded initial marker, kernel singleton object,
protected or TPM-backed authentication/high-water source, power-loss or reboot
evidence, or executable/top-level production caller. The only internal
consumers are the separately gated dormant Phase 2F-c/2G runtime chain and Phase
2C Windows provisioning compositor.
Existing LPAC user storage and the signing journal are not
reused as service run-state authority. Phase 1 and Phase 2 remain **STOP-SHIP**;
both compiled policies remain `None`, and ordinary/release execution remains
silent exit 78.

**Current Phase 2C status: started, not passed.** This zero-runtime-root
slice replaces the ordinary fixture's out-of-band generation-one Clean seed
with a production-compiled provisioning typestate. A fixture-only, move-only
fresh-install authority is bound to one installation, backend, nonzero
provisioning attempt, and exact opaque provider identity. It cannot become
runtime authority. The backend must first acquire a distinct provisioning writer and,
while that writer remains held, independently observe both the run marker and
high-water checkpoint as missing before it can produce
`UnprovisionedWithWriter`.

A production-compiled but dormant Windows-only child now composes that logical
typestate with the fixed Phase 2F-b marker/checkpoint pair. The child is reached
through one private `#[path = "windows_provisioning.rs"]` module and an exact
`pub(super)` re-export; it has no executable or top-level entry. A move-only
`WindowsInstallerProvisioningGrant` carries an expected opaque provider identity
and nonzero attempt; only a `cfg(test)` current-user fixture can seal and
construct that grant. The sole binder,
`bind_windows_fresh_install_authority(provider, grant)`, can create
`WindowsFreshInstallAuthority` only when the exact provider identity matches.
There is no direct fresh-authority fixture constructor, and a second provider is
rejected even when its installation and fixture bytes are identical. This is a
test surrogate, not evidence that the caller is an elevated installer or that a
missing store is a virgin installation.

`start_windows_initial_provisioning` consumes the already-held OS writer and
that authority. Writer transfer precedes backend binding and writer epoch
allocation. The authority's carried attempt, backend binding, and writer epoch
are nonzero and pairwise distinct. It then freshly observes the fixed pair and
admits only exact Missing/Missing before creating the logical
`UnprovisionedWithWriter`. Any observation error, nonempty pair, one-sided
state, or malformed record is terminal and retains the exact pair and logical
writer-exit obligations for checked retirement.

The only candidate from that authority is canonical Clean generation one with
a zero predecessor. It requires an exact absent/absent compare-and-swap,
distinct commit and reread receipts, and the same backend, installation,
provisioning writer, attempt, and ambiguity round. An ambiguous commit may
recover only an exact fully committed candidate or an exact still-empty pair;
the latter requires a fresh backend-issued round before retry. A one-sided,
malformed, pre-existing, wrong-provider, cross-backend, stale, or drifting state is
terminal and is never repaired or adopted. Every consumed durable-outcome or
receipt-validation failure retains only provisioning-writer exit authority. A
non-consuming request-validation, duplicate, or replay rejection cannot issue
a second or replacement receipt and does not invalidate an already-issued
exact receipt.

The Windows child prepares `ExpectedWindowsPair::missing()` from the logical
Clean-one candidate. The exact consuming order is logical begin-commit, OS
commit, logical commit receipt, logical begin-reread, independent OS reread,
and logical completion. A known-not-committed failure is terminal. From the
first native rename attempt onward, any non-confirmed or error outcome is
ambiguity-bearing and exposes only one independent reload or retirement. Only
a fully confirmed commit proceeds to the independent reread. Reload classifies
exact Missing/Missing as `Retry`, the exact authenticated candidate as
`Committed`, and every partial, malformed, or drifting observation as terminal.
A confirmed commit reread failure is terminal `RereadDrift`; it never re-enters
ambiguity reload or restores the prior empty state.

The same private one-shot commit, reread, reload, normal-release, and terminal-
retirement phases apply to provisioning. An ambiguity preserves both the prior backend round and the
candidate fresh round, so terminal retirement uses the last round actually
issued by the backend. Exact writer-epoch latches prevent same-round commit or
release retry and block both provisioning and runtime writer reacquisition
until matching reload or terminal reconciliation.

Provisioning completion remains withheld until the exact provisioning writer
is released. The resulting `ProvisionedRunState` retains the consumed fresh
authority as a hidden field and has no conversion to `BootEvidence` or a runtime
writer. `ProvisioningRecoveryExitEvidence` likewise retains it through checked
retirement. Runtime startup must separately acquire a fresh runtime writer and
only then reopen and authenticate the new Clean pair through the existing boot
path. Ordinary boot on a missing pair still requires recovery and never auto-
initializes storage.

The Windows release path first compares the pair observation with the exact
logical Clean bytes, prepares and begins logical release, and then calls the
pair-bound verified OS release. It distinguishes writer-retained,
released-without-receipt, and post-release terminal outcomes. Only an exact
released pair, matching logical release receipt, and logical completion mint
`WindowsProvisionedRunState`, which exposes generation only while retaining the
fresh authority privately. Every live or reload state also has a reason-neutral
checked retirement path ordered as
logical begin-release, exact OS-pair retirement, logical receipt recording,
then logical completion. `WindowsProvisioningCheckedRetired` retains that hidden
authority. A checked-retirement failure is irreversible and cannot mint normal,
retry, Boot, or recovery authority.

The Windows composition has seven passing `windows_provisioning` tests: exact
Missing/Missing to Clean generation one followed by a separately acquired fresh
runtime Boot; unchanged rejection of a pre-existing full pair; ambiguity reload
classification for still-missing, marker-only, and exact-candidate states;
terminal confirmed-commit reread drift; distinct writer-retained,
released-without-receipt, and post-release outcomes; and complete live-state
retirement, move-only, and Debug-redaction coverage. A focused grant/binder test
also proves exact identity matching and non-vacuous rejection of another
provider made from the same installation and bytes. The focused
`durable_run_state` inventory is therefore 88/88: 34 parent tests, two private
authentication-child tests, 25 external logical provisioning tests, six
`windows_pair` tests, seven `windows_provisioning` tests, and fourteen
`windows_runtime` tests. The kernel
run-state-root inventory remains 56 total, with 54 passing and the same two
environment-dependent tests ignored; the pre-Phase 2F-c Phase 2F-b inventory
remains 55 total with 53 passing and two ignored.

This remains a current-user fixture/local composition, not product
provisioning. It does not prove that a missing pair is a virgin installation
and supplies no elevated installer provenance, lease, or journal, production
fresh-authority constructor or caller, `%ProgramData%`
service-SID from-birth storage/ACL or ancestor sealing, SCM/restricted-token
composition, trusted `SYSTEM` peer or mapped-I/O exclusion, signed immutable
artifact/install binding, TPM/protected authentication key, non-rollbackable
anchor, or supported-kernel crash, power-loss, reboot, torn-sector, storage-
durability, or pair-atomicity evidence. Deletion of an existing store must never
be accepted as fresh installation by a future adapter. Those are external
**STOP-SHIP** obligations. The bounded logical fixture still has no production
constructor, or production caller. Phase 1 and Phase 2 remain **STOP-SHIP**;
both compiled policies remain `None`, and ordinary/release execution remains
silent exit 78.

**Current Phase 2D status: started, not passed.** The Boot-producing runtime
path now mirrors the writer-first provisioning boundary. A move-only
`RuntimeRunStateAuthority` is minted from a mutable borrow of its exact sealed
provider and enters the writer acquisition with the provider's installation and
opaque identity already bound. Fixture `begin_runtime_boot` yields the move-only
`RuntimeWriterAcquired` state; `finish_runtime_boot` consumes it exactly once
into either exact authenticated Clean `BootEvidence` or
`RuntimeBootStartFailure`. Its typed `RuntimeBootBeforeWriterFailure` arm owns
the consumed authority but no writer or writer-release obligation. Every
observation, authentication, state, backend-binding, or writer-epoch failure
after acquisition instead retains both the authority and exact writer through
terminal writer retirement. A separate `cfg(test)` inspection may authenticate fixture bytes
without a writer, but it has no lease-binding, Boot, or mutation authority and
cannot later bind a newly acquired writer.

Missing/Missing, either one-sided missing state, malformed bytes, a wrong
provider, Active or RecoveryRequired state, and cross-backend or cross-epoch
substitution never initialize, provision, repair, or mint `BootEvidence`.
Pre-acquisition rejection retains the provider-bound authority in its typed
terminal without claiming a writer; post-acquisition rejection preserves the
observed durable state and terminal writer-exit authority and blocks writer
reacquisition until exact retirement. A fresh-install provisioning authority
remains a separate fixture-only capability and cannot be derived from any
runtime-boot result.

The eleven logical startup requirements are therefore nine external
observations plus storage-binding and single-instance evidence carried
structurally by the lease-bound `BootEvidence`. Shutdown likewise distinguishes
request-scoped hardware/storage cleanup from service-lifetime run-state
authority. `SingleWriterLease` owns the runtime authority and exact writer; that
pair is the sole carrier after writer acquisition and remains live through every
later startup/live/reload/release state and every writer-bound terminal,
recovery, and stopped evidence. Before acquisition, the typed authority-bearing
terminal owns the authority directly and has no writer-retirement path. The
separate Phase 2E adapter retains its root and lock
through its own release, but a future composition must bind that handle to this
durable writer and also supply OS provenance for the writer/provider, a
protected provider backend, and the anchor handle across the same boundary.

At the pre-Phase 2F-c boundary this remained a module-private, zero-runtime-root
contract over only the bounded memory fixture and `cfg(test)` sealed provider.
It had no filesystem or other OS adapter. The separately gated dormant Phase
2F-c composite below is its sole private Windows runtime durable adapter, and the
separately gated Phase 2G compositor is now its sole production-compiled policy
consumer. Neither bridge has an executable, top-level, or exported caller or a
production protected-provider source.
There is still no installer or SCM integration, power-loss/reboot proof,
TPM-backed key or anchor, secret, signing
transition, or release authority. The separate dormant Phase 2E adapter below
can hold an already-installed service root and `run.lock`, but it has no
conversion into `RuntimeWriterAcquired`, `BootEvidence`, or any provisioning
authority and is not a runtime caller of this contract. Phase 1 and Phase 2
remain **STOP-SHIP**; both compiled policies remain `None`, and ordinary/release
execution remains silent exit 78.

**Current Phase 2E status: started, not passed.** The Phase 2E portion of a
production-compiled, Windows-only, module-private adapter models the narrow OS
boundary for one already-installed service run-state root and its persistent
`run.lock`. The separate Phase 2F-a extension below adds the installed `state`
directory without weakening these root/lock requirements. The
production path obtains the fixed machine location only through
`SHGetKnownFolderPath(FOLDERID_ProgramData)`, opens the drive root with
`OPEN_EXISTING`, and then opens every known-folder and fixed
`YourWallet\KeyAgent\v1` component from its already-held parent with
one-component, root-relative `NtCreateFile(FILE_OPEN)` calls. Thread
impersonation is rejected around known-folder resolution, every open, and each
held-object revalidation. The final root is held without delete sharing; the exact
installer-created `run.lock` is opened as a non-directory, zero-length,
single-link file with `GENERIC_READ | SYNCHRONIZE` and zero sharing. The kernel
must map that request to the exact `FILE_GENERIC_READ` grant, including
`FILE_READ_EA`; the handle then acquires the exclusive, nonblocking byte range
`[0, 1)` with `LockFileEx`. Every production handle must report handle flags
exactly zero, rejecting both inheritance and protect-from-close, and every open
uses reparse-safe semantics. The adapter rejects a remote or
non-fixed/non-NTFS volume, missing objects, unexpected open disposition,
object-shape drift, and full `FILE_ID_INFO` mismatch. It never uses
`OPEN_ALWAYS`, `CREATE_NEW`, a global named mutex, or the enrolled-user/LPAC
store or signing journal, and it never creates, repairs, replaces, deletes, or
adopts either installed object.

`ExpectedInstalledRunStateObjects` carries the independently supplied expected
root and lock identities plus the service security policy; the current combined
type also carries the separate Phase 2F-a state-directory identity described
below. It intentionally has no production mint, and observed identities cannot
be converted into expected installer authority. The adapter verifies the
service SID as owner and an exact
protected, non-inherited three-ACE DACL: an `OWNER RIGHTS` deny for
`WRITE_DAC | WRITE_OWNER | DELETE | FILE_DELETE_CHILD`, the exact service
operational allow (`FILE_GENERIC_READ` for the lock), and `SYSTEM`
`FILE_ALL_ACCESS`. It also requires exact-zero
handle flags, local fixed NTFS with persistent ACL support, complete
non-sentinel file identities, and root identity/security revalidation before
and after lock acquisition. Each revalidation succeeds only after the reopened
no-delete-share root is identity-checked and explicitly checked-closed; an
ambiguous probe close is a failure, and after lock acquisition it remains
writer-retaining and cannot mint a release receipt. `SE_DACL_PROTECTED` plus
zero flags on every exact
ACE proves the current DACL contains no inherited ACE semantics;
`SE_DACL_AUTO_INHERITED`, if present, is only a historical/model control marker
and is not treated as from-birth provenance. `SE_DACL_AUTO_INHERIT_REQ`, a
defaulted or unprotected descriptor, and any nonzero ACE flags are rejected.
Group and all SACL policy, including audit, mandatory-label, and
resource-attribute semantics, are deliberately not claimed by this slice; the
current production query reads only owner and DACL.

The root's own `OWNER RIGHTS` deny does not by itself prove at-rest delete or
rename denial because an ancestor can grant `FILE_DELETE_CHILD`. The surrogate
tests therefore keep distinct claims: fresh root opens requesting `WRITE_DAC`,
`WRITE_OWNER`, or `FILE_DELETE_CHILD` are denied; a fresh lock `DELETE` open is
denied; and a fresh root `DELETE` open while `HeldServiceRunStateRoot` exists
fails with `ERROR_SHARING_VIOLATION` because that held handle omits delete
sharing. Actual installer proof must additionally seal the `YourWallet` and
`KeyAgent` ancestor ACLs against service or untrusted delete-child and
rename/delete paths. That ancestor policy and at-rest integrity remain external
**STOP-SHIP** evidence rather than a claim of this runtime adapter.

`HeldServiceRunStateRoot`, `HeldServiceRunStateWriter`, and
`HeldRunLockFailure` are move-only. A failure before Windows returns the lock is
`RuntimeRunLockStartFailure::BeforeLock`; every status, disposition,
impersonation, identity, security, shape, root-revalidation, or revalidation
probe checked-close failure after a lock handle exists is `WithLock` and
retains terminal retirement authority. Here `WithLock` means that a valid
`run.lock` handle is retained; the byte-range lock may or may not have been
acquired. Only the successful `HeldServiceRunStateWriter` result proves the
exclusive range lock was acquired.
Normal release revalidates the writer, explicitly calls `UnlockFileEx` for the
exact `[0, 1)` range, checked-closes the lock, revalidates the still-held root,
and checked-closes the root before it can produce `ServiceRunLockReleased`. A
native `UnlockFileEx` failure retains the writer and range and cannot mint that
normal receipt. Checked retirement retries the explicit unlock when the range is
still held and attempts to checked-close both handles even when unlock fails; it
produces `FailedRunLockRetired` only if any acquired range was explicitly
unlocked and both closes succeed. Neither receipt nor held authority converts
into the Phase 2D durable writer, Boot, Clean, stopped, provisioning, or signing
authority.

The kernel tests use an explicitly `cfg(test)` current-user surrogate because
this non-elevated development slice cannot install or rewrite the real machine
root. That surrogate alone may create fixture objects and retain a
non-inheritable, share-neutral `READ_CONTROL | WRITE_DAC` cleanup handle with no
data or delete access across the production opener for the test lifetime. It
checked-closes the `FILE_ADD_FILE | FILE_DELETE_CHILD` setup handle and lock
creator handle before recording `FILE_ID_INFO` and calling the production
opener, then closes the retained cleanup handle only after the held adapter and
test are torn down. This is not from-birth installer evidence and does not prove
that an actual installer closes every setup or cleanup-capable handle before
service start. The default focused suite exercises same-process contention,
cross-process crash/reacquisition with unchanged identities, synchronized child
non-inheritance, and junction rejection. While the writer is held, a test-only
raw `NtCreateFile` probe requests the exact generic lock access with all three
share modes. It accepts only either exact sharing-violation status with no
handle, or an exact same-identity verified handle whose byte-range lock attempt
returns `ERROR_LOCK_VIOLATION`; every returned handle is checked-closed. A
separate non-vacuous test opens two share-readable handles to the exact same
file, requires the first exclusive `[0, 1)` lock to succeed and the second to
return `ERROR_LOCK_VIOLATION`, and checked-closes both. Its `run.lock`
symbolic-link negative is ignored by default because creating that file reparse
point requires a qualified host with Developer Mode or
`SeCreateSymbolicLinkPrivilege`; that test must be invoked explicitly there,
and the default suite alone does not prove the file-symlink negative. The
production adapter has no constructor for the expected installer authority and
no caller, so it does not prove the actual
`%ProgramData%\YourWallet\KeyAgent\v1` objects, virtual service-SID positive
access, elevated installer from-birth descriptor and independently sealed
identity provenance, closure of every installer/setup/cleanup handle before the
service open, sealed `YourWallet`/`KeyAgent` ancestor ACLs and at-rest integrity,
SCM account/configuration or a LocalSystem token with restricted service-SID
composition, group policy, or any SACL policy (including audit,
mandatory-label, and resource attributes),
install/repair/upgrade/uninstall, marker/checkpoint I/O, atomic CAS or flush
behavior, authentication-key or rollback-anchor custody, crash/power-loss or
reboot recovery, or a production kernel singleton composition. Those items
remain external **STOP-SHIP** evidence. Byte-range locks are cooperative and do
not constrain mapped-file I/O; this zero-length, no-write service DACL narrows
that surface, but actual service and `SYSTEM` peers must remain trusted not to
bypass the protocol. Retirement/no-receipt close fallback and crash process
termination can also delay range-lock release; graceful release instead requires
the explicit successful `UnlockFileEx` ordering above. The current host test
bounds child-exit observation to 30 seconds and, after
confirmed exit, retries only exact `Contended` acquisitions for five seconds,
checked-retiring every returned `WithLock` handle before retry, then proves
reacquisition with unchanged root and lock identities. That is bounded
repository-host crash-teardown evidence, not an instantaneous-unlock claim or a
supported-kernel, power-loss, or reboot guarantee; those broader guarantees
remain external **STOP-SHIP** evidence. The ordinary/release service still has
both compiled policies set to `None` and remains silent exit 78.

**Current Phase 2F-a status: started, not passed.** The production-compiled,
Windows-only, module-private Phase 2F-a extension adds exactly one
installer-created `state` directory beneath the already-held fixed `v1` root.
It can be opened only after the existing `run.lock` handle has acquired and
verified its exclusive nonblocking `[0, 1)` range and after the held root has
been revalidated. The open is one-component and root-relative through
`NtCreateFile(FILE_OPEN)` with `OBJ_DONT_REPARSE`,
`FILE_OPEN_REPARSE_POINT`, directory-only shape, and share-read/share-write but
no delete sharing. Thread impersonation is rejected before and after the native
state open. A pre-open rejection performs no native state open, while a
post-open rejection retains the returned state handle inside `WithLock`; both
retain the already-acquired range until checked retirement. The exact service
grant is the unchanged Phase 2E
`ROOT_ACCESS` plus only `FILE_ADD_FILE`; it adds neither
`FILE_ADD_SUBDIRECTORY` nor `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC`, or
`WRITE_OWNER`. The Phase 2E root and `run.lock` requested and mapped masks remain
unchanged.

The independently supplied expected-object authority now also includes the
complete non-sentinel `FILE_ID_INFO` for `state`. The opened directory must have
exact-zero handle flags, be a non-reparse directory on the same local fixed NTFS
volume as the root, match that exact identity, and carry the same service owner
and protected exact three-ACE DACL shape as the other installed objects. Its
service allow ACE is exactly the state-directory grant above; `OWNER RIGHTS`
still denies `WRITE_DAC | WRITE_OWNER | DELETE | FILE_DELETE_CHILD`, and
`SYSTEM` retains `FILE_ALL_ACCESS`. Each writer revalidation checks the held
state handle and independently reopens the fixed leaf from the held root with
the same no-delete-share contract. That candidate must be identity/security
verified and checked-closed. An ambiguous candidate close poisons later
revalidation and prevents every normal or retired receipt.

`HeldServiceRunStateWriter` retains the state-directory handle as the only
future state-mutation authority introduced by this slice; Phase 2F-a itself
exposes neither a raw handle nor marker/checkpoint operations. The separately
gated Phase 2F-b adapter below consumes that opaque writer without changing the
Phase 2F-a open, revalidation, release, or retirement contracts. A
post-`run.lock` failure remains
`WithLock`; its byte range may or may not be held and its state handle may or may
not have been obtained. Normal verified release first revalidates all three
objects, checked-closes state mutation authority, explicitly unlocks the exact
byte range, checked-closes `run.lock`, revalidates the still-held root, and then
checked-closes the root before issuing `ServiceRunLockReleased`. State-close
failure or ambiguity therefore occurs while the range is still held and cannot
mint a normal receipt. Both a successful writer and a `WithLock` failure have an
explicit terminal-retirement path. Retirement attempts the optional state close
first, conditionally unlocks any acquired range, and then attempts checked close
of both lock and root even after an earlier failure; `FailedRunLockRetired` is
issued only when every required step succeeds. No ambiguous close, unlock, or
revalidation result issues either receipt.

The current-user kernel fixture installs and records an exact surrogate state
directory and exercises its missing, wrong-identity, wrong-shape, reparse,
security, no-delete-share, revalidation, release-order, and terminal-retirement
boundaries. Its no-delete-share proof is non-vacuous: a custom from-birth test
DACL grants the service `STATE_ACCESS | DELETE`, the production-held state
handle makes a fresh `DELETE` open fail with exact `ERROR_SHARING_VIOLATION`,
and the same `DELETE` open succeeds after checked retirement. The focused
inventory is exactly 36 tests: 34 passed and two ignored. The seven tests
attributed specifically to Phase 2F-a are
`missing_state_failure_holds_lock_until_checked_retire`,
`stale_and_cross_root_state_identities_are_never_adopted`,
`wrong_state_type_reparse_and_security_are_rejected_with_lock`,
`exact_state_authority_allows_file_create_but_denies_directory_mutation`,
`state_no_delete_share_is_nonvacuous_when_delete_acl_allows_access`,
`successful_writer_terminal_retire_has_exact_order_and_close_fault_no_receipt`,
and `state_open_impersonation_bookends_preserve_exact_failure_authority`. The
two ignored cases remain the existing Phase 2E
`cross_process_child_fixture` helper and the qualified-host
`symlink_reparse_at_run_lock_is_rejected_when_capability_is_available` test.
That fixture is not installer provenance. The Phase 2F-a evidence boundary has
no production expected-authority mint or caller and does not itself implement
marker/checkpoint I/O; Phase 2F-b now supplies a separate bounded fixed-pair I/O
adapter, not a retroactive widening of the Phase 2F-a state-directory gate.
Neither slice converts authority to the Phase 2D runtime writer, Boot, Clean,
stopped, provisioning, secret, signing, or release authority. Actual ProgramData
and virtual service-SID positive-path
evidence; installer creation and from-birth descriptor/identity provenance for
`state`; closure of every setup or cleanup-capable handle; sealed ancestor ACLs
and at-rest rename/delete integrity; SCM and restricted-token composition;
group and every SACL policy; mapped-I/O and trusted service/`SYSTEM` peer
assumptions; marker/checkpoint persistence and recovery; TPM authentication-key
and rollback-anchor custody; and supported-kernel crash, power-loss, and reboot
evidence remain external **STOP-SHIP** obligations. Both compiled policies stay
`None`, and ordinary/release execution remains silent exit 78.

**Current Phase 2F-b status: started, not passed.** A production-compiled,
Windows-only, module-private adapter consumes the exact held Phase 2F-a writer
and exposes no native handle. It is limited to four fixed one-component leaves
under that writer's held `state` directory: `marker.v1`, `marker.tmp`,
`checkpt.v1`, and `checkpt.tmp`. Final leaves use exact existing-file opens;
temporary leaves use exact from-birth `FILE_CREATE`. Every native open is
root-relative, case-insensitive, `OBJ_DONT_REPARSE`, non-directory,
`FILE_OPEN_REPARSE_POINT`, synchronous, write-through, and share-zero. Thread
impersonation is rejected before and after each native open, inspection,
identity/length query, read, write, flush, cleanup disposition, and rename.

Purpose-specific access is exact and includes `SYNCHRONIZE` where required:
create requests `GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE`; ordinary
final inspection requests `GENERIC_READ | SYNCHRONIZE` and must map to
`FILE_GENERIC_READ`; cleanup requests `GENERIC_READ | DELETE | SYNCHRONIZE` and
must map to `FILE_GENERIC_READ | DELETE`; the held newly created temporary file
must grant exactly `FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE`. The pair
files are service-owned and created with an exact protected three-ACE DACL:
`OWNER RIGHTS` denies only `WRITE_DAC | WRITE_OWNER`, the service SID receives
exactly the pair-file grant, and `SYSTEM` receives `FILE_ALL_ACCESS`. The
Phase 2E root/lock masks and Phase 2F-a state-directory mask remain unchanged.

Every opened pair file must have zero handle flags, exact granted access, exact
owner/DACL, one link, no delete-pending state, and the same local fixed NTFS
volume as the held root. It must be a non-directory, non-reparse default stream
with no ADS and no read-only, sparse, compressed, or encrypted attribute. The
held `state` directory is also required to report zero case-sensitive-directory
flags before it can supply leaf authority. A final file is `Missing`,
`Malformed`, or exactly one 148-byte record; exact reads require all 148 bytes
and a separate zero-byte EOF probe. A staged record is written in one exact
148-byte request, flushed with `FlushFileBuffers`, reread byte-for-byte, checked
for the same full `FILE_ID_INFO`, and independently reinspected before rename.
The production shape predicate is also exercised directly with the compressed
and encrypted attribute bits, rather than relying only on the read-only and
sparse kernel fixtures.

Four deterministic, one-shot `cfg(test)` staging faults cover marker short
write, marker flush failure, checkpoint short write, and checkpoint flush
failure. Every case is consumed at its exact record/operation boundary, returns
`RecordIo` as known-not-committed before any native rename attempt, leaves the
rename count at zero, removes every temporary/final pair leaf through checked
retirement, and leaves no armed fault. These synthetic branches prove the
state-machine response to the reported short-write/flush outcomes; they are not
evidence that NTFS naturally produced a short write, nor power-loss evidence.

An observation clears only safe stale temps and then captures the two final
leaves twice; a mismatch is terminal known-not-committed. Missing/missing and
exact/exact are the only committable pair shapes. Commit revalidates the writer,
compares the complete observed bytes, lengths, and full identities, stages both
new records, rejects all old/new and marker/checkpoint identity aliasing, then
performs a second writer revalidation and full-identity CAS immediately before
replacement. Replacement is handle-relative and ordered marker first,
checkpoint second. The marker replacement is confirmed by full identity and
bytes before the checkpoint CAS and replacement; both temps must then be absent
and both final identities and bytes must be the exact candidate. This is an
ordered two-file protocol, not an atomic pair transaction.

A test-only snapshot of the production variable-length rename packet fixes the
current Windows x64 `FILE_RENAME_INFORMATION` ABI fields, alignment, offsets,
packet/backing lengths, replace-if-exists bit, exact parent binding, and exact
non-NUL-terminated UTF-16 payloads for both `marker.v1` and `checkpt.v1`. The
snapshot does not widen the production API or expose a native handle.

Every failure before the first native rename attempt is known-not-committed and
retains only terminal retirement authority. From the first rename attempt
onward, success or failure is ambiguity-bearing: the only nonterminal action is
one independent reload, and a failed reload remains ambiguity-bearing and can
only retire. Cleanup is bound to the exact staged full identities. Startup may
delete only descriptor-valid stale temps whose length is in `0..=148`; an
oversized temp, wrong identity, wrong descriptor, ADS, forbidden attribute, or
other hostile shape is preserved and poisons every later normal or retired
receipt. Any inspected-candidate checked-close ambiguity likewise poisons the
writer. Post-commit reread and ambiguity reload first revalidate the complete
writer and independently reopen the pair; a mismatch never becomes committed
evidence.

The pre-Phase 2F-c focused root inventory is exactly 49 tests: 47 passed and the
two existing Phase 2E cases remain ignored after the seven separately gated
Phase 2F-c release tests are excluded. The thirteen tests attributed specifically
to Phase 2F-b are
`fixed_pair_absent_commit_flushes_renames_and_independently_rereads`,
`fixed_pair_existing_commit_replaces_both_full_identities`,
`fixed_pair_leaf_set_and_from_birth_file_security_are_exact`,
`fixed_pair_one_sided_malformed_and_hostile_temp_are_terminal_known_failures`,
`fixed_pair_rejects_ads_and_forbidden_file_attributes`,
`fixed_pair_staging_short_write_and_flush_failures_are_known_not_committed`,
`fixed_pair_rename_packet_abi_and_leaf_payload_are_exact`,
`fixed_pair_startup_cleans_safe_partial_temps_but_preserves_oversized`,
`fixed_pair_full_id_second_cas_rejects_same_bytes_replacement_without_mutation`,
`fixed_pair_first_rename_boundary_reload_and_close_poison_are_exact`,
`fixed_pair_inspection_has_individual_impersonation_bookends_and_close_poison`,
`fixed_pair_ambiguous_cleanup_is_bound_to_staged_full_ids`, and
`fixed_pair_reread_revalidates_writer_and_probe_close_poison_blocks_receipts`.
The private `windows_pair` codec bridge has six further passing tests:
`record_shapes_map_without_widening_the_codec`,
`exact_pair_round_trips_the_two_canonical_envelopes`,
`missing_expectation_accepts_only_missing_missing`,
`exact_expectation_requires_both_complete_canonical_records`,
`expectation_debug_redacts_exact_envelopes`, and
`authority_states_and_receipts_are_move_only`. The combined relevant inventory
is therefore exactly 55 tests: 53 passed and two ignored.

At the pre-Phase 2F-c boundary, the `windows_pair` child mapped the private
148-byte durable codec envelopes into move-only fixed-pair expectations and
outcomes without a production caller, expected-authority mint,
authentication-key provider, TPM/non-rollbackable anchor integration, or
conversion into Phase 2D Boot, Active, Clean, stopped, provisioning, signing,
or normal-release authority. The separately gated Phase 2F-c runtime and Phase
2C Windows provisioning composites are now its exact two production consumers
and remain dormant. The runtime composite's sole production-compiled caller is
the private Phase 2G compositor, while Windows provisioning has no production
fresh-authority constructor or caller.
Neither slice establishes pair atomicity or power-loss durability. Direct
compressed and encrypted attribute-policy branches, four deterministic
synthetic short-write/flush-failure staging branches, and variable-length rename
packet ABI/payload assertions are now covered. One direct evidence gap remains
explicit: a kernel negative test with a nonzero case-sensitive-directory flag.
That gap,
actual elevated ProgramData/service-SID and installer from-birth evidence, SCM
and restricted-token composition, trusted service/`SYSTEM` peer race analysis,
supported-kernel crash/power-loss/reboot recovery, and TPM/authentication-key
integration remain external **STOP-SHIP** obligations. Both compiled policies
stay `None`, and ordinary/release execution remains silent exit 78.

**Current Phase 2F-c status: started, not passed.** A production-compiled,
Windows-only, module-private dormant composite now binds one Phase 2D logical
runtime writer to one independently verified Phase 2F-b operating-system pair.
Its normal internal convenience entry, `start_windows_runtime`, consumes an
already-held `HeldServiceRunStateWriter` and one move-only
`RuntimeRunStateAuthority`; installation and provider identity come only from
that authority. Its only production-compiled call site is
the private dormant Phase 2G `begin_windows_lifecycle` compositor; neither entry
has an executable, top-level, exported, or aliased caller. The bridge has no
expected-authority source, protected or TPM-backed authentication-key provider,
native-handle return, raw-writer
escape, Phase 2C provisioning conversion, secret, signing, RPC, or release-
activation bridge. The provider backend is uninhabited and has no production
constructor; no test-secret import remains in the production
partition. A private nonzero backend binding is allocated only after the OS
writer already exists. Binding-allocation failure retains both the unbound pair
writer and runtime authority for checked retirement; every pre-retirement
writer-holding failure retains the logical writer-exit obligation, provider-
bound authority, and exact corresponding OS-pair typestate. Checked-retirement
failure is irreversible but still retains the authority in a typed terminal; it
exposes neither a recovery-exit nor a normal receipt.

Startup is writer-first. The bridge seals the held OS writer into the logical
runtime acquisition, freshly observes the four-leaf fixed pair, and only then
authenticates the logical observation with the lease-owned authority. Missing,
malformed, wrong-installation, wrong-provider, Active, RecoveryRequired, one-sided,
or backend-drift state cannot mint Windows Boot evidence. Exact authenticated
Clean Boot prepares a logical Active successor and the identical full-pair OS
expectation before either side may attempt a commit.

Active commit ordering is exact: logical `begin_commit`, OS pair commit, logical
commit-receipt latch, logical `begin_reread`, independent OS reread, then logical
completion. A pre-first-rename OS failure is terminal known-not-committed; an
unconfirmed commit failure or ambiguity from the first rename attempt onward is
`WindowsActiveReloadRequired`. Confirmed success continues only through the
independent reread path described below. Reload first obtains
the independent OS pair, then records the logical reload receipt, and may
classify only the exact prior pair as Boot or the exact candidate as Active;
partial or drifting state is terminal. The confirmed-commit reread defect found
by the Critical/High review is closed: once the OS reports the Active commit as
confirmed, any subsequent OS reread failure is terminal `RereadDrift`. It can
never reload or downgrade to the prior Clean Boot state.

Clean follows the same full-pair expectation and logical-before-OS commit gate.
An ambiguous Clean commit or confirmed-commit reread failure retains a single
`WindowsCleanReloadRequired`; reload can return Clean only for the exact
candidate, while prior, partial, or drifting state is terminal. Every live or
reload-required composite state exposes a consuming reason-neutral
`into_retirement`; the legacy `into_terminal(RecoveryRequired)` wrappers remain
durable-internal compatibility only and are absent from the Phase 2G facade.
No state can drop one authority and continue with the other. Before logical
binding, the binding-failure wrapper preserves the runtime authority directly
beside the still-held OS writer; the unbound-terminal wrapper continues to hold
it directly after writer retirement. After binding, `SingleWriterLease` is the
sole writer-plus-provider carrier through live, reload, checked-retired,
released-no-receipt, post-release, recovery, and stopped wrappers.

Current-host forced-process-death evidence is isolated behind a private
`cfg(test)` facade and exercises exactly three production-order cutpoints:
before marker rename, after marker rename succeeds but before its handle cleanup
and confirmation, and after checkpoint rename succeeds but before its handle
cleanup and confirmation. The child receives each 148-byte candidate record
only through an environment-cleared, private transport that accepts exactly 296
ASCII lowercase-hex characters; wrong length, non-ASCII, uppercase, and every
non-hex character fail closed. The child reconstructs the existing current-user
fixture installation-object identities, acquires `run.lock`, stages the fixed
pair, signals one named event only after consuming the selected hook, and then
parks. Before killing the child, the parent proves that a second writer sees
exact run-lock
contention. It then force-terminates and waits for the child, confirms that the
root/lock/state installation identities did not change, and checks exact bytes,
temporary-leaf presence, and complete file identities:

- before marker rename, both prior finals remain at their prior identities and
  both candidate temps exist, with all four file identities distinct;
- after marker rename, the candidate marker is the new final identity and its
  temp is absent, while the prior checkpoint retains its identity and the
  distinct candidate checkpoint temp remains; and
- after checkpoint rename, both candidate finals have new distinct identities
  and both temps are absent.

Only after those physical checks does the parent perform bounded writer
reacquisition. A fresh composite runtime started from that returned writer
boots the prior authenticated Clean generation 1 only at the pre-marker
cutpoint. The marker-only pair is root-level exact/exact but is rejected by the
authenticated runtime as `HighWaterDrift`; the fully replaced candidate Active
pair is rejected as `PersistedNonCleanState`. Both terminal classifications
carry no platform cause and complete checked retirement, while the prior-Clean
Boot takes the reason-neutral retirement path. The same three cutpoints are
also exercised from authenticated Active generation 2 toward Clean generation
3: the pre-marker prior Active generation 2 is `PersistedNonCleanState`, the
Clean marker with the prior Active checkpoint is `HighWaterDrift`, and the fully
replaced Clean candidate boots generation 3. Both rejection cases again carry
no platform cause and complete checked retirement; full Clean Boot takes the
reason-neutral retirement path. Every case in both transition directions
finishes by proving the exact expected final pair and no temps. This evidence
is deliberately limited to forced child-process termination and reopen on the
current Windows host. It does not prove power-loss or reboot behavior,
torn-sector or storage durability, or atomicity of the two-file pair.

Normal stop first compares the held OS observation with the logical Clean bytes,
then prepares and begins the logical release, and only then attempts the
pair-bound OS release. That low-level release revalidates the writer, reopens and
holds both final leaves share-zero, rechecks their full identities, exact
lengths, and bytes, proves both temps absent, and keeps every opened pair handle
held throughout writer release. A low-level verification failure before native
writer release, or a native writer-release failure, returns `WriterRetained` and
permits only checked terminal retirement; a logical precheck failure instead
enters the ordinary composite terminal path. If the writer was
released but a later pair-handle checked close failed, `WindowsReleasedNoReceipt`
is irreversible and has no retry, retirement, recovery-exit, or stopped API,
but retains the provider-bound authority privately. On
an exact OS receipt the composite compares the receipt pair to logical Clean,
records the logical release receipt, and completes logical stop; only that path
mints `WindowsStoppedRunEvidence`. Any failure after the OS receipt becomes
`WindowsPostReleaseTerminal`, which likewise has no writer, retry, retirement,
recovery-exit, or stopped conversion and still retains that authority.

Checked terminal retirement is ordered logical `begin_release`, OS pair
retirement, logical release-receipt latch, then logical completion. Every error
suppresses both normal and recovery receipts. Composite states and receipts are
move-only and their Debug views redact authority; the production composite has
no `unsafe`, native handle type, ownership cast, or generic type-erasure site.
The exact composite inventory is fourteen passing tests:
`kernel_clean_boot_active_clean_stop_is_exact`,
`kernel_process_death_restart_boots_only_prior_clean_and_rejects_partial_or_active`,
`kernel_process_death_restart_boots_only_full_clean_and_rejects_prior_active_or_partial`,
`kernel_missing_pair_is_terminal_and_checked_retired`,
`kernel_wrong_provider_and_nonclean_pairs_never_boot`,
`kernel_active_ambiguity_reload_classifies_prior_candidate_and_partial`,
`kernel_confirmed_active_reread_failure_never_reloads_as_boot`,
`kernel_clean_ambiguity_reload_accepts_only_exact_candidate`,
`kernel_stop_failures_never_mint_stopped`,
`kernel_post_release_receipt_fault_is_irreversible`,
`kernel_stop_precheck_rejects_crossed_pair_before_release`,
`kernel_live_and_reload_states_have_checked_terminal_retirement`,
`composite_authority_and_receipts_are_move_only`, and
`composite_live_states_expose_consuming_terminal_transitions`. The focused
`durable_run_state` module inventory is 88/88 passing: 34 parent tests, two
private authentication-child tests, 25 logical provisioning, six
`windows_pair`, seven `windows_provisioning`, and fourteen `windows_runtime`
tests. The named child and composite slices are
therefore subsets of that module total, not additional disjoint counts. The
kernel run-state-root suite is 56 total, with
54 passing and the same two
environment-dependent tests ignored.

This is still not a product runtime, pair-atomic transaction, or power-loss
proof. A production protected/TPM provider source and executable/top-level caller,
elevated ProgramData/service-SID installer provenance, SCM/restricted-token
composition, a trusted single service/`SYSTEM` writer and peer-race proof,
mapped-I/O exclusion, rollback-anchor integration, and supported-kernel crash,
power-loss, and reboot reconciliation remain external **STOP-SHIP** obligations.
Both compiled policies stay `None`, and ordinary/release execution remains
silent exit 78.

**Current Phase 2G status: started, not passed.** A separate
production-compiled, Windows-only, module-private dormant compositor binds the
authority-independent Phase 2A policy to the Phase 2F-c durable/OS typestates.
`begin_windows_lifecycle` is the sole direct production consumer of
`start_windows_runtime`; both entries consume exactly one already-held writer
and one move-only `RuntimeRunStateAuthority`, with no parallel installation,
provider, or effect input. `begin_windows_lifecycle` itself has zero production
call sites and is neither exported nor reachable from an executable or top-level
service entry.

The private `windows_lifecycle_effects` child adds an owned, move-only local
effect authority only after an exact Active reread, at
`WindowsListenerPending::prepare_listeners(effects)`. Its production backend is
the uninhabited `Unavailable(Infallible)` variant and has zero production
constructors, sources, or callers. Only cfg(test) fixtures can execute the six
fixed purposes: `PrepareListeners`, `PublishScmRunning`, `OpenAdmission`,
`CloseAdmission`, `DrainListeners`, and `PublishScmStopped`. Every successful
receipt must match the exact opaque lifecycle binding, nonzero attempt, and
purpose before a checked attempt increment. Known-not-applied, ambiguous,
cross-bound, replayed/exhausted-attempt, or wrong-purpose results become typed
effect failures and retain the consumed authority. This is local receipt and
composition evidence only: the production slice still has no listener, SCM,
admission, installer, provider-source, secret, or `process::exit` adapter.

Cause ownership remains explicit. `StartupFailure`, `RuntimePolicyFailure`,
`LifecycleError`, and `FatalReason` remain policy causes and never become a
fabricated `RecoveryRequired`; effect failures retain their exact stage and
disposition; durable/platform failures remain inside `WindowsTerminalCause`.
Every writer-holding failure consumes the exact Windows state through
reason-neutral retirement. A successful check reattaches the original lifecycle
cause and is the fully checked terminal path that can authorize silent code 78.
Retirement ambiguity preserves both the original lifecycle cause and platform
cleanup cause in an irreversible code-78 state. After effect attachment, the
same effect authority remains inside every checked or irreversible terminal as
well as every live, Clean/reload/release, and stopped carrier; pre-Active and
revalidation terminals are explicitly unattached. No irreversible state exposes
retry, second retirement, stopped conversion, or a normal receipt.

Startup and Active ordering are consuming. A fresh Clean boot owns a fresh
nine-observation `StartupChecklist`; only `CompletedStartupChecklist` may
prepare Active. An exact prior-Clean ambiguity discards the completed checklist
and requires all nine observations again, while an exact Active candidate carries
the checklist forward. After exact Active, listener preparation effect success
precedes the policy listener record, SCM-running effect success precedes the
policy SCM record, and admission-open effect success precedes `RuntimePolicy`
admission. Any effect failure retires the same durable authority and retains its
effect binding; no zero-argument record/open bypass remains.

Shutdown is equally fixed: admission-close effect, begin-stop, reject-new-work,
invalidate-non-durable-authority, listener-drain effect, policy listener close/
drain, then exactly six named remaining-cleanup methods for request cancellation,
helper termination, helper reap, user-token discard, defined durable-record
flush, and request hardware/storage-handle release. The Windows facade exposes
no generic `complete_cleanup_step` delegate. Only empty registries and all nine
pre-Clean steps can reach exact Clean commit/reload and writer release. A writer
release first creates `WindowsScmStopPending`; only exact `PublishScmStopped`
effect evidence mints `WindowsLifecycleStopped`. Released-no-receipt and
post-release durable failures remain irreversible with terminal effects. A
post-writer-release SCM publication failure is also irreversible and retains
both `WindowsStoppedRunEvidence` and the exact effect-failure authority, with no
retry, retirement, or stopped conversion.

All Phase 2G evidence is move-only, Debug-redacted, safe-only, and free of raw
handle/path access, `unsafe`, `dyn`/`Any`, downcast, dereference, or ownership
escape. The exact compositor inventory is 22 passing tests:
`clean_startup_active_runtime_clean_release_reaches_normal_stopped`,
`startup_missing_and_mismatch_require_checked_silent_exit78`,
`active_ambiguity_reloads_prior_with_fresh_checks_candidate_with_carried_checks_and_partial_terminal`,
`confirmed_active_reread_failure_never_restores_boot_or_listener_authority`,
`listener_scm_and_admission_typestates_are_ordered_and_move_only`,
`effect_authority_is_sealed_move_only_redacted_and_production_unmintable`,
`effect_backed_startup_is_exactly_ordered_consuming_and_one_shot`,
`cross_binding_duplicate_and_wrong_purpose_receipts_are_rejected_non_vacuously`,
`listener_preparation_failure_and_ambiguity_preserve_effects_through_checked_exit`,
`scm_running_failure_and_ambiguity_preserve_effects_through_checked_exit`,
`admission_open_failure_and_ambiguity_preserve_effects_through_checked_exit`,
`admission_close_precedes_stop_reject_and_failure_never_enters_cleanup`,
`invalidate_then_effect_drain_gates_fixed_remaining_cleanup_without_generic_bypass`,
`effect_carrier_survives_clean_reload_release_and_every_durable_terminal_class`,
`post_writer_release_scm_stop_failure_and_ambiguity_are_irreversible_with_both_evidences`,
`runtime_policy_alone_enforces_work_token_and_quarantine_bounds`,
`cleanup_requires_exact_order_and_empties_all_runtime_registries_before_clean`,
`clean_ambiguity_advances_release_policy_for_candidate_only`,
`release_writer_retained_checks_retirement_and_no_receipt_is_irreversible_exit78`,
`post_release_logical_failure_is_irreversible_exit78_and_never_stopped`,
`retirement_fault_preserves_original_lifecycle_and_platform_cleanup_causes`, and
`debug_and_source_surfaces_are_redacted_silent_and_path_handle_free`. Supporting
evidence remains fourteen passing `windows_runtime` tests, 88/88 focused
`durable_run_state` tests (34 parent, two authentication, 25 logical
provisioning, six pair, seven Windows provisioning, and fourteen runtime), and
the 56-test kernel root suite with 54 passing and the same two environment-
dependent tests ignored. Lifecycle core remains 21/21 and the Windows compositor
is 22/22.

This remains composition evidence, not release activation. Actual listener and
admission implementations, a production lifecycle-effect backend/source/caller,
SCM `SetServiceStatus`/restricted-token/service-SID composition, elevated
ProgramData installer provenance, an independently protected or TPM-backed key
and rollback anchor, trusted service/`SYSTEM` single-writer and peer-race proof,
mapped-I/O exclusion, signed immutable artifact binding, and supported-kernel
crash/power-loss/reboot reconciliation remain external **STOP-SHIP** obligations.
Both compiled policies stay `None`; ordinary/release execution still uses the
existing silent exit-78 path, and no Phase 2G typestate calls `process::exit`.

**Current Phase 2H status: started, not passed.** Phase 2H adds a dormant,
production-compiled Windows adapter for the six Phase 2G leaf effects without
making the compositor executable-reachable. The Windows RPC module now compiles
in ordinary Windows library builds, and `key-agent-service-rpc-sys` plus
`key-agent-service-wire` are nonoptional `platform-windows` dependencies. This
is compile-time availability of RPC and SCM mechanics, not activation: the
debug feasibility features remain the only executable probes.

`WindowsServiceEffectSource` is move-only, single-use, and Debug-redacted. Its
only production constructor consumes one sealed `WindowsScmStatusAuthority`,
whose registered `SERVICE_STATUS_HANDLE` has no raw accessor and whose sole mint
is private to the SCM registration boundary. Consuming the source allocates one
opaque lifecycle binding and installs `WindowsServiceEffectBackend` as the
sealed backend. That backend is an exact 8-stage automaton: six ordered live
stages for listener preparation, `SCM_RUNNING`, admission open, admission close,
listener drain, and `SCM_STOPPED`, followed by `Stopped` or fail-closed
`Terminal`. Each successful leaf still returns the Phase 2G receipt bound to the
exact lifecycle, nonzero attempt, and purpose; the adapter does not add a second
effect authority or a bypass around the existing compositor.

The production listener is the already implemented status RPC worker. Listener
startup reports `KnownNotApplied` only when startup proves that resources were
released; a retained runtime maps to `Ambiguous`. `SCM_RUNNING` and
`SCM_STOPPED` publication failures are ambiguous. Admission may open only while
the exact registered invocation is `SERVICE_RUNNING` and no stop, control
failure, or finalization is latched; that predicate and `begin_accepting` run
while the same `CONTROL_CONTEXT` lock is held. A failed admission-open attempt
retains an admission-closed worker and is ambiguous. The consuming
`close_admission` transition only closes admission. It must produce the
admission-closed typestate before `AdmissionClosedStatusRpcWorker::drain` may
invalidate epochs, stop listening, unregister with waiting enabled, wait for
rundown, and release resources. Any unproved rundown retains the RPC resources
and maps to `Ambiguous`. The final `SCM_STOPPED` transition terminalizes the
shared control context under that same lock before calling `SetServiceStatus`,
so a concurrent control callback cannot publish a later `STOP_PENDING`; a send
failure therefore remains terminal and ambiguous rather than restoring status
authority.

The existing Phase 2G compositor inventory remains exactly 22/22. Phase 2H adds
a separate 9/9 `windows_service_effects` inventory:
`production_effect_source_is_single_use_redacted_and_resource_opaque`,
`production_effect_backend_success_has_exact_six_stage_order`,
`listener_prepare_failure_distinguishes_unapplied_from_ambiguous`,
`scm_running_failure_never_opens_admission`,
`admission_open_failure_retains_closed_listener_and_effect_authority`,
`admission_close_precedes_epoch_invalidation_and_listener_drain`,
`listener_drain_failure_never_claims_clean_or_writer_release`,
`scm_stopped_failure_after_writer_release_retains_both_terminal_evidences`, and
`default_and_release_service_remain_silent_exit78_without_durable_provider`.
These fixtures replace only the leaf driver and exercise the same consuming
service-effect state machine; they do not call process-global RPC or SCM.

`WindowsServiceEffectSource::new`, the registered SCM authority mint, a real
durable run-state provider source, `begin_windows_lifecycle`, and every
executable or top-level production composition each still have zero production
call sites. Default and release service execution therefore remains silent exit
78, and both `COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` remain
`None`. External SCM registration/source mint composition, elevated installer
and service-SID provisioning, a real protected durable provider and rollback
anchor, trusted production Broker/service-peer authentication and mapped-I/O/
peer-race proof, crash/power-loss/reboot reconciliation, TPM/authentication-key
custody, supported-kernel matrices, signed immutable artifacts, and release
evidence all remain **STOP-SHIP**. Phase 2H does not pass Phase 1, Phase 2, or
the product release gate.

**Current Phase 2I status: started, not passed.** Phase 2I adds a private,
production-compiled `windows_session_events` bridge that translates an already
copied Windows session-change notification into the existing no-secret session
lifecycle vocabulary. `ValidatedWindowsSessionEvent::decode` accepts only
the native event type plus an owned `WTSSESSION_NOTIFICATION`, requires
`cbSize == size_of::<WTSSESSION_NOTIFICATION>()`, and requires `dwSessionId`
to form a nonzero `SessionId`. The validated value may then be consumed once by
`dispatch`; `handle_windows_session_change` is the single safe decode-and-
dispatch composition.

The mapping is deliberately closed. `WTS_SESSION_LOCK`,
`WTS_SESSION_UNLOCK`, and `WTS_SESSION_LOGOFF` become `Lock`, `Unlock`, and
`Logoff`. `WTS_CONSOLE_CONNECT`, `WTS_CONSOLE_DISCONNECT`,
`WTS_REMOTE_CONNECT`, `WTS_REMOTE_DISCONNECT`, `WTS_SESSION_LOGON`, and
`WTS_SESSION_REMOTE_CONTROL` become `UserSwitch`. `WTS_SESSION_CREATE`,
`WTS_SESSION_TERMINATE`, every unknown event type, a wrong structure size, and
session zero are rejected without dispatch.

The separate Phase 2I inventory is 8/8. It covers the three direct mappings,
all six topology-to-`UserSwitch` mappings, create/terminate/unknown rejection,
exact native layout and size validation, nonzero-session validation, and the
move-only redacted single-dispatch route. Rejection variants are unit-only and
the runtime variant retains only its policy cause; failures retain no raw
notification, event code, or session identifier, and Debug is fixed/redacted.
This is a safe semantic bridge only. No service status advertises
`SERVICE_ACCEPT_SESSIONCHANGE`; the
SCM control handler has no session-change branch and does not read `event_data`;
`handle_windows_session_change` and the bridge have zero production callers.
Actual SCM callback-pointer validation and copying, bounded mailbox delivery,
ownership across concurrency, cancellation, and rundown ordering remain
**STOP-SHIP**. Default and release service execution remains silent exit 78,
both compiled policies remain `None`, and Phase 2I does not pass Phase 1,
Phase 2, or the product release gate.

### Phase 3 — Authenticated Broker and helper runtime

Add the bounded Broker control protocol, exact request admission, service-owned
Approval/Secret Input creation, selected non-inherited bootstrap, full helper
transcripts, deadlines, cancellation, session invalidation, and cleanup. UI
decisions terminate in opaque service evidence with no private-key operation.

**Current Phase 3A status: started, not passed.** The production-compiled
expected-helper registry now binds every suspended registration to one nonzero
Windows session derived only from the service-created target proof. The getter
chain is exact: `ExpectedHelperPeer::session_id` delegates through
`DetachedSuspendedServiceProbe::session_id` to the session retained by
`ExpectedServiceCreatedLpac`. `ExpectedPeerKey` remains only the epoch nonce and
request ID; no wire frame, candidate, caller-supplied request, or environment
value becomes session authority.

`ExpectedHelperAdmission::invalidate_session` first commits one session to a
fixed 64-entry quarantine while holding the registry mutex, then extracts only
matching live owners and marks only matching in-flight owners for cancellation.
`invalidate_active_sessions` atomically quarantines the departing session plus
every session represented by the current live/in-flight topology before
retiring that whole topology. Both paths release the mutex before process
cancel/reap or condition-variable waiting, preserve the existing five-second
quiescence bound and cleanup-error precedence, and leave unrelated owners
untouched on targeted invalidation. Registration that loses either side of the
race observes the quarantine and is terminally cancelled outside the mutex.
If targeted invalidation overlaps an otherwise-successful consume, the public
result is `Denied` and each unaffected owner is restored to its original phase;
an otherwise-successful terminal malformed-candidate rejection instead keeps
its planned retirement so the rejected peer cannot become retryable. Selective
and global cancellation provenance remain distinct.
The quarantine bound is fixed at 64 to match the lifecycle policy; exhaustion
sets the registry to stopping, requests cancellation of every in-flight owner,
extracts every live owner, and returns `Stopping` only after bounded settlement,
unless cleanup first returns `Internal`.

The focused expected-peer inventory is 37/37, including eight new session
authority, targeted/live/in-flight race, unrelated-owner preservation, active-
topology, exhaustion, and data-free failure/Debug tests. The two invalidation
entries intentionally have zero production callers and do not activate
`SERVICE_ACCEPT_SESSIONCHANGE`, an SCM callback branch, a mailbox, a Broker
protocol, helper UI transcripts, signing, or release policy. Default/release
execution remains silent exit 78 and both compiled policies remain `None`.
Actual native callback copying and delivery, bounded mailbox concurrency and
rundown, lifecycle-to-registry composition, signed helper E2E, and installed
restricted-service evidence remain **STOP-SHIP**. Phase 3A does not pass Phase
1, Phase 2, Phase 3, or the product release gate.

**Current Phase 3B status: started, not passed.** A private, production-compiled
pure ordering policy models only the Approval decision prefix as
`Admitted -> UIStarting -> UIAuthenticated -> Approved/Rejected`. Its
`Admitted` is a policy-local request state and is deliberately separate from
the expected-peer registry's `Admitted`, which records `HelperReady` manager
admission. Secret Input `Accepted/Cancelled` remains a separate future path and
is not representable as an Approval result.

The concrete consuming typestate is
`AdmittedRequestPolicy -> UiStartingRequestPolicy ->
UiAuthenticatedRequestPolicy -> ApprovedRequestPolicy | RejectedRequestPolicy`,
using `begin_ui`, `authenticate_ui`, and `decide`. Every non-rejected state also
has consuming `recheck_liveness`, `cancel`, `invalidate_session`, and
`invalidate_active_sessions` transitions.

One move-only policy instance binds the server-derived expected-peer key,
nonzero Windows session, Approval role, and the request's original inclusive
monotonic deadline, and owns the monotonic clock used to enforce it. Every
positive edge requires exact correlation, the Approval role, a fresh move-only
one-shot observation, and a fresh check of that policy-owned clock against the
unchanged deadline. In this slice, liveness means only that
one-shot observation shape plus policy-local deadline revalidation: the policy
does not inspect an OS process or authenticate a helper. Clock failure, reaching
or passing the deadline, role/key/session mismatch, or a failed observation is
a terminal rejection rather than a retryable state.

Targeted session invalidation rejects only a matching policy instance and
preserves unrelated state. Active-topology invalidation and cancellation reject
`Admitted`, `UIStarting`, `UIAuthenticated`, and even `Approved`. Approval is
therefore non-durable and cancellable: it is neither signing authority nor
intent, candidate, cryptographic-key, or private-key-operation authority. Seed, observation,
and policy-state types remain private and move-only; `Rejected` is terminal,
and rejection plus `Debug` surfaces are data-free.

The focused policy inventory is exactly 10/10. Architecture mutations pin the
closed state order, server-only binding, inclusive deadline and terminal-failure
rules, selective versus topology-wide invalidation, cancellable Approval,
privacy/move-only constraints, and exact absence of a production mint or
caller. This is local policy evidence only. Actual Broker-to-policy admission,
helper-owner transfer, Approval transcript, concurrent composition,
cleanup/reap, and SCM callback delivery are not implemented. No production
observation constructor exists; a future compositor must mint each observation
only after fresh authenticated Approval UI and expected-peer liveness proof.
Default and release execution stays at silent exit 78, both compiled policies
remain `None`, and the whole runtime, signed-helper, installed-service, kernel,
and release boundary remains **STOP-SHIP**. Phase 3B does not pass Phase 1,
Phase 2, Phase 3, or the product release gate.

**Current Phase 3C status: started, not passed.** The separate private,
production-compiled `secret_input_lifecycle` module models only the pure Secret
Input ordering path. Its closed consuming graph is
`AdmittedSecretInputPolicy -> SecretInputUiStartingPolicy ->
SecretInputUiAuthenticatedPolicy ->
SecretInputCompletion::{Accepted(AcceptedSecretInputPolicy),
Cancelled(CancelledSecretInputPolicy)}`. The three positive methods are
`begin_ui`, `authenticate_ui`, and `complete`. Any validation failure instead
terminates as `RejectedSecretInputPolicy`. Policy-local admission is distinct
from expected-peer `Admitted` and from the Phase 3B Approval policy; Approval
and Secret Input outcomes are not interchangeable.

A test-only `SecretInputPolicySeed` supplies one move-only instance;
`SecretInputPolicyObservation` and `SecretInputCompletionObservation` are its
one-shot inputs. The instance owns the monotonic clock used to enforce its
original inclusive monotonic deadline and binds only the server-derived
expected-peer key, one nonzero Windows session, the Secret Input role, and
that unchanged deadline. Admission, every positive edge, and each live
liveness recheck
consume a fresh move-only one-shot observation. Each observation must correlate
the exact key, session, and Secret Input role before the policy-owned clock
reports the deadline; clock failure, an observation at or after the deadline,
or any mismatch terminally produces `RejectedSecretInputPolicy`.

The four live stages are `AdmittedSecretInputPolicy`,
`SecretInputUiStartingPolicy`, `SecretInputUiAuthenticatedPolicy`, and
`AcceptedSecretInputPolicy`. Every live stage has consuming
`recheck_liveness`, `cancel`, `invalidate_session`, and
`invalidate_active_sessions` methods.
Targeted invalidation rejects only a matching-session instance and preserves
unrelated state, while active-topology invalidation rejects all four live stages.
Lifecycle cancellation terminates in data-free `RejectedSecretInputPolicy` with
`SecretInputPolicyRejectionCause::Cancelled`; only authenticated `complete`
cancellation yields data-free `CancelledSecretInputPolicy`.

Accepted is deliberately non-durable and cancellable. It carries no secret
bytes or vault handle and grants no signing, cryptographic-key, private-key, or
private-key-operation authority. It exposes no secret, vault,
cryptographic-key, or private-key accessor or conversion to any such authority.
Seeds, observations, completion values, and policy states remain private and
move-only; terminal states retain no request or secret data, and
`SecretInputPolicyRejectionCause` plus `Debug` surfaces are data-free and
redacted.

The focused policy inventory is exactly 10/10; production has zero seed,
observation, or completion mints and zero callers. Architecture mutations pin the
closed graph, same-clock and unchanged-deadline binding, exact Secret Input
correlation, fresh one-shot observations, all live rechecks and terminal
branches, targeted preservation versus topology-wide invalidation, cancellable
non-authoritative Accepted state, terminal privacy, and exact zero production
mint or caller. No production seed or observation constructor exists. A future
compositor must mint each observation only from fresh
authenticated Secret Input UI and actual expected-helper liveness and
authentication evidence.

This remains local policy evidence. The production Approval path, Broker-to-
policy compositor, actual helper authentication, Approval or Secret Input
transcript, secret transport and vault handoff, concurrent composition,
cleanup/reap, SCM callback delivery, and release composition are not
implemented and remain **STOP-SHIP**. Default and release execution stays at
silent exit 78, both compiled policies remain `None`, and Phase 3C does not pass
Phase 1, Phase 2, Phase 3, or the product release gate.

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

- 2026-09-05 - Added the started-but-not-passed Phase 3C dormant Secret Input
  ordering boundary: exact admitted, UI-starting, UI-authenticated, and
  Accepted/Cancelled completion types; same-clock key/session/Secret Input role
  and inclusive-deadline binding; fresh one-shot correlation at admission,
  positive edges, and live rechecks; cancellable and invalidatable
  non-authoritative Accepted state; lifecycle cancellation as Rejected with a
  `Cancelled` cause, distinct from authenticated UI-completion Cancelled;
  data-free terminal states; exactly 10/10 focused tests; and zero production
  mint or caller.
  Production Approval/compositor, actual helper authentication, transcripts,
  secret transport/vault handoff, cleanup, SCM delivery, and release remain
  **STOP-SHIP** with both compiled policies `None`.
- 2026-09-05 - Added the started-but-not-passed Phase 3B dormant Approval
  ordering policy boundary: exact
  `Admitted -> UIStarting -> UIAuthenticated -> Approved/Rejected` states,
  service-derived request/session/deadline binding, exact positive-edge
  correlation and one-shot/deadline liveness checks, terminal
  failure/invalidation, cancellable
  non-authoritative Approval, 10/10 focused policy tests, architecture mutation
  coverage, and zero production seed, observation mint, or callers. Fresh
  authenticated OS/UI liveness composition, Broker/helper/transcript,
  concurrency, cleanup/reap, SCM delivery, and release composition remain
  **STOP-SHIP** with both compiled policies `None`.
- 2026-09-05 - Added the dormant Phase 3A session-bound expected-helper
  invalidation slice: service-proof-only nonzero session ownership, fixed
  64-entry quarantine-before-cleanup ordering, targeted and active-topology
  cancellation with mutex-free reap/wait, fail-closed exhaustion, 37/37 focused
  tests, zero production invalidation callers, and unchanged release-disable
  boundaries.
- 2026-09-05 - Added the dormant Phase 2I safe Windows session-change bridge.
  It production-compiles a private closed decoder over an already copied exact-
  size, nonzero-session `WTSSESSION_NOTIFICATION`; maps lock, unlock, and logoff
  directly; maps six console/remote/logon topology events to `UserSwitch`; and
  rejects create, terminate, unknown, wrong-size, and zero-session inputs. A
  separate Phase 2I inventory is 8/8; failures retain no event code or session
  identifier and have fixed redacted Debug output. No service status advertises
  `SERVICE_ACCEPT_SESSIONCHANGE`, the SCM handler has no branch or `event_data`
  read for it, and the bridge has zero production callers. Actual callback-
  pointer copying, mailbox ownership/delivery, cancellation, and rundown remain
  **STOP-SHIP**; default/release stays silent exit 78 and both policies stay
  `None`.
- 2026-09-01 - Added the dormant Phase 2H production lifecycle-effects adapter.
  Windows ordinary builds now compile the SCM/status-RPC mechanics with
  nonoptional RPC dependencies. A move-only, single-use, redacted
  `WindowsServiceEffectSource` seals registered SCM authority into the exact
  8-stage `WindowsServiceEffectBackend`; its six leaf effects enforce
  `SCM_RUNNING` before admission, consuming `close_admission` before
  `AdmissionClosedStatusRpcWorker::drain`, and terminalize `SCM_STOPPED` under
  `CONTROL_CONTEXT` before the native send. The Phase 2G inventory remains
  22/22 and a separate Phase 2H service-effect inventory is 9/9. Production
  source mint, durable provider, lifecycle/executable callers, installer and
  service-SID composition, TPM/authentication, crash/power/reboot,
  supported-kernel, signed-artifact, and release evidence remain absent;
  policies stay `None`, default/release stays silent exit 78, and Phase 2H is
  started but not passed.
- 2026-09-01 - Replaced the legacy direct-key and parallel installation/key
  surfaces with the H1/H2 sealed run-state authentication model. The exact
  installation-bound provider has an uninhabited production backend and zero
  production constructors; its private codec exposes only fixed marker and
  checkpoint purposes, including a same-body cross-purpose rejection test. Each
  provider has a unique opaque identity. `runtime_authority(&mut self)` returns
  a move-only authority and prevents a second mint while the first authority's
  mutable borrow remains live. After writer acquisition, `SingleWriterLease`
  preserves it through every later live, reload, release, terminal, recovery,
  and stopped state; pre-writer terminal evidence retains it directly.
  Windows runtime/lifecycle entries now consume only writer plus authority.
  Provisioning requires an exact-identity installer grant/binder and keeps the
  fresh authority hidden in both successful and checked-retired evidence. The
  durable inventory is exactly 88/88: 34 parent, two authentication, 25 logical
  provisioning, six pair, seven Windows provisioning, and fourteen runtime;
  lifecycle core remains 21/21, Windows lifecycle 22/22, and kernel root 56
  total with 54 passing and two ignored. A production protected/TPM backend and
  source, elevated installer provenance, OS provenance tying writer/provider,
  service ACL/SCM/listener/admission composition, and supported-kernel crash,
  power-loss, and reboot evidence remain external **STOP-SHIP** obligations.
- 2026-09-01 - Added the dormant Phase 2C Windows initial-provisioning
  composition. It transfers the held pair writer before allocating distinct
  backend-binding and writer-epoch values, admits only a fresh exact
  Missing/Missing pair, commits canonical Clean generation one in logical/OS/
  receipt/reread order, classifies ambiguity through independent reload, and
  releases or retires authority with exact pair-bound receipts. Seven focused
  Windows tests contribute to the current durable inventory of 88/88. This is current-user
  fixture/local evidence only; production fresh-install authority, elevated
  installer provenance, protected storage/key/rollback custody, SCM wiring, and
  supported-kernel durability evidence remain external **STOP-SHIP**.
- 2026-09-01 - Added current-host forced child-process termination evidence at
  the three exact fixed-pair rename cutpoints. A private strict lowercase-hex
  child transport, pre-kill run-lock contention, exact byte/temp/full-identity
  matrices, bounded reacquisition, fresh Clean-to-Active and Active-to-Clean
  runtime classification, and checked retirement now cover process death and
  reopen. This does not claim power-loss,
  reboot, torn-sector/storage durability, or pair atomicity.
- 2026-09-01 - Added the dormant Phase 2G Windows no-secret lifecycle
  compositor. It is the sole private production consumer of the Phase 2F-c
  entry while remaining unreachable from executables, keeps policy causes
  separate from durable recovery causes, and attaches a move-only local effect
  authority only after exact Active. The sealed child validates binding/attempt/
  purpose receipts for six exact listener/SCM/admission effects, enforces the
  fixed shutdown sequence without a generic cleanup bypass, and carries effect
  authority through checked and irreversible terminals. Only writer release
  followed by an exact SCM-stopped receipt mints stopped evidence; publication
  failure retains both durable stopped and effect-failure evidence. The
  production effect backend is uninhabited with zero source/caller, so actual
  listeners, SCM/admission calls, installer, restricted token, protected key/
  TPM, crash/power/reboot, and release activation remain **STOP-SHIP**. Phase 2G
  is started but not passed, with 22/22 focused compositor tests.
- 2026-09-01 - Added the dormant Phase 2F-c logical/OS composite. It binds the
  writer-first Phase 2D lifecycle to the exact Phase 2F-b pair, preserves
  logical receipt ordering and OS commit/reload ambiguity, makes confirmed
  Active commit reread failure terminal, verifies and holds the exact pair
  through final writer release, and separates writer-retained, released-without-
  receipt, and post-release terminal states. Its sole production caller is the
  private dormant Phase 2G compositor, which itself has no executable caller or
  production provider source; installer/SCM, trusted-peer and mapped-I/O proof,
  crash/power/reboot recovery, rollback anchor, TPM, and product integration
  remain **STOP-SHIP**, so Phase 2F-c is started but not passed.
- 2026-08-31 - Added the dormant Phase 2F-b fixed marker/checkpoint-pair
  adapter. It consumes the held Phase 2F-a writer, limits I/O to four fixed
  leaves, stages and verifies exact 148-byte records, performs a full-identity
  second CAS and ordered marker-then-checkpoint handle-relative replacement,
  and preserves first-rename-onward ambiguity and ID-bound cleanup authority.
  The private `windows_pair` child maps the durable codec without a production
  caller, authentication-key/TPM bridge, or Phase 2D authority mint. Pair
  atomicity, power-loss durability, the four named direct evidence gaps, actual
  ProgramData/service-SID and installer/SCM evidence, trusted-peer race analysis,
  crash/reboot recovery, and TPM/auth integration remain **STOP-SHIP**, so
  Phase 2F-b is started but not passed.
- 2026-08-31 - Added the dormant Phase 2F-a held mutable run-state-directory
  extension. Only after the existing `run.lock` range is exclusively held, it
  opens the installer-created `state` leaf relative to the held root with exact
  `ROOT_ACCESS | FILE_ADD_FILE`, no delete sharing, exact identity/security, and
  checked path-binding revalidation. State mutation authority is checked-closed
  before range unlock on normal release; both successful and failed writers can
  terminally retire all optional authority, but any close, unlock, or
  revalidation ambiguity suppresses receipts. This adds no marker/checkpoint
  I/O, production caller, expected-authority mint, Phase 2D bridge, or release
  activation. Installer state-directory provenance and actual ProgramData,
  service-SID, SCM, TPM/anchor, crash, power-loss, and reboot evidence remain
  **STOP-SHIP**, so Phase 2F-a is started but not passed.
- 2026-08-31 - Added the dormant Phase 2E held service run-state-root adapter.
  The Windows-only production path resolves fixed ProgramData, walks every
  component with held-parent existing-only opens, verifies local NTFS,
  non-reparse shape, exact-zero handle flags, complete installer-recorded
  identities, and the exact owner/protected-DACL policy, then holds the final
  root without delete sharing and installer-created `run.lock` with zero sharing
  plus an exclusive nonblocking byte lock. Startup distinguishes `BeforeLock`
  from lock-retaining `WithLock`; normal release explicitly unlocks the exact
  range before checked close, while retirement retries unlock and issues no
  receipt after any unlock/close failure. There is no
  production expected-authority mint or caller and no Phase 2D conversion.
  Tests use a current-user surrogate; actual ProgramData, service-SID,
  installer, and SCM evidence, group/SACL policy, marker I/O/CAS, and crash and
  reboot behavior remain **STOP-SHIP**, so Phase 2E is started but not passed.
- 2026-08-31 - Added the Phase 2D lease-first runtime-boot contract. The Boot-
  producing runtime path now acquires the exact backend/installation writer
  before its fresh durable observation, consumes `RuntimeWriterAcquired` exactly once, and
  distinguishes `BeforeWriter` from writer-retaining `WithWriter` failures.
  Free or stale observations cannot bind later; missing, one-sided, malformed,
  wrong-provider, non-Clean, cross-backend, and cross-epoch state remains terminal
  and cannot auto-initialize or provision. Clarified that nine startup facts are
  external observations while storage binding and single-instance evidence are
  carried structurally by `BootEvidence`. The model retains durable authority
  and its writer through Clean commit/reread and final release; retaining actual
  root, protected-provider provenance, and anchor handles remains a future
  adapter obligation. This remains a `cfg(test)`-provider, zero-runtime-root model; Phase 1 and Phase 2 are
  not passed and both compiled policies remain **STOP-SHIP**/`None`.
- 2026-08-30 - Added the debug-only Phase 1B executable service/helper RPC
  slice. The live role-aware manager now consumes V2 launch actions while
  retaining completion locally; an occupied single worker rejects queueing
  behind active work and derives role/correlation only from the exact request.
  Added the eight-slot lifetime-retired expected-peer registry contract,
  five-second quiescence, role-fixed Approval/Secret Input probe entrypoints,
  exact WINNT packet-private `HelperReady`/ACK/`YWKHRC01` flow, fatal cleanup/
  internal health latching, RPC-rundown -> coordinator-join -> helper-stop
  ordering, the LPAC-only derived 30-second hard fail-fast watchdog, and split
  Low/`NW` endpoint-connect/If3-call ACLs derived from both fixed-profile package
  SIDs. This closes the prior debug transport-reachability defect. It is no-
  secret debug wiring, not signed or production E2E: actual installed
  restricted-SCM, cross-session/elevated, signed immutable-helper, and supported-
  kernel evidence remain absent; Phase 1 is not passed and both policies remain
  **STOP-SHIP**/`None`.
- 2026-08-30 - Added the Phase 1A debug-only protocol foundation without
  changing immutable `YWKASV01` V1: non-default `YWKASV02` V2 now has six exact
  20/52/72/72/68/68-byte open-epoch, desktop-command, and helper-ready frames,
  closed Status/Approval-probe/Secret-Input-probe commands and results, and
  fail-closed `Unavailable`. Bound epochs now permanently record V1 or V2 and
  make wrong-version use terminal. Added the distinct 72-byte `YWKHRC01`
  correlation-only helper confirmation, private zeroizing retention of the
  validated hello key/deadline, and malformed-manager-candidate retirement in
  the expected-peer foundation. Pure V2 desktop dispatch now returns immediate
  results or authenticated launch actions. That Phase 1A checkpoint intentionally
  left RPC-manager reachability and helper RPC send/launch to the later Phase 1B
  slice; signed-helper `ncalrpc`, installed SCM/cross-session/elevated evidence,
  support matrix, and release authority remained absent.
- 2026-08-29 - Extended the Phase 1 debug-only evidence with an actual suspended
  inert target, exact 96-byte `TARGET_FROZEN` plus 56/96-byte parent-death
  command/report frames, an exact two-member kill-on-close Job, third-member
  quota denial, current-host topology `2 -> 1 -> 0`, and forced parent death at
  pre-`READY_FROZEN`, `READY_FROZEN`, and post-handoff stages. Recorded the
  narrow target masks and current-host `THREAD_RESUME` normalization. Tightened
  desktop admission to reject assigned-but-disabled `SeDebugPrivilege` and to
  require authenticated exact `PROCESS_DUP_HANDLE` denial after creation. Added
  the then-dormant role-aware helper-candidate/expected-peer registry foundation
  for suspended registration, resume publication, non-consuming callbacks,
  exact-once manager use, and bounded cancellation reap. The target remains an
  untrusted helper-resolved `current_exe`; parent-pinned image, system-wide sole
  Job-handle proof, supported kernels, production RPC/lifecycle/wire callers,
  signed-helper `ncalrpc`, installed SCM/cross-session/elevated evidence, and
  both compiled policies remain **STOP-SHIP**/`None`. Phase 1 is not passed.
- 2026-08-29 - Corrected the Key Agent `cfg(test)` copied-image fixture to set
  and exactly read back a Medium/`NW` mandatory label on both its private
  directory and executable while preserving the protected owner/profile DACL
  and the full mitigation policy including `NO_LOW_LABEL`. This repairs the
  kernel fixture without advancing the remaining Phase 1 exit gates.
- 2026-08-29 - Added fail-closed accounting for the two borrowed
  `CREATE_PROCESS` event process/thread raw slots. Immediately after each
  successful `DebugActiveProcessStop` and before another Win32 call, the creator
  thread now accepts only two `GetHandleInformation` failures with exact
  `ERROR_INVALID_HANDLE`; a live slot, asymmetric result, or other error
  fail-fasts. Normal detach and attached mapped-image rejection use the same
  rule, never call `CloseHandle` on those system-managed aliases, and retain
  checked ownership/close only for event `hFile`. Both ignored current-host
  kernel tests pass. This proves only invalid numeric slots at the measured
  observation points, not object destruction or a Windows-wide contract;
  supported-kernel alias-retirement remains **STOP-SHIP**.
- 2026-08-28 - Composed the dormant Key Agent debugger admission and transport
  under one private umbrella. The debug-gated transport now consumes
  `PreparedReleaseDebuggerArtifact`, creates the held absolute path with the
  exact suspended/private-debug flags, authenticates the first pre-user-mode
  `CREATE_PROCESS_DEBUG_EVENT` `hFile` by full `FILE_ID_INFO`, checked-closes it,
  installs one explicit suspend count, continues and detaches on the creator
  thread, and proves debugger absence, live process, suspend 1 -> 2 -> 1, and
  one-member Job before installing the unchanged sentinel. A linear, redacted
  `MappedReleaseDebuggerArtifact` remains held through cleanup. Raw numeric
  slots are checked across the held artifact, exact three pipes, creator/Job,
  and event handles before ownership; unexpected initial-resume counts and
  successful wrong post-probe resume counts fail-fast, and rejected cleanup
  drops the creator thread owner before Job-zero polling. Same/distinct-file,
  exact flag/raw-slot/event-classifier, and separate ignored current-host
  positive and mapped-mismatch tests cover this slice. At that checkpoint the
  wire still had only its original three frame kinds; the 2026-08-29 entry above
  records the later target/topology, parent-death, and desktop-denial evidence.
  Production callers, signed E2E, and supported-kernel matrices remain
  **STOP-SHIP**.
- 2026-08-28 - Replaced the unbounded post-`CancelIoEx` pipe wait with a fixed
  five-second, non-alertable `GetOverlappedResultEx` terminal drain. Async
  `ReadFile`/`WriteFile` now receive no byte-count pointer, and the same raw
  `*mut OVERLAPPED` flows from initiation through completion and cancellation
  without a shared Rust reference. The exact buffer, event, and `OVERLAPPED`
  remain live until success, cancellation, or an exact pipe-terminal status;
  timeout, incomplete/alertable completion, and ambiguous errors abort without
  unwind instead of releasing borrowed storage.
  Current-host pending-read tests cover the ordinary cancellation path. This
  does not prove universal kernel liveness, the system-wide last Job handle, or
  helper death after adversarial Job-handle duplication; those remain
  **STOP-SHIP**.
- 2026-08-27 - Added the initial dormant dedicated-debugger transport-mechanics
  slice with its original three big-endian CRC32C-framed values, a secretless
  default/release-disabled silent exit-78 executable, and a private debug-only
  typestate. An ignored current-host kernel test covers exact three-handle
  private inheritance, suspended bootstrap, `SYNCHRONIZE` sentinel install,
  `READY_FROZEN` (a protocol state, not OS suspension),
  `DUPLICATE_SAME_ACCESS` pull-back, the listed terminal/error scenarios, and
  process-exit table cleanup. Its initial one-member Job and no-target scope were
  superseded by the 2026-08-29 two-member target/topology fixture above. Nonce,
  PID, and CRC remain non-authenticating; signed identity, parent-pinned target,
  system-wide Job-handle exclusion, supported kernels, production callers, and
  enabled policies remain **STOP-SHIP**.
- 2026-08-27 - Added ignored host-local kernel evidence for exact Approval and
  Secret Input service-local source authority/direction and the actual
  `channel.rs::WindowsDuplicateHandle` target-table candidates. The latter are
  measured through test-only `DUPLICATE_SAME_ACCESS` pull-back, WDK
  `NtQueryObject`, and positive/rejected reverse I/O. Recorded that this is
  change-prone test evidence, not runtime admission or universal kernel support;
  real child production duplicate/capture/adoption and signed-helper E2E remain
  `UnverifiedSourceAccessAndDirection` **STOP-SHIP** work. Raw `DEBUG_EVENT`
  alias ABA/TOCTOU still requires the atomic dedicated-debugger cutover.
- 2026-08-26 - Added the dormant parent two-gate feasibility flow: bounded
  pinned-PE preflight, exact minimum-right non-inherited channel duplication,
  authenticated capture/context mutation, 100-byte hello/72-byte ACK ordering,
  independent 28-byte adoption-complete gate and suspend, no-kill debugger-
  thread exit, and post-join debugger/alias/Job/suspend verification. Recorded
  process-terminal cleanup for every partial remote duplicate, omission of
  `PeekNamedPipe`/`FlushFileBuffers` to preserve minimum masks, no production
  reachability, and real signed-helper/full-kernel-matrix `STOP-SHIP` status.
- 2026-08-26 - Added the initial child-only
  `key-agent-service-helper-bootstrap` feasibility boundary: a secret-free
  72-byte correlation ACK codec plus a Windows-x86_64/debug-feature-only exact
  34-byte R10/R11
  capture and local-adoption API. Recorded its candidate rejection, explicit-
  rights fresh duplication, continuity and close behavior; its lack of raw
  handles/I/O and runtime reachability; process-terminal failure with no UI
  continuation and parent-owned Job termination/reap; and the unresolved
  source-candidate `GrantedAccess`/direction, parent, UI, transport, detach,
  signed-artifact, and kernel-matrix blockers.
- 2026-08-26 - Added the dormant one-shot service LPAC process-creation seam:
  exact five-flag `CreateProcessAsUserW`, no command line or inheritance,
  paired service-owned creation security, immediate native-result ownership,
  exact child LPAC/desktop identity and Job readback, and fresh debugger-thread
  exit/join-gated bounded failure cleanup. It receives no debug event and has no
  RPC, executable, or release reachability.
- 2026-08-26 - Added compile-only target-user launch inputs: auth-owned
  exact-once desktop impersonation, fixed Approval/Secret Input profile
  observation, exact AppContainer `LOCALAPPDATA`, zero-capability/AAP-opt-out
  storage, and a five-slot no-handle-list startup owner. Those prerequisites
  later feed the dormant one-shot seam above; neither slice enables helper
  execution, RPC reachability, or release authority.
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
