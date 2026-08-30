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
  service SID and the primary group must occur exactly once in `TokenGroups`.
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
session notifications, and deterministic stop/crash cleanup. The cryptographic
models may be loaded with fixture keys only.

**Exit gate:** install/repair/upgrade/uninstall, token/DACL, storage identity,
network denial, session, crash, and reboot suites pass with no signing surface.

**Current Phase 2A status: started, not passed.** A production-compiled,
module-private lifecycle core with zero production callers now models all eleven
mandatory no-secret startup observations; exact Active-marker commit and
readback before listener preparation; `SERVICE_RUNNING` publication before
admission; lock, unlock, logoff, and user-switch invalidation; and the fixed
eleven-step stop sequence ending in single-instance release and exact
Clean-marker commit/readback. Each startup typestate consumes its preceding
authority. The final cleanup precheck consumes the live runtime into a
`CleanCommitPending` authority only after exact cleanup order, empty work and
retained-token registries, and single-instance release are proven. Only that
move-only pending authority may accept distinct committed and reread Clean
receipts and directly mint the sole stopped-report permit; an invalid or
ambiguous receipt requires recovery instead of claiming an Active restart.
This leaves no modeled post-Clean/pre-stopped crash window. Work,
retained-token, and quarantined-session registries are bounded at 256, 64, and
64 entries. Quarantine exhaustion invalidates every live fixture authority,
discards retained tokens, latches the first fatal reason, and preserves the
Active restart observation. Work, session, and generation identifiers are
redacted from debug output, and no session is automatically revalidated.

This is an ordering model and test slice only. It creates no SCM listener,
handle, process, RPC endpoint, storage or rollback-anchor binding, firewall
rule, cryptographic key, secret, approval result, or signing authority. There
is no production caller or OS adapter. Installer/configuration readback,
service-token and DACL enforcement, durable storage/recovery, a live
single-instance lease, outbound-denial proof, session-notification hookup, and
crash/reboot kernel evidence remain absent. Phase 1 and Phase 2 exit gates
remain not passed; `COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` remain
`None`, and the ordinary/release service executable remains silent exit 78.

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
