# Windows boundary crate

This crate contains narrowly isolated Windows 11 process and IPC boundary
primitives. It is fail-closed and is **not** a claim that named-pipe ACLs or PID
checks defend against malware already executing as the same logon user.

Implemented:

- random one-shot named-pipe capabilities, a protected current-logon-SID DACL,
  local-only/first-instance flags, and connected-client PID/session validation;
- a crate-private legacy, role-checked Approval entry point. It rejects a wrong
  helper role and otherwise returns `LogicalParentUnavailable` before nonce
  sampling or pipe, process, and request allocation because it lacks the
  complete logical-parent aggregate. It has zero production callers;
- a non-cloneable parent-side Secret Input launch/channel API that accepts only
  a manifest-derived `secret-input-ui.exe` role and the release-attested
  restricted launcher, creates separate private request/response endpoints,
  places only child stdin and the shared stdout/stderr pipe object in the
  `HANDLE_LIST`, then injects parent-process and image-file proof handles
  directly into the still-suspended child with inheritance disabled before
  resume. It transfers the canonical prompt and request EOF under one monotonic
  deadline, then reads at most
  `MAX_RESPONSE_BYTES + 1` through exact EOF with cancellable/drained overlapped
  I/O. It binds held file/process/LPAC identity, the exact prompt, and a fresh
  OS-CSPRNG challenge; cancellation remains distinct and accepted bytes remain
  zeroizing. The verified result can be consumed only for that same prompt;
- a crate-private, two-process recovery channel built on the same restricted
  Secret Input Frontend boundary. Display and confirmation have distinct launch
  functions, bootstrap domains, typed requests, fresh parent/child nonces, and
  non-cloneable outcomes. Both stages carry the same fresh, nonzero 32-byte
  opaque ceremony ID, so a display receipt cannot be swapped into another
  confirmation. Only an acknowledged display can mint the one-shot receipt
  consumed by confirmation; the exact held display process/job is explicitly
  terminated and awaited before that receipt is constructed. The receipt also
  preserves the display stage's original absolute expiry. Confirmation must
  start before that expiry and uses the earlier of it and its requested
  deadline, so the second stage can never extend the ceremony lifetime.
  Confirmation carries only four positions
  in its request and returns zeroizing answer words plus the independently
  entered address. Exact request hash, held process/image/LPAC identity, prior
  display transcript, response disposition, ceremony ID, and both nonces are
  bound under the original clamped monotonic deadline of at most two minutes.
  The facade is deliberately
  not public until a Key Agent adapter can prove anti-phishing-phrase provenance
  from a live protected-settings lease. Tests exercise only codecs, kernel pipe
  transfer, replay/cross-stage/timeout failures, and the disabled release gate;
  they never launch a visible recovery window;
- separate persistent, deterministic revision-v1 LPAC profiles for the exact
  manifest-derived Approval Frontend and Secret Input Frontend roles. Their
  profile names and derived SIDs differ, so the helpers do not share an
  AppContainer profile directory or per-profile registry state. Callers cannot
  select a role: the crate-private Approval entry point accepts only Approval
  Frontend and the crate-private secret/recovery entry point accepts only Secret Input Frontend,
  with cross-role, Other, and Key Agent artifacts rejected before release-policy
  evaluation or Win32 process/profile calls. Both profiles have zero capability
  SIDs, an explicit `ALL APPLICATION PACKAGES` opt-out, child-process
  prohibition, an exact inherited named-pipe handle list, a fixed two-variable
  Unicode environment (`SystemRoot`/`WINDIR`) derived from the OS-reported
  system-shared Windows root, a verified non-user-writable/reparse-free
  System32 working directory, no parent ambient environment/current-directory
  inheritance,
  suspended token verification, process mitigations, and a single-process
  kill-on-close job;
- helper verification for absolute install-root containment, reparse traversal,
  current-token writable parents, held file identity, SHA-256, file version,
  Authenticode trust, and pinned leaf-certificate SHA-256;
- a dormant crate-private Key Agent activation proof. Role, release evidence,
  manifest allowlist, and absolute path are checked before a fresh dedicated
  debugger OS thread owns `CreateProcessW`, every debug event through the
  authenticated cooperative gate, and no-kill arming. The original
  `CREATE_SUSPENDED` count is consumed to let Windows produce the first event.
  That event's image handle must match the retained verifier handle by volume
  serial plus all 128 `FILE_ID_INFO` bits; zero volume, all-zero and all-`FF`
  non-unique identifiers fail closed. As soon as the CREATE_PROCESS event exposes
  independently safe process/thread aliases, the worker records them in the exact
  run's shared join-cleanup owner before hFile, mapped-image, ID/object, LPAC, or
  later fallible checks; a malformed partial set retains every safe alias. The
  held event authenticates the LPAC and creates only the pending token proof,
  then continues into the test/production-identical strict
  loader/system-breakpoint loop. The green real-GUI-Key-Agent regression uses an
  explicitly built Cargo artifact, rejects non-primary loader activity before
  detach, checked-closes the event thread alias after debugger join, and verifies
  Job cleanup; a separate minimal import-free GUI PE fixture proves the
  exact-primary gate machinery but not product compatibility. The pre-resume
  default-DACL matrix also excludes
  the current same-user LPAC architecture: it cannot deny `WRITE_DAC` from birth
  while remaining loader-compatible. A revised loader policy could exercise the
  conditional exact main-image gate, which would add the one explicit primary
  thread suspend count, finalize/read back the default DACL, and continue while
  retaining that count, but cannot repair the from-birth gap; a distinct OS
  principal/service is the next design option. Only after such a
  complete gate may the no-kill arm require the authenticated registration and
  make `DebugSetProcessKillOnExit(FALSE)` its final fallible operation. The
  resulting opaque final owner crosses the
  boundary, and the dedicated OS thread exits and is joined. Worker error, panic, or abandonment of
  the joined proof invokes post-join checked alias closure; failed adoption and
  partial closure preserve the remaining set for bounded retry, and each pass
  attempts the process and thread aliases independently so one failure cannot
  starve the other close. Finalization
  requires the exact matching per-run join/root-Job witness,
  `CheckRemoteDebuggerPresent == false` on the retained creator process handle,
  authenticated checked closure of the registered aliases, an exact
  `SuspendThread`/`ResumeThread` 1→2→1 probe on the retained creator
  primary-thread handle, and renewed token, Job, provisioning, and lease checks.
  Only that sequence can enter least-authority attenuation; no PID/TID reopen is used.
  The crate-private generic restricted launcher
  rejects the manifest-derived Key Agent role before release evaluation or process
  creation, so the shared artifact allowlist cannot bypass this seam. The
  activation-owned fresh worker now also creates the exact two-process
  kill-on-close root Job and private Key Agent pipes. `CreateNamedPipeW` keeps
  `FILE_FLAG_FIRST_PIPE_INSTANCE` even though its `0x00080000` bit is also
  `WRITE_OWNER` in the returned access mask. Each persistent server source is
  immediately duplicated to exact request read-plus-synchronize `0x00100001` or
  response write-plus-synchronize `0x00100002`, non-inheritable with options
  zero, and the original is checked-closed before client open. Child stdin,
  stdout, and NUL-backed stderr are separate exact-access inheritable duplicates
  without `DUPLICATE_SAME_ACCESS`. An ignored host-local kernel test uses official
  `windows` WDK function/class bindings plus a test-only ABI-checked local
  pipe-information mirror. Exact sources omit `FILE_READ_ATTRIBUTES`, so only the
  sealed parent response client supplies pipe-local information; request direction
  comes from successful forward and rejected reverse I/O. The WDK wrappers link
  native symbols as test-binary load-time imports rather than resolving them
  dynamically, leaving a test-host compatibility limit but no production
  reachability. That probe covers only `PrivateKeyAgentPipes`; separate ignored
  probes now cover the common attenuation path and Phase 1 service-helper
  target candidates. Neither evidence set permits production activation. One
  `STARTUPINFOEXW` call
  uses an exact five-slot list in handle, Job, full mitigation, security-
  capabilities, and ALL APPLICATION PACKAGES opt-out order. The mitigation is
  identical to the restricted-helper and service-startup policy, including the
  non-Microsoft-binary block, and its immutable `Box<u64>` backing outlives
  `CreateProcessW` and list deletion. Exactly three short-lived inherited stdio
  handles, one Job-list handle, and the fixed zero-capability
  `YourWallet.KeyAgent.LPAC.v1` identity cross that boundary; the short-lived
  handles are dropped before the worker returns. The separate fresh-provisioning
  boundary creates
  both the fixed profile and the fixed `YourWallet.KeyAgent.Storage.v1` leaf
  beneath its validated `AC` folder, but yields only a non-launchable pending
  capability, with no direct pending/candidate conversion. The sole
  production-compiled mint of `PreparedKeyAgentProvisioning` is the private
  sealed existing-install adoption transition. It consumes an initial and
  contractually post-observation authenticated snapshot plus a fixed-profile
  binding and retained no-delete-share root, revalidates the binding and held
  root before and after matching, and seals the prepared capability inside
  `VerifiedExistingKeyAgentInstall`. The implemented dormant release-binding
  preflights the held Key Agent and then constant-time compares the journal
  `release_identity` with the whole-release `ReleasePolicy` `ArtifactDigest`
  accepted by `ReleaseAttestation`. That identity is not the helper-manifest
  digest or a Windows file identity: the manifest separately binds role,
  version, executable hash, and signer, while the retained handle and full
  `FILE_ID_INFO` bind the exact child file object. Only the supervisor's sealed
  split can consume `ArtifactBoundExistingKeyAgentInstall`, and install
  continuity remains retained through the dormant and storage-proven states.
  A changed committed whole-release identity is `RecoveryRequired`, not an
  in-place upgrade under this contract. No exclusive installer lease yet
  serializes checkpoint, observation, and post-observation reread, so production
  upgrade orchestration remains closed.
  On the measured Windows host, where third-party injected modules were
  observed in the surrounding process, the full-policy kernel matrix fails
  closed earlier at process creation. This is host-local evidence, not proof of
  injection causation or supported-kernel readiness. Raw `DEBUG_EVENT`
  generation/same-object ABA/atomic compare-close remain unresolved and require
  a dedicated debugger process that contains all borrowed raw aliases until
  process exit. Separate ignored host-local probes now measure exact Approval/
  Secret Input service-local source authority/direction and the actual
  `channel.rs::WindowsDuplicateHandle` target-table candidates through test-only
  `DUPLICATE_SAME_ACCESS` pull-back, WDK `NtQueryObject`, and I/O. This is
  change-prone test evidence, not runtime admission or universal supported-
  kernel proof. The real helper child's production
  `WindowsHandleOperations::duplicate` and capture/adoption path, plus signed-
  helper E2E, remain `UnverifiedSourceAccessAndDirection` **STOP-SHIP** work, so
  production activation stays forbidden and both compiled policies remain
  `None`.
  A separate dormant solution-mechanics probe adds fixed, big-endian
  `key-agent-debugger-wire` bootstrap/`READY_FROZEN`/decision frames of exactly
  80/72/56 bytes with zeroed reserved fields and CRC32C framing. The CRC, run
  nonce, and private-pipe PID topology are not authentication or authority.
  Secretless `key-agent-debugger.exe` is silent and exits 78 in default and
  release builds; only its debug test hook runs the protocol. Private platform
  typestate and an
  ignored current-host kernel test cover a suspended helper with an exact
  three-handle `HANDLE_LIST` and private control/status pipes, parent-to-helper
  installation of a `SYNCHRONIZE`-only sentinel, `READY_FROZEN`, test-only
  helper-to-parent `DUPLICATE_SAME_ACCESS` pull-back, `COMMIT`, `ABORT`, EOF,
  timeout, malformed input, forced termination, natural-exit/Drop cleanup, and
  process-exit handle-table cleanup. The same creation call installs an exact
  one-entry `PROC_THREAD_ATTRIBUTE_JOB_LIST`: an unnamed, non-inheritable Job
  with only `KILL_ON_JOB_CLOSE`, no active-process limit, and no breakaway
  policy. This parent creates and retains one Job handle before resume. Readback
  then proves those exact limits, helper membership, and current active count
  one. A Job-only path terminates and reaches exact-zero accounting without
  consulting the process handle; another current-host path closes the
  parent-retained handle before benign suspended-helper code can run and proves
  the live helper becomes terminal without an explicit termination API.
  `READY_FROZEN` is a fixed-source, decision-only protocol state, not an OS
  suspend claim.
  The dormant artifact-admission seam accepts an already verified and pinned
  helper only in this order: the exact manifest-derived `KeyAgentDebugger` role,
  opaque whole-release attestation, the dedicated debugger-manifest digest kept
  separate from the three generic helpers and the Broker, an absolute verified
  path whose file is held without write/delete sharing, and complete
  `FILE_ID_INFO` queried from that same held file handle without reopen or path
  lookup. `PreflightDebuggerArtifact`, `PreparedReleaseDebuggerArtifact`, and
  the resulting `MappedReleaseDebuggerArtifact` are private,
  move-only/non-cloneable, and redacted. The prepared value exposes its held
  path only to the sibling transport inside the private umbrella; no external
  path, raw-handle, artifact, release-digest, or generic-launch surface exists.
  Admission and preparation still allocate no Job, pipe, channel, thread,
  process, or debug resource.

  The private debug-only transport is now the sole consumer of the prepared
  value. Its non-test path uses only that verified absolute path as the
  application name and creates the helper with exactly `CREATE_SUSPENDED |
  CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT |
  EXTENDED_STARTUPINFO_PRESENT | DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS`; the
  exact three-entry stdio `HANDLE_LIST`, one-entry Job list, private pipes, and
  80/72/56-byte wire remain unchanged. Before the returned process/thread slots
  are adopted, their raw numeric values must be pairwise distinct from the held
  artifact, Job, and all three exact `HANDLE_LIST` pipe slots; ambiguity aborts
  the parent. On the same creator thread it then validates the creator handles
  and Job. The initial `ResumeThread` must report previous count one or fail
  fast; only that exact result establishes count zero and permits the bounded
  first event to be the exact
  `CREATE_PROCESS_DEBUG_EVENT`. Event PID/TID, borrowed process/thread alias
  IDs, owning PID, zero handle flags, and same-object comparisons must all bind
  to the creator-owned objects. Before event-file ownership is adopted, raw
  numeric distinctness is rechecked across the held artifact, all three pipes,
  creator process/thread, Job, and event process/thread/file slots; the event
  `hFile` must also be present, zero-flag, and exact-object-distinct from the
  event process/thread aliases. Each event process/thread alias is exact-object
  compared with its creator counterpart, while `hFile` is exact-object compared
  only against those aliases; artifact binding instead uses complete
  `FILE_ID_INFO` equality. That identity is compared with the identity in
  `PreparedReleaseDebuggerArtifact`, which is consumed only on equality into
  `MappedReleaseDebuggerArtifact`. The event file is then checked-closed before
  any continuation; ambiguous close aborts the parent.

  While the create event still freezes the process, `SuspendThread` must report
  prior count zero, leaving one explicit count. Only then may the same creator
  thread call `ContinueDebugEvent(DBG_CONTINUE)` and
  `DebugActiveProcessStop`. Post-detach proof requires no remote debugger, a
  live exact process, a 1 -> 2 -> 1 suspend-count probe, and the same one-member
  Job. A failed probe resume rejects; a successful resume reporting anything
  other than previous count two fail-fasts because execution may have escaped.
  Rejected attached cleanup drops the creator primary-thread owner before its
  exact-zero Job poll. The mapped release capability remains owned by
  `DebuggerChild` through cleanup. Only after this gate does the parent install
  the existing `SYNCHRONIZE`-only sentinel; it writes the unchanged 80-byte
  bootstrap before the sole resume into helper user mode. Separate ignored
  current-host kernel tests cover this positive path and a `cfg(test)`
  application-override mismatch that must return `MappedImage`; unit tests cover
  equal/distinct file identities, the exact creation flags, raw-slot
  distinctness, and first-event rejection fields.

  The secretless helper still creates or debugs no Key Agent target and receives
  no target `DEBUG_EVENT`; this parent-side first-event image gate does not
  resolve target raw-slot generation, ABA, or atomic compare-close. A future
  atomic cutover must move the complete target debug engine into the dedicated
  process, keep target-event aliases borrowed without individual close, and
  reclaim them only at debugger-process exit. Signed packaged-artifact, exact PE
  version-resource, and Authenticode/signer E2E remain **STOP-SHIP**, as do a
  separate principal plus from-birth process DACL and explicit
  `PROCESS_DUP_HANDLE` denial, actual target transfer and token/image/suspend/Job
  proof, target membership and process-count topology, Job-owner handoff beyond
  helper exit, adversarial parent-death containment, and supported-kernel
  debug-event-alias retirement and cancellation-drain matrices. There is still no
  production caller, and `COMPILED_RELEASE_POLICY` remains `None`.
  A deadline that observes pending overlapped pipe I/O now treats `CancelIoEx`
  only as a cancellation request. Async `ReadFile`/`WriteFile` receive no byte-
  count output pointer; one raw `*mut OVERLAPPED` established before initiation
  is carried unchanged through completion and cancellation, without forming a
  shared Rust reference while the kernel may update it. The exact buffer,
  manual-reset event, and `OVERLAPPED` stay live through a separate fixed five-
  second, non-alertable `GetOverlappedResultEx` drain, which is also the sole
  source of the transferred-byte count, and returns only after success,
  `ERROR_OPERATION_ABORTED`, or an exact pipe-terminal status. A drain timeout,
  incomplete or alertable result, or any ambiguous error calls
  `std::process::abort()` without unwinding, so borrowed storage cannot leave
  scope while kernel I/O may still reference it. Abort does not run `Zeroizing`
  drops; this lifetime fail-safe is not evidence against WER/minidump, paging,
  or hibernation capture, whose host policies remain **STOP-SHIP**. Current-host
  pending-read tests
  exercise the ordinary terminal-cancellation path, but this remains bounded
  fail-closed implementation evidence rather than universal kernel liveness.
  Process-wide abort closes the Job handle retained by the parent and prevents
  unsafe parent continuation, but kill-on-close terminates members only when
  that is the system-wide last Job handle. This slice does not prove that
  condition after helper code runs. Supported-kernel cancellation-drain
  liveness remains explicit **STOP-SHIP** work.
  The adoption transition, release-binding, and dormant supervisor binder all
  have zero production call sites. A separate dormant storage-only
  `open_existing_fixed_key_agent_storage_root` also has zero production callers.
  Given only an observer-validated `AC` folder and a live fixed-profile SID, it
  hard-codes `YourWallet.KeyAgent.Storage.v1` and performs no create, repair,
  delete, adoption, or recovery. It opens with `OPEN_EXISTING`,
  `FILE_FLAG_OPEN_REPARSE_POINT`, and no delete sharing; verifies the initial
  handle's directory/non-reparse state, local NTFS, exact owner/protected DACL/
  inherited Low-`NW` label, and complete `FILE_ID_INFO`; canonicalizes and
  reopens the path under the same policy; and requires identical security and
  full identity. The resulting root-only capability privately retains the
  canonical path and reopened handle, and `revalidate` compares both the held
  handle and a fresh canonical-path reopen. This is neither the fresh
  `CreateDirectoryW` pending path nor the child opener that derives its path and
  principals from `LOCALAPPDATA` and the child token. No authoritative
  profile-registration observer or held-aggregate constructor calls this seam,
  so it cannot mint `Prepared`/`Verified` or journal/checkpoint authority, reach
  adoption/recovery/activation/signing/RPC/GUI, establish supervisor ownership,
  or create a Broker+Key Agent same-release aggregate.

  A private one-shot storage-startup transition now closes the former child-open
  and transcript-binding gap for this narrow object proof. The parent writes the
  fixed request while the exact child is still suspended, consumes and closes
  that writer, and only then releases its sole verified suspend count. The child
  requires the fixed 188-byte request followed by EOF before decoding or opening
  the root. It then detaches both ambient protocol entries, closes raw stdin, and
  retains raw stdout only in a response-capability object. After that preflight
  it opens the compiled production leaf, or the exact `cfg(test)` CSPRNG-leaf
  grammar, through its OS-rerouted `LOCALAPPDATA` locator. It obtains `TokenUser`
  and the AppContainer SID from its own process token, checks the directory object and exact
  owner/protected DACL/inherited Low/`NW` label, obtains the complete
  volume-serial plus 128-bit `FILE_ID_INFO`, and retains that independently opened
  handle. Its one response binds the fresh nonce, PID, process creation time, and
  root identity. The first response-write attempt is a commit point: its result
  and the following `FlushFileBuffers`/`CloseHandle` results are ignored, no error
  returns to `main`, and the child leaves a startup-only lexical scope. The live
  request frame, decoded request, response, and response frame run their
  `Zeroizing` drops there; only the resident stderr boundary and fixed store
  bindings escape into a non-alertable `Sleep(INFINITE)` loop.
  The parent requires the exact 88-byte frame followed by EOF within the original
  startup deadline. That observation is authoritative for complete output and
  response-handle closure. It then independently compares the fields and
  revalidates the held root, exact resident-process liveness, root-Job membership,
  and Job topology before and again after consuming the startup lease, so process
  exit alone cannot satisfy the join. It then commits the
  artifact identity plus exact request and response into a domain-separated
  SHA-256 startup transcript commitment.

  Parent-side Key Agent and frontend profile APIs share one process-wide non-reentrant,
  poison-fail-closed coordinator; the central profile API rejects thread
  impersonation before acquiring it. The separate Secret Input child process
  does not share that parent-side mutex. Its sole deterministic
  `DeriveAppContainerSidFromAppContainerName` call uses child-local pre- and
  post-call thread-impersonation checks and captures any successful raw SID in
  a private RAII owner before the post-call check. Except for the minimal
  success/error split needed for that capture, native-error interpretation,
  SID-validity checking, and `EqualSid` occur only after the post-call check;
  the owner releases the SID on every failure path. These bookends are
  fail-closed observations, not atomic proof that an impersonation token could
  not be installed and removed between them. This child boundary adds no
  `CreateAppContainerProfile`, `GetAppContainerFolderPath`, or
  `DeleteAppContainerProfile` call, profile-registration authority, or new
  production reachability. `COMPILED_PARENT_POLICY` remains `None`. The Key
  Agent's and restricted frontends' supplied three-name Unicode environments
  validate the exact profile `AC` layout returned by
  `GetAppContainerFolderPath`, derive its containing user-local-data base, and
  pass that as `LOCALAPPDATA` for Windows to rebase inside the AppContainer,
  alongside OS-derived `SystemRoot` and `WINDIR`. The Restricted helpers prepare this context before
  parent-proof, persistent profile, or Job work; the Key Agent prepares it
  before acquiring the inheritable-handle flight. Both recheck that the creator
  thread is not impersonating immediately before `CreateProcessW`. This context
  proof is limited to DOS-path shape, Windows-root/System32 layout,
  directory/reparse state, path-replacement rights on every ancestor, and
  content-creation rights on the Windows root and System32 under the current
  primary token. It retains no directory handle and is not an atomic
  object-identity proof; it also makes no claim about error mode, priority,
  every other inherited Win32 process setting, or DLL/dependency identity. The
  initial crate-private aggregate uniquely owns the detached suspended `Held`
  process capability, root Job, two parent endpoints, internally timed one-shot
  startup lease, and independently verified profile/root proof. `Held` retains a
  process handle with exact mask `0x00101001` (`PROCESS_TERMINATE |
  PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`) and one resume-only
  primary-thread handle with exact mask `0x1000` (`THREAD_RESUME`). The ephemeral
  suspend/resume probe is already closed. `Held` is `Send` but `!Sync`, `!Clone`,
  and `!Copy`, exposes no raw handle or generic resume API, and its only
  consuming resume transition is the fixed storage-startup proof above. That
  transition immediately checked-closes the thread handle after its sole
  successful `ResumeThread`. The resulting private post-startup `Running`
  aggregate has the same transfer traits and structurally retains only the
  narrow process capability, Job, transcript commitment, and parent-held root
  proof, but no thread handle or startup endpoint. The running child retains
  sealed stderr and the fixed generation-store bindings derived from its
  independently opened root and remains inert in `Sleep(INFINITE)` until Job
  termination; the aggregate exposes no runtime I/O or signing operation. Drop
  first attempts bounded synchronous cleanup of the exact process tree. Drop
  cannot report cleanup failure, so closing the retained kill-on-close Job
  remains the fail-closed fallback before the held storage root is released. The
  suspended token must
  prove the fixed SID, zero capabilities, and the exact
  `CheckTokenMembershipEx`
  differential: `CTMF_INCLUDE_APPCONTAINER` denies while adding
  `CTMF_INCLUDE_LPAC` allows, before detach. The module cannot arm a release
  while `COMPILED_RELEASE_POLICY` is `None`;

- a private, pure install-provenance state model and canonical prefix-journal
  verifier. Each fixed record is authenticated with an installer-owned
  HMAC-SHA256 key before parsing, uses phase-specific payloads, and must follow
  the exact `Prepared=1`, `ProfileCreated=2`, `RootCreated=3`, `Committed=4`
  sequence with exact predecessor commitments. A separately sealed,
  rollback-resistant checkpoint supplies the independent installation/release
  identities, high-water generation, and current journal commitment; lower,
  higher, same-generation alternate, gapped, reordered, malformed, or
  non-canonical histories fail closed. The initial phases carry no fictitious
  root identity, while `RootCreated` and `Committed` must bind the same full
  `FILE_ID_INFO` and canonical profile/owner SIDs. The resulting authenticated
  journal and expected identities remain distinct sealed classifier inputs.
  Production has no installer-key/checkpoint constructor, journal reader/writer
  backend, or caller for the canonical journal validator. The authenticated
  two-snapshot matcher has exactly one production-code consumer: the private
  dormant adoption transition.
  Authenticated absence plus no objects is only an uninitialized candidate;
  exact committed consistency is only an existing candidate; every partial,
  pending, stale, mismatched, sentinel, or squatted state requires recovery.
  Neither candidate is adoption or launch authority, and the existing candidate
  retains no root handle. Fresh profile/root creation now returns a different
  non-launchable `PendingKeyAgentProvisioning`; the activation boundary still
  accepts only `PreparedKeyAgentProvisioning`, and there is no direct
  pending/candidate conversion. The sole sealed mint described above revalidates
  the fixed-profile binding and same held root around the pure match and retains
  the result inside a private verified aggregate. Its one compiled downstream
  boundary performs the whole-release artifact match described above but has no
  production caller. Production still lacks an authoritative
  profile-registration observer and held-aggregate constructor, a production
  caller for the dormant fixed existing-root opener or adoption/binding path, an
  exclusive installer lease that enforces the post-observation reread, a
  production installer-key/checkpoint and journal reader/writer backend,
  recovery, and release-activation orchestration. Canonical reopen comparison is
  implemented inside the dormant root capability, but does not make ancestor
  validation atomic or exclude another same-user process;
- an earliest Key Agent child bootstrap with no caller-supplied handle input.
  The Key Agent entrypoint makes this its first Windows application operation.
  Before mutation it requires exactly three distinct kernel objects with exact
  `PIPE`/`PIPE`/`CHAR` types and exactly `HANDLE_FLAG_INHERIT`; it then attempts
  to clear the inherit bit on all three, never restores inheritance after a
  partial failure, and requires all three flag words to read back as exactly
  zero. The returned non-clone, `!Send + !Sync` proof exposes no handle. An
  isolated child/grandchild kernel test uses `CompareObjectHandles` to prove
  that none of the three original exact stdio objects reaches the grandchild.
  The entrypoint then requires exactly one fixed startup request followed by EOF
  before decoding or opening the root. It detaches ambient stdin/stdout, closes
  raw stdin, and keeps raw stdout only in a response capability before root work.
  After the process/root checks it attempts one exact response, ignores the
  write/flush/close results, and leaves the lexical scope that owns all four
  zeroizing startup transcript values before entering a non-alertable
  `Sleep(INFINITE)` loop without returning a post-output error to `main`. It retains sealed stderr and
  fixed generation-store bindings derived from the child-opened root. The
  parent's deadline-bound exact response plus EOF is authoritative for successful
  response-handle closure; no startup handle is reused for runtime I/O;

- a dormant, crate-private Approval release-admission seam. It checks the
  manifest-derived Approval Frontend role, complete release attestation, exact
  helper-manifest allowlist membership, and an absolute verified path in that
  order. `PreflightApprovalArtifact` retains the already pinned artifact and
  opaque whole-release `AttestedArtifactDigest`; its sole consuming transition
  derives `FILE_ID_INFO` from that same held file and produces non-cloneable
  `PreparedReleaseApprovalSupervisor`. This preparation allocates no process,
  Job, pipe, channel, thread, launch state, or second file handle and exposes no
  artifact, path, identity, PID, or raw-handle accessor. The legacy
  `launch_approval_frontend`, `PendingApproval`, `LaunchedHelper`, and
  `RestrictedLauncher::spawn` surfaces are no longer externally callable. The
  legacy launcher rejects a wrong role first, then returns
  `LogicalParentUnavailable` before nonce, pipe, process, or request work and no
  longer calls `RestrictedLauncher::spawn`. The generic `spawn` itself rejects
  Approval with `ApprovalRequiresParentBoundActivation` before resource work,
  and the internal legacy launch leaf accepts only Secret Input as a second
  fail-closed check. A
  second private transition consumes this complete Approval proof together with
  the intact `BoundStorageProvenKeyAgent`. From that same running Key Agent
  process object it mints one fresh, non-inheritable duplicate with exactly
  `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`, without reopening by PID,
  and retains both complete aggregates in the opaque, non-cloneable
  `ParentBoundReleaseApprovalSupervisor`. Neither the narrow process capability
  nor the final binding exposes a PID, path, raw handle, constituent, generic
  desired-access input, or launch operation. The final production binder has one
  private consumer. It fixes the revision-v1 Approval profile, creates the exact
  two-object private stdio boundary, and uses the pinned verified Approval
  artifact to create a process in its single-process Job without resuming the
  primary thread; this is not mapped-image provenance. Before this allocation,
  the caller must consume the opaque `BoundApprovalTransport`; an already
  expired original session rejects before pipe or process creation. The ordinary
  channel-supervisor process/image proof remains intact; the narrow Key Agent
  handle is copied separately into the suspended child as a fifth,
  non-inheritable logical-parent capability. The returned
  `BoundDormantApproval` retains the suspended process/thread/Job, unused parent
  endpoints, complete parent-bound aggregate, and bound request/lifetime carrier;
  it exposes no direct resume, request, response, signing, launcher, profile,
  PID, path, or handle operation, and
  attempts bounded Approval termination/reap before releasing pipes and the Key
  Agent tree. This outer transition has zero production callers and both
  compiled policies remain `None`.

  The platform issues one opaque monotonic session window by sampling its clock
  internally, then splits it into non-Clone authorization and transport halves
  that share the exact issuance identity. `wallet-protocol` privately retains
  both; invalidation drops an unused transport half. After the Key Agent builds
  one canonical request from the exact digest, one-shot nonce, display, and
  protected phrase, the matching authorization half consumes the transport half
  once and returns opaque `BoundApprovalTransport`.

  A second sealed consuming transition derives its bootstrap deadline as the
  earlier of the original expiry and a fresh five-second grace. It writes the
  exact version-2 parent hello before releasing exactly one primary-thread
  suspend count, reads and decodes
  the exact child hello, and revalidates the running child/Job plus the intact
  parent-bound aggregate. Its opaque `AuthenticatedApprovalBootstrap` retains
  the running Approval, both endpoints, both hellos, and the full Key Agent
  aggregate and bound carrier but exposes no protocol method. Only a separate
  sealed function can consume it, with no raw request or deadline parameter.
  This transition has zero production callers. Explicit bootstrap failures
  attempt bounded Approval
  termination/reap and give cleanup failure precedence. Drop retains the
  kill-on-close fallback without claiming unconditional reap success.

  The full-exchange function reads the exact canonical request and original
  monotonic deadline only from its carrier. It uses that same deadline for
  response arming, the consuming finish plus canonical request write and request EOF, fixed response plus response
  EOF, and the exact held child's natural-exit wait. It revalidates child/Job
  and Key Agent state before arming and before response read. Response bytes and
  EOF remain exit-pending until the exact process exits naturally with code 0
  before that same deadline. Final Key Agent revalidation occurs only after
  natural exit, followed by a final deadline observation. Only then is opaque
  crate-private `VerifiedParentBoundApprovalExchange` minted. It retains the
  exited child, intact parent-bound aggregate, both hellos, sealed response
  evidence, and the original request/lifetime carrier, but has no response
  accessor or conversion to
  `VerifiedApprovalResponse` or signing. The transition also has zero production
  callers. The post-exit Key Agent check is point-in-time evidence; any future
  evidence-to-authorization transition must revalidate the retained exact Key
  Agent again immediately before use. No such transition exists. It never
  force-terminates a live child to create success. Protocol
  failure, timeout, nonzero exit, or wait failure rejects and uses a separate
  bounded terminate/reap where a child remains owned; cleanup failure takes
  precedence. Bootstrap v2 binds the ordinary
  supervisor and distinct Key Agent authority into one transcript. The ordinary
  supervisor remains the transport and pipe-peer PID/session authority; the Key
  Agent remains only the separately checked logical parent. This remains an
  ownership-bound logical parent proof source, not Windows parent selection or
  an implementation of `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.
  A repo-local `cfg(test)` integration now copies the exact non-inheritable
  handle into an actual zero-capability Approval LPAC. It proves `TOKEN_QUERY`,
  session/image/PID/liveness/zero flags, twelve stronger or standard token-right
  denials, and `SeDebugPrivilege` absence. Its local `DuplicateHandle` denial
  matrix requests `PROCESS_DUP_HANDLE`, `PROCESS_TERMINATE`,
  `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`,
  `PROCESS_VM_WRITE`, `PROCESS_CREATE_PROCESS`, `PROCESS_QUERY_INFORMATION`,
  `PROCESS_SET_QUOTA`,
  `PROCESS_SET_INFORMATION`, `PROCESS_SET_LIMITED_INFORMATION` (`0x2000`),
  `PROCESS_SUSPEND_RESUME`, `WRITE_DAC`,
  `WRITE_OWNER`, `READ_CONTROL`, and `DELETE`. Its PID-reopen denial matrix
  requests `PROCESS_DUP_HANDLE`, `PROCESS_QUERY_INFORMATION`,
  `PROCESS_QUERY_LIMITED_INFORMATION`, `PROCESS_SET_LIMITED_INFORMATION`
  (`0x2000`), `SYNCHRONIZE`, the exact query-limited/synchronize combined mask,
  and `WRITE_DAC`. The production Key Agent activation hardening step opens the
  suspended process's then-current token as `Hwrite` with exactly
  `TOKEN_QUERY | WRITE_DAC | READ_CONTROL`. Before resume it installs the
  protected token DACL, then immediately performs a
  bounded two-pass `GetKernelObjectSecurity(DACL_SECURITY_INFORMATION)` readback
  through that same `Hwrite`. The sizing pass must return
  `ERROR_INSUFFICIENT_BUFFER` with 1..=64 KiB required; the aligned second pass,
  its returned length, and `GetSecurityDescriptorLength` must all equal that
  exact size. The descriptor must be valid and self-relative, with a present,
  protected, non-defaulted, non-auto-inherited DACL. Its self-relative offset,
  bounds, `ACL_REVISION`, zero reserved fields, exact ACL/descriptor end, and
  three zero-flag explicit `ACCESS_ALLOWED_ACE`s must be byte-exact: stable
  `TokenUser` SID with `TOKEN_ALL_ACCESS`, fixed Key Agent SID with
  `TOKEN_QUERY | TOKEN_DUPLICATE`, then fixed Approval SID with exactly
  `TOKEN_QUERY`. Each mask, declared SID length, SID bytes, and ACE size must
  consume its exact region; extra ACEs and ACE/ACL/descriptor slack or trailing
  bytes fail closed. The `cfg(test)` integration executes that
  production-compiled hardening and proves the Approval query-only outcome.
  Its dormant-lifecycle branch uses the pinned libtest response topology, the
  test-only process context, and the fixture mitigation; production exact
  response topology and the unchanged full mitigation are compile/scanner
  evidence rather than this kernel E2E's evidence.
  The token continuity contract now has a gate-pending and a final phase. At
  `CREATE_PROCESS_DEBUG_EVENT`, `Hwrite` has exactly
  `TOKEN_QUERY | WRITE_DAC | READ_CONTROL`, while a separate temporary
  current-token `Hadjust` has exactly `TOKEN_QUERY | TOKEN_ADJUST_DEFAULT`.
  Before mutation, `CompareObjectHandles` must prove that both name the exact
  same token. This phase installs and immediately reads back only the protected
  three-ACE token-object DACL. A fresh `Hfinal` with exactly
  `TOKEN_QUERY | TOKEN_DUPLICATE | READ_CONTROL` must compare as that same
  object and pass LPAC, token-object-DACL, and identity checks. `Hwrite` is
  checked-closed, but `Hadjust` remains hidden only inside the opaque
  `PendingKeyAgentLpac` returned by
  `PreparedKeyAgentLpac::prepare_suspended_process_for_gate(...)`.

  The eight-case pre-resume `TokenDefaultDacl` kernel matrix now fixes the current
  same-user LPAC boundary. In the green
  `pre_resume_token_default_dacl_matrix_proves_loader_and_same_user_boundary`,
  the no-mutation and exact original-DACL deep-copy controls both exit user mode
  with code 0. All six deny-first cases exit exact `0xC0000142`
  (`STATUS_DLL_INIT_FAILED`): an `OWNER RIGHTS` deny mask `0x000e0000` remains
  loader-fatal across the tested `SYSTEM`, exact-package, and child-user
  `GENERIC_ALL` combinations. The green
  `pre_resume_owner_rights_deny_mask_axis_proves_each_standard_right_breaks_loader`
  further grants all three principals `GENERIC_ALL` and shows that a standalone
  `READ_CONTROL`, `WRITE_DAC`, or `WRITE_OWNER` `OWNER RIGHTS` deny is individually
  loader-fatal. The sanitized original default DACL is exactly child-user
  `GENERIC_ALL`, `SYSTEM` `GENERIC_ALL`, logon-session
  `GENERIC_READ | GENERIC_EXECUTE`, and exact-package `GENERIC_ALL` allows. The
  green `lpac_package_sid_is_absent_from_groups_and_not_token_owner_eligible`
  proves that the package SID is absent from `TokenGroups` and that making it
  `TokenOwner` fails with `ERROR_INVALID_OWNER`.

  The precise inference is that the current same-user LPAC principal cannot
  supply a loader-compatible from-birth policy that denies `WRITE_DAC`. This
  excludes the current architecture, not every possible Windows design. The
  post-loader final-DACL and gate machinery cannot retroactively close the
  from-birth gap; the next design option is a distinct OS principal/service
  boundary with new principal, IPC, and service-lifecycle proofs. The compiled
  default-DACL finalization still occurs only at the reviewed semantic gate
  inside `serve`, after loader, DLL, TLS, and CRT initialization. This is not
  the first machine or Rust instruction, and objects created before it remain
  outside the proof.
  Creation security is now production-compiled. The launcher obtains
  `TokenOwner` and `TokenPrimaryGroup` through separate bounded exact token
  queries and owns two distinct `LocalAlloc` self-relative descriptors. Each is
  attached to a non-inheritable `SECURITY_ATTRIBUTES` and has a protected DACL
  containing no allow ACE and exactly one zero-flag `OWNER RIGHTS` (`S-1-3-4`)
  deny ACE with mask `0x000e0000`
  (`READ_CONTROL | WRITE_DAC | WRITE_OWNER`). An inseparable
  pair supplies `CreateProcessW`'s `lpProcessAttributes` and
  `lpThreadAttributes` together.
  Before the first `ResumeThread`, the exact returned creator-owned process and
  thread handles must match the returned PID/TID, return flags exactly zero from
  `GetHandleInformation`, and read back through bounded exact
  `GetKernelObjectSecurity` the captured owner/group, exact expected self-relative
  and DACL-present/protected control state, a zero SACL offset in the requested
  owner/group/DACL projection, the one-ACE ACL, and no slack or trailing
  descriptor bytes. The readback does not request the SACL and therefore does not
  prove its actual absence. Any mismatch fails closed through child cleanup; the
  descriptor owners are dropped before resume. The creator handles are not
  replaced with a PID/TID reopen, but they do not enter `Held`.

  Child-side gate eligibility is fixed before the marker.
  `serve_inherited_key_agent_storage_startup()` first calls
  `verify_current_key_agent_lpac_before_gate()`, before stdio or INT3. That
  read-only check opens the current process token through a fresh exact
  `TOKEN_QUERY | TOKEN_DUPLICATE` handle, verifies the fixed Key Agent SID and
  complete zero-capability LPAC policy, and checked-closes the handle. Only
  successful verification may enter the debugger gate. The green
  `default_disabled` proves that
  ordinary non-LPAC `key-agent.exe` execution remains a silent exit 78 without
  executing INT3; an LPAC-policy mismatch likewise fails before stdio and INT3.
  This proves eligibility ordering, not actual production-gate success.

  Gate preflight parses the already-held authenticated Key Agent file as
  bounded AMD64 PE32+ and requires exactly one whole-file
  `49 BA <marker-le> CC` sequence. All 11 bytes must lie in initialized raw
  non-padding bytes of one executable section. The `CREATE_PROCESS_DEBUG_EVENT`
  image handle must authenticate that same held file and be checked-closed before
  its event is continued; the expected gate INT3 is derived only
  as authenticated `lpBaseOfImage + sequence_rva + 10`, never from preferred
  `ImageBase` or `lpStartAddress`.

  The original `CREATE_SUSPENDED` count was consumed 1→0 to produce the first
  debug event; that authenticated CREATE_PROCESS event itself is the process-wide
  stop. Only after the pending token proof and checked create-event hFile close
  may it be continued into the loader. The currently compiled candidate loop is
  monotonic-deadline bounded to 160 post-create events and 128
  `LOAD_DLL_DEBUG_EVENT`s, requires every event to carry the expected
  PID/primary TID, and rejects `CREATE_THREAD`/`EXIT_THREAD`, `UNLOAD_DLL`, and non-landmark
  exceptions. It fails closed, but it is not a production-compatible contract.
  Test and production now use this same strict policy; no diagnostic worker
  allowance remains. The green
  `real_key_agent_loader_activity_fails_closed_before_detach` copies the exact
  GUI-subsystem `key-agent.exe` reported by a fresh Cargo build into the
  profile-private fixture and launches that copy rather than guessing a profile
  sibling. It records the non-primary loader `CREATE_THREAD` as the
  pending event, registers its exact thread/process identity and non-inheritable
  `hThread` alias in the shared cleanup owner, rejects before detach, and proves
  that raw alias returns `ERROR_INVALID_HANDLE` after debugger join. It also
  verifies joined Job cleanup. GUI subsystem selection structurally removes
  `conhost.exe`, and the root Job active-process count stays one. This proves
  rejection and cleanup, not a product-compatible gate. An
  earlier CUI diagnostic fixture had an exact System32 `conhost.exe` and root
  count two and observed multiple loader workers, worker-TID DLL loads,
  first-chance C++ `0xe06d7363`, and DLL unload; those observations are historical
  threat-model input, not the current accepted event contract or gate evidence.

  A replacement bounded allowlist must authenticate each loader worker's creation
  provenance, exact thread object/ID, admitted events and lifetime, every exit
  before the semantic gate, and fresh post-exit reopen denial, while
  checked-closing every non-null hFile before
  continue. Its policy and bounds remain **STOP-SHIP**. Any eventual automatic
  system-breakpoint admission must still pin an exact System32 `ntdll.dll`
  `FILE_ID_INFO` allocation base and require first chance, remote `0xCC`,
  `RIP == ExceptionAddress + 1`, and a `MEM_COMMIT | MEM_IMAGE`, executable,
  non-guard page with that `AllocationBase`. Neither a `DbgBreakPoint` export RVA
  nor a fixed exception `NumberParameters` shape is assumed.
  Even a successful replacement loader policy would not close the measured
  from-birth `WRITE_DAC` gap, so it is not sufficient to admit the current
  same-user architecture into production.

  If the revised loader policy reaches and authenticates it, the cooperative gate
  itself must be an exact-PID/primary-TID first-chance
  `EXCEPTION_BREAKPOINT` at the authenticated INT3. It requires
  `RIP == address + 1`, `R10 == marker`, the exact remote 11 bytes, and a
  `MEM_COMMIT | MEM_IMAGE`, executable, non-guard region allocated from the
  authenticated main-image base. Before continue, the debugger zeros `R10` and
  verifies the context readback through an explicitly 16-byte-aligned AMD64
  `CONTEXT` wrapper. Only the reserved always-one EFLAGS bit 1 representation may
  canonicalize; every mutable flag bit and every other reviewed context field
  remains exact. While the debug event holds every thread, one
  `SuspendThread` on the primary thread must observe prior count zero and leave
  explicit count one.

  The separately green
  `minimal_primary_gate_proof_detaches_with_one_verified_suspend_count` uses a
  deterministic import-free relocatable GUI PE fixture to prove the exact
  PID/primary-TID gate, `PendingKeyAgentLpac`→`VerifiedKeyAgentLpac`, one verified
  suspend count, detach, and root Job count one. It proves the gate machinery,
  not actual Key Agent loader compatibility, a signed artifact, or product E2E.

  Supervisor tests keep the same layering. The green minimal-PE
  `integrated_kernel_binding_owns_one_member_and_no_inheritable_parent_handles`
  and `dormant_aggregate_unwind_synchronously_aborts_the_exact_process` cover
  dormant ownership, non-inheritance, and drop/unwind cleanup only. All seven
  supervisor integration tests that drive the Rust-startup fixture through
  storage or Approval are explicitly ignored **STOP-SHIP** because loader
  workers precede the exact-primary gate. The green
  `rust_startup_fixture_loader_activity_fails_closed_before_supervisor_binding`
  instead proves that activity maps to `KeyAgentSupervisorError::Activation`
  and removes the prepared storage root. No actual production gate or
  storage-startup success is claimed.

  Only that gate may call `PendingKeyAgentLpac::finalize_after_gate(...)` and
  consume the pending proof into `VerifiedKeyAgentLpac`. It revalidates current-token
  association, `Hfinal`/`Hadjust` object and identity continuity, LPAC, and the
  token-object DACL. `Hadjust` then installs the exact 28-byte deny-only
  `TokenDefaultDacl`: `ACL_REVISION`, zero reserved fields, no allow ACE, and one
  zero-flag `ACCESS_DENIED_ACE` for binary `OWNER RIGHTS` (`S-1-3-4`) with mask
  `0x000e0000` (`READ_CONTROL | WRITE_DAC | WRITE_OWNER`), with no slack or
  trailing bytes. Its immediate bounded readback validates the complete fixed
  prefix/returned range and, with checked arithmetic before slicing, the
  non-null aligned `PACL` header and entire 28-byte ACL. Initialized API-wrapper
  padding/trailing bytes may surround the pointed ACL, but the 28-byte ACL itself
  permits no internal slack. A post-mutation exact
  statistics read establishes the final baseline and preserves provisional
  `TokenId` continuity; `Hadjust` is then checked-closed. With adjustment
  authority gone, `Hfinal` bookends full policy, both DACLs, identity, and
  baseline-equal statistics and must match a fresh current-token object. Only
  then is the final Hfinal-only proof minted. When the later sole post-gate
  `ResumeThread` releases the explicit count, the child's first semantic step
  calls `verify_current_key_agent_default_dacl_after_gate()`, opens its current
  token with a fresh `TOKEN_QUERY` handle, and reads back the same exact default
  DACL before any later `serve` step.

  Final revalidation runs after the post-detach suspend probe, through the
  narrow process after the ephemeral `0x1002` probe, immediately before the sole
  `ResumeThread` that releases post-gate application execution, and at resident
  authority checks. Each pass bookends the retained `Hfinal`'s LPAC policy,
  token-object DACL, and `TokenDefaultDacl` with baseline-equal statistics, then
  requires a fresh current token to be the same object and identity. These are
  point-in-time checks, not an atomic freeze; the last-check/resume and
  swap-away/back races remain **STOP-SHIP**, and no DACL mutation is assumed to
  update `ModifiedId`.

  The first `CREATE_PROCESS_DEBUG_EVENT` process and thread aliases must be valid,
  distinct from each other and the creator handles, report the expected PID/TID,
  and compare as the same kernel objects. They remain system-managed observations
  while attached. Their independently safe raw slots and identities move into the
  witness-branded shared cleanup registry immediately after event extraction and
  before hFile or any other fallible authentication; no-kill later requires the
  complete authenticated set. After the matching debugger
  OS thread exits and joins and `CheckRemoteDebuggerPresent` returns false, normal
  finalization requires both aliases still to be present and distinct,
  reauthenticates their object/ID and exact-zero flags, then checked-closes the
  thread and process aliases exactly once. Worker `Err`, panic, abandoned join
  proof, failed adoption, and partial closure retain a post-join owner and
  checked-close/retry path. Every cleanup pass attempts both independent aliases
  even if one fails validation or close. This thread-exit detach path supplies no later exit
  event, and the tested host kernel leaves both aliases live. Supported-Windows variant
  evidence remains **STOP-SHIP**.

  After the creator handle's post-detach 1→2→1 probe and token/root-Job checks,
  `DuplicateHandle` creates three non-inheritable, options-zero capabilities. The
  process handle has exact `0x00101001` (`PROCESS_TERMINATE |
  PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`). An ephemeral thread probe
  requests exact `THREAD_SUSPEND_RESUME` (`0x2`); modern Windows automatically
  adds `THREAD_RESUME`, so the host observes effective
  `GrantedAccess == 0x1002` with zero attributes. A distinct retained startup
  handle requests only `THREAD_RESUME` (`0x1000`). Every duplicate must compare as
  the source object and have exact-zero flags.

  The narrow process itself repeats PID/liveness/token and root-Job checks. The
  ephemeral `0x1002` handle itself repeats 1→2→1 and is checked-closed before
  `Held`. Kernel tests require the retained handle to have exact `0x1000` granted
  access and zero attributes, and require `SuspendThread` through it to fail with
  `ERROR_ACCESS_DENIED`. Only then are the creator thread and process handles
  checked-closed in order and `Held` minted. Explicit failure performs bounded
  synchronous reject cleanup with cleanup-error precedence; `Drop` retries but
  cannot report failure.

  Microsoft Learn's current [`ResumeThread` documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
  still requires `THREAD_SUSPEND_RESUME`, while the current SDK exposes
  `THREAD_RESUME` and host/integration kernel tests prove resume-only behavior.
  That mismatch, automatic right addition, and supported-Windows version variance
  remain **STOP-SHIP** kernel-proof obligations.

  `Held` is `Send` but `!Sync`, `!Clone`, and `!Copy`. Its only startup transition
  revalidates the narrow process, performs one post-gate application-releasing `ResumeThread`
  through exact `THREAD_RESUME` (`0x1000`) with prior count one, and immediately
  checked-closes the thread handle. `Running` has the same transfer traits and
  structurally retains only the narrow process, whose rights support resident
  checks and bounded termination, wait, and exit-code cleanup. Kernel tests prove
  initial process/primary-thread pseudo-handle behavior. The green
  `post_loader_worker_feasibility_default_dacl_hardens_later_null_security_thread`
  and its ignored child `post_loader_worker_feasibility_default_dacl_child` prove
  a separate cooperative post-loader parent install/readback/adjust-close,
  child independent current-token/default-DACL readback, real
  `CreateThread(NULL, ...)`, pseudo `GetThreadTimes`,
  `OpenThreadToken(ERROR_NO_TOKEN)`, exact owner/group and one-ACE DACL,
  parent/child one-bit `OpenThread` denial matrices, privilege bookends, checked
  cleanup, and natural exit 0. Because a default-created descriptor is
  kernel-generated, its parser requires only
  `SE_SELF_RELATIVE | SE_DACL_PRESENT` and does not pin
  `SE_DACL_PROTECTED` or `SE_DACL_DEFAULTED` to the explicit protected creation
  descriptor. The ignored libtest probe runs on a non-primary TID, so this is
  kernel feasibility rather than a substitute for the real Key Agent's
  loader-compatible authenticated exact-primary production gate.

  In post-loader feasibility on the tested host, a default-security Win32 later
  thread created after the final lock inherits this policy. Because the actual
  Key Agent gate has not succeeded and a loader-compatible from-birth
  `WRITE_DAC` denial is unavailable, this is not production coverage for the
  current architecture. Caller-supplied descriptors, raw native or
  remote thread creation, and returned, preexisting, or duplicated high-right
  handles remain outside it. `TokenDefaultDacl` is a token-global default-object
  policy, not a thread-only switch. Objects created by loader/DLL/TLS/CRT code before
  the gate retain their old copied descriptors. The observed loader-worker thread
  history is neither authenticated yet nor a non-thread-object inventory.
  Enabled-privilege behavior and a distinct OS principal/service boundary remain
  **STOP-SHIP** inputs to the next design. The fixture
  does not directly read back the copied image's mandatory-label state either.
  Its test-only mitigation removes only `NO_LOW_LABEL` to permit the profile-scoped
  copy; production mitigation is unchanged. This is not
  a runtime-ready security boundary or release proof. Signed DLL/TLS provenance,
  pre-gate non-thread-object inventory, loader-worker
  provenance/lifetime/exit/reopen-denial policy, a distinct OS principal/service
  design with IPC/lifecycle proof, a real GUI Key Agent
  loader-compatible exact-primary gate E2E, supported architecture/Windows matrices for the AMD64
  marker/context and ntdll breakpoint, same-user owner separation,
  caller-supplied/raw-native/remote-thread and
  preexisting/duplicated-handle policy, enabled privileges, bootstrap/provenance,
  endpoint topology, signed-artifact cleanup evidence, production orchestration,
  signing, and release activation remain blockers;

- an earliest runtime-enabled Approval child bootstrap. Its first Windows/CRT
  application operation, before binary-mode conversion, retrieves all three
  numeric stdio values and requires exactly two distinct `PIPE` objects: stdin
  differs from stdout, while stdout and stderr are the same numeric handle-table
  value. Before mutation it requires both unique objects to have flags exactly
  `HANDLE_FLAG_INHERIT`; it attempts both inherit-bit clears without rollback
  and accepts only exact-zero readback for both. The launcher `HANDLE_LIST`
  remains exactly those two synchronous server pipe objects inherited by the
  child; the parent retains the corresponding overlapped client ends. While the
  Approval child is suspended, the launcher remotely injects supervisor-process,
  supervisor-image, and Key Agent logical-parent process proof handles with
  inheritance disabled. After sealing stdio, the child verifies the Approval
  LPAC and Job and requires the sealed stdin, shared output pipe, both supervisor
  proofs, and Key Agent process proof to be five pairwise-distinct exact objects
  with zero flags. Only fresh child-local duplicates of all three injected proofs
  become authoritative and remain retained through response write; the
  launcher-known original injected slots are never adopted and are left only
  for bounded process-exit cleanup. It derives the supervisor PID and
  process-token `TokenSessionId` from the retained live exact supervisor process
  handle and requires the parent-hello supervisor PID, both child-held server ends' client
  PID/session observations, and the child token session to match. It owns and
  revalidates that binding across UI presentation and response write. The
  distinct Key Agent process must match the logical-parent PID, stay live and
  image-queryable in the same session, and expose the fixed Key Agent LPAC SID,
  AppContainer/LPAC state, zero capabilities, and least-authority denials through
  `TOKEN_QUERY`. While both process handles remain live, this prevents PID-reuse
  substitution and corroborates the pipe observations against the exact live supervisor process
  object. Transferable and duplicable pipe handles still prevent proof of
  exclusive endpoint ownership, endpoint topology/exclusivity, or per-write
  attribution. The image check applies
  case-preserving exact normalized path-string equality: it normalizes only an
  optional `\\?\` prefix and separators and compares the live process image path with a separate
  held file's final path; a casing mismatch fails closed. It then checks the held
  path's `\\key-agent.exe` suffix and version metadata, supplies the held handle
  plus path to Authenticode signer validation, and computes SHA-256 through a
  cloned held handle against the compiled parent policy. It does not prove that the live process was mapped
  from that exact file object. A separate repo-local `cfg(test)` probe proves
  that a real zero-capability Approval LPAC can complete
  `OpenProcessToken(..., TOKEN_QUERY)` for its exact injected Key Agent
  logical-parent process proof
  and denies the exact local `DuplicateHandle` and PID-reopen requests
  enumerated above. The copied image's mandatory-label state is not directly
  read back, and the test-only `NO_LOW_LABEL` removal only permits that
  profile-scoped copy; production mitigation remains unchanged. This is not
  mapped release evidence; compiled policies
  remain `None`. The wire and child runtime define this complete Parent-auth order: a fixed 74-byte version-2
  parent hello, fixed 106-byte child hello, a 110-byte parent-finish header plus
  exact request and request EOF, then a fixed 75-byte response and response EOF.
  After response-plus-EOF the parent locally hashes held child PID/file
  identity, manifest digest, profile revision, request digest, one-shot Approval
  nonce and canonical request hash, exact response bytes, a fresh parent-local
  transcript salt, and both bootstrap nonces. The salt is never sent to the
  child and is not challenge-response evidence. Job policy/membership is a live gate,
  not hashed identity. The fixed 75-byte response is ordered as magic, version,
  decision, request digest, and the one-shot Approval request nonce. Only the
  digest and nonce echo request fields; neither bootstrap nonce is echoed.
  Replay resistance also depends on the private one-shot endpoint and a
  fresh one-shot Approval request nonce. Direct executable launch exits without
  diagnostics, while the legacy Rust API returns `LogicalParentUnavailable`
  before resource allocation. The sealed parent implements hello bootstrap and
  full exchange as separate consuming typestates. The bootstrap uses the earlier
  of the carrier's original expiry and a fresh five-second grace. The full
  transition accepts no raw request/deadline, writes finish plus the carrier's
  exact request and EOF, verifies fixed response plus EOF, requires
  natural exit code 0 from the exact held child under the same deadline, and
  performs final Key Agent revalidation after exit. It returns only
  `VerifiedParentBoundApprovalExchange`, which retains the original carrier and
  has no public response/signing conversion. Both transitions have zero
  production callers; the legacy
  `launch_approval_frontend` still fails before allocation with
  `LogicalParentUnavailable`. A repo-local child/grandchild kernel test
  makes a separate positive sentinel inheritable and uses
  `CompareObjectHandles` to prove that the sentinel reaches a broad-inheritance
  grandchild while neither original exact stdio object does. The sequential
  clears are non-atomic and do not prevent later inherit-bit re-enabling or
  explicit duplication. This remains a two-object negative, not a five-object
  grandchild proof; it is neither exhaustive stray-handle enumeration nor
  evidence for the exact signed helper, intended supervisor topology, immutable
  installation, DLL/dependency identity, or release activation. Signed
  release-path positive evidence covering case-sensitive directories and
  alternate path forms, live mapped exact-file-object proof, the complete
  DLL/dependency graph, immutable installation, a supervisor-held activation
  capability, and exact endpoint topology/exclusivity remain **STOP-SHIP**.
  There are zero production orchestration callers for the sealed launch-to-
  `VerifiedParentBoundApprovalExchange` transition, no conversion from that
  evidence into the public verified response or signing, and no positive
  signed-handshake E2E. `COMPILED_PARENT_POLICY` and
  `COMPILED_RELEASE_POLICY` remain `None`, so default `approval-ui` builds still
  exit 78.

  The session and transport lifetime now come from one platform-issued monotonic
  window. Matching non-Clone halves preserve one issuance identity, invalidation
  drops the unbound transport half, and the bound carrier keeps the original
  deadline authoritative through dormant activation, bootstrap, full exchange,
  and terminal retention. The full exchange has no substitute timing source
  reconstructed from wire data.

- an earliest runtime-enabled Secret Input/recovery child bootstrap. Its first
  Windows/CRT application operation requires stdin and the shared stdout/stderr
  entry to be two distinct exact `PIPE` objects with exact inherit-only flags,
  attempts both inherit-bit clears without rollback, and accepts only exact-zero
  readback. The parent process and image-file proof handles are not in the
  `HANDLE_LIST`: the launcher remotely duplicates them into the suspended child
  with inheritance disabled after Job/LPAC verification and before resume.
  Immediately after reading the fixed parent hello, the child requires the two
  sealed stdio objects and two proof objects to be four pairwise-distinct exact
  objects with zero flags. A repo-local child/grandchild kernel test supplies an
  inheritable positive sentinel and uses `CompareObjectHandles` to prove that
  none of those four exact objects reaches a broad-inheritance grandchild. The
  sequential stdio clears are not atomic, do not prevent later re-enabling or
  explicit duplication, and this exact-object negative is not exhaustive
  stray-handle enumeration or signed-artifact/topology/immutable-install proof.
  `COMPILED_PARENT_POLICY` remains `None`;

  **Test-only storage-startup accommodation:** all seven Rust-startup supervisor
  integration positives are explicitly ignored **STOP-SHIP**. Their fixture
  code, when deliberately invoked, accepts a pinned libtest terse preamble before
  the fixed response and only the expected fixture process plus at most the exact
  System32 `conhost.exe` in the root Job. Production requires response magic at
  byte zero and exactly one active Job member. The green minimal-PE dormant
  ownership/cleanup positives and Rust-startup failure-cleanup negative prove
  neither storage-startup success nor production fresh-fixed-root or signed
  artifact release evidence;

  **Exact startup-EOF boundary:** the consumed parent request writer closes
  before resume, and the child requires exact request EOF before root work and
  preflights ambient stdin/stdout detachment plus raw-stdin close. Its retained
  response handle is write/flush/close-attempted without a result escaping to
  `main`, after which the child sleeps inert. The parent requires the exact
  response plus EOF under the original deadline before accepting it; that is the
  authoritative response-close proof. The post-startup aggregate retains no endpoint. This is
  repo-local framing proof; signed-artifact E2E must still cover the exact binary
  and lifecycle;

  **Private fixed generation-store proof:** the child-held root can now be
  consumed only into one crate-private set of four non-cloneable, thread-bound
  bindings: `Vault`, `NonceLedger`, `SignedCandidateJournal`, and
  `LocalSettings`. Their namespaces, record classes, and ciphertext bounds are
  compiled in (`4,194,416`, `16,777,216`, `16,777,216`, and `226` bytes); no
  caller path, principal, record selector, bound, or frontend reference enters
  the binding-to-`WindowsBackend::open_key_agent` call graph. This narrow backend
  is dormant outside its `cfg(test)` integration, and the public
  `WindowsGenerationStore` remains unchanged and stable-`TokenUser`-only.

  Every Key Agent lock, slot, manifest, and same-directory temporary file must
  have the stable `TokenUser` owner and a protected canonical DACL with exactly
  two explicit allow ACEs in order: `FILE_ALL_ACCESS` (`0x001f01ff`) for that
  user, then `FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE` (`0x0013019f`)
  for the exact Key Agent profile SID. The live file must also have exactly one
  inherited Low/`NW` mandatory-label ACE with `INHERITED_ACE` (`ID`) as its only
  ACE flag. Other, frontend, broad, deny, inherited-DACL, reordered, extra, or
  partial ACEs fail closed. File opens reject reparses and link counts other
  than one, use full `FILE_ID_INFO`, and require the root volume identity.
  Thread-impersonation and held/reopened-root identity checks bookend each fixed
  child-path operation. Replacement additionally requires the target's initial
  identity/absence baseline to match immediately before replace and performs
  exact installed byte/hash/identity/security readback afterward. The backend
  security-context hook also bookends every untrusted fault callback, including
  both callbacks around rollback-anchor advancement.

  The integrated zero-capability LPAC kernel positive exercises the private
  adapter for all four fixed roles, commits and loads generations one and two
  across close/reopen, and verifies all seven physical names per role. On each
  name, `WRITE_DAC`, `WRITE_OWNER`, and `FILE_EXECUTE` must fail with
  `ACCESS_DENIED`, while `ACCESS_SYSTEM_SECURITY` must fail with
  `PRIVILEGE_NOT_HELD`. The held-root matrix separately requires an actual
  `DELETE` open to hit the retained handle's `SHARING_VIOLATION` plus a denied
  `AccessCheck`; `FILE_DELETE_CHILD`, `WRITE_DAC`, and `WRITE_OWNER` must return
  `ACCESS_DENIED`, and `ACCESS_SYSTEM_SECURITY` must return
  `PRIVILEGE_NOT_HELD`. The integrated fixture still uses
  the persistent test profile, a CSPRNG test leaf, in-memory rollback anchors,
  and synthetic authentication keys/payloads; it is not a production fresh
  fixed profile/root E2E or release activation.

  **Remaining storage/release boundary:** the pure candidate classifier,
  pending/launch typestate split, dormant fixed existing-root opener with
  canonical-path revalidation, and compiled dormant adoption transition do not
  supply production journal inputs, authoritative profile-registration
  observation or a held-aggregate constructor, production callers for the root
  opener/adoption/whole-release binding, exclusive lease/reread orchestration,
  recovery, or release activation.
  The artifact-bound continuity is not runtime/signing IPC, an installer key,
  rollback anchor, storage/AEAD key, or protected-settings authority. The root's
  `TokenUser` ACE permits other same-user processes while ancestor checks remain
  non-atomic. Production rollback-anchor and storage/AEAD-key provisioning,
  live protected-settings/lease authority, authenticated Broker/supervisor
  topology and single-instance enforcement, signed immutable artifacts, and
  exact DLL/dependency E2E evidence are not connected. Exact request EOF and the
  parent's authoritative response-plus-EOF proof do not create a runtime channel or signing authority;
  no generic Key Agent runtime or signing IPC exists.
  `COMPILED_RELEASE_POLICY` remains `None`;

  **Implemented Rust coordination boundary:** the dormant Broker activation,
  dormant Key Agent activation, and restricted helper launcher are the three
  production Rust inheriting-creation paths. They acquire one private,
  deadline-bound process-wide flight before the first temporary inheritable
  handle. Temporary owners borrow that flight's lifetime, and the per-launch
  attribute list plus all temporary inheritable handles are destroyed
  immediately after `CreateProcessW` before the flight is released. Reentrant
  acquisition fails closed, waiting is bounded by the path's trusted deadline,
  and unwind poisons the coordinator. The deadline covers flight acquisition
  and explicit pre-create admission checks; it cannot interrupt synchronous
  Windows `CreateProcessW` or the fresh worker's eventual join.
  The restricted launcher additionally binds its attribute list to the retained
  kill-on-close Job and uses `PROC_THREAD_ATTRIBUTE_JOB_LIST`, then verifies
  exact membership before token verification and resume.

  **Scope and remaining STOP-SHIP conditions:** this single-flight guarantee is
  limited to cooperating call sites in one loaded `platform-windows` crate
  instance. It is not an operating-system hook and does not intercept arbitrary
  foreign FFI, `std::process::Command`, a separately linked copy, or another
  process. The release PowerShell runtime's C# toolset runner therefore uses a
  separate matching static lock from inheritable-pipe creation through
  `CreateProcessW` and attribute/temporary-handle cleanup; that lock likewise
  covers only cooperating calls through that runner type. The Key Agent child
  now does clear the inherit bit on its three received stdio handles before any
  later application operation, and the repo-local grandchild test supplies an
  exact-object negative for that boundary. The runtime-enabled Approval child
  likewise seals its two unique synchronous server pipe objects as its first
  Windows/CRT application operation, requires numeric stdout/stderr aliasing,
  exact inherit-only preflags and zero readback; the parent retains overlapped
  client ends. Its launch `HANDLE_LIST` contains only those two child objects;
  supervisor-process, supervisor-image, and logical Key Agent process proofs are
  injected non-inheritable while the child is suspended. After Approval LPAC
  and Job verification, it requires all five exact objects to be pairwise
  distinct with zero flags. The retained live exact supervisor process handle
  supplies the authoritative PID and process-token `TokenSessionId`; the v2
  parent hello, both server-end client PID/session observations, and child token
  session must match. The separate retained logical-parent process must match
  the Key Agent PID in the hello, remain live and image-queryable in the same
  session, and satisfy its fixed LPAC SID, AppContainer/LPAC, zero-capability,
  and least-authority checks. Both bindings are retained and revalidated through
  UI presentation and response write. This prevents PID-reuse substitution
  while the process handles are live and corroborates the pipe observations
  against the exact supervisor process object. It does not prove exclusive
  endpoint ownership, topology/exclusivity, or per-write attribution because
  pipe handles remain transferable and duplicable. A separate repo-local
  `cfg(test)` logical-parent probe proves exact `TOKEN_QUERY` availability and
  denial of the exact local `DuplicateHandle` and PID-reopen request matrices
  enumerated above in a real zero-capability Approval LPAC, but
  it does not prove this channel binding or a mapped release image and leaves
  both policies `None`. The image policy separately requires case-preserving exact
  normalized path-string equality between live and held-file paths, checks the
  held path's suffix/version metadata, uses held handle plus path for
  Authenticode validation, and hashes a cloned held handle for SHA-256. It does
  not prove the live mapped exact file object. Its
  positive-sentinel grandchild negative still covers only the two stdio
  objects. That sequential clear is not atomic, does not prevent later
  re-enabling or explicit duplication, and is not exhaustive enumeration or
  exact signed-artifact/topology evidence. The
  runtime-enabled Secret Input/
  recovery child likewise seals its two unique stdio objects first, then
  validates those objects together with two separately injected non-inheritable
  parent proofs as one exact-zero, pairwise-distinct four-object set. Its repo-
  local positive-sentinel grandchild test is an exact-object propagation
  negative, not exhaustive enumeration of every child handle. A standalone
  supervisor still needs independently proven single-instance/process topology;
  signed-install,
  Native Host provenance, signed release-path positive evidence for
  case-sensitive directories and alternate path forms, artifact-bound execution
  of this bootstrap, exact signed-artifact E2E, immutable installation, complete
  DLL/dependency evidence, a release-proven resumable supervisor-held activation
  capability, and endpoint topology/exclusivity remain absent. Approval's sealed
  bootstrap and full exchange both have zero production callers. The full
  exchange requires response EOF, natural child exit code 0, and post-exit final
  Key Agent revalidation before minting opaque
  `VerifiedParentBoundApprovalExchange`, but that evidence has no public
  verified-response/signing conversion and there is no positive signed-handshake
  E2E. The platform-issued session window now carries one original monotonic
  deadline through matching non-Clone authorization/transport halves, exact
  request binding, dormant activation, and terminal exchange retention.

  **구현 범위와 남은 릴리스 차단 조건:** 휴면 Broker, 휴면 Key Agent, 제한 helper
  launcher의 세 Rust 운영 상속형 생성 경로는 첫 임시 inheritable handle 생성 전부터
  `CreateProcessW` 직후 attribute list와 임시 핸들을 모두 정리할 때까지 하나의
  deadline-bound process-wide flight를 공유합니다. 임시 owner는 flight 수명을 빌립니다.
  이 deadline은 flight 획득과 명시적인 생성 직전 검사만 제한하며, 동기식
  `CreateProcessW` 호출이나 fresh worker의 최종 join을 중단시키지는 못합니다.
  다만 이 보장은 같은 프로세스에 적재된 하나의 crate instance와 협력 Rust 호출에만
  적용되며 임의의 FFI/표준 라이브러리 생성이나 다른 프로세스를 가로채지 않습니다.
  Key Agent 자식은 이제 첫 Windows application 동작에서 정확한 `PIPE`/`PIPE`/`CHAR`
  stdio 세 개를 사전검사하고 inherit bit를 모두 제거한 뒤 flags 0을 재검사하며,
  grandchild exact-object 음성 테스트도 통과해야 합니다. runtime-enabled Approval
  launcher의 `HANDLE_LIST`는 계속 stdin과 shared stdout/stderr인 두 stdio `PIPE`
  객체만 포함합니다. 자식은 synchronous server ends를 상속하고 부모는 대응하는
  overlapped client ends를 보유합니다. supervisor process/image proof와 별도 Key Agent
  logical-parent process proof는 suspended 자식에 inherit 불가로 주입됩니다. 자식은 첫
  Windows/CRT application 동작에서 stdio를 봉인한 뒤 Approval LPAC과 Job을 확인하고,
  stdio 둘과 proof 셋이 flags 0인 다섯 pairwise-distinct exact object인지 검증합니다.
  자식은 retained live exact supervisor process handle에서 authoritative PID와
  process-token `TokenSessionId`를 도출하고, parent hello의 supervisor PID, 두 child-held
  server ends의 client PID/session observation, child token
  session이 모두 일치해야 합니다. 이 binding은 UI 표시와 response write 동안
  보유되고 재검증됩니다. 별도 Key Agent handle은 logical-parent PID, same session,
  liveness/image query, fixed Key Agent LPAC SID/zero capabilities와 least-authority denial을
  독립적으로 만족해야 하며 pipe PID로 사용하지 않습니다. 따라서 두 handle이 live인 동안
  PID-reuse substitution을 막고 pipe observation을 exact supervisor process object와
  대조합니다. 다만 pipe handle은
  transferable/duplicable이므로 exclusive endpoint ownership,
  topology/exclusivity, per-write attribution은 증명하지 못합니다. 별도 repo-local
  kernel probe가 zero-capability Approval LPAC의 exact logical-parent handle에서
  Key Agent logical-parent process proof의 `OpenProcessToken(..., TOKEN_QUERY)` 성공과
  stronger token/process 및 PID-reopen
  거부를 입증하지만, policies는 `None`이고 signed/mapped release E2E가 아니므로 이
  성공 경로는 release-unproven입니다. image 검사는
  case-preserving exact normalized path-string equality를 사용합니다. 즉 선택적인 `\\?\` prefix와 separator만
  정규화해 live process image path와 별도 held file final path를 비교하며 casing
  mismatch는 fail closed입니다. 이어 held path의 `\\key-agent.exe` suffix와 version
  metadata, held handle+path 기반 Authenticode signer, cloned held handle 기반 SHA-256를
  확인합니다. 이는 live
  process가 그 exact file object에서 mapped되었다는 증명이 아닙니다. wire와 child runtime이
  정의하는 전체 교환 순서는 고정
  74-byte version-2 parent hello, 고정 106-byte child hello, 110-byte finish header와 exact request
  및 request EOF, 고정 75-byte response와 response EOF입니다. 부모가 response 뒤
  로컬에서 계산하는 transcript는 held child PID/file identity, manifest/profile,
  request digest/one-shot nonce/hash, exact response, child에게 전송되지 않는 fresh
  parent-local transcript salt, 두 bootstrap nonce를 해시합니다. 이 salt는
  challenge-response 증거가 아닙니다. Job은 live gate이지 hashed identity가 아닙니다. 고정 75-byte
  response는 magic, version, decision, request digest, one-shot Approval request nonce
  순서이며 request에서 echo하는 값은 digest와 nonce뿐입니다. bootstrap nonce를 echo하지
  않으므로 replay 방어는 private one-shot endpoint와 fresh one-shot Approval request nonce에도
  의존합니다. raw executable direct launch는 진단 없이 종료되고, legacy Rust API는
  resource allocation 전에 `LogicalParentUnavailable`을 반환합니다. 플랫폼은 하나의
  opaque monotonic session window를 내부에서 발급하고 exact issuance identity를 공유하는
  non-Clone authorization/transport half로 나눕니다. `wallet-protocol`은 둘을 비공개로
  보유하고 invalidation 때 unbound transport half를 버립니다. Key Agent는 exact
  digest/one-shot nonce/canonical display/protected phrase request를 만든 다음 matching half를
  한 번 소비해 `BoundApprovalTransport`로 묶습니다. 이 carrier는 pipe/process allocation
  전에 dormant transition으로 소비되고, 이미 만료됐으면 allocation 전에 거절됩니다.
  sealed parent는 hello bootstrap과 full exchange를 별도 typestate로 구현합니다.
  bootstrap deadline은 original expiry와 fresh 5초 grace 중 이른 값이며, full exchange는
  raw request/deadline 인수 없이 carrier의 exact request와 original monotonic deadline을
  response arming, finish+request EOF, 고정 response+EOF, exact child의 자연 exit wait에
  공유합니다. response EOF만으로는 완료 증거가 아니며 exact process가 같은
  deadline 안에서 스스로 exit code 0으로 종료해야 합니다. 그 뒤 final Key Agent
  revalidation과 final deadline check가 성공해야 accessor 없고 carrier를 보존하는
  crate-private `VerifiedParentBoundApprovalExchange`가 만들어집니다. 살아 있는 child를 강제
  종료해 성공 증거를 만들지 않으며, timeout/nonzero exit/wait 오류는 실패이고
  cleanup 실패가 원래 오류보다 우선합니다. ordinary supervisor는 transport/pipe
  authority로 남고 Key Agent는 별도 logical parent일 뿐입니다. 두 transition의 production caller는
  모두 0개이고 public verified response/signing conversion은 없으며, legacy
  `launch_approval_frontend`는 계속 allocation 전에 실패합니다.
  별도 inheritable positive sentinel grandchild 테스트는 sentinel이 전파되는 동안
  원래 stdio 두 객체만 전파되지 않음을 `CompareObjectHandles`로 확인하며 five-object
  proof가 아닙니다. 이 순차 clear는 원자적이지 않고 이후 inherit-bit 재설정이나
  explicit duplication을 막지 않으며, exact-object 음성은 stray handle 전체 열거,
  exact signed artifact/topology 또는 릴리스 증거가 아닙니다. case-sensitive directory와
  alternate path form을 포괄하는 signed release-path positive evidence, live mapped exact
  file object, complete DLL/dependency graph, immutable installation, supervisor-held
  activation capability, exact endpoint topology/exclusivity는 모두 **STOP-SHIP**입니다.
  sealed launch-to-`VerifiedParentBoundApprovalExchange` transition의 production
  orchestration caller는 0개이고, 그 증거를 public verified response나 signing으로
  전환하는 composition과 positive signed-handshake E2E도 없습니다. 수명 carrier는 같은
  original deadline과 issuance identity를 dormant, bootstrap, full exchange, terminal까지
  보존하며 wire-relative lifetime을 exchange 시작 뒤 다시 샘플하지 않습니다.
  `COMPILED_PARENT_POLICY`와 `COMPILED_RELEASE_POLICY`는 모두 `None`이고
  default helper는 exit 78입니다. runtime-enabled Secret Input/
  recovery 자식도 첫 Windows/CRT 동작에서 stdin과 shared stdout/stderr 두 `PIPE` 객체의
  inherit bit를 제거하고, suspended 상태에서 별도로 주입된 non-inheritable parent
  process/image proof와 합친 네 exact object가 pairwise-distinct이며 flags 0인지
  확인합니다. positive sentinel을 둔 grandchild 테스트는 이 네 객체의 전파만 부정하며
  stray handle 전체를 열거하지 않습니다. 순차 clear는 원자적이지 않고 이후 재설정이나
  explicit duplication도 막지 않습니다. 이 repo-local 경계와 별개로
  독립 supervisor 단일 인스턴스와 인증된 topology, signed install/Native Host
  provenance 및 서명 artifact 기반 실행 증거는 계속 STOP-SHIP입니다.
- an HMAC-authenticated, bounded dual-slot generation store for already-encrypted
  vault/nonce/journal/local-settings records, with a stable class discriminant,
  a strict per-class ciphertext-format matrix, generation CAS, previous-digest chaining,
  a required independent rollback anchor, same-directory write-through temporary
  files, `FlushFileBuffers`, atomic `MoveFileExW` replacement, directory flush,
  held-handle identity plus exact byte/hash readback before manifest or anchor
  advancement, corruption/truncation tests, and crash recovery at every commit
  stage. Storage is accepted only on a fixed, non-redirected local volume whose
  held directory handle reports persistent ACLs and the exact filesystem name
  `NTFS`; mapped/remote, removable, optical, RAM-disk, ReFS, FAT/exFAT, CsvFS,
  and unknown filesystems fail closed. ReFS remains disabled until every handle
  identity comparison uses its required 128-bit `FILE_ID_INFO` identifier.
  Persistent directories and files
  use the stable current `TokenUser` SID as both owner and the sole full-control
  principal in a protected DACL; per-logon SIDs remain an IPC-only boundary.
  Opens reject invalid or noncanonical ACL revision/reserved/slack layouts, any
  other/defaulted/inherited/object/callback/deny ACE or owner, reparse point,
  and hard-linked persistent file. Recovery preserves path, ACL, bounds, and I/O
  proof errors exactly instead of reclassifying them as corruption or absence;
- a platform-independent global rollback-anchor registry model that binds one
  installation and key epoch to the fixed vault, nonce-ledger, signed-candidate
  journal, and local-settings stores. Its authenticated dual slots prepare a
  future state before exactly one monotonic-counter increment and finalize an
  authenticated manifest afterward. Fresh state requires sealed one-time
  provisioning evidence bound to the installation, key epoch, counter identity,
  and baseline; ordinary startup can only open an existing registry. Reads are
  bounded, registry deletion cannot reset the counter or provisioning proof, and
  deterministic recovery rejects equivocation, gaps, rollback, missing state,
  and overflow. No file, registry, DPAPI, or TPM backend is supplied, so this
  model cannot enable production. The public Windows generation-store facade is
  concrete rather than generic and consumes only the registry's opaque,
  non-cloneable bound-anchor handle; application crates cannot implement or
  inject an alternative rollback-anchor trait;
- an artifact-bound release evidence type whose public gate remains false in
  development builds;
- a private dormant Broker artifact preflight that keeps one dedicated Broker
  transport-suite digest and manifest separate from the exactly three
  signing-TCB helpers, then checks Broker role, complete evidence, the exact
  manifest, and an absolute retained path before `PreflightBrokerArtifact`
  retains the pinned Broker and the opaque whole-release
  `AttestedArtifactDigest` from the successful `ReleaseAttestation`. That proof
  denotes the overall `ReleasePolicy` `ArtifactDigest`; it is neither the
  dedicated Broker/helper manifest digest nor a Windows file-object identity,
  and no raw release digest is exposed. On Windows,
  `prepare_release_broker_supervisor` consumes that
  capability by value and derives volume serial plus all 128 `FILE_ID_INFO` file
  ID bits from the same already-held file handle. The resulting
  `PreparedReleaseBrokerSupervisor` retains the admitted artifact, the same
  opaque whole-release proof, and the separate opaque file identity, has
  redacted `Debug`, and is non-cloneable and drop-only. Only the admission module
  can mint it. A production-compiled, crate-private exact-image
  activation core consumes the whole value exactly once, creates the child on a
  fresh debugger thread, compares the first mapped-image handle with that same
  held identity before user mode, and retains the prepared value with the exact
  process, one-member Job, and private process-bound channel through cleanup.
  The release entry accepts no path, raw handle, PID, command line, or generic
  launcher input and performs no identity path reopen. Retaining the release
  proof does not create a Broker-plus-Key-Agent same-release aggregate,
  authenticated topology, single-instance enforcement, or runtime/signing authority;
  this release-bound Broker preflight, preparation, and activation
  path still has no production caller. `COMPILED_RELEASE_POLICY = None`
  keeps the core unreachable from release execution. The three cooperating Rust
  launch paths now have process-wide inheritable-handle coordination, but signed
  immutable installation, native-host provenance, cross-process supervisor
  topology/single-instance evidence, and artifact-bound execution of the
  implemented child-side Key Agent, Approval, and Secret Input/recovery
  de-inheritance
  remain STOP-SHIP.

Stop-ship before any signing-capable release:

1. Independently review the LPAC profile, security-capabilities and
   all-application-packages attributes, environment/current-directory policy,
   suspended token verification, and inherited-handle validation implemented in
   `restricted_process_context.rs` and `launch.rs`.
2. Run negative network tests (TCP, UDP, DNS, loopback, private addresses, and
   inherited sockets) against the exact signed helpers.
3. Run an artifact-bound child-side enumeration test proving that no handle
   except the explicit list crosses the boundary. The repo-local Key Agent
   child/grandchild test already proves that its three sealed exact stdio objects
   do not propagate. The Approval test proves that its positive sentinel reaches
   the broad-inheritance grandchild while its two sealed exact stdio objects do
   not. The Secret Input/recovery test likewise proves only that
   its two sealed stdio and two non-inheritable parent-proof objects do not reach
   one broad-inheritance grandchild. None of these exact-object negatives is
   exhaustive stray-handle enumeration or evidence for the exact signed
   artifacts.
4. Exercise path/reparse/ACL tests under the release installer identity and
   secure installed ACLs, including environments where symlink creation is
   permitted. Supply separate exact-artifact DLL/dependency loading and identity
   evidence; the string/reparse/rights process-context validation is not an
   atomic held-directory identity proof.
5. Generate an immutable compiled release policy from independently signed test
   evidence and bind it to the exact artifact digest. The source currently sets
   `COMPILED_RELEASE_POLICY` to `None`. Bind the separate Broker transport suite
   and Broker manifest to the signed immutable install, bind the existing
   prepared-value exact-image activation core to authenticated native-host
   provenance, prove the standalone supervisor's single-instance and exact
   process topology, exclude or mediate every foreign/uncoordinated inheriting
   creation path, and bind the implemented Key Agent first-operation stdio
   sealing plus grandchild exact-object negative, the Approval five-object
   runtime parent-auth check plus its separate two-stdio grandchild negative,
   and the Secret Input/recovery four-object boundary, to their exact signed
   artifacts.
   The in-crate coordinator and repo-local child test are not signed-install,
   provenance, cross-process topology, or release-activation proof.
6. Exercise the complete launch/request/gesture/response/EOF path plus timeout,
   cancellation, extra-output, helper-crash, and handle-enumeration negatives
   against the exact signed `approval-ui.exe`. That suite must cover the fixed
   74-byte version-2 parent hello, fixed 106-byte child hello, two fresh nonzero nonces,
   110-byte finish header, exact request EOF, fixed 75-byte response and response
   EOF, plus the parent transcript's held child PID/file identity,
   manifest/profile, request digest/one-shot nonce/hash, exact response, a fresh
   parent-local transcript salt, and both bootstrap nonces. The salt is never
   sent to the child and is not challenge-response evidence. Job policy/membership is a live gate,
   not hashed identity. Because the response does not echo the bootstrap nonces,
   replay evidence must also cover the private one-shot endpoint and fresh one-
   shot Approval request nonce. Signed release evidence must prove
   signed release-path positive evidence covering case-sensitive directories
   and alternate path forms, that the live image was mapped from the exact held
   file object, the complete DLL/dependency graph, immutable installation, a
   release-proven resumable supervisor-held activation capability, and exact endpoint
   topology/exclusivity. Current pipe inspection is corroborated against a
   retained live exact supervisor process object: the child derives PID and
   process-token `TokenSessionId`, matches the hello, both server-end client
   PID/session observations, and child token session. It separately authenticates
   and retains the fixed-profile Key Agent logical-parent process without using
   it as the pipe peer, and revalidates both authorities through response write.
   That blocks PID-reuse substitution while both handles are live, but transferable/duplicable pipe
   handles still leave exclusive endpoint ownership, topology/exclusivity, and
   per-write attribution unproven. The dormant logical-parent binder now owns a
   fresh non-inheritable exact Key Agent process duplicate with only
   `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`; it never reopens by PID,
   exposes no raw handle, and does not set `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`
   or change Windows process parentage. One platform-issued monotonic session
   window splits into matching non-Clone authorization/transport halves; the Key
   Agent binds its exact request once, and dormant activation consumes the opaque
   carrier before allocation. One sealed zero-caller transition uses the earlier
   of original expiry and a fresh five-second grace, writes the complete v2 hello
   before exactly one resume, and validates the exact child hello. A second sealed
   zero-caller transition consumes that bootstrap with no raw request/deadline
   input, uses the carrier's exact original deadline, and writes finish/request
   plus EOF, verifies fixed response plus EOF, waits for the exact held child to
   exit naturally with code 0, and finally revalidates the Key Agent after exit.
   Its opaque `VerifiedParentBoundApprovalExchange` exposes no public response or
   signing conversion. One of the seven explicitly ignored **STOP-SHIP**
   supervisor `cfg(test)` integrations is written to launch an actual
   zero-capability Approval LPAC and exercise exact handle/token
   usability, twelve token-right denials, denial of the exact per-right local
   `DuplicateHandle` and PID-reopen matrices enumerated above, and
   `SeDebugPrivilege` absence. At `CREATE_PROCESS_DEBUG_EVENT`, the production
   Key Agent activation opens the then-current token as `Hwrite` with exactly
   `TOKEN_QUERY | WRITE_DAC | READ_CONTROL`, installs
   the protected three-ACE DACL, and reads it back through that same handle with
   the bounded two-pass kernel query. The exact valid self-relative descriptor
   must contain a present/protected, non-defaulted, non-auto-inherited DACL and
   exactly three zero-flag explicit allow ACEs in stable-user-all / Key Agent
   query+duplicate / Approval query-only order, with exact masks, binary SIDs,
   ACE/ACL sizes, descriptor end, and no extra or slack bytes. When deliberately
   invoked, that ignored integration executes the production-compiled hardening;
   it is not current green query-only or end-to-end evidence.
   A separate `Hadjust` with exactly `TOKEN_QUERY | TOKEN_ADJUST_DEFAULT` must
   compare as the same object as `Hwrite` and least-authority `Hfinal`, but stays
   only in the opaque gate-pending state. The final pre-resume kernel evidence is
   stronger than the original A/B: no mutation and an exact original-DACL deep
   copy exit 0, while all six deny-first `0x000e0000` cases across the tested
   `SYSTEM`/package/user `GENERIC_ALL` combinations exit exact `0xC0000142`.
   Standalone `READ_CONTROL`, `WRITE_DAC`, or `WRITE_OWNER` owner-rights denies
   also each produce that failure even with all three allows. The package SID is
   absent from `TokenGroups` and is not owner-eligible (`ERROR_INVALID_OWNER`).
   Thus the current same-user LPAC architecture cannot provide a loader-compatible
   from-birth `WRITE_DAC` denial; a distinct OS principal/service is the next
   design option, not a claim that every Windows design is impossible.

   The compiled conditional path therefore waits for the first reviewed semantic gate inside
   `serve`, after DLL/TLS/CRT initialization. A bounded AMD64 PE32+ preflight
   authenticates one whole-file-unique `49 BA <marker-le> CC` sequence whose all
   11 bytes lie in initialized raw non-padding bytes of exactly one executable
   section, and derives its runtime INT3 only from authenticated
   `lpBaseOfImage`. Test and production share the current
   primary-TID-only/zero-loader-thread policy. The green real GUI Key Agent
   regression rejects its non-primary loader thread before detach and verifies
   Job cleanup with GUI-subsystem root count one; historical CUI trace details,
   including exact System32 conhost/root count two, are not accepted-path proof.
   A bounded policy that proves every worker exits before the gate and fresh
   post-exit reopen is denied is still **STOP-SHIP**, but would not repair that
   from-birth gap. Only as a conditional mechanism, if that revised policy reaches one
   exact PID/primary-TID main-image gate with the pinned address, bytes, `RIP`,
   `R10`, and memory-region context may the debugger, using an explicit
   16-byte-aligned AMD64 `CONTEXT` wrapper, zero `R10` with exact readback apart
   from reserved always-one EFLAGS bit 1 representation, add
   exact explicit suspend count one, installs and boundedly reads back the exact
   28-byte one-ACE deny-only `OWNER RIGHTS` `TokenDefaultDacl`, establishes the
   post-mutation identity baseline, checked-closes `Hadjust`, and only then
   completes the two-DACL/current-token `Hfinal` bookends that yield the
   `Hfinal`-only `VerifiedKeyAgentLpac`. When the later sole post-gate resume
   releases the explicit count, the child's first semantic step calls
   `verify_current_key_agent_default_dacl_after_gate()` and independently reads
   the same policy through a fresh current `TOKEN_QUERY` handle before later
   `serve` work.
   Baseline-equal statistics bookend both DACLs and fresh-current exact-object
   continuity after detach/attenuation, immediately before the sole post-gate
   application-releasing `ResumeThread`, and at resident checks. This is fail-closed
   point-in-time evidence, not an atomic freeze; holding `Hfinal` freezes neither
   current-token association nor token contents. The last-check/resume and
   swap-away/back races remain **STOP-SHIP**, and DACL changes are not assumed to
   update `ModifiedId`. The production creation-security and attenuation path
   described above applies the exact deny-only protected DACL to the initial
   process and primary thread, validates the creator and distinct debug-event
   aliases, checked-closes the event aliases after joined detach, derives the
   exact `0x00101001` process and `0x1000` resume-only retained thread
   capabilities. The separate requested-`0x2`/effective-`0x1002` probe is used,
   then closed with a checked result before the supervisor closes both creator
   handles and mints `Held`. The sole successful resume immediately closes
   the retained thread capability, leaving `Running` with only the narrow
   process. Its kernel tests cover pseudo-handle usability and fresh owner
   PID/TID single-right denials with `SeDebugPrivilege` and
   `SeTakeOwnershipPrivilege` disabled. A separate green deterministic
   import-free relocatable GUI PE fixture proves the exact-primary gate,
   Pending→Verified transition, one verified suspend count, and detach, but not
   real Key Agent loader compatibility. It also retains the green dormant
   ownership/non-inheritance and cleanup positives. Seven Rust-startup supervisor
   integrations remain explicitly ignored **STOP-SHIP**, while the green
   supervisor negative maps loader activity to `Activation` and deletes the
   prepared storage root. A separate post-loader cooperative child
   proves independent readback plus actual `CreateThread(NULL, ...)`, exact
   default descriptor, pseudo/self behavior, parent/child denial matrices, and
   exit 0, but its libtest worker is non-primary and supplies feasibility only.
   The policy remains point-in-time and does not cover caller-supplied/raw-native/
   remote thread creation, revoke returned/preexisting/duplicated high-right
   handles, inventory pre-gate non-thread objects, separate a same-user
   supervisor/owner, or constrain enabled privileges. Signed DLL/TLS provenance,
   loader-worker provenance/lifetime/exit/reopen-denial policy, a distinct OS
   principal/service design with IPC/lifecycle proof, a real GUI Key
   Agent loader-compatible exact-primary gate E2E, and supported
   architecture/Windows gate matrices remain **STOP-SHIP**. The
   copied image's mandatory-label state is likewise not
   directly read back; the test-only
   `NO_LOW_LABEL` removal permits the profile-scoped copy and leaves production
   mitigation unchanged. This feasibility proof is not release activation.
   Current held-file policy checks likewise do not provide the
   immutable-install, signed DLL/TLS graph, pre-gate object inventory,
   supported-architecture matrix, distinct-supervisor-principal,
   endpoint, bootstrap/provenance, or production-composition proofs.
   Kernel-level pipe tests cover the framing and cancellation primitives, and
   the repo-local positive-sentinel grandchild test supplies only a non-
   exhaustive two-object propagation negative. Its sequential clears are non-
   atomic and do not prevent later re-enabling or explicit duplication. That
   test is not evidence for the exact signed helper or intended release
   topology. Both sealed transitions have zero production callers; conversion
   from the terminal exchange evidence into verified-response/signing and a
   positive signed-handshake E2E are absent. The terminal exchange retains the
   bound carrier and its original issuance identity; no exchange-start deadline
   reconstruction remains. Direct executable launch exits without
   diagnostics, while the legacy Rust API returns `LogicalParentUnavailable`
   before allocation,
   while `COMPILED_PARENT_POLICY = None`, `COMPILED_RELEASE_POLICY = None`, and
   the default exit 78 prevent signed-artifact release activation.
7. Connect the global registry model to independently reviewed, production
   non-rollbackable physical-counter and durable-slot backends (for example, a
   TPM-backed policy), derive and rotate its independent registry MAC key plus
   storage MAC and nonce/journal/local-settings AEAD keys inside the Key Agent,
   and connect the store to the vault, settings, and signing state. An adjacent
   file, registry value, or DPAPI blob is not an independent rollback anchor.
8. Exercise the complete Secret Input launch/request/presentation/response/EOF
   path plus timeout, cancellation, oversize/trailing output, helper crash,
   direct-launch/parent-identity denial, and inherited-handle enumeration
   against the exact signed `secret-input-ui.exe`. The atomic parent integration
   and the repo-local four-object grandchild negative exist, but the latter is
   neither exhaustive enumeration nor signed-artifact evidence. The sequential
   stdio clears are not atomic and do not prevent later re-enabling or explicit
   duplication. `COMPILED_RELEASE_POLICY = None`,
   `COMPILED_PARENT_POLICY = None`, and the default helper exit 78 keep ordinary
   builds fail closed. Direct-launch
   parent authentication remains stop-ship evidence rather than an implemented
   claim.
9. Connect the crate-private recovery facade to a Key Agent protected-settings
   lease and recovery-session state machine, then exercise display and confirm
   as two separately signed one-shot child processes. Artifact-bound evidence
   must cover cross-stage/cross-request replay, parent/image/profile mismatch,
   timeout and forced termination, capture resistance before first paint, and
   secret-zeroization behavior. Headless codec and pipe tests do not substitute
   for this signed-artifact release evidence.
10. Connect the private one-shot storage-startup proof to the authenticated Broker
    protocol/process topology and a live protected-settings lease without adding
    a generic Key Agent runtime or signing API. Repeat request-before-resume,
    nonce/PID/creation-time/root-identity mismatch, transcript, caller-event
    contamination, exact request/response EOF, suffix and missing-EOF negatives,
    ambient stdin/stdout detach and raw-stdin-close failures, partial/failed
    response writes, ignored flush/close results, parent-authoritative EOF, inert
    `Sleep(INFINITE)` residence, concurrent activation, worker panic/error cleanup,
    timeout, image mismatch, post-return supervisor Job assignment, and pre-user-mode sentinel tests against the exact signed
    `key-agent.exe`. The pinned libtest preamble and optional exact System32
    `conhost.exe` topology accommodation are test-only and are not release
    attestation.
11. Non-launchable fresh fixed-profile/root creation, the pure non-authoritative
    provenance classifier, private dormant sealed adoption and whole-release
    artifact-binding transitions, fixed zero-capability LPAC token verification,
    test-root child open/binding, and the narrow private generation-file policy
    are implemented and covered together by the `cfg(test)` integrated LPAC
    fixture. The root-only fixed existing-root opener and canonical reopen
    revalidation are implemented separately with zero production callers and a
    bounded exact-CSPRNG-leaf test seam. Keep production storage authorization
    **STOP-SHIP** until installer-owned authenticated and rollback-resistant
    journal inputs, authoritative profile-registration observation and a held-
    aggregate constructor, production callers for the dormant root opener and
    adoption/binding path, and an exclusive installer lease/post-observation
    reread invoke the already implemented dormant artifact-binding and supervisor
    path; production
    installer-key/checkpoint and journal I/O backends plus recovery and release
    activation are supplied; the production rollback
    anchor and storage/AEAD keys are
    provisioned, and a protected-settings lease plus authenticated
    Broker/supervisor/single-instance topology consumes the sealed bindings. The
    public `WindowsGenerationStore` remains `TokenUser`-only; no frontend profile
    is granted access. This test proof does not establish a production fresh-root
    or signed-artifact/DLL/dependency E2E. The implemented exact request EOF and
    parent-authoritative response-plus-EOF boundary remain repo-local evidence
    only. Helper trust/profile setup must
    not depend on file, certificate-store, registry, or profile APIs unavailable
    inside the LPAC.
    Do not add `registryRead`, reuse either frontend profile for the Key Agent,
    add generic runtime/signing IPC, or activate the dormant Key Agent to work
    around these blockers.

The implementation follows Microsoft's [AppContainer launch
contract](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer):
`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` creates the AppContainer token,
zero capability SIDs omit every network capability, and
`PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT` selects LPAC rather than the
broader regular-AppContainer resource set.

Neither the public generation-store DACL nor the fixed-root/private-generation-
file DACLs contain a SYSTEM or Administrators ACE. The public facade remains
stable-`TokenUser`-only. The fixed root adds the exact Key Agent profile SID at
the directory boundary; each private generation file has exactly two explicit
allow ACEs, stable `TokenUser` first with `FILE_ALL_ACCESS` (`0x001f01ff`) and
that profile second with `FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE`
(`0x0013019f`), plus the exact inherited ID-only Low/NW mandatory label. An
administrator or SYSTEM process may still use operating-system privileges to
take ownership or perform backup operations; that privileged compromise is
outside these DACLs' guarantee. The stable-user ACE also means the policy does
not defend stored data from malware already executing as the same user.

Until items 1, 2, 3, 4, and 5 have artifact-bound evidence,
`ReleaseAttestation::signing_enabled` remains false and
`RestrictedLauncher::spawn` cannot return a running process. The LPAC code has no
permissive fallback. In particular, local unit tests do not constitute proof of
TCP, UDP, DNS, loopback, private-network, or inherited-socket denial on the exact
signed Windows 11 release artifact.
