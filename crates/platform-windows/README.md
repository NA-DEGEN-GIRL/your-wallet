# Windows boundary crate

This crate contains narrowly isolated Windows 11 process and IPC boundary
primitives. It is fail-closed and is **not** a claim that named-pipe ACLs or PID
checks defend against malware already executing as the same logon user.

Implemented:

- random one-shot named-pipe capabilities, a protected current-logon-SID DACL,
  local-only/first-instance flags, and connected-client PID/session validation;
- a role-checked approval launch API that creates separate private request and
  response endpoints, inherits only their child ends, transfers the canonical
  bounded v2 request, and consumes the held helper/job with an overlapped,
  monotonic-deadline response reader. The reader cancels and drains pending I/O,
  requires the exact fixed response followed by EOF, and binds file identity,
  manifest, LPAC profile, process object, request digest/nonce, response bytes,
  and a fresh Key-Agent challenge into the one-shot transcript;
- a non-cloneable parent-side Secret Input launch/channel API that accepts only
  a manifest-derived `secret-input-ui.exe` role and the release-attested
  restricted launcher, creates separate private request/response endpoints,
  inherits only child stdin/stdout/stderr, transfers the canonical prompt and
  request EOF under one monotonic deadline, then reads at most
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
  select a role: the public entry point accepts only Approval Frontend and the
  crate-private secret/recovery entry point accepts only Secret Input Frontend,
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
  debugger OS thread owns the complete `CreateProcessW`/first-event/image-check/
  continue/detach sequence. The debug-event image handle must match the retained
  verifier handle by volume serial plus all 128 `FILE_ID_INFO` bits; zero volume,
  all-zero and all-`FF` non-unique identifiers fail closed. Only successful
  debugger detach followed by an exact one-count suspend probe creates the
  non-clone detached capability. The public generic restricted launcher rejects
  the manifest-derived Key Agent role before release evaluation or process
  creation, so the shared artifact allowlist cannot bypass this seam. The
  activation-owned fresh worker now also creates the exact two-process
  kill-on-close root Job and private Key Agent pipes. One `STARTUPINFOEXW` call
  receives exactly three short-lived inherited stdio handles, one Job-list
  handle, the fixed zero-capability `YourWallet.KeyAgent.LPAC.v1` identity, and
  the ALL APPLICATION PACKAGES opt-out; the short-lived handles are dropped
  before the worker returns. The separate fresh-provisioning boundary creates
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
  The adoption transition, release-binding, and dormant supervisor binder all
  have zero production call sites, so an existing production profile or leaf
  still fails closed and is not opened, adopted, repaired, or deleted. A future
  production adapter that constructs the held aggregate must validate a stable
  current-`TokenUser` owner and exact protected
  DACL for that SID plus the fixed profile SID, the exact inherited Low/`NW`
  mandatory label, fixed local NTFS with persistent ACLs, non-reparse state, and
  a nonzero-volume, non-sentinel 128-bit `FILE_ID_INFO`. Its directory handle
  omits delete sharing, is revalidated before and throughout binding, and
  remains held until cleanup closes it last.

  A private one-shot storage-startup transition now closes the former child-open
  and transcript-binding gap for this narrow object proof. The parent writes the
  fixed request while the exact child is still suspended and only then releases
  its sole verified suspend count. The child opens the compiled production leaf,
  or the exact `cfg(test)` CSPRNG-leaf grammar, through its OS-rerouted
  `LOCALAPPDATA` locator. It obtains `TokenUser` and the AppContainer SID from its
  own process token, checks the directory object and exact owner/protected DACL/
  inherited Low/`NW` label, obtains the complete volume-serial plus 128-bit
  `FILE_ID_INFO`, and retains that independently opened handle. Its one response
  binds the fresh nonce, PID, process creation time, and root identity. Immediately
  after each side reads its fixed 188-byte request or 88-byte response,
  `PeekNamedPipe` must report no already-buffered suffix. The parent then
  independently compares the response fields, revalidates the held root, Job,
  topology, and lease, and commits the artifact identity plus exact request and
  response into a domain-separated SHA-256 startup transcript commitment.

  Key Agent and frontend profile APIs share one process-wide non-reentrant,
  poison-fail-closed coordinator; the central profile API rejects thread
  impersonation before acquiring it. The Key Agent's explicit three-name
  Unicode environment sets `LOCALAPPDATA` directly to the exact profile `AC`
  path returned by `GetAppContainerFolderPath`, alongside OS-derived
  `SystemRoot` and `WINDIR`. The Restricted helpers prepare this context before
  parent-proof, persistent profile, or Job work; the Key Agent prepares it
  before acquiring the inheritable-handle flight. Both recheck that the creator
  thread is not impersonating immediately before `CreateProcessW`. This context
  proof is limited to DOS-path shape, Windows-root/System32 layout,
  directory/reparse state, path-replacement rights on every ancestor, and
  content-creation rights on the Windows root and System32 under the current
  primary token. It retains no directory handle and is not an atomic
  object-identity proof; it also makes no claim about error mode, priority,
  every other inherited Win32 process setting, or DLL/dependency identity. The
  initial crate-private aggregate uniquely owns the detached suspended process,
  root Job, two parent endpoints, internally timed one-shot startup lease, and
  independently verified profile/root proof. It is non-clone, `!Sync`, exposes no raw handle or
  generic resume API, and its only consuming resume transition is the fixed
  storage-startup proof above. The resulting private post-startup aggregate
  retains the running process, Job, both now-non-inheritable parent endpoints,
  transcript commitment, and parent-held root proof while the running child
  separately retains its independently opened root handle; the aggregate exposes
  no runtime I/O or signing operation. Drop synchronously terminates the exact
  process tree before closing the held storage root. The suspended token must
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
  production caller. Production still lacks an
  authoritative profile-registration observer, fixed existing-root opener and
  held-aggregate constructor, an exclusive installer lease that enforces the
  post-observation reread, canonical-path reopen identity comparison, a
  production installer-key/checkpoint and journal reader/writer backend,
  recovery, and release-activation orchestration;
- an earliest Key Agent child bootstrap with no caller-supplied handle input.
  The Key Agent entrypoint makes this its first Windows application operation.
  Before mutation it requires exactly three distinct kernel objects with exact
  `PIPE`/`PIPE`/`CHAR` types and exactly `HANDLE_FLAG_INHERIT`; it then attempts
  to clear the inherit bit on all three, never restores inheritance after a
  partial failure, and requires all three flag words to read back as exactly
  zero. The returned non-clone, `!Send + !Sync` proof exposes no handle. An
  isolated child/grandchild kernel test uses `CompareObjectHandles` to prove
  that none of the three original exact stdio objects reaches the grandchild.
  The entrypoint then reads exactly one fixed startup request and rejects an
  already-buffered suffix before opening the root or responding. It writes
  exactly one response only after the process/root checks succeed, fails closed
  on any input byte that arrives afterward, and retains its sealed stdio and
  child-opened root until the parent request endpoint disconnects;

  **Test-only storage-startup accommodation:** the integrated kernel positive
  uses a pinned libtest terse preamble before the fixed response and permits only
  the expected fixture process plus at most the exact System32 `conhost.exe` in
  the root Job. Both exceptions are `cfg(test)`-only. Production requires the
  response magic at byte zero and exactly one active Job member, so this fixture
  is not production fresh-fixed-root or signed-artifact release evidence;

  **Immediate-suffix boundary:** both `PeekNamedPipe` checks are snapshots of
  bytes already queued immediately after their fixed frame. Because both parent
  endpoints remain open and retained, they are not proof of a future delayed
  trailing byte's absence or of EOF. Signed-artifact E2E must still cover that
  temporal boundary;

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
  pending/launch typestate split, and compiled dormant adoption transition do
  not supply production journal inputs, authoritative profile-registration
  observation, fixed existing-root opening, exclusive lease/reread
  orchestration, canonical-path identity rebinding, a production caller for the
  implemented dormant whole-release binding, recovery, or release activation.
  The artifact-bound continuity is not runtime/signing IPC, an installer key,
  rollback anchor, storage/AEAD key, or protected-settings authority. The root's
  `TokenUser` ACE permits other same-user processes while ancestor checks remain
  non-atomic. Production rollback-anchor and storage/AEAD-key provisioning,
  live protected-settings/lease authority, authenticated Broker/supervisor
  topology and single-instance enforcement, signed immutable artifacts, and
  exact DLL/dependency E2E evidence are not connected. The future-delayed
  suffix/EOF boundary remains unproved and no generic Key Agent runtime or
  signing IPC exists. `COMPILED_RELEASE_POLICY` remains `None`;

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
  exact-object negative for that boundary. A standalone supervisor still needs
  independently proven single-instance/process topology; signed-install,
  Native Host provenance, artifact-bound execution of this bootstrap, exact
  signed-artifact E2E, and DLL/dependency evidence remain absent.

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
  grandchild exact-object 음성 테스트도 통과해야 합니다. 이 repo-local 경계와 별개로
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
  manifest, and an absolute retained path before minting a non-clone opaque
  capability. On Windows, `prepare_release_broker_supervisor` consumes that
  capability by value and derives volume serial plus all 128 `FILE_ID_INFO` file
  ID bits from the same already-held file handle. The resulting
  `PreparedReleaseBrokerSupervisor` retains the admitted artifact and opaque
  identity, has redacted `Debug`, and is non-cloneable and drop-only. Only the
  admission module can mint it. A production-compiled, crate-private exact-image
  activation core consumes the whole value exactly once, creates the child on a
  fresh debugger thread, compares the first mapped-image handle with that same
  held identity before user mode, and retains the prepared value with the exact
  process, one-member Job, and private process-bound channel through cleanup.
  The release entry accepts no path, raw handle, PID, command line, or generic
  launcher input and performs no identity path reopen. `COMPILED_RELEASE_POLICY = None`
  keeps the core unreachable from release execution. The three cooperating Rust
  launch paths now have process-wide inheritable-handle coordination, but signed
  immutable installation, native-host provenance, cross-process supervisor
  topology/single-instance evidence, and artifact-bound execution of the
  implemented child-side Key Agent stdio de-inheritance remain STOP-SHIP.

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
   do not propagate, but it is not evidence for the exact signed artifacts.
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
   sealing plus grandchild exact-object negative to the exact signed artifact.
   The in-crate coordinator and repo-local child test are not signed-install,
   provenance, cross-process topology, or release-activation proof.
6. Exercise the complete launch/request/gesture/response/EOF path plus timeout,
   cancellation, extra-output, helper-crash, and handle-enumeration negatives
   against the exact signed `approval-ui.exe`. Kernel-level pipe tests cover the
   framing and cancellation primitives, but the intentionally disabled helper
   binary and absent compiled release policy prevent that signed-artifact E2E.
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
   and kernel pipe tests exist, but `COMPILED_RELEASE_POLICY = None` and the
   default helper exit 78 keep ordinary builds fail closed. Direct-launch
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
    contamination, concurrent activation, worker panic/error cleanup, timeout,
    image mismatch, post-return supervisor Job assignment, and pre-user-mode
    sentinel tests against the exact signed `key-agent.exe`. The pinned libtest
    preamble and optional exact System32 `conhost.exe` topology accommodation are
    test-only and are not release attestation.
11. Non-launchable fresh fixed-profile/root creation, the pure non-authoritative
    provenance classifier, private dormant sealed adoption and whole-release
    artifact-binding transitions, fixed
    zero-capability LPAC token verification,
    test-root child open/binding, and the narrow private
    generation-file policy are implemented and covered together by the
    `cfg(test)` integrated LPAC fixture. Keep production storage authorization
    **STOP-SHIP** until installer-owned authenticated and rollback-resistant
    journal inputs, authoritative profile-registration observation, fixed-root
    opening, and an exclusive installer lease/post-observation reread invoke the
    already implemented dormant artifact-binding and supervisor path; production
    installer-key/checkpoint and journal I/O backends plus recovery and release
    activation are supplied; the production rollback
    anchor and storage/AEAD keys are
    provisioned, and a protected-settings lease plus authenticated
    Broker/supervisor/single-instance topology consumes the sealed bindings. The
    public `WindowsGenerationStore` remains `TokenUser`-only; no frontend profile
    is granted access. This test proof does not establish a production fresh-root
    or signed-artifact/DLL/dependency E2E, and it does not close the delayed
    suffix/EOF boundary. Helper trust/profile setup must not depend on file,
    certificate-store, registry, or profile APIs unavailable inside the LPAC.
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
