# Architecture and trust boundaries

This repository is an incomplete implementation of a self-only Windows 11 and
Chrome private-mainnet canary. It is not authorized for public distribution,
high-value use, or real-mainnet funds.

## Current implementation status

**Release status: STOP-SHIP.** The diagram and trust rules below are target
invariants, not a claim that the current binaries establish every boundary.

| Component | Current evidence and limitation |
| --- | --- |
| MV3 extension | Strict top-level HTTPS routing, exact 128-bit request IDs, bounded envelopes/state, deadline checks, freeze/navigation cancellation, replay handling, and incognito rejection have unit tests. Native response sequences must now be exact rather than merely increasing. Every native reconnect samples a distinct session ID, resets the per-connection sequence, rejects responses from an earlier session, and is bounded to 4,096 attempts per worker lifetime. Default and release operation still receives only the unavailable response; an explicit debug-only subprocess contract can return only the local Sepolia chain ID. |
| Native host | The default executable runs the bounded persistent dispatcher: strict JSON and exact version-1 envelopes, combined inbound sequencing, independent response sequencing, cancellation without response, and a 4,096-frame connection cap. Every valid request receives stable provider error 4900 and the process exits with code 78 on EOF or the first terminal error because it constructs only a disabled release attestation. A Cargo-feature **and** `debug_assertions` gated headless contract hook can spawn only the regular-file `broker` sibling beside its own executable, with hidden, cleared-environment stdio, unwind-safe child kill/wait cleanup, and a typed two-nonce/role/sequence handshake. Broker independently admits at most 4,096 post-handshake commands; the hello is outside that count and the next complete frame fails before dispatch. The local chain-ID execution surface is crate-private and absent from ordinary/release library builds. That hook can execute only Broker-owned `eth_chainId`; every other allowlisted method crosses only as a parameter-free enum plus request correlation, is recorded complete by Broker, and then receives 4900. Exact late cancellation is acknowledged internally as already completed and never produces a Chrome response. No raw unavailable-request params, messages, accounts, addresses, or origins cross that hook. A second Windows-only feature/debug hook uses an exact-image-authenticated, process-bound named pipe and a retained one-process Job instead of Broker stdio; it reuses the same payload-only typed state. Feature-enabled release binaries still take the disabled path and exit 78. Chrome-launched native-host image proof, immutable signed installation/registration, stable release extension identity, RPC, signing, and Key Agent access remain absent and stop-ship. |
| Approval helper | `approval-wire` is the single bounded v2 codec used by the authorization TCB, Key Agent, Windows channel, and native frontend. The Key Agent creates one crate-private, non-clone `PreparedApprovalPrompt`; its exact digest, nonce, sampled expiry, locally protected anti-phishing phrase, risk, and every display field are request-hashed and retained across the interaction. The prompt additionally carries a one-shot protected-settings lease bound to the authenticated generation, phrase revision, canonical record digest, exclusive owner evidence, process instance, and a fresh nonce. Immediately before authorization or key use, the Key Agent consumes that lease and freshly reloads the exact protected record; lock, rotation, owner takeover, restart, or replay invalidates it. The Windows library creates the exact inherited request/response pipes, launches the allowlisted LPAC helper, enforces monotonic I/O deadlines and exact response-plus-EOF, and binds held process/file/manifest/profile identity into a fresh transcript. High-risk approval requires a monotonic two-second physical pointer or Space hold. Default executable builds exit 78; the opt-in runtime contract consumes one complete bounded inherited request, invokes the native surface, and writes one exact response without diagnostics. Signed-artifact end-to-end evidence is absent. |
| Secret-input helper | The library has exact prompt/outcome codecs, bounded zeroizing response reads, and a non-persisting native secret surface. Its high-level parent API requires the release-attested restricted launcher and exact manifest-derived Secret Input role, atomically owns separate request/response pipes and the held helper/job, transfers the canonical prompt plus EOF, and performs cancellable/drained bounded response reads through EOF. The proof binds the exact prompt, held file/process/LPAC identity, and a fresh OS-CSPRNG challenge, then permits consumption only for that same prompt. Default executable builds exit 78 and the compiled release policy is absent. Direct-launch parent-identity denial and immutable signed-artifact evidence remain stop-ship. |
| Broker/key agent/Windows boundary | Method schemas, state bounds, typed chain evidence, canonical display derivation, request-hashed one-shot approval, nonce lifecycle, signer self-checks, protected pipe/helper verification, and an opaque verified-response capability exist. The Key Agent now also has a crate-private offline-lifecycle wire/controller: exact magic/version/type/request-ID/sequence/deadline/length framing, fixed 64-byte frames, exact EOF, zero reserved fields, a 64-request controller-activation lifetime across one-shot inherited request channels, and distinct duplicate/replay/out-of-order outcomes. Admission pins the bounded wall-clock remainder to a trusted monotonic `Instant`; every frontend receives the exact absolute expiry. After a frontend returns, only the controller can mint a private-field, non-clone checked-deadline capability, and every service/session mutation must consume it. The same capability owns the trusted clock borrow and rechecks the pinned expiry after KDF/derivation/seal/reseal at the last safe point before durable commit, unlock, or pending-state activation; expiry locks without advancing generation or decrypted state. Its closed command set is status, 12/24-word creation, separate backup display/confirmation stages, open, lock, and confirmed-address lookup; no password, mnemonic, confirmation answers, signing, import/export, or network payload is representable. Status, lock, and confirmed-address access use the owned `OfflineWalletService`. Secret-bearing transitions require a crate-sealed frontend capability that can acquire inputs or present a borrowed view but cannot receive the vault service. Recovery display returns a non-clone, live-session-bound capability without mutation; only the deadline-checked controller may consume it into one pending positions-only confirmation, which lock, restart, cross-stage use, or replay clears or rejects. The compiled capability returns stable `Unavailable` and locks because authenticated Secret Input/Recovery adapters and the inherited channel launcher are not wired. The anti-phishing phrase has a sealed Key Agent-only lifecycle: a five-word OS-CSPRNG cue is first committed as pending and is unavailable to prompts until a trusted exact enrollment confirmation. Rotation is a persisted old-to-new pending ceremony. Loads carry typed authenticated-empty/record state, installation/store/class identity, an exclusive owner generation, exact record digest, and previous/high-water anchor evidence; same-generation equivocation, empty-after-observed, rollback, owner takeover, or ambiguous commits lock the lifecycle. The platform storage layer now reserves `RecordClass::LocalSettings`, but no Key Agent adapter or production settings key provisioning is wired yet; independent settings AEAD key custody, exclusive-owner enforcement, and a release-approved non-rollbackable anchor remain blockers. The launcher uses separate deterministic revision-v1, zero-capability LPAC profiles for manifest-derived Approval and Secret Input roles; the names and derived SIDs differ and callers cannot select the profile role. The launcher verifies every suspended child against its exact expected SID, and the Secret Input/recovery bootstrap independently repeats that check. Both use an exact inherited-handle list, minimal environment, suspended token verification, process mitigations, and a single-process kill-on-close job. The authenticated dual-slot store and encrypted Key Agent journal cover reservation, approval-pending, potentially-signed, signed-unbroadcast, broadcasting, submitted, and broadcast-unknown recovery. Raw transaction bytes remain journal-owned and reach an RPC adapter only through a non-clone lease after `Broadcasting` commits. Production rollback-anchor/key provisioning and signed-artifact helper/network/RPC evidence are absent; the compiled release policy is `None`, so launch and signing remain disabled. |
| Key Agent activation proof | A dormant crate-private Windows seam verifies the manifest-derived Key Agent role and release allowlist before creating a fresh dedicated OS thread. That one thread owns `CreateProcessW`, the first debug event, mapped-image authentication, continuation, and debugger detach. The simultaneously held verifier handle and debug-event image handle must match by volume serial plus all 128 `FILE_ID_INFO` bits; zero volume and all-zero or all-`FF` non-unique IDs fail closed. Only a successful detach plus an exact one-count suspend probe can construct the non-clone detached capability. Both restricted-launch entry points reject the Key Agent role before release evaluation or process creation, so the shared artifact allowlist is not launch-role authority. The detached capability exposes no raw handle or resume operation and terminates/waits the exact process on drop. The module remains private and `COMPILED_RELEASE_POLICY` is `None`; zero-capability Key Agent LPAC provisioning, a Key Agent-only storage ACL, registry-independent helper/profile trust setup, Broker channel, profile/job, protected-settings lease, and signed-artifact evidence are not connected. |
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
STOP-SHIP without an isolated Key Agent and a zeroizing KDF implementation.

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
can mint an opaque non-clone capability. A Windows-only private preparation seam
then consumes that capability by value. It queries volume serial and all 128
`FILE_ID_INFO` file-ID bits from the same already-held file handle and retains
both the admitted artifact and opaque identity in
`PreparedReleaseBrokerSupervisor`. The prepared state is non-cloneable,
redacted under `Debug`, and drop-only. It exposes no path, file, raw handle, PID,
artifact, identity, launch, Job, pipe, channel, process, or thread operation and
allocates none of those activation resources. No path is reopened and no PID is
trusted. This is an inert supervisor typestate handoff, not Broker activation or
an exact mapped-image proof.

`COMPILED_RELEASE_POLICY` remains `None`; the default and all-feature release
binaries therefore remain on the 4900/exit-78 path. A later reviewed slice must
make the exact-image activation supervisor consume the prepared state and must
add signed-install/native-host provenance, process/Job/channel, and negative
release evidence before release use.

### Key Agent activation invariant (STOP-SHIP)

Windows routes debug events to the thread that created the debuggee. The activation
boundary therefore performs `CreateProcessW`, `WaitForDebugEventEx`, image-handle
authentication, `ContinueDebugEvent`, and `DebugActiveProcessStop` on one fresh
dedicated OS thread that owns no other debuggee. The caller cannot contaminate or
consume that worker's event queue.

The first event must be the exact pre-user-mode `CREATE_PROCESS_DEBUG_EVENT` for
the returned PID and primary thread. Its image `hFile` is compared with the
still-held verified artifact by volume serial and the complete 128-bit
`FILE_ID_INFO`. Per [MS-FSCC 2.1.10](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/98860416-1caf-4c80-a9ab-8d61e1ccf5a5),
an all-zero ID means the filesystem does not support that identity and all-`FF`
means a unique ID could not be established; both are rejected rather than
compared. A zero volume serial is also rejected.

While the create event freezes the process, the worker installs exactly one
explicit primary-thread suspend count, continues the event, detaches, then probes
that the count remains exactly one. Only this path may create the private
detached type-state that crosses the thread join boundary. The attached/pending
state stays non-`Send`; the detached wrapper alone is `Send`, is neither `Sync`
nor cloneable, exposes no raw handle or resume API, and may only report redacted
metadata or synchronously terminate/wait on drop.

The three-artifact release allowlist is not launch-role authority. Both generic
restricted-launch entry points reject a manifest-derived Key Agent before
release evaluation or Win32 side effects. Only this private activation module
may create that role.

The dormant supervisor composition now binds that exact-image proof to one
preconfigured two-process kill-on-close root Job, one private request pipe, one
separate private response pipe, and one internally timed one-shot startup nonce.
The activation-owned fresh thread creates the Job and pipes, retains exactly
three short-lived inheritable stdio duplicates plus one borrowed Job handle
through a two-slot `STARTUPINFOEXW` attribute list, and drops those creation-only
capabilities before returning the aggregate. The Job context is checked before
`CreateProcessW`, after exact-image detach while the child is still suspended,
and once more before the aggregate crosses the join. Exactly one active Job
member is required. The aggregate is non-clone, `!Sync`, externally private,
has no raw-handle or resume operation, and aborts the process tree on drop.

**STOP-SHIP (English):** Before this dormant path is armed, the standalone
supervisor must be single-instance and process-wide single-flight for Key Agent
bind/arm. While any of the three ephemeral `HANDLE_FLAG_INHERIT` duplicates
exist, it must perform no other inheriting child creation. Every production
process-creation path must pass through one sealed coordinator, or Key Agent
creation must be isolated in a dedicated launcher process; a module-local mutex
does not coordinate direct or unrelated Win32 process creation.

**릴리스 차단 조건 (한국어):** 이 휴면 경로를 활성화하기 전에 독립 supervisor는
단일 인스턴스여야 하며 Key Agent bind/arm을 프로세스 전역 single-flight로
직렬화해야 합니다. 세 개의 임시 `HANDLE_FLAG_INHERIT` 중복 핸들이 하나라도
존재하는 동안에는 다른 상속형 자식 프로세스를 생성하면 안 됩니다. 모든 운영
프로세스 생성은 하나의 sealed coordinator를 거치거나 Key Agent 생성을 전용
launcher process로 격리해야 하며, 모듈 내부 mutex만으로는 직접 또는 무관한
Win32 프로세스 생성을 통제할 수 없습니다.

This proof remains dormant. It must not be armed until the same capability is
bound to the authenticated Broker protocol, a distinct Key Agent LPAC/profile,
Key Agent-only storage access, the exact startup-nonce exchange, and a live
protected-settings lease, with concurrent/event-contamination, panic, timeout,
cleanup, and signed-artifact tests included in release evidence. Preventing an
external Job assignment after the dormant aggregate returns additionally needs
a standalone supervisor bootstrap and reviewed supervisor process ACL.

Zero-capability Key Agent LPAC/profile provisioning, storage authorization, and
helper trust APIs remain **STOP-SHIP**. The current persistent-store DACL grants
only the TokenUser principal, which does not by itself grant an AppContainer
token access; granting either frontend profile access would expose vault or
settings state to that UI role. A trusted installer/supervisor must provision a
distinct Key Agent profile and narrowly scoped profile-SID storage access, and
must perform any profile, file, certificate-store, or registry-dependent trust
work outside the zero-capability child. Do not add `registryRead`, reuse a
frontend profile, or activate the dormant Key Agent as a workaround.

### Secret Input parent activation invariant (STOP-SHIP)

`COMPILED_PARENT_POLICY` must remain `None`. A process image path and a separately
hashed file handle do not prove that the running process was mapped from that file
object. The policy may become `Some` only after reviewed release evidence proves
all of the following as one fail-closed launch capability:

- a trusted supervisor opens the exact Key Agent artifact without write or delete
  sharing before launch and retains that same handle through the helper session;
- the supervisor binds that held artifact to the exact launched PID and process
  creation time, not merely to an equal path string;
- the same capability binds both inherited request/response pipe peers, the child
  job/profile, and fresh bootstrap nonces to that launched process; and
- adversarial replacement, rename, stale-PID, handle-substitution, and parent-exit
  tests pass against the signed release artifacts.

Path equality from `QueryFullProcessImageNameW` and
`GetFinalPathNameByHandleW` is explicitly insufficient activation evidence.

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
are mandatory. This runtime aggregate is a consistency/version pin; the already
executing wrapper and Windows PowerShell bootstrap must themselves come from
trusted write-protected media. An approved 64-bit Node image requires a fresh
trusted 64-bit Windows PowerShell host.

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
external ceremony requirements.
