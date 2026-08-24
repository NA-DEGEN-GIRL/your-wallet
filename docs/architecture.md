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
| Approval helper | `approval-wire` is the single bounded v2 codec. Its 74-byte parent hello binds an ordinary channel supervisor PID/process/image proof and a distinct logical Key Agent PID/process proof; the 106-byte child hello, 110-byte finish header, bounded request, and 75-byte response retain the existing nonce/transcript framing. The runtime child seals its two stdio objects first, verifies Approval LPAC/Job state, then requires stdio plus all three injected proofs to be five pairwise-distinct exact objects with zero flags. Fresh child-local duplicates of the injected proofs remain authoritative through response write. Pipe PID/session observations bind only to the retained supervisor process, while the logical Key Agent is independently checked for live exact PID, same session, image, fixed `YourWallet.KeyAgent.LPAC.v1` SID, AppContainer/LPAC state, zero capabilities, and least-authority denials. One private zero-caller transition performs parent hello, one exact resume, child hello, and revalidation; a second sealed zero-caller transition consumes that bootstrap and the exact request under one monotonic transport deadline, writes finish plus request and EOF, verifies the fixed response plus EOF, requires the exact held child to exit naturally with code 0 before that same deadline, and finally revalidates the Key Agent. Its crate-private opaque `VerifiedParentBoundApprovalExchange` has no response or signing conversion. The ordinary supervisor remains transport authority and the Key Agent remains only the logical parent. The legacy launcher fails closed before resource allocation because it lacks the complete logical-parent aggregate. Transferable pipe handles, mapped-image provenance, signed immutable installation and DLL graph, a distinct supervisor principal, process/thread creation-time DACLs, endpoint topology/exclusivity and per-write attribution, signed cleanup, a positive real-binary handshake, production composition through signing, and opaque transport delivery/enforcement of the original monotonic expiry already retained by `PreparedAuthorization` remain **STOP-SHIP**. `COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` remain `None`, so default builds exit 78. |
| Secret-input helper | The library has exact prompt/outcome codecs, bounded zeroizing response reads, and a non-persisting native secret surface. Its high-level parent API requires the release-attested restricted launcher and exact manifest-derived Secret Input role, atomically owns separate request/response pipes and the held helper/job, transfers the canonical prompt plus EOF, and performs cancellable/drained bounded response reads through EOF. The proof binds the exact prompt, held file/process/LPAC identity, and a fresh OS-CSPRNG challenge, then permits consumption only for that same prompt. Default executable builds exit 78 and the compiled release policy is absent. Direct-launch parent-identity denial and immutable signed-artifact evidence remain stop-ship. |
| Broker/key agent/Windows boundary | Method schemas, state bounds, typed chain evidence, canonical display derivation, request-hashed one-shot approval, nonce lifecycle, signer self-checks, protected pipe/helper verification, and an opaque verified-response capability exist. The Key Agent now also has a crate-private offline-lifecycle wire/controller: exact magic/version/type/request-ID/sequence/deadline/length framing, fixed 64-byte frames, exact EOF, zero reserved fields, a 64-request controller-activation lifetime across one-shot inherited request channels, and distinct duplicate/replay/out-of-order outcomes. Admission pins the bounded wall-clock remainder to a trusted monotonic `Instant`; every frontend receives the exact absolute expiry. After a frontend returns, only the controller can mint a private-field, non-clone checked-deadline capability, and every service/session mutation must consume it. The same capability owns the trusted clock borrow and rechecks the pinned expiry after KDF/derivation/seal/reseal at the last safe point before durable commit, unlock, or pending-state activation; expiry locks without advancing generation or decrypted state. Its closed command set is status, 12/24-word creation, separate backup display/confirmation stages, open, lock, and confirmed-address lookup; no password, mnemonic, confirmation answers, signing, import/export, or network payload is representable. Status, lock, and confirmed-address access use the owned `OfflineWalletService`. Secret-bearing transitions require a crate-sealed frontend capability that can acquire inputs or present a borrowed view but cannot receive the vault service. Recovery display returns a non-clone, live-session-bound capability without mutation; only the deadline-checked controller may consume it into one pending positions-only confirmation, which lock, restart, cross-stage use, or replay clears or rejects. The compiled capability returns stable `Unavailable` and locks because authenticated Secret Input/Recovery adapters and the inherited channel launcher are not wired. The anti-phishing phrase has a sealed Key Agent-only lifecycle: a five-word OS-CSPRNG cue is first committed as pending and is unavailable to prompts until a trusted exact enrollment confirmation. Rotation is a persisted old-to-new pending ceremony. Loads carry typed authenticated-empty/record state, installation/store/class identity, an exclusive owner generation, exact record digest, and previous/high-water anchor evidence; same-generation equivocation, empty-after-observed, rollback, owner takeover, or ambiguous commits lock the lifecycle. The platform storage layer now has a narrow private fixed-role Key Agent generation-store adapter, but no production protected-settings consumer or settings key provisioning is wired yet; independent settings AEAD key custody, exclusive-owner enforcement, and a release-approved non-rollbackable anchor remain blockers. The launcher uses separate deterministic revision-v1, zero-capability LPAC profiles for manifest-derived Approval and Secret Input roles; the names and derived SIDs differ and callers cannot select the profile role. The launcher verifies every suspended child against its exact expected SID, and the Secret Input/recovery bootstrap independently repeats that check. Both use an exact inherited-handle list, minimal environment, suspended token verification, process mitigations, and a single-process kill-on-close job. The authenticated dual-slot store and encrypted Key Agent journal cover reservation, approval-pending, potentially-signed, signed-unbroadcast, broadcasting, submitted, and broadcast-unknown recovery. Raw transaction bytes remain journal-owned and reach an RPC adapter only through a non-clone lease after `Broadcasting` commits. Production rollback-anchor/key provisioning and signed-artifact helper/network/RPC evidence are absent; the compiled release policy is `None`, so launch and signing remain disabled. |
| Key Agent activation proof | A dormant crate-private Windows seam verifies the manifest-derived role, exact image, zero-capability LPAC token, Job, pipes, and independently prepared supervisor-held fixed root before detaching with one proven suspend count. Fresh profile/root creation remains a distinct non-launchable pending path. A separate dormant storage-only opener, with zero production callers, opens only the fixed existing leaf using `OPEN_EXISTING`, `FILE_FLAG_OPEN_REPARSE_POINT`, and no delete sharing; it verifies initial security and complete `FILE_ID_INFO`, canonicalizes and reopens the path, requires identical security and identity, privately retains the canonical path/reopened handle, and revalidates both the held handle and canonical reopen. It neither creates nor repairs/deletes/adopts the root and is distinct from the child `LOCALAPPDATA`/token-derived opener. It cannot observe profile registration or construct `HeldExistingKeyAgentInstallObjects`, `PreparedKeyAgentProvisioning`, or `VerifiedExistingKeyAgentInstall`. The sole production-compiled prepared mint remains the private sealed adoption transition; whole-release binding retains helper-manifest and exact file-object proofs separately, but the opener, adoption transition, release-binding, and dormant supervisor binder all have zero production call sites. The one-shot child/root transcript requires exact request EOF before the child detaches both ambient protocol entries and closes raw stdin; raw stdout survives only in a response capability. Once response output is attempted, write/flush/close results cannot return to `main` and the child enters `Sleep(INFINITE)`. The parent's deadline-bound exact response plus EOF authoritatively proves response-endpoint closure; separate resident-process/Job revalidation completes startup. The parent consumes both endpoints and the retained aggregate has none. This dormant boundary exposes no generic runtime/signing IPC. Production installer key/checkpoint and journal I/O backends, authoritative profile-registration observation and held-aggregate construction, an exclusive installer lease covering checkpoint/observation/reread ordering, production call sites and recovery, atomic same-user/ancestor race closure, rollback-anchor and storage/AEAD-key provisioning, protected settings/lease wiring, authenticated Broker/supervisor topology and single-instance enforcement, signed immutable artifact/DLL/dependency E2E, and release activation remain **STOP-SHIP**; `COMPILED_RELEASE_POLICY` is `None`. |
| Dormant Approval/Key Agent logical-parent binding | One private non-clone binding transition consumes the complete release-prepared Approval artifact and intact storage-proven Key Agent and retains a fresh `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` duplicate of that same running Key Agent process without PID reopen. A separate consuming transition launches Approval suspended with the ordinary supervisor proofs, injects the retained capability as the fifth logical-parent proof, and retains the full aggregate. A further sealed, consuming, zero-caller transition writes the complete v2 parent hello before resuming the exact primary thread once, reads/decodes the child hello, and revalidates the running child, Job, and parent-bound aggregate. Only another sealed zero-caller transition may consume that opaque bootstrap with the exact request. It uses one monotonic transport deadline for arming, finish/request plus request EOF, fixed response plus response EOF, and natural child exit; response EOF alone remains exit-pending. The exact held child must exit naturally with code 0 before evidence, final Key Agent revalidation occurs after that exit, and only then is opaque `VerifiedParentBoundApprovalExchange` minted. It has no response/signing/raw-resource accessor or conversion. Early protocol failure and failed natural-exit observation use bounded terminate/reap with cleanup-error precedence; successful evidence is never manufactured by force-terminating a live child. Drop retains kill-on-close fallback without claiming unconditional reap success. Repo-local kernel tests cover the exact query/synchronize process proof, `TOKEN_QUERY` access to its token, and enumerated stronger-right denial, but the logical proof is not Windows process parentage, mapped-image proof, signed release evidence, or runtime readiness. Both compiled policies remain `None`. Resampling request-relative expiry after bootstrap can let the transport/UI evidence window outlive the original authorization session, which still rejects at its retained expiry; opaque delivery and transport enforcement of that cap before signing are **STOP-SHIP**. |
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

Only after that mapped-image proof succeeds, and while the create event still
freezes every process thread, the worker installs exactly one explicit
primary-thread suspend count and verifies the exact process token. The proof
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

Only the verified LPAC state may continue the event and detach. The worker then
probes that the explicit count remains exactly one. Only this path may create
the private detached type-state that crosses the thread join boundary. The
attached/pending state stays non-`Send`; the detached wrapper alone is `Send`,
is neither `Sync` nor cloneable, and exposes no raw handle or generic resume
API. Its only consuming execution transition releases that one count for the
fixed storage-startup proof described below; otherwise it may only report
redacted metadata. When the enclosing aggregate drops, this wrapper's bounded
cleanup attempt precedes retained kill-on-close Job closure; Drop cannot report
synchronous cleanup failure.

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
consumer creates the fixed two-object Approval stdio boundary and exact Approval
process in the revision-v1 LPAC and single-process Job, but leaves the primary
thread suspended. It preserves the existing channel-supervisor process/image
proof and separately copies the narrow Key Agent handle into the child as a
fifth non-inheritable logical-parent capability. The resulting
`BoundDormantApproval` owns the process, thread, Job, unused parent endpoints,
and complete parent-bound aggregate, exposes no direct resume/request/response/signing
or resource accessor, and attempts bounded Approval termination and reap before
releasing the pipes and Key Agent tree. This outer transition has zero
production callers.

One further sealed consuming transition writes the exact version-2 parent hello
before releasing exactly one primary-thread suspend count, reads and decodes the
exact child hello, and revalidates the live child/Job and intact parent-bound
aggregate. Its opaque `AuthenticatedApprovalBootstrap` retains the running
Approval, unused endpoints, both hellos, and the full Key Agent aggregate. It
has no protocol method; only one separate sealed function may consume it with
the exact `ApprovalRequest`. The transition has zero production callers.

That full-exchange function samples one monotonic transport deadline from the
request's relative expiry and uses it for response arming, the consuming
finish-plus-request write and request EOF, the fixed response and response EOF,
and the exact held child's natural-exit wait. It revalidates child/Job and Key
Agent state before arming and before reading the response. The verified response
remains exit-pending until the exact process exits naturally with code 0 before
the same deadline. No success evidence is manufactured by terminating a live
child. Final Key Agent revalidation occurs only after that successful exit,
followed by one last observation of the same deadline. Only then does the
transition mint crate-private opaque `VerifiedParentBoundApprovalExchange`,
which retains the exited child, intact parent-bound aggregate, both hellos, and
sealed response evidence but exposes no response or signing conversion. This
transition also has zero production callers. The post-exit Key Agent check is
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
`SeDebugPrivilege` LUID is absent. Before resume, production Key Agent activation
successfully installs a protected three-ACE token DACL for the stable user
`TOKEN_ALL_ACCESS`, the Key Agent SID `TOKEN_QUERY | TOKEN_DUPLICATE`, and the
Approval SID exactly `TOKEN_QUERY`. The `cfg(test)` integration executes that
production-compiled hardening and proves the Approval query-only outcome.
Ordinary LPAC/token attributes are verified before and after installation; this
slice does not read back the token security descriptor.

The current exchange reconstructs its transport deadline by adding the wire
request's relative expiry to `Instant::now()` at full-exchange start. If the
request came from a `PreparedApprovalPrompt` created before bootstrap, the
transport/UI window and terminal evidence mint can outlive the original session
by the elapsed bootstrap interval. The existing authorization TCB still rejects
at that original expiry.
The prompt already retains that original monotonic `Instant` through its
`PreparedAuthorization`, but the parent-bound transport neither receives nor
enforces it. Delivering that expiry without making it caller-controlled and
capping transport by it before any signing composition is **STOP-SHIP**.

That is repo-local kernel feasibility evidence, not release evidence. The
Approval fixture does not directly read back the copied image's mandatory-label
state. Its test-only mitigation removes exactly the `NO_LOW_LABEL` bit to permit
the profile-scoped copy; production mitigation remains unchanged. A
signed/mapped exact image, complete
DLL/dependency provenance, a distinct supervisor principal, same-user owner
separation, protected process/thread DACLs supplied at creation, endpoint
topology/exclusivity, signed-artifact cleanup evidence, and production composition/signing remain
**STOP-SHIP**. The production binder still has zero callers and both compiled
policies stay `None`.

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
user-local-data base, and prepends it as `LOCALAPPDATA` for Windows to rebase
inside the AppContainer. Each final environment contains exactly
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
OS-managed `AC` folder, and applies a protected DACL granting the current user
full access and only the fixed profile SID read/execute. The kernel-only
provisioning seam likewise reuses that persistent test profile and creates a
separate CSPRNG-named storage leaf. Drop removes only those exact test objects;
it neither changes the workspace image ACL nor deletes the persistent profile.
Together with the one-shot startup test this proves repo-local child opening and
binding of that exact test root. It does not prove the production fresh fixed
profile/root, install root, or exact signed artifact end to end.

The dormant supervisor composition initially binds that exact-image proof to one
preconfigured two-process kill-on-close root Job, one private request pipe, one
separate private response pipe, and one internally timed one-shot startup nonce.
The activation-owned fresh thread creates the Job and pipes, acquires the shared
flight up to the startup-lease deadline, and creates exactly three short-lived
inheritable stdio duplicates plus one borrowed Job handle through an exact
four-slot `STARTUPINFOEXW` attribute list: `HANDLE_LIST`, `JOB_LIST`,
`SECURITY_CAPABILITIES`, and `ALL_APPLICATION_PACKAGES_POLICY`. The attribute
list retains its three-handle array, Job value, profile SID, and both LPAC values
through `CreateProcessW`; it is then deleted and all three duplicates close
before the flight is released and mapped-image authentication begins. The Job
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
The integrated kernel fixture has two explicit `cfg(test)` accommodations: its
reader consumes only the pinned terse libtest preamble before the exact response,
and its Job topology permits only the fixture plus at most the exact
`GetSystemDirectoryW` `conhost.exe`. Production requires response magic at byte
zero and exactly one Job member; neither test accommodation is release evidence.

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
zero production callers. The latter requires finish/request EOF, fixed
response/EOF, natural child exit code 0, and post-exit final Key Agent
revalidation before minting opaque `VerifiedParentBoundApprovalExchange`, but
it provides no public verified-response or signing conversion and no positive
signed-handshake E2E. The prompt's `PreparedAuthorization` retains its original
monotonic expiry, but opaque transport delivery and enforcement of that cap
rather than relative-expiry resampling after bootstrap remain a **STOP-SHIP**
prerequisite for signing.

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
