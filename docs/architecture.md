# Architecture and trust boundaries

This repository is an incomplete implementation of a self-only Windows 11 and
Chrome private-mainnet canary. It is not authorized for public distribution,
high-value use, or real-mainnet funds.

## Current implementation status

**Release status: STOP-SHIP.** The diagram and trust rules below are target
invariants, not a claim that the current binaries establish every boundary.

| Component | Current evidence and limitation |
| --- | --- |
| MV3 extension | Strict top-level HTTPS routing, exact 128-bit request IDs, bounded envelopes/state, deadline checks, freeze/navigation cancellation, replay handling, and incognito rejection have unit tests. The native backend is unavailable. |
| Native host | The library enforces bounded framing, strict JSON structure, and the exact version-1 extension envelope. In this development tree a valid request receives stable provider error 4900 and the process exits with code 78 because no release-attested broker transport is injected; it never falls through to signing or RPC. |
| Approval helper | `approval-wire` is the single bounded v2 codec used by the authorization TCB, Key Agent, Windows channel, and native frontend. The Key Agent creates one crate-private, non-clone `PreparedApprovalPrompt`; its exact digest, nonce, sampled expiry, locally protected anti-phishing phrase, risk, and every display field are request-hashed and retained across the interaction. The prompt additionally carries a one-shot protected-settings lease bound to the authenticated generation, phrase revision, canonical record digest, exclusive owner evidence, process instance, and a fresh nonce. Immediately before authorization or key use, the Key Agent consumes that lease and freshly reloads the exact protected record; lock, rotation, owner takeover, restart, or replay invalidates it. The Windows library creates the exact inherited request/response pipes, launches the allowlisted LPAC helper, enforces monotonic I/O deadlines and exact response-plus-EOF, and binds held process/file/manifest/profile identity into a fresh transcript. High-risk approval requires a monotonic two-second physical pointer or Space hold. Default executable builds exit 78; the opt-in runtime contract consumes one complete bounded inherited request, invokes the native surface, and writes one exact response without diagnostics. Signed-artifact end-to-end evidence is absent. |
| Secret-input helper | The library has exact prompt/outcome codecs, bounded zeroizing response reads, and a non-persisting native secret surface. Its high-level parent API requires the release-attested restricted launcher and exact manifest-derived Secret Input role, atomically owns separate request/response pipes and the held helper/job, transfers the canonical prompt plus EOF, and performs cancellable/drained bounded response reads through EOF. The proof binds the exact prompt, held file/process/LPAC identity, and a fresh OS-CSPRNG challenge, then permits consumption only for that same prompt. Default executable builds exit 78 and the compiled release policy is absent. Direct-launch parent-identity denial and immutable signed-artifact evidence remain stop-ship. |
| Broker/key agent/Windows boundary | Method schemas, state bounds, typed chain evidence, canonical display derivation, request-hashed one-shot approval, nonce lifecycle, signer self-checks, protected pipe/helper verification, and an opaque verified-response capability exist. The Key Agent now also has a crate-private offline-lifecycle wire/controller: exact magic/version/type/request-ID/sequence/deadline/length framing, fixed 64-byte frames, exact EOF, zero reserved fields, a 64-request controller-activation lifetime across one-shot inherited request channels, and distinct duplicate/replay/out-of-order outcomes. Admission pins the bounded wall-clock remainder to a trusted monotonic `Instant`; every frontend receives the exact absolute expiry. After a frontend returns, only the controller can mint a private-field, non-clone checked-deadline capability, and every service/session mutation must consume it. The same capability owns the trusted clock borrow and rechecks the pinned expiry after KDF/derivation/seal/reseal at the last safe point before durable commit, unlock, or pending-state activation; expiry locks without advancing generation or decrypted state. Its closed command set is status, 12/24-word creation, separate backup display/confirmation stages, open, lock, and confirmed-address lookup; no password, mnemonic, confirmation answers, signing, import/export, or network payload is representable. Status, lock, and confirmed-address access use the owned `OfflineWalletService`. Secret-bearing transitions require a crate-sealed frontend capability that can acquire inputs or present a borrowed view but cannot receive the vault service. Recovery display returns a non-clone, live-session-bound capability without mutation; only the deadline-checked controller may consume it into one pending positions-only confirmation, which lock, restart, cross-stage use, or replay clears or rejects. The compiled capability returns stable `Unavailable` and locks because authenticated Secret Input/Recovery adapters and the inherited channel launcher are not wired. The anti-phishing phrase has a sealed Key Agent-only lifecycle: a five-word OS-CSPRNG cue is first committed as pending and is unavailable to prompts until a trusted exact enrollment confirmation. Rotation is a persisted old-to-new pending ceremony. Loads carry typed authenticated-empty/record state, installation/store/class identity, an exclusive owner generation, exact record digest, and previous/high-water anchor evidence; same-generation equivocation, empty-after-observed, rollback, owner takeover, or ambiguous commits lock the lifecycle. The platform storage layer now reserves `RecordClass::LocalSettings`, but no Key Agent adapter or production settings key provisioning is wired yet; independent settings AEAD key custody, exclusive-owner enforcement, and a release-approved non-rollbackable anchor remain blockers. The launcher uses separate deterministic revision-v1, zero-capability LPAC profiles for manifest-derived Approval and Secret Input roles; the names and derived SIDs differ and callers cannot select the profile role. The launcher verifies every suspended child against its exact expected SID, and the Secret Input/recovery bootstrap independently repeats that check. Both use an exact inherited-handle list, minimal environment, suspended token verification, process mitigations, and a single-process kill-on-close job. The authenticated dual-slot store and encrypted Key Agent journal cover reservation, approval-pending, potentially-signed, signed-unbroadcast, broadcasting, submitted, and broadcast-unknown recovery. Raw transaction bytes remain journal-owned and reach an RPC adapter only through a non-clone lease after `Broadcasting` commits. Production rollback-anchor/key provisioning and signed-artifact helper/network/RPC evidence are absent; the compiled release policy is `None`, so launch and signing remain disabled. |
| Key Agent activation proof | A dormant crate-private Windows seam verifies the manifest-derived Key Agent role and release allowlist before creating a fresh dedicated OS thread. That one thread owns `CreateProcessW`, the first debug event, mapped-image authentication, continuation, and debugger detach. The simultaneously held verifier handle and debug-event image handle must match by volume serial plus all 128 `FILE_ID_INFO` bits; zero volume and all-zero or all-`FF` non-unique IDs fail closed. Only a successful detach plus an exact one-count suspend probe can construct the non-clone detached capability. Both restricted-launch entry points reject the Key Agent role before release evaluation or process creation, so the shared artifact allowlist is not launch-role authority. The detached capability exposes no raw handle or resume operation and terminates/waits the exact process on drop. The module remains private and `COMPILED_RELEASE_POLICY` is `None`; zero-capability Key Agent LPAC provisioning, a Key Agent-only storage ACL, registry-independent helper/profile trust setup, Broker channel, profile/job, protected-settings lease, and signed-artifact evidence are not connected. |
| Device key protection | The crate-private model generates epoch-1 installation bundles with six pairwise-distinct role secrets and releases them only through role-typed views after an anchored open. Rotation preserves the installation ID, advances the key epoch exactly once, rekeys every role, and remains pending until opaque external evidence binds the exact predecessor commitment to the exact new canonical signed envelope at a strictly newer shared-anchor generation. RSA-3072 OAEP-SHA-256/empty-label and low-S P-256 P1363 identities hash one canonical RFC 5280 SPKI form; CNG blobs are adapter-internal inputs only. The raw identity constructors and sealing markers are private to the key-material module, and the architecture gate scans every production Rust source under `key-agent` for an unreviewed PCP implementation. No production PCP or rollback-anchor adapter exists, so this path remains fail-closed and release-blocking. |

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
