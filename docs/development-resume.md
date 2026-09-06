# Development checkpoint — 2026-09-06

The standalone desktop service probe and unsigned operator harness are
implemented on top of Phase 3D. Their committed-snapshot tests, the complete architecture
scan and actual preparation passed. Product and
release remain STOP-SHIP; automated checks are not installed-service or
signed-helper evidence.

## Current live checkpoint

The user has now supplied the elevated Inspect report: all 32 non-status
observations PASS, cleanup PASS and report COMPLETE, but service status OTHER.
The current implementation groups states 3, 5, 6 and 7 into OTHER; it does not
distinguish STOP_PENDING from continue/pause states. This is read-only inspection,
not ownership-bound mutation authority or proof of cleanup/startup. A read-only
elevated `sc.exe queryex YourWalletKeyAgent` report has been requested. Do not
retry Stop/Remove/Install/Start, run a client, or use a pending-state PID as a
termination target before the precise state is understood.

Independent source review found an unreported-termination defect shared by the
installed old service and the prepared `7916943` source: a quick failed drain
finishes/cancels the progress watchdog, then returns from ServiceMain without
STOPPED. The binary's exit occurs only after StartServiceCtrlDispatcher returns,
but that dispatcher waits for all services to enter STOPPED. Returning from
ServiceMain alone does not stop the service. Registration failure, retained
startup and failed final status publication have analogous unreported-return
paths. See [dispatcher completion](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw)
and [ServiceMain thread lifetime](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nc-winsvc-lpservice_main_functionw).
This is a code-path defect, not proof that the observed OTHER used this path.
The narrow explicit-completion/fail-fast correction is now implemented and
verified. A private move-only `StoppedReported` permits the four callbacks to
return only after successful final STOPPED reporting after cleanup. Registration
failure, retained startup, uncertain cleanup or failed final reporting abort the
fixture's own process instead. No successful cleanup, STOPPED or auth diagnostic
is fabricated. Authentication, privileges, wire behavior, dormant lifecycle
authority and default/release facade gates are unchanged.

Current correction verification, all native exit 0: full `scripts/check.ps1 test`
with platform 1024 passed/47 existing ignored, demo 266, extension 33, native
harness 139, actual architecture CLI 24 and preparation/operator CLI 20; fmt,
lint, typecheck and final privacy (seven tests plus source scan);
default/desktop-only/release-all-feature binary fallback
two tests each; release probe unit tests 17. Four added tests include a 64-case
child-process terminal matrix, exact abort-control status comparison, zero/one
report checks, hidden child creation and a parent-owned bounded kill/reap guard.
The intentional callback-return-only negative stays blocked in the simulated
dispatcher until the parent watchdog fires; corrected paths must finish without
that watchdog. Registration/retained-startup tests model the shared failure sink,
not real SCM calls. Focused tests passed in 181.86 seconds; the final platform
suite, including hidden child creation, passed in 184.07 seconds.

The one final no-argument architecture scan passed in 325285 milliseconds,
progressing through 672 checks. New termination family: 8 checks/20 effective
negatives; prior runtime-auth 17/39 and startup 14/50 remain active, together
with all historical lifecycle/Phase-one mutations. The current 182-file Rust
closure is `0e29ac67222b64319b5c0be5515c12788654f4b91892b64d3b2d0eddb7dcf9c6`;
scanner SHA256 is `6c871e8bd4587e4245ba969403db31cd6367cf79f7a60a6773c699f894a76a83`.

The prior `7916943` candidate was strictly verified against its recorded hashes,
scope-checked and moved without overwrite to
`artifacts/service-probe-candidate-before-unreported-stop-fix-7916943`.
Held canonical-manifest/all-four-file readback matched before and after. Fresh
unelevated preparation and independent strict held readback then passed for the
new `artifacts/service-probe-candidate`. Its canonical manifest SHA256 is
`ad2ba7a01785711854421b08b48eb6bf3006549e5c1113c0630d4455ed89e03d`;
service SHA256 is
`b5a7a4fba1c3b4a9324af33f97719ae4c18f45e79eb827f22598ec7db7726316`.
This new candidate combines runtime-auth diagnostics with the termination fix.
The installed fixture was not changed and no actual service/RPC/UI request was
made by these tests. The user's exact queryex result is still pending: do not
apply the candidate or retry Stop/Remove until the retained state is understood.

Latest operator attempt after preparing `7916943`: the user reported only
`SERVICE_PROBE_FAILED_STATE_RETAINED_FOR_REVIEW` from the guarded
Stop/Remove/Install/Start line. If that is the complete output, Stop did not
return PASS and the later actions were not invoked. This does not locate the
failure or prove that Stop had no effect. Do not repeat the replacement line.

Read-only checks on 2026-09-06 found the agent token still non-elevated; direct
fixed-service SCM query returned access denied (native 5), and fixed-name CIM
returned no unique row, which is not absence evidence. The bounded 48-hour
fixed-service System event query returned 11 historical observations only:
newest installation event was 2026-09-05T16:39:45Z, and newest failure remained
the superseded `0x5008` event. No new failure stage or current status is proven.
Source review confirms the service handle includes STOP/query rights, and Stop
validates the installed manifest/journal rather than comparing against the new
workspace candidate. Neither a missing STOP access bit nor the expected old/new
candidate hash difference explains this report. No operator/RPC action or code
change was made during those read-only checks. The later user-run Inspect is
recorded above; precise queryex status remains the next operator input.

The user applied the corrected `b3bb834` candidate and reported Remove, Install
and **Start PASS_NOT_RELEASE_EVIDENCE**. Startup is now observed to succeed;
do not repeat replacement or diagnose the historical `0x5008` as a current
failure. The installed service remains unchanged. Its matched workspace
candidate is now preserved in the runtime-diagnostic archive recorded below.

The agent then strictly verified the candidate and ran its non-signing client
exactly once from the eligible unelevated preparation context, with the client
file held read-only. It returned exactly
`SERVICE_APPROVAL_TRANSPORT_UNAVAILABLE`, native exit 78, in 168 ms. This
establishes a client failure, not its stage or whether a window appeared.
No completion/response or signing evidence was obtained. A bounded read-only
SCM query returned historical failure events only; a fixed-executable Application
crash query returned no observations, which is not proof of absence of a crash.

The binary source now preserves the library's six safe error categories as a
second fixed line after the original unavailable marker. An explicitly ignored,
feature-gated native preflight test observes only its own process without RPC.
Verify the workspace-only diagnostic build before another deliberate attempt;
do not rebuild/replace the installed service just for client diagnostics.

That exact ignored native preflight passed (one test, native exit 0). The newly
reviewed client then passed strict Cargo artifact provenance and held-file
verification and ran exactly once: `FAILURE_CATEGORY=TRANSPORT`, native exit 78,
155 ms. The original candidate passed strict readback before and after and was
not modified. A separate ignored native binding-setup test also passed (one
test, native exit 0); it composes/configures and drops only a local binding,
without issuing a request. Neither current query proves the earlier process's
observations. TRANSPORT still combines binding setup and RPC exchange failure;
it is not a correlated server `Unavailable` response or helper-completion result.

One further explicitly ignored, opening-only native diagnostic was independently
reviewed and run in a fresh dedicated test process after exact Cargo JSON artifact
verification. Its executable and directories were held against replacement, and
the owning parent imposed a 25-second kill-and-reap bound with asynchronous output
draining. The test sent exactly one canonical V2 OpenEpoch and no command/helper
request, preserving the original five-second deadline through binding cleanup.
It failed with only the closed category `AccessDenied`, native test exit 101, in
406 ms. The watchdog did not fire. This proves denial on this opening attempt,
not the earlier client's exact stage or the denied server predicate. Callback
failures are collapsed to access denied; a previous fatal callback observation
could already have closed admission while SCM remains running. No further live
request or operator mutation has been made. A successful opening would retain
bounded remote epoch/token state, so this test is not read-only and cannot prove
remote cleanup. Investigate service-side failure observability next; do not guess
an ACL grant or relax authentication to clear this result.

### Remaining RPC diagnosis boundary

No service-side per-attempt cause is persisted or queryable in the installed
`b3bb834` candidate. The existing `Status` result is deliberately unavailable,
and its SCM startup codes do not expose runtime authentication failures. The
first-wins diagnostic described below is now implemented and prepared, but has
not been applied to that installation. Acceptance, callback/manager independence,
exact process/token correlation, deadlines and cleanup remain unchanged.
Do not claim that client instrumentation alone fixes the RPC refusal.

Cross-account access is a hypothesis, not the observed failed predicate:
`authenticate_identity_with` opens the caller process before RPC impersonation;
later revalidation opens its primary token again after reversion. Both operations
are independently DACL-checked ([OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess),
[OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)).
Current-user tests cannot establish access for the restricted service account.
Moving only the first open or granting Debug would not validate that chain.

An unregistered fixed EventLog source can fall back to Application, but this
service's actual write access is not guaranteed and the APIs are synchronous.
No EventLog API, source registration, ACL/LSA grant or background reporting
worker was added. The new existing-SCM-channel path separates observed runtime
failure from proven resource cleanup: drain
errors deliberately suppress STOPPED, and RUNNING exit/checkpoint fields must
not be repurposed as diagnostics. Neither absent logs nor process termination
proves which authentication check failed or that remote resources were reaped.

### Prior `7916943` runtime-auth checkpoint

New source adds a closed per-call observer around the existing auth operations;
the policy/identity/reversion algorithm and native adapter are unchanged. It
delegates each observation once, retains only the first failed operation category,
and preserves the original `RpcAuthError`. A rejection with no failed native
observation is classified as `PolicyOrContinuity`. Repeated observations of the
same operation remain grouped; the code does not invent the exact repeated call
or native error. Existing unsafe-reversion fail-fast behavior is retained.

The LPAC debug service records the first failure across calls, then closes
admission and requests the existing bounded shutdown. Callback stage offsets
1..15 map to `0x6001..0x600f`; manager offsets map to `0x6101..0x610f`.
The exact table is in `scripts/service-probe/README.md`. Only clean RPC rundown,
coordinator/helpers stop, exact context removal, progress-thread completion and
event close allow a terminal SCM diagnostic. A separate monotonic unrelated-fatal
latch prevents a concurrent or later cleanup/internal error from being excused
by a previously captured auth category. Legacy drain and non-LPAC behavior retain
their original failure semantics. No new log sink, native API, permission, wire
command or retry is introduced.

The fixture intentionally stops on its first auth rejection; no automatic
restart is added. A caller refused before entering auth, an admission refusal,
or a router/helper failure may still yield no auth report. This first caller is
not necessarily the intended client, and the diagnostic is not identity or
release evidence. No new actual service, RPC, UI or operator run was performed
for this implementation checkpoint; the previously observed AccessDenied is
still unresolved.

The frozen source passed the full `scripts/check.ps1 test`, fmt, lint, typecheck
and privacy targets, each with native exit 0. Platform: 1020 passed, 47 ignored;
demo: 266; extension: 33; helper: 69; native harness: 139; preparation/operator
CLI: 20; actual architecture CLI: 24. The 18 new tests are ordinary non-ignored
tests. Focused auth diagnostics: 9; RPC module: 24 passed/one existing ignored;
SCM: 13; default, debug-desktop and release-all-feature binary fallback: two
each; release probe unit tests: 17. Separate release JS tests: 66 passed; both
PowerShell release-helper sentinels passed. An initial release-helper invocation
omitted the required `-NoLogo`/`-NonInteractive` host flags and correctly failed
bootstrap; the exact reviewed invocation passed without a source/policy change.

The single final no-argument architecture scan passed with native exit 0 and
progress through 672 checks. New runtime diagnostics: 17 predicates and 39
effective negative mutations; startup diagnostics retain 14 predicates and all
50 negatives. Existing lifecycle/Phase-one/auth checks and historical mutations
remain active. The 182-file Rust compilation closure is
`2d18db41d61f201c419313b63ac5a46fadea25177f1c9d5730c4a0db647f3e73`;
scanner SHA256 is
`9ea347c788052ad4ee9010c9f2b141ad26d061959fa78fb87d48aa6242c1b2dc`.

Before fresh preparation, the exact prior candidate was scope-checked and moved
without overwrite to
`artifacts/service-probe-candidate-before-runtime-auth-diagnostics-b3bb834`.
Held canonical-manifest and all-four-artifact verification passed before and
after the move with the same manifest digest. Fresh unelevated `prepare.ps1`
passed, followed by independent strict held inventory, single-link, size, hash
and canonical-manifest readback. The new `artifacts/service-probe-candidate`
contains both client failure categories and service runtime-auth diagnostics.
Its canonical manifest SHA256 is
`765e6cf2833904676c939f774c2c2862cd1f8ce645a0f1cef6fb5d8cc3f148a0`;
its service SHA256 is
`423d26f661438ff5a48fbce2e9218c047beb62c0b790e6e489677b804d31c994`.
These are the prior `7916943` candidate hashes; that candidate is now archived
as recorded above. They are not the current candidate or installed-runtime evidence.
No installed-file, LSA/ACL, acceptance, signing, mnemonic or private-key change
was made during preparation. The subsequent user-run replacement failed as
recorded at the top; read-only Inspect is now required before resuming that
workflow. No automatic elevation or restart is authorized by these tests.

### Prior `0039995` diagnostic checkpoint

The frozen diagnostic source passed `scripts/check.ps1 test`, fmt, lint,
typecheck and privacy, each with native exit 0. Platform: 1002 passed, 47 ignored
(the previous 44 plus three explicit native diagnostic opt-ins); demo: 266;
extension: 33; native harness: 139; operator/preparation CLI: 20; architecture
actual CLI: 24. Default/debug-desktop/release-all-feature binary matrices passed
17+2, 18+2 and 17+2 respectively. Separate 66-case release-policy checks were not
rerun in this checkpoint; their source is unchanged.

An earlier standalone platform invocation failed one loader test because it
omitted `YW_TEST_KEY_AGENT_EXECUTABLE` setup (1001 passed, one failed, 47 ignored,
native 101). The proper harness built and selected the exact required executable;
the same loader test then passed without changing its source or suppressing it.
This harness-setup failure is separate from the real AccessDenied diagnostic.

The single final no-argument architecture scan passed, native exit 0, in 256.477
seconds, reporting progress through 672 checks. Desktop contract: 20 predicates
and 86 negative mutations, preserving all previous 35. Auth/binding production
bodies and native adapters remain unchanged. The exact 182-file Rust closure is
`d1fca017192b7d48b82b0516660bdb815ecc35141c38d2af7f0ddb85893c1b60`;
scanner SHA256 is
`66e63785425619290bf24b927582c3548e421ad5113cd779105fd6b924e29cf6`.
Final strict workspace-candidate readback passed; it is not a new installed-image
readback. No candidate rebuild, installed-file write, operator action, LSA/ACL
change, signing, auto-click or mnemonic/private-key fixture was performed.

The user-run elevated Install/conditional-Start command reported
`SERVICE_PROBE_FAILED_STATE_RETAINED_FOR_REVIEW`. That first output alone did not
identify the failing action. The user's subsequent elevated Inspect reported every check
PASS, cleanup PASS, and service STOPPED. The subsequent strict Readback passed,
but Start failed. The new scoped SCM event 7024 carries service-specific code 1
(the service's INITIALIZATION_FAILURE, not Win32 error 1). Repeating Start with
the unchanged binary cannot distinguish token observation/policy from RPC
startup. The debug-only, data-free startup-code refinement is implemented;
security predicates and privileges are unchanged. The old workspace candidate
is preserved in `artifacts/service-probe-candidate-before-startup-diagnostics-d1e1bbd`.
That candidate was prepared and independently verified, and repository tests
plus the final full architecture scan passed. The user subsequently reported
Remove PASS, Install PASS, then Start failure. The then-latest fixed-service SCM 7024
event was service-specific `0x2192` (8594): the service-identity normal-group
multiplicity check failed. The old code merges absent and duplicate entries;
neither case is separately established by this event. A narrow source correction
now accepts a fixed virtual-account user without requiring a redundant normal
group, while rejecting duplicate groups and bad present-group attributes.
That correction's tests, candidate verification and full architecture scan passed.
The user applied it: Remove and Install passed, then Start failed with the newer
scoped SCM 7024 service-specific code `0x2184` (8580). Service identity now passes;
the combined primary/Local/logon predicate does not. Read-only native kernel
evidence and LSA construction contracts exposed a second incorrect assumption:
primary group can equal TokenUser without a redundant normal group. The narrow
primary-user binding correction and seven-bit aggregate failure report are now
implemented. Repository tests, static checks, fresh preparation and strict
candidate readback and the final full architecture scan passed.
The user subsequently applied `fad7ba8`: Remove and Install passed, Start failed.
The newest fixed-service SCM 7024 is `0x4010`, identifying only logon-attribute
failure; all six other aggregate predicates passed. No alternate service-logon
attribute contract is established. A diagnostic-only refinement is implemented
to report all nine semantic attribute differences together without changing
acceptance. Repository tests, static/focused checks and fresh candidate
preparation/readback and the final full architecture scan passed. Do not
retry that old build unchanged. The user has now applied `f48fa87`, with Remove
and Install PASS and Start failure. Its new SCM 7024 code is `0x5008`: only the
OWNER flag is additionally present on the logon group; the other six aggregate
checks passed. This establishes the exact observed `0xC000000F` form. A narrow
shared-predicate correction accepts that form or the documented `0xC0000007`,
without masking attributes or changing the fixed actual owner. Repository tests,
static checks, fresh corrected-candidate preparation/readback and the final full
architecture scan passed. This historical failure sequence is superseded by the
corrected candidate's actual Start PASS recorded above.

## Saved implementation

- Phase 3D debug-only, non-signing service Approval transport in helper bootstrap,
  Approval UI, and platform `debug_gate.rs` / `rpc_probe.rs`.
- Exact 12-byte bounded prefix, canonical request, 75-byte bound response plus
  EOF before termination; original five-second deadline is retained.
- Fresh registry-owned admitted-helper liveness before role extraction and
  unconditional process/Job cleanup; both decisions confer no signing authority.
- Actual staged Windows pipe regression and public-correlation tests. No wallet
  mnemonic or private-key fixture was introduced.
- Current status/completion gates are in `docs/development-status.md`.
- Separate desktop V2 client, query-only fresh desktop preflight, isolated debug
  feature, exactly OpenEpoch then Approval on one fixed thread-bound binding,
  canonical correlation, original deadlines, no retry, and silent default/release.
- Local RPC ignores its call-timeout option; that ineffective call was removed.
  A binary-only 25-second process watchdog covers RPC and output/flush, with
  actual blocked-work/output/flush and main/worker-panic child regressions.
- Separate `scripts/service-probe` preparation and elevated operator harness:
  exact Cargo JSON provenance, fresh canonical candidate, protected fixed
  restricted-service installation, selective journaled rights, exact readback,
  and identity-held nonrecursive removal. Unknown/partial state is retained.
- Architecture CLI regressions expanded to 24; C# is included in privacy
  scanning. New harness regressions are wired into `scripts/check.ps1 test`.

## Prior verified checkpoint (before the current client/harness changes)

Repository fmt, lint, typecheck, test (Rust/doctests/demo/extension), and privacy
targets passed. The complete no-argument architecture scan passed with native
exit 0 in about 283 seconds; no historical check or mutation was removed.
Platform tests: 953 passed, 44 explicitly ignored. Demo tests: 266 passed.
Extension tests: 33 passed. Final diagnostic CLI tests: 12 passed, none skipped.
Separate release-policy checks passed 66 tests and both PowerShell sentinels.
Current-user Windows readiness passed its 22-test local fixture; this is
explicitly not release evidence. Helper feature tests 69 and Approval UI tests
19 passed. No actual native UI or installed-service E2E ran.

## Resume here

1. The latest replacement attempt returned a retained-state failure, probably
   at the first Stop if the supplied output is complete. Elevated Inspect passed
   all non-status observations but returned OTHER; obtain the requested read-only
   `sc.exe queryex YourWalletKeyAgent` report before any further mutation. Pending
   state or a reported PID alone is not process identity for termination. The
   installed `b3bb834` service previously
   started successfully; its observed OpenEpoch denial remains unresolved.
   The guarded Stop/Remove/Install/Start workflow may be resumed only after the
   current retained state is understood, stopping at the first failure.
   This replaces the owned debug fixture with new instrumentation, not an
   unchanged retry. No installed state was changed by this checkpoint.
   The current candidate contains both auth diagnostics and the termination fix
   at `artifacts/service-probe-candidate`; do not rerun prepare against or
   overwrite it. The previous auth-only diagnostic candidate is in
   `artifacts/service-probe-candidate-before-unreported-stop-fix-7916943`.
   The matched prior `b3bb834` candidate is in
   `artifacts/service-probe-candidate-before-runtime-auth-diagnostics-b3bb834`.
   Never force adoption or bypass ownership/readback. Inspect completion is not
   startup evidence. The previous `f48fa87` diagnostic-only candidate is preserved in
   `artifacts/service-probe-candidate-before-logon-owner-fix-f48fa87`.
   The older `fad7ba8` candidate is preserved in
   `artifacts/service-probe-candidate-before-logon-attribute-diagnostics-fad7ba8`.
   The older redundant-group candidate
   is preserved in
   `artifacts/service-probe-candidate-before-primary-group-fix-3dec6ce`.
   The diagnostic-only build is preserved in
   `artifacts/service-probe-candidate-before-virtual-account-group-fix-691a7fc`.
   The original candidate is preserved in
   `artifacts/service-probe-candidate-before-startup-diagnostics-d1e1bbd`.
   A later runtime source change requires a newly reviewed build.
2. After the new user-run Start PASS, verify the exact candidate, run only one
   controlled provenance-held, externally bounded opening-only diagnostic, and
   inspect the fixed service's new scoped SCM evidence. Do not send an Approval
   command or automatically retry that epoch. A runtime code identifies only the
   first reached auth category in that service invocation, not a raw native
   error, particular repeated observation, correlated request or proven identity.
   An absent code is inconclusive; pre-auth access denial and uncertain cleanup can
   suppress it. Diagnose from that evidence before changing any auth predicate.
3. Record exact installed-service/readback/helper results and clean up via the
   verified Stop/Remove workflow. Never run Cargo elevated, retry single-use
   epochs, adopt unrelated services, or repair uncertain partial state by force.
   Watchdog process termination is not proof of remote service cleanup.
4. Collect actual non-signing cross-session evidence, then implement SCM session
   cancellation, Broker/policy and Secret Input composition, hardware custody,
   durable state, and signing in the documented exit-gate order.

## Prior committed-snapshot verification (before Inspect)

Repository fmt, lint, typecheck, full tests and privacy passed after the final
watchdog/build-alias changes. Platform: 976 passed, 44 explicitly ignored; demo:
266 passed; extension: 33 passed; helper: 69 passed; binary: 15 passed. Actual
architecture CLI: 24 passed. Preparation/operator CLI: 14 + 4 passed; native
self-checks: 30 passed. Default, feature-debug and release binary subprocess
fallback checks each passed 2 tests. Separate release-policy checks passed 66
tests and both PowerShell sentinels. The final no-argument architecture scan
passed with native exit 0 in about 255 seconds, preserving all historical gates.
The desktop diagnostic has 20 predicates/35 mutations; the operator/preparation
harness has 22 predicates/31 mutations plus closed source inventories and pins.

Actual unelevated preparation passed, and all four staged executables passed
independent strict single-link/size/hash readback. Cargo's ordinary root/deps
hardlink pair is accepted only by the separate fixed build-file opener; writes
through either name and deletion of the held name are denied. Deletion of an
unopened alias is possible and is rejected as link-count drift before publishing
the manifest. Installer/candidate files stay strictly single-link. No actual
service installation/start, LSA change, native Approval UI or signing was run
by that verification suite. The later user-run installation attempt is recorded
separately below.

For quick checks, `--check-group service-desktop-probe` checks the fixed desktop
client sources. `--check-group service-approval-transport` shares 14 transport
predicates plus framing and 15+7 mutations with the full scanner. Exact ordered
predicate/mutation inventories and allowlisted failure names are enforced.
Every diagnostic outcome includes NOT_FULL_SCAN. The 24 actual-CLI regressions
run from check.ps1; omission/skip of that invocation also fails the full scan.
Use the no-argument full scan at integration milestones.

Capture the native command's exit status before piping output through a
redactor: the Python pipeline's success must never mask a failed Node gate.

## Failed first operator run: read-only observations

The new Inspect path has 33 fixed observations and a separate query-only
dispatcher. The original five mutation/readback actions are unchanged. Native
self-checks now pass 139 cases (including all original 30); the preparation and
operator CLI suites pass 14 + 6, architecture diagnostic CLI passes 24, and
privacy passes 7 tests plus source scanning. Format, lint, typecheck and diff
checks passed. The harness contract retains its original 22 predicates and 31
negative mutations, adding six read-only inspection predicates and 28 effective
negative mutations (28/59 total). Shared query helpers, handle construction and
disposal, fixed role routing, and absence/reparse classification are included.
The final no-argument architecture scan passed with native exit 0, progressing
through 672 checks in about 304 seconds. The final scanner's actual CLI suite
also passed all 24 tests with no skips.
These tests inject fake inspection adapters; none performs an elevated
inspection of the retained machine fixture. The actual unelevated Inspect
entry returns only REQUIRES_ELEVATED_OPERATOR with exit 20. Independent candidate
readback still passes strict single-link, size and hash checks for all four
executables; no candidate rebuild or overwrite was needed.

The agent process remains non-elevated. The fixed installed directory exists,
but its enumeration and ACL query are denied. `sc.exe query` for the fixed
service returns OpenService access denied; a filtered Get-Service result must
not be treated as proof of absence.

The fixed service registry configuration is readable: own-process type, demand
start, normal error control, restricted SID type, exact virtual account, quoted
fixed image path, display name, and the exact four ordered required privileges
match the planned values. Group/dependencies are empty. The service security
subkey cannot be read from this token. These are registry observations, not
authoritative SCM/security/LSA/file readback or proof of successful installation.
They suggest the attempt reached Configure, but do not identify the failing
native call. If an Install PASS line was omitted from the user's report, the
failure could instead be in the conditional Start.

The user has now supplied the full elevated Inspect report: all 32 non-status
observations PASS, service status STOPPED, cleanup PASS, and report COMPLETE.
This includes exact service and file security, restricted configuration, direct
rights, manifest/journal, all four executable hashes, and inventory. It does not
replace the stricter ownership-bound Readback/Start entry or prove a past start.
The agent's read-only System log query, limited to the exact service and the last
48 hours, found only one SCM installation event (7045); no matching failure
event was returned. Absence of an event does not prove Start was never attempted.
A bounded independent startup-code review found no deterministic mismatch with
the configured four privileges and no reason to weaken the token/RPC policy.

After the next user-run Readback/conditional-Start, Readback returned PASS and
Start returned the generic retained-state category. A fresh query of the same
bounded System-log scope found event 7024 with service-specific code 1 in
addition to the older 7045. This proves the service reached its own SCM failure
publication; it is not an SCM account-logon rejection. Existing code maps both
stop-event creation and worker startup failures to this code, before RUNNING.
A separate unelevated, query-only fixed service-name lookup confirmed expected
SID_NAME_USE, exact domain and stable returned size without emitting identities.
The actual SCM-created process-token predicates and RPC startup stage still
need the refined closed failure code; no alternate account or privilege grant
is justified by the current evidence.

The agent performed no retry, service start/stop/delete, privilege change,
ACL change, installed-candidate replacement, or partial-state deletion during
this diagnosis. The user's explicit Start attempt is recorded above.
Actual restricted-service execution remains unverified; production and release
remain STOP-SHIP.

## Closed startup diagnosis and fresh candidate

The explicit debug LPAC worker now publishes only fixed startup categories
through the existing SCM service-specific status field: token observation/policy
`0x21xx`, stop-event creation `0x2201`, and RPC initialization `0x23xx`.
The already-rejected service-identity policy has three data-free subcategories:
owner mismatch `0x2191`, missing/duplicate service group `0x2192`, and unexpected
service-group attributes `0x2193`. No token values, raw Windows errors, paths,
identities or secrets are logged. Error Debug/Display remain redacted.
Acceptance predicates, token queries and their order, four privileges, default/
status-only/release behavior and retained-runtime no-STOPPED rules are unchanged.
Independent reciprocal runtime review found no blocker.

The old workspace candidate was checked with held non-reparse directories and
strict single-link/size/hash/canonical-inventory readback, then renamed within
the exact artifacts parent to
`service-probe-candidate-before-startup-diagnostics-d1e1bbd`. The destination was
absent, and post-rename readback passed all four executables. Nothing was deleted.
Unelevated `prepare.ps1` then passed with native exit 0. Independent fresh-candidate
readback passed all four strict single-link/size/hash checks and canonical
inventory; the new service executable differs from the preserved one.
This is build evidence, not installed-service execution or release evidence.

The next elevated operation is the existing ownership-verified stopped Remove,
then Install only on success, then Start only on success. No Cargo build belongs
in that elevated chain. Any failure stops progression and retains uncertain
state. The old protected installation is not overwritten or adopted, and no
wallet storage belongs to this debug fixture.

Repository fmt, lint, typecheck, full tests and privacy passed with native exit 0.
Platform tests: 985 passed, 44 explicitly ignored; demo: 266 passed; extension:
33 passed; helper: 69 passed; diagnostic binary: 15 passed. Native harness:
139 passed; preparation/operator CLI: 14 + 6 passed; architecture actual CLI:
24 passed. Separate release-policy verification passed 66 JavaScript tests and
both exact PowerShell sentinels. Default, debug-desktop-only and release
all-feature binary fallback suites each passed two tests without SCM/UI calls.

The startup architecture guard has 10 predicates and 25 effective negative
mutations, including retained-runtime early-return rejection. The first full
scan stopped at a historical Phase 1B consumer of the renamed startup error.
Only its five obsolete markers were adapted; all ten existing Phase 1B negative
mutations remain and pass. Runtime code and prepared bytes were unchanged.
The next full scan reached 448 checks before finding the new token-error
`cfg_attr` lint-allowance shape missing from the closed provider inventory.
Only that reviewed compiler attribute was registered; no general macro
provider or policy allowance was added. The final no-argument architecture scan
then passed with native exit 0, reaching the 672-check progress checkpoint at
266 seconds before final PASS. The final scanner's actual CLI suite also passed
24 tests with zero skips. Final scanner SHA256:
`b8a99f9bc755c33ad226b7bc95085ad89fdd408ce7c85744b4d357a56b235d2a`.
Both failed earlier full runs are preserved above rather than counted as passes.
The existing Inspect harness remains at 28 predicates and 59 effective mutations.

The guarded one-line Remove/Install/Start command was parsed successfully without
execution. Its three actions were verified in order; each later action is inside
the preceding native-exit-zero condition. The agent has not run that elevated
chain. Obtain the user's complete output, then use the fixed service's bounded
SCM event scope to interpret any new service-specific startup code. Do not treat
the generic operator failure line itself as the detailed diagnosis or retry a
failed action unchanged.

## Virtual-account redundant-group correction

The user's subsequent exact Remove/Install/Start chain produced Remove PASS and
Install PASS, then Start failure. The agent's query-only fixed-service System
log inspection found the newest SCM 7024 service-specific code `0x2192` (8594),
followed by its installation event and the older generic-code failure. This
establishes rejection by the service-identity group-count rule, not successful
evaluation of later group/restricted-SID/privilege policy checks. The old code
combined zero and multiple matching entries, so absence on this host remains
an inference, not captured evidence.

The corrected shared `service_identity_rejection` helper accepts zero redundant
normal service-group entries or one with the original exact attributes, while
rejecting duplicates and incorrect present-group attributes. The native capture
still matches TokenUser to the exact OS-resolved fixed virtual account; owner
must equal that user. Microsoft distinguishes TokenUser from normal groups and
permits a user SID as TokenOwner. Descriptor creation still copies and validates
the actual owner and primary-group bytes against the retained complete baseline.
At that checkpoint the primary group still had to occur exactly once in normal
groups; this assumption is superseded by the primary-group correction below. The strict
restricted-SID quartet, candidate privileges, Local/logon groups, primary
Session-0 shape, no impersonation, same token object and complete baseline
continuity are unchanged. No raw token data, new native API, new privilege,
account fallback, production policy or signing path was introduced.
See the rationale and official references in `scripts/service-probe/README.md`.

Independent security review found no blocker. Four new tests cover both accepted
forms, all 32 single-bit attribute changes, mixed duplicates, 19 absent-branch
scalar/group mutations, missing/duplicate/malformed restricted identities,
missing/invalid/forbidden privileges, primary-group-as-user rejection, handle
continuity, descriptor principals and bidirectional present/absent baseline
drift. The intentional old missing-service-group negative became positive;
all other historical rejection conditions remain. The acceptance and diagnostic
classification use the same helper, so corrected `0x2192` means duplicates only.

The prior diagnostic candidate was independently held/read back, renamed to
`artifacts/service-probe-candidate-before-virtual-account-group-fix-691a7fc`
only after exact path/scope/absent-destination checks, and read back again.
Nothing was deleted. Unelevated preparation passed with native exit 0, followed
by independent strict single-link/size/hash/canonical-inventory checks for all
four fresh executables. The corrected service bytes differ from the preserved
diagnostic bytes. The agent did not remove/install/start the real service.

Focused LPAC token tests passed 20 (including three sys tests), with one existing
installed-context test ignored. Release binary tests passed 15, and all four
release fail-closed entrypoint checks passed. Workspace fmt/lint/typecheck and
privacy passed. Separate release-policy tests passed 66 JavaScript cases and
both exact PowerShell sentinels. Full repository tests passed with native exit 0:
platform 989 passed/44 explicitly ignored, demo 266, extension 33, helper 69,
native harness 139, preparation/operator CLI 14 + 6, actual architecture CLI 24.
The frozen no-argument architecture scan passed with native exit 0 in 353.17
seconds, with progress through 672 checks and final PASS. Exactly one full run
was needed: affected token checks and all 24 historical plus seven new mutations,
all 25 diagnostic mutations and the exact 182-file compilation closure were
checked before it. Scanner SHA256:
`0a7a1621373b099f4e1df72e0460521c0c70b0272fc982b94588a89e5691a7f4`.
Do not claim real service start or release success from these checks.

Only an explicit elevated ownership-verified stopped Remove/Install/Start chain
can apply the corrected candidate. Each next action requires the previous native
exit 0; uncertain state is retained. The installer does not overwrite or adopt
partial fixtures, and no wallet storage is in its fixed targets. The agent
remains non-elevated and has not run this chain. After application, read the
fixed-service scoped System log if Start still fails: `0x2192` on the new build
would mean actual duplicates, whereas the prior code conflated absent/duplicate.
Do not relax duplicate, restricted-SID or privilege checks merely to make the
next stage pass. The later primary-group change below has independent evidence.

## Primary-group correction and consolidated remaining-policy diagnostics

The next user-run Remove/Install/Start again passed Remove and Install. The latest
fixed-service SCM 7024 is `0x2184` (8580), following the older `0x2192` and generic
1 failures. This proves the earlier identity rule no longer rejects this run;
it does not distinguish primary-group, Local or logon failure.

Two query-only native current-process checks, including the raw TokenGroups
array, found primary group equal to TokenUser and both absent from normal groups.
This is actual current-kernel evidence, not service-token evidence. The stronger
LSA V1/V3 logon-token construction contracts allow primary-group metadata that
does not correspond to assigned SIDs. The previous blanket reading of the
TOKEN_PRIMARY_GROUP structure documentation was incorrect. Official references
and the precise bounded correction are in `scripts/service-probe/README.md`.

`primary_group_is_bound` now accepts the already OS-resolved fixed TokenUser or
exactly one matching normal group. Earlier owner/identity/duplicate/attribute
checks remain; malformed/foreign absent or duplicated primary groups still fail.
Full token revalidation rejects drift between either independently accepted
representation, and descriptors retain the actual sealed owner/group bytes.
No native capture API, privilege, ALLOW ACE, release policy or signing path changed.

Only already rejected ServiceGroups/RestrictedSidSet/Privileges baselines acquire
the seven-boolean remaining-predicate report. The debug LPAC accessor encodes
only failures in `0x4001..0x407f`; all-zero falls back to the original rejection.
Missing/duplicate Local or logon groups make dependent checks UNAVAILABLE, not
PASS. No raw token values are encoded. Acceptance order and failure results,
default/release behavior and retained-RPC-runtime cleanup are unchanged.

Focused LPAC token tests pass 25 with one existing installed-context test ignored.
They include four query-only native sys tests, all 128 encoder combinations,
each of seven real single-predicate failures, simultaneous independent failures,
missing/duplicate dependency semantics, fallback/redaction and both accepted
primary representations with complete baseline/descriptor continuity. The sys
production prefix is unchanged; its only change is one nonignored query-only
regression. Independent review found no correctness/security blocker. Workspace
fmt/lint/typecheck, privacy and full repository tests passed with native exit 0.
The final-source integrated rerun passed platform 994/44 existing ignored, demo
266, extension 33, helper 69, native harness 139, preparation/operator CLI 20,
and actual architecture CLI 24. No new installed-service ignore was added.
Final-source release probe unit tests passed 15, and the four release fixture
entrypoint tests passed. Release-policy tests passed 66 JavaScript cases and
both exact PowerShell sentinels; default/debug-desktop/release-all-features
binary fallback tests passed two each, retaining required child exit 78.

The exact prior candidate passed strict held readback, was safely renamed to
`artifacts/service-probe-candidate-before-primary-group-fix-3dec6ce` after
explicit absolute-parent/destination checks, then passed readback again. Nothing
was deleted. Fresh unelevated preparation passed, followed by independent strict
single-link/size/hash checks on all four executables and exact canonical manifest
comparison. New service bytes differ from the preserved `3dec6ce` candidate.
The agent has not removed/installed/started the real service. Actual startup is
still unverified; the corrected candidate must be explicitly applied through the
existing guarded elevated workflow before any new startup conclusion.

The first full architecture attempt stopped with native exit 1 after progress through 352
after 154.646 seconds because an older Phase 2I bridge also pins the changed
design paragraph. Its semantic checks and negative mutations passed; a missed
document pin is not a service-runtime result. The matching security-decisions
paragraph was then corrected too. All six design and nine security-document pin
consumers, their affected semantic windows and negative mutations were reviewed
and rechecked before the final full run; no runtime policy changed for this.

The final no-argument architecture scan passed with native exit 0 in 290.412
seconds, reporting progress through 672 checks. All 35 token negative probes
(24 historical, seven service-group, four primary-binding) and all 12 startup
diagnostic predicates with 37 negative probes passed. The 182-file Rust
compilation closure is
`35aecb2af5ca4dc1796902b881e415e5517bced61404db0eb5c9ddf2fe932164`.
Frozen scanner SHA256:
`9b6b9fbec9cc0ae8d1f30c39e86c1e76c5df1eba6b3c23098dd63367d087d944`.

The remaining operator action is the existing stopped, ownership-verified
Remove, then Install only on native exit 0, then Start only on native exit 0.
It applies different, independently verified service bytes; do not retry the old
installed build unchanged. If Start still fails, read the fixed-service scoped
SCM 7024 code and decode the aggregate range using the README dependency rules.
This correction is not a claim that the host's actual service has started or
that a production wallet or signing path is ready. No test wallet, mnemonic or
private-key fixture was added.

## Logon-attribute-only failure evidence and diagnostic refinement

The next user-run Remove/Install/Start passed Remove and Install but failed Start.
Query-only fixed-service System log inspection found newest SCM 7024 `0x4010`:
primary binding PASS, Local uniqueness/attributes PASS, logon uniqueness PASS,
restricted quartet PASS and privilege policy PASS; only logon attributes failed.
The SID-shape alternative is ruled out by the exact canonical restricted-SID
match. Missing/extra attribute bits are not identified by that code.

The official SERVICE_SID_INFO contract still gives `0xC0000007`; an independent
review found no alternate service-generated mask contract. Do not infer a new
allowable mask or weaken exact acceptance from a current-process token sample.
The current change is diagnostic only: nine private booleans classify missing
Mandatory/Enabled-by-default/Enabled, extra Owner/Deny-only/Integrity/
Integrity-enabled/Resource, and any unknown bits in the already captured rejected
baseline. Unknown bits collapse to one category without native values. Both
Logon-ID bits are already required by the unique-group selector.

Only a sole aggregate `0x4010` can refine to nonzero `0x5001..0x51ff`; this implies
the other six predicates passed. Mixed aggregates are unchanged. Absent/zero
detail preserves `0x4010`, not success. The existing error facade stays redacted;
the detailed accessor remains exact debug LPAC only. Acceptance, native capture,
operator workflow, service/RPC cleanup and all signing gates are unchanged.

Three added tests cover all 512 semantic combinations with real rejected
baselines and redacted errors, all 128 original aggregate masks with absent/zero/
nonzero detail, missing/duplicate logon prerequisites, SID-shape-only failure,
every single attribute bit change and unchanged early rejection precedence.
Focused token tests passed 28 with the one existing installed-context ignore.
Workspace fmt/lint/typecheck and privacy passed. Independent code review found
no blocker. Release-policy tests passed 66 JavaScript cases and both exact
PowerShell sentinels; default/debug-desktop/release-all-features fallback tests
passed two each, release probe unit tests passed 15 and release fail-closed
fixture entrypoint tests passed four, all with native exit 0.

The exact current candidate was held/read back, safely renamed after explicit
absolute-parent/absent-destination checks to
`artifacts/service-probe-candidate-before-logon-attribute-diagnostics-fad7ba8`,
and read back again. No files were deleted. Unelevated preparation then passed;
independent strict single-link/size/hash checks on all four new executables and
the canonical manifest passed. New service bytes differ from the preserved
candidate. No real-service remove/install/start, ACL/LSA change or raw token dump
was performed by the agent. Full repository tests passed with native exit 0:
platform 997 passed/44 existing ignored, demo 266, extension 33, helper 69,
native harness 139, preparation/operator CLI 20 and actual architecture CLI 24.
The only full architecture scan of this turn passed with native exit 0 in
288.415 seconds, reporting progress through 672 checks. All 35 historical token
negative probes and all 14 startup predicates/50 startup negative probes passed
(the 37 previous negatives plus 13 logon-detail probes). No documentation
authority pin or native capture source changed this turn. Frozen scanner SHA256:
`52f6a996cf65655a89713c127b0e7043e9ecc357cfec22017c336444e060ea01`.
The exact 182-file Rust compilation closure is
`bfc01f59b2585c0215dfca46585a32aadf6495a696b6f62cee5cdbead355a5d9`.

The remaining action is an explicit elevated stopped/ownership-verified
Remove/Install/Start chain, each next action conditional on native exit 0.
This applies the new diagnostic bytes, not a guessed acceptance change. A
continued startup failure is expected until the real mismatch has been observed
and reviewed. Read the fixed-service SCM 7024 code and use the README nine-bit
table if it is `0x5001..0x51ff`; unknown bits are one category, not a raw mask.
Do not relax attributes or claim a startup fix, release evidence or production
wallet completion from the tests or candidate preparation. No mnemonic or
private-key fixture was introduced.

## Observed owner-capable logon-group correction

The user's next guarded replacement passed Remove and Install but Start failed.
Read-only fixed-service SCM inspection found newest service-specific `0x5008`:
OWNER is the sole extra logon attribute; no expected flag is missing and no
other known or unknown bit is present. All six other aggregate checks passed.
The unique logon selector already requires both Logon-ID bits, establishing the
exact observed `0xC000000F` mask on this host.

Independent security review found no blocker to accepting exactly the existing
documented `0xC0000007` or the observed owner-capable `0xC000000F`. SE_GROUP_OWNER
is eligibility, not selection of the actual TokenOwner. That actual owner remains
the OS-resolved fixed service user and is sealed into protected creation
descriptors. No other attribute is stripped or accepted; logon SID ownership
substitution, baseline drift, malformed/duplicate groups, restricted-set changes
and privilege changes remain rejected. No native capture, ACL/LSA/operator,
role, RPC cleanup or signing boundary changed.

`service_logon_group_attributes_are_supported` is the shared exact-equality OR
used by acceptance, aggregate classification and detail filtering. An owner-only
accepted baseline now produces no error/detail. The closed diagnostic encoder
remains compatible: OWNER can accompany another unsupported difference, but
is not independently prohibited. Pure `0x5008` is historical evidence, not a
reachable owner-only rejection in this corrected policy. This host observation
is not a universal Windows SCM-generation guarantee.

Four regression tests cover both attribute forms across optional-service-group
and primary-group representations, all 256 bit-flip cases, 15 scalar/group
negative mutations, missing/duplicate groups, restricted-set and privilege
negatives, full-baseline drift in both directions and descriptor/actual-owner
substitution. The 512-profile diagnostic test now has exactly two accepted forms
and 510 rejected forms. Focused final tests passed 32 with one existing installed
context test ignored. Workspace fmt/lint/typecheck and privacy passed. Independent
review found no blocker. Full repository tests passed with native exit 0;
the final frozen-source rerun passed platform 1001/44 existing ignored, demo 266,
extension 33, helper 69, native harness 139, preparation/operator CLI 20 and
actual architecture CLI 24. No new ignored test was added.
Release-policy tests passed 66 JavaScript cases and both exact PowerShell
sentinels; default/debug-desktop/release-all-feature fallback tests passed two
each, release probe unit tests passed 15 and four release fixture entrypoint
tests passed, all with native exit 0.

The prior candidate passed held readback, was safely renamed after exact
absolute-parent/absent-destination checks to
`artifacts/service-probe-candidate-before-logon-owner-fix-f48fa87`, then passed
readback again. Nothing was deleted. Fresh unelevated preparation passed,
followed by independent strict single-link/size/hash verification on all four
executables and canonical manifest readback. New service bytes differ from the
preserved diagnostic candidate. The agent did not modify the installed service
or run its operator actions. The single final no-argument architecture scan
passed with native exit 0 in 325.415 seconds, reporting progress through 672
checks. All 39 token negatives (35 previous plus four two-form guards), 14 startup
predicates and 50 startup negatives passed. The exact 182-file Rust closure is
`4b75ab47904971469edae375960759499017111889544fbc0f1dc77c3576f366`.
Frozen scanner SHA256:
`044f06efe4f988abd7135c862636a0da0f4d960a0487ff72a71366894f32b64b`.
Native source and authority-document pins remain unchanged.

That checkpoint required applying the newly verified corrected candidate through
the existing guarded operator chain. The user has now completed it with Remove,
Install and Start PASS; follow the current live checkpoint at the top instead
of repeating that replacement. RPC/UI completion remains unverified. Product
stays STOP-SHIP, compiled signing policies stay None, and no mnemonic or
private-key fixture was introduced.
