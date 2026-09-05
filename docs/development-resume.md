# Development checkpoint — 2026-09-06

The standalone desktop service probe and unsigned operator harness are
implemented on top of Phase 3D. Their committed-snapshot tests, the complete architecture
scan and actual preparation passed. Product and
release remain STOP-SHIP; this is not installed-service or signed-helper evidence.

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
retry the installed `fad7ba8` build unchanged.

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

1. The user applied `fad7ba8`; Remove/Install passed, Start now reports `0x4010`,
   not the earlier `0x2184`. The diagnostic-only logon-attribute refinement has
   been prepared and independently read back; final full architecture verification
   passed. Apply it only through the existing guarded operator workflow. Actual
   mismatching attributes are not yet known.
   Any operator replacement must use the existing
   stopped, ownership-verified Remove/Install workflow, never overwrite or force
   adoption. Inspect completion is not startup evidence. The current candidate is at
   `artifacts/service-probe-candidate`; do not rerun prepare against that existing
   directory or overwrite it. It now also contains the diagnostic-only
   logon-attribute refinement. The installed `fad7ba8` candidate is preserved in
   `artifacts/service-probe-candidate-before-logon-attribute-diagnostics-fad7ba8`.
   The older redundant-group candidate
   is preserved in
   `artifacts/service-probe-candidate-before-primary-group-fix-3dec6ce`.
   The diagnostic-only build is preserved in
   `artifacts/service-probe-candidate-before-virtual-account-group-fix-691a7fc`.
   The original candidate is preserved in
   `artifacts/service-probe-candidate-before-startup-diagnostics-d1e1bbd`.
   A later runtime source change requires a newly reviewed build.
2. Only after diagnosing the retained state and obtaining verified installed
   service/readback/start results, run the candidate client in a separate
   eligible non-elevated desktop. The
   real candidate returned exact UNAVAILABLE/78 with no installed service and
   no stderr; this is fail-closed negative evidence, not a positive RPC/UI test.
   The operator's actual Readback entry returned REQUIRES_ELEVATED_OPERATOR/20
   before native operations. These observations predate the failed user-run
   operator command; they do not describe the current installation state.
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
