# Development checkpoint — 2026-09-05

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
Remove PASS, Install PASS, then Start failure. The newest fixed-service SCM 7024
event is service-specific `0x2192` (8594): the service-identity normal-group
multiplicity check failed. The old code merges absent and duplicate entries;
neither case is separately established by this event. A narrow source correction
now accepts a fixed virtual-account user without requiring a redundant normal
group, while rejecting duplicate groups and bad present-group attributes.
The correction and its fresh candidate are prepared; repository tests and the
single final full architecture scan passed. The next step requires applying the
corrected candidate through the explicit elevated operator workflow. Do not retry
the currently installed diagnostic-only binary unchanged.

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

1. The user replaced the original fixture with the diagnostic build: Remove and
   Install passed, but Start reported service-specific `0x2192`. Review and full
   verification of the virtual-account redundant-group correction passed. Use
   the already prepared corrected candidate for explicit operator replacement.
   Any operator replacement must use the existing
   stopped, ownership-verified Remove/Install workflow, never overwrite or force
   adoption. Inspect completion is not startup evidence. The current candidate is at
   `artifacts/service-probe-candidate`; do not rerun prepare against that existing
   directory or overwrite it. It now contains the group-policy correction.
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
The primary group still must occur exactly once in normal groups. The strict
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
Do not relax duplicate, primary-group, restricted-SID or privilege checks merely
to make the next stage pass.
