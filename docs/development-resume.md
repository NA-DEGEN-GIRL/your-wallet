# Development checkpoint — 2026-09-05

The standalone desktop service probe and unsigned operator harness are
implemented on top of Phase 3D. Their committed-snapshot tests, the complete architecture
scan and actual preparation passed. Product and
release remain STOP-SHIP; this is not installed-service or signed-helper evidence.

The user-run elevated Install/conditional-Start command reported
`SERVICE_PROBE_FAILED_STATE_RETAINED_FOR_REVIEW`. The failing action has not yet
been confirmed from independent readback. Do not repeat Install, Start,
or Remove against that partial state. The next operator step is read-only Inspect,
not another installation attempt. The candidate has not been replaced.

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

1. Follow `scripts/service-probe/README.md` for the elevated read-only Inspect
   action and return its fixed categories. The first elevated operator run failed;
   protected partial state remains. A real, fresh, hash-verified candidate exists at
   `artifacts/service-probe-candidate`; do not rerun prepare against that existing
   directory or overwrite it. Preparation was non-elevated and included the
   final watchdog binary. A later source change requires a newly reviewed build.
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
failure could instead be in the conditional Start. Inspect must check current
service state and the remaining boundaries before any repair.

No retry, service start/stop/delete, privilege change, ACL change, candidate
replacement, or partial-state deletion was performed during this diagnosis.
Actual restricted-service execution remains unverified; production and release
remain STOP-SHIP.
