# Development checkpoint — 2026-09-05

Phase 3D implementation and harness integration are verified. This note records
the next development work, not production readiness or release approval.

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

## Verification completed after reboot

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

1. Implement a standalone, non-elevated desktop V2 probe client before claiming
   a real service/helper round trip. Prefer a separate debug-only binary in the
   existing key-agent-service crate, a private platform client, and the existing
   RPCsys exchange/desktop token policy. Keep SCM features independent of this
   client feature, and default/release behavior silent exit 78 before any RPC.
2. Send only OpenEpoch followed immediately by one LaunchApprovalRpcProbe on the
   same fixed binding. Use a fresh public request ID, exact correlated responses,
   bounded original deadlines, and fixed data-free output. Do not mint an
   AuthenticatedRpcClient from local preflight or claim installed-service mutual
   identity merely from packet privacy and a fixed endpoint.
3. Build the restricted-service install/configuration-readback/cleanup harness
   separately. Actual provisioning requires elevation; the desktop probe must
   run in an eligible non-elevated interactive token. Do not offer a bare
   service-create command as proof of the intended restricted-service policy.
4. Collect actual non-signing cross-session evidence, then implement SCM session
   cancellation, Broker/policy and Secret Input composition, hardware custody,
   durable state, and signing in the documented exit-gate order.

For quick checks, `--check-group service-approval-transport` shares 14 transport
predicates plus framing and 15+7 mutations with the full scanner. Exact ordered
predicate/mutation inventories and allowlisted failure names are enforced.
Every diagnostic outcome includes NOT_FULL_SCAN. Its 12 actual-CLI regressions
run from check.ps1; omission/skip of that invocation also fails the full scan.
Use the no-argument full scan at integration milestones.

Capture the native command's exit status before piping output through a
redactor: the Python pipeline's success must never mask a failed Node gate.

The current host is non-elevated and `YourWalletKeyAgent` is not installed.
Installed restricted-service provisioning/readback/cleanup tooling and a separate
non-elevated desktop V2 probe client are both still missing; elevation alone
does not supply that harness. Production composition and release remain STOP-SHIP.
