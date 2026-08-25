# ADR 0001: Windows Key Agent Service Boundary

## Status

Accepted on 2026-08-25.

This ADR selects an architecture; it does not claim that the selected Windows
composition has been implemented or proven. Release status remains `STOP-SHIP`.
The accepted Design Brief is
[`docs/designs/windows-key-agent-service.md`](../designs/windows-key-agent-service.md).

## Context

The current Key Agent prototype runs as a zero-capability LPAC under the same
Windows user as the Broker and other untrusted desktop processes. Repository
kernel evidence shows that this principal cannot receive a loader-compatible
process/thread policy that denies `WRITE_DAC` from birth. The later authenticated
R10 gate can harden a token default DACL, but it cannot retroactively protect
objects or high-authority handles created before that gate.

The current LPAC launch, Job, token, storage, and Approval exchange code remains
useful evidence and implementation material, but it is not production-reachable:
`COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` are `None`, the sealed
Approval terminal has no signing conversion, and the Key Agent has no runtime
signing protocol.

The required threat boundary includes same-user non-elevated malware and a
compromised Browser, Native Host, or Broker. Local Administrator, kernel,
hypervisor, firmware, and compromised Windows TCB remain out of scope.

## Decision

### Distinct restricted service principal

The Key Agent signing authority MUST move to an own-process Windows service with
the fixed service name `YourWalletKeyAgent`, the virtual account
`NT SERVICE\YourWalletKeyAgent`, and `SERVICE_SID_TYPE_RESTRICTED`.

The service MUST be headless in Session 0 and MUST NOT use
`SERVICE_INTERACTIVE_PROCESS`. LocalSystem, NetworkService, shared LocalService,
and a password-managed account are not accepted final identities. The final
service token MUST contain only privileges demonstrated necessary by Phase 1
kernel evidence. `SeTcbPrivilege`, `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`,
and `SeRestorePrivilege` are forbidden in the final policy.

The service alone MUST own decrypted key material, PCP/TPM private-key handles,
protected settings authority, durable nonce/signing/broadcast state, helper
creation, Approval authorization, and the private signing transition. Broker
data is untrusted input and cannot itself authorize signing.

### Service-owned user-session LPAC helpers

Approval and Secret Input MUST remain distinct, fixed, zero-capability LPAC
frontends in the enrolled user's interactive session. The service MUST derive an
exact primary user token from an already authenticated local client context,
verify its user/logon/session/elevation state, and create each helper directly
with `CreateProcessAsUserW` and `STARTUPINFOEXW`.

The service MUST retain the returned process/thread handles and the helper Job.
The Broker MUST NOT create, resume, debug, inject, or retain any process, thread,
token, Job, endpoint, or channel handle for a trusted helper. Broker-owned helper
creation followed by handle transfer is a forbidden downgrade.

### ncalrpc-first authenticated control plane

The first IPC design to prove MUST be authenticated local RPC over `ncalrpc`.
The service endpoint MUST be local-only, use an explicit security descriptor and
security callback, pin its final Windows authentication policy, and derive the
caller's token user, AppContainer state, session/logon identity, local PID, live
process object, image role, and one-shot epoch rather than trusting wire fields.

The service MUST bind Broker and helper calls to distinct roles. Secret Input or
Approval results MUST be accepted only from an exact helper process created and
still retained by the service. Endpoint-name secrecy, a current-user DACL, or a
numeric PID alone is not authentication.

Zero-capability LPAC-to-Session-0 `ncalrpc` behavior and exact mutual identity are
unverified until Phase 1. If this proof fails, implementation MUST stop for a new
ADR. It MUST NOT silently fall back to the current session-scoped
`\\.\pipe\LOCAL\...` primitive, a Broker-mediated secret channel, or an
unauthenticated named endpoint.

### No inherited helper handles

Every service-created helper MUST use `bInheritHandles = FALSE` and MUST NOT
receive `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, inherited stdio, inherited sockets,
or any other ambient handle capability.

After the exact child has been created suspended and authenticated, the service
MUST use its retained process handle to `DuplicateHandle` exactly the minimum
one-shot request and response handles into the child. Duplication MUST use
explicit minimum access, `bInheritHandle = FALSE`, and zero duplication options.
The Broker MUST never observe either endpoint or the returned child-table handle
values.

The child MUST verify that the candidates are distinct, non-pseudo,
non-inheritable, non-stdio, exact-type, exact-direction, and exact-access handles.
It MUST immediately replace them with fresh child-local least-authority
duplicates, close the launcher-known candidates, and bind the resulting channel
to the authenticated service epoch, child process identity, nonce, role, and
deadline before parsing a request.

### Exact R10/R11 child-owned bootstrap gate

The selected bootstrap is an x64 child-owned exact R10/R11 breakpoint gate. The
signed helper MUST contain one unique preflighted executable sequence that loads
independent fixed public markers into R10 and R11, executes `INT3`, and captures
the post-continue values into child-owned state before any call, allocation, TLS,
stdio, UI, or protocol operation.

The service MUST authenticate the exact mapped image, PID, primary TID,
first-chance exception, gate RVA and bytes, executable image page, allocation
base, RIP, both marker registers, token/session, creation security, Job, and
admitted debug-event history before duplicating either handle. It then MAY place
the two returned child-table values in R10 and R11 with `SetThreadContext` only
while the authenticated event stops the exact primary thread. Complete context
readback MUST show no unintended mutation. The child MUST capture and clear both
registers immediately.

The debug relationship MUST remain on one dedicated service OS thread. Detach,
creator-handle attenuation, UI resume, and channel use occur only after exact
handle adoption while an independent suspend count still holds the child.
Partial duplication, wrong context, an unexpected event/thread, failed
readback, timeout, or child rejection MUST terminate and reap the exact child and
close its Job.

A remote-memory bootstrap is not an automatic fallback under this ADR. It would
add VM authority and compiler/linker placement risks and therefore requires a
separate ADR and security review.

### No service network authority

The service MUST contain no DNS, chain RPC, HTTP, WebSocket, update, telemetry,
or broadcast adapter. Installation MUST apply and read back an outbound block
for the exact service identity/image. Release evidence MUST prove denial of TCP,
UDP, DNS, loopback, private addresses, remote named pipes, inherited sockets,
and machine-credential outbound access. UI helpers retain their independent
zero-network requirement. Broker remains the only networking process.

### Fail-closed lifecycle and release policy

Service start MUST verify the service token, restricted SID state, privilege
set, installed image/configuration, storage/PCP/anchor bindings, network block,
single-instance state, enrolled user state, and durable recovery state before
listening.

Lock, logoff, user switch, cancellation, deadline expiry, Broker/helper exit,
RPC disconnect, Job violation, SCM stop, service crash, and failed revalidation
MUST invalidate non-durable authority and terminate/reap every live helper. A
restart MUST enter recovery and MUST NOT continue or automatically re-sign an
unfinished request. Ambiguous durable results remain quarantined until an
authenticated recovery transition resolves them.

`COMPILED_PARENT_POLICY` and `COMPILED_RELEASE_POLICY` MUST remain `None` through
feasibility and integration. They may change only through the reviewed,
reproducible release-generation path after the complete signed-artifact,
installer, kernel, IPC, lifecycle, key-custody, network, and independent-review
evidence set passes.

## Consequences

- The wallet becomes an administrator-installed Windows application rather than
  a portable same-user process bundle.
- The service principal supplies the ownership separation that the current
  same-user LPAC cannot supply; Approval and Secret Input retain LPAC isolation
  for their narrow interactive roles.
- SCM configuration, service privileges, session-token derivation, service-only
  storage, firewall policy, session notifications, crash recovery, and hardware
  key custody enter the security TCB and release evidence.
- The current Key Agent process shell, inherited startup channel, and
  AppContainer persistent-storage authority are replaced. Existing domain,
  authorization, journal, vault, and signing types may be reused only where
  their invariants remain valid under service ownership.
- Service creation of a user-session LPAC, ncalrpc identity, post-create handle
  injection, and the R10/R11 gate are all conditional on Phase 1 kernel proof.
  Acceptance of this ADR is not evidence that Windows supports the combination.
- A Phase 1 failure keeps release disabled and requires an explicit design
  decision; it does not authorize a weaker implementation.

## Rejected alternatives

- **Continue hardening the same-user LPAC Key Agent:** rejected because a later
  gate cannot close the measured from-birth `WRITE_DAC` gap.
- **Broker-owned helper creation:** rejected because the attacker begins with
  creator-strength process/thread authority and transferable handles.
- **LocalSystem plus `WTSQueryUserToken`:** rejected as unnecessarily powerful
  and dependent on `SeTcbPrivilege`.
- **Interactive Session 0 service:** rejected; trusted UI belongs in a
  service-created interactive-session LPAC.
- **Inherited handles across Session 0 and the user session:** rejected by the
  cross-session inheritance contract and the `bInheritHandles = FALSE`
  invariant.
- **Current `\\.\pipe\LOCAL\...` as the trust boundary:** rejected because it is
  session-scoped and its current-logon DACL does not exclude same-user malware.
- **Command-line, environment, raw PID, or name-secret bootstrap:** rejected as
  forgeable, observable, transferable, or insufficiently object-bound.
- **Post-creation DACL repair:** rejected as birth security because authority may
  escape before repair.
- **Service networking for convenience:** rejected; all network activity stays
  in Broker.
- **Remote-memory bootstrap without a new ADR:** rejected because it introduces
  additional VM authority not accepted by this decision.

## Release blockers

Phase 1 MUST first prove, with an inert no-secret service and real user-session
LPAC fixture on every initially claimed Windows 11 x64 build:

- restricted virtual-account token/privilege behavior;
- authenticated-client impersonation and exact primary-token derivation;
- Session-0 `CreateProcessAsUserW` composition with `STARTUPINFOEXW`,
  zero-capability LPAC, explicit process/thread security, mitigations, debug
  flags, interactive desktop access, and creation-time Job assignment;
- service ownership and exact from-birth DACL readback that denies the enrolled
  user without breaking loader/helper startup;
- cross-session zero-capability LPAC `ncalrpc` authentication and exact
  PID/token/session/service-role binding;
- `bInheritHandles = FALSE`, post-create `DuplicateHandle`, exact injected-handle
  type/access/flag validation, and no child/grandchild leakage;
- unique real-helper R10/R11 sequence, context mutation/readback, debugger-event
  provenance, suspend counts, detach, handle attenuation, and cleanup;
- lock/logoff/user-switch, timeout, crash, SCM stop/restart, and failure at every
  bootstrap edge;
- complete service/helper outbound-network denial.

Even after Phase 1, release remains blocked on the production installer and
immutable signed dependency graph, service-only storage, PCP/TPM non-exportable
key provisioning, rollback-resistant anchor, rotation/recovery, protected
settings, durable crash reconciliation, authenticated real Approval/Secret Input
E2E, canonical authorization-to-signature-to-broadcast binding, final Windows
negative matrix, Authenticode identities, offline release lineage/checkpoint,
independent review, and the final offline verifier.

No Phase 1 fixture or partial integration permits either compiled policy to
change from `None`.
